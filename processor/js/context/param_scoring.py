# C:\Users\Cheng\Desktop\JScanner2\processor\js\context\param_scoring.py
from typing import Optional, Set

from tree_sitter import Node

_FUNCTION_TYPES = {
    'function_declaration', 'function_expression',
    'arrow_function', 'method_definition'
}

_LITERAL_TYPES = {'string', 'number', 'true', 'false', 'null', 'undefined'}

_DATA_KEYS = frozenset({'data', 'params', 'body', 'query', 'payload'})


def get_param_score(func_node: Optional[Node], api_node: Node, code_bytes: bytes,
                    trace: Optional[list] = None) -> int:
    """
    对函数 AST 子树进行参数信号评分（在完整 AST 上操作，非截取文本）

    参数:
        trace: 可选的追踪列表。传入后每一步命中的信号会被 append 进去，
               形如 {"stage": "score", "signal": "...", "desc": "...", "score": n}。
               传 None（默认）时行为与迁移前完全一致。

    返回值:
        -1 → 无 enclosing function，无法判定，应放行（避免假阴性）
         0 → 函数体内无任何参数信号
        ≥1 → 存在参数信号，数值越大信号越强

    评分维度（6 个信号，总分最高理论 8）：
        信号1: 请求调用有 URL 以外的实质参数    → +1
        信号2: 对象 pair 的 key 是数据承载键     → +2（强信号）
        信号3: API URL 参与了变量拼接            → +1
        信号4: FormData / URLSearchParams 构造   → +2（强信号）
        信号5: stringify 序列化调用              → +1
        信号6: 动态属性赋值构造数据               → +1
    """
    if func_node is None:
        if trace is not None:
            trace.append({
                "stage": "score", "signal": "no_enclosing_function",
                "desc": "没有外层函数，无法判定", "score": -1,
            })
        return -1

    state = {
        'score': 0,
        'signal_request_call': False,
        'signal_data_key': False,
        'signal_url_concat': False,
        'signal_formdata': False,
        'signal_stringify': False,
        'signal_dynamic_assign': False,
    }

    checks = (
        ('signal_request_call', '请求调用带 URL 以外的实质参数',
         lambda n: _check_signal_request_call(n, api_node, code_bytes, state)),
        ('signal_data_key', '对象 key 是数据承载键 data/params/body/query/payload',
         lambda n: _check_signal_data_key(n, code_bytes, state)),
        ('signal_url_concat', 'API URL 参与了变量拼接',
         lambda n: _check_signal_url_concat(n, api_node, state)),
        ('signal_formdata', '构造了 FormData / URLSearchParams',
         lambda n: _check_signal_formdata(n, code_bytes, state)),
        ('signal_stringify', '调用了 xxx.stringify 序列化',
         lambda n: _check_signal_stringify(n, code_bytes, state)),
        ('signal_dynamic_assign', '动态属性赋值构造数据对象',
         lambda n: _check_signal_dynamic_assign(n, state)),
    )

    def _walk(node: Node):
        if not node:
            return

        for key, desc, checker in checks:
            if state[key]:
                continue
            before = state['score']
            checker(node)
            if state['score'] != before and trace is not None:
                trace.append({
                    "stage": "score", "signal": key, "desc": desc,
                    "score": state['score'] - before,
                    "line": _line_of(node, code_bytes),
                })

        for child in node.children:
            _walk(child)

    _walk(func_node)
    return state['score']


def _same_node(a: Optional[Node], b: Optional[Node]) -> bool:
    """
    判断两个 Node 是否为同一个节点。

    注意：不能用 `a is b`。tree-sitter 的 Python binding 每次访问 .children /
    .parent 都会新建 Node 对象，因此"自顶向下遍历"得到的节点和"沿 parent 链
    向上回溯"得到的节点即使指向同一处，`is` 也为 False。

    本项目里 api_node 来自自顶向下遍历，而 func_node 来自沿 parent 链回溯，
    后续再从 func_node 往下遍历时拿到的对象与 api_node 不同实例 ——
    这会让所有 `node is api_node` 判断恒为 False，导致依赖它的信号永不命中。
    统一改用字节区间比较。
    """
    if a is None or b is None:
        return False
    return a.start_byte == b.start_byte and a.end_byte == b.end_byte


def _line_of(node: Node, code_bytes: bytes) -> int:
    """节点起始行号（1-based），仅用于追踪输出"""
    try:
        return code_bytes[:node.start_byte].count(b'\n') + 1
    except Exception:
        return 0


# ==================== 辅助函数 ====================

def _find_enclosing_call_expression(node: Node) -> Optional[Node]:
    """从节点向上查找最近的 call_expression（不跨越函数边界）"""
    current = node.parent
    while current:
        if current.type == 'call_expression':
            return current
        if current.type in _FUNCTION_TYPES:
            return None
        current = current.parent
    return None


def _get_substantive_arg_count(args_node: Node) -> int:
    """计算 call_expression 的 arguments 中实质参数个数（排除括号和逗号）"""
    if not args_node:
        return 0
    count = 0
    for child in args_node.children:
        if child.type not in ('(', ')', ','):
            count += 1
    return count


def _strip_quotes(key_text: str) -> str:
    """去除字符串节点的首尾引号"""
    if len(key_text) >= 2 and key_text[0] in ('"', "'", '`') and key_text[-1] == key_text[0]:
        return key_text[1:-1]
    return key_text


# ==================== 6 个信号检测 ====================

def _check_signal_request_call(node: Node, api_node: Node, code_bytes: bytes, state: dict):
    """
    信号1: 请求调用有 URL 以外的实质参数（+1）

    从 API 字符串节点向上查找 call_expression，检查其 arguments 是否包含
    URL 以外的参数（即配置对象、数据对象等）。

    节点同一性判断用 _same_node，不能用 is（原因见 _same_node 注释）。
    """
    if not _same_node(node, api_node):
        return
    call_expr = _find_enclosing_call_expression(api_node)
    if not call_expr:
        return
    args_node = call_expr.child_by_field_name('arguments')
    if not args_node:
        return

    arg_count = _get_substantive_arg_count(args_node)

    if arg_count > 1:
        state['signal_request_call'] = True
        state['score'] += 1
        return

    if arg_count == 1:
        for child in args_node.children:
            if child.type == 'object':
                non_url_keys = []
                for pair_child in child.children:
                    if pair_child.type == 'pair':
                        key_node = pair_child.child_by_field_name('key')
                        if key_node:
                            key_text = _strip_quotes(
                                code_bytes[key_node.start_byte:key_node.end_byte].decode('utf-8')
                            )
                            if key_text and key_text != 'url':
                                non_url_keys.append(key_text)
                if len(non_url_keys) > 1:
                    state['signal_request_call'] = True
                    state['score'] += 1


def _check_signal_data_key(node: Node, code_bytes: bytes, state: dict):
    """
    信号2: 对象 pair 的 key 是数据承载键（+2，强信号）

    扫描函数子树内所有 object → pair，检查 key 是否为
    data / params / body / query / payload。
    """
    if node.type != 'pair':
        return
    key_node = node.child_by_field_name('key')
    if not key_node:
        return
    key_text = _strip_quotes(
        code_bytes[key_node.start_byte:key_node.end_byte].decode('utf-8')
    )
    if key_text in _DATA_KEYS:
        state['signal_data_key'] = True
        state['score'] += 2


def _check_signal_url_concat(node: Node, api_node: Node, state: dict):
    """
    信号3: API URL 字符串参与了二元表达式拼接（+1）

    从 API string 节点向上查找，如果 parent 是 binary_expression 且
    operator 是 +，说明 URL 在与变量拼接（路径参数）。

    节点同一性判断用 _same_node，不能用 is（原因见 _same_node 注释）。
    """
    if not _same_node(node, api_node):
        return
    current = api_node.parent
    while current and current.type not in _FUNCTION_TYPES:
        if current.type == 'binary_expression':
            op_node = current.child_by_field_name('operator')
            if op_node and op_node.type == '+':
                state['signal_url_concat'] = True
                state['score'] += 1
            return
        current = current.parent


def _check_signal_formdata(node: Node, code_bytes: bytes, state: dict):
    """
    信号4: FormData 或 URLSearchParams 构造（+2，强信号）

    扫描 new_expression 节点，检查 constructor 是否是 FormData 或 URLSearchParams。
    """
    if node.type != 'new_expression':
        return
    constructor = node.child_by_field_name('constructor')
    if constructor and constructor.type == 'identifier':
        name = code_bytes[constructor.start_byte:constructor.end_byte].decode('utf-8')
        if name in ('FormData', 'URLSearchParams'):
            state['signal_formdata'] = True
            state['score'] += 2


def _check_signal_stringify(node: Node, code_bytes: bytes, state: dict):
    """
    信号5: stringify 序列化调用（+1）

    扫描 call_expression 节点，检查被调用函数是否包含 stringify 属性。
    匹配: JSON.stringify(...)、qs.stringify(...)、(0, s.stringify)(...)
    """
    if node.type != 'call_expression':
        return
    callee = node.child_by_field_name('function')
    if not callee:
        return
    if callee.type == 'member_expression':
        prop = callee.child_by_field_name('property')
        if prop:
            prop_name = code_bytes[prop.start_byte:prop.end_byte].decode('utf-8')
            if 'stringify' in prop_name:
                state['signal_stringify'] = True
                state['score'] += 1


def _check_signal_dynamic_assign(node: Node, state: dict):
    """
    信号6: 动态属性赋值（+1）

    扫描 assignment_expression 节点，如果 left 是 member_expression（obj.prop = value）
    且 right 不是纯字面量（是变量/表达式），说明在动态构造数据对象。
    匹配: config.data = {id: e}; obj[key] = value;
    """
    if node.type != 'assignment_expression':
        return
    left = node.child_by_field_name('left')
    right = node.child_by_field_name('right')
    if left and left.type in ('member_expression', 'subscript_expression'):
        if right and right.type not in _LITERAL_TYPES:
            state['signal_dynamic_assign'] = True
            state['score'] += 1
