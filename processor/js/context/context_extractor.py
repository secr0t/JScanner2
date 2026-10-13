import re
from typing import Any, Dict, Optional, List, Set, Tuple
from tree_sitter import Node

from processor.js.context.parse import get_parser, get_logger
from processor.js.context.param_scoring import get_param_score

# 上下文大小限制常量
MAX_CONTEXT_BYTES = 5000  # 约5KB
MAX_CONTEXT_TOKENS_ESTIMATE = 1500
_MAX_OBJECT_BYTES = 50000

_FUNCTION_TYPES = {
    'function_declaration', 'function_expression',
    'arrow_function', 'method_definition'
}


def _line_of(node: Node, code_bytes: bytes) -> int:
    """节点起始行号（1-based），仅用于过程追踪输出"""
    try:
        return code_bytes[:node.start_byte].count(b'\n') + 1
    except Exception:
        return 0


def _node_text_equals(node: Node, source_bytes: bytes, target_bytes: bytes) -> bool:
    if not node:
        return False
    return source_bytes[node.start_byte:node.end_byte] == target_bytes


def _find_identifiers_in_node(node: Node, code_bytes: bytes) -> Set[str]:
    """提取一个节点内使用的所有标识符 (变量名)"""
    idents = set()
    if node.type == 'identifier':
        idents.add(code_bytes[node.start_byte:node.end_byte].decode('utf-8'))
    for child in node.children:
        idents.update(_find_identifiers_in_node(child, code_bytes))
    return idents


def _find_semantic_boundary(node: Node) -> Optional[Node]:
    """
    寻找包含该节点的最小有意义语义边界
    优先级：函数/方法定义 > 对象属性 > 语句
    """
    current = node
    while current:
        # 第一优先级：函数/方法定义
        if current.type in {
            'function_declaration',
            'function_expression',
            'arrow_function',
            'method_definition'
        }:
            return current

        # 第二优先级：对象属性（当值是函数时）
        if current.type in {'pair', 'property'}:
            value_node = current.child_by_field_name('value')
            if value_node and value_node.type in {
                'function',
                'function_expression',
                'arrow_function',
                'method_definition'
            }:
                return current

        current = current.parent

    return None


def _extract_complete_boundary(boundary_node: Node, code_bytes: bytes) -> str:
    """提取完整的语义边界节点代码"""
    return code_bytes[boundary_node.start_byte:boundary_node.end_byte].decode('utf-8')


# ==================== 变量传播法 ====================

def _is_scope_boundary(node: Node) -> bool:
    return node.type in _FUNCTION_TYPES or node.type == 'program'


def _extract_string_content(node_bytes: bytes) -> Optional[str]:
    """从 string 节点的原始 bytes 中提取字符串内容（去掉引号）"""
    text = node_bytes.decode('utf-8')
    if len(text) < 2:
        return None
    quote = text[0]
    if quote in ('"', "'", '`') and text[-1] == quote:
        inner = text[1:-1]
        return inner.replace('\\"', '"').replace("\\'", "'").replace('\\\\', '\\')
    return text


def _build_scope_chain(usage_node: Node, code_bytes: bytes) -> List[List[Node]]:
    """
    从使用点向上遍历，收集作用域链（局部 → 全局）
    每个 scope 是该作用域内所有 variable_declaration / lexical_declaration / assignment_expression 节点列表
    """
    scopes = []
    current = usage_node.parent

    while current:
        if _is_scope_boundary(current):
            scope_decls = []
            _collect_decls_in_subtree(current, scope_decls)
            scopes.append(scope_decls)
            if current.type == 'program':
                break
        current = current.parent

    return scopes


def _collect_decls_in_subtree(node: Node, decls: List[Node]):
    """递归收集节点子树中所有声明/赋值节点"""
    if node.type in ('variable_declaration', 'lexical_declaration'):
        decls.append(node)
        return
    if node.type == 'assignment_expression':
        decls.append(node)
    for child in node.children:
        if child.type in _FUNCTION_TYPES:
            continue
        _collect_decls_in_subtree(child, decls)


def _find_var_value_node(var_name: str, usage_node: Node, code_bytes: bytes) -> Optional[Node]:
    """
    带作用域优先级的变量查找：局部作用域 → 全局作用域
    返回变量定义的 value 节点（声明必须在使用点之前）
    """
    target = var_name.encode('utf-8')
    scopes = _build_scope_chain(usage_node, code_bytes)

    for decls in scopes:
        for decl in decls:
            if decl.start_byte >= usage_node.start_byte:
                continue
            if decl.type == 'assignment_expression':
                left_node = decl.child_by_field_name('left')
                if left_node and left_node.type == 'identifier':
                    if code_bytes[left_node.start_byte:left_node.end_byte] == target:
                        value_node = decl.child_by_field_name('right')
                        if value_node:
                            return value_node
                continue
            for child in decl.children:
                if child.type != 'variable_declarator':
                    continue
                name_node = child.child_by_field_name('name')
                if not name_node:
                    continue
                if code_bytes[name_node.start_byte:name_node.end_byte] == target:
                    value_node = child.child_by_field_name('value')
                    if value_node:
                        return value_node
    return None


def _resolve_object_lookup(obj_node: Node, prop_name: str, code_bytes: bytes) -> Optional[Node]:
    """在对象字面量 AST 节点中查找指定 key 的 value 节点"""
    if obj_node.type != 'object':
        return None
    if obj_node.end_byte - obj_node.start_byte > _MAX_OBJECT_BYTES:
        return None

    target = prop_name.encode('utf-8')
    for child in obj_node.children:
        if child.type != 'pair':
            continue
        key_node = child.child_by_field_name('key')
        if not key_node:
            continue
        key_text = code_bytes[key_node.start_byte:key_node.end_byte]
        key_str = key_text.decode('utf-8')
        if len(key_str) >= 2 and key_str[0] in ('"', "'"):
            key_str = key_str[1:-1]
        if key_str == prop_name:
            return child.child_by_field_name('value')
    return None


def _resolve_array_lookup(arr_node: Node, index: int, code_bytes: bytes) -> Optional[Node]:
    """在数组字面量 AST 节点中按索引取值"""
    if arr_node.type != 'array':
        return None
    if arr_node.end_byte - arr_node.start_byte > _MAX_OBJECT_BYTES:
        return None

    elements = [c for c in arr_node.children if c.type not in ('[', ']', ',')]
    if 0 <= index < len(elements):
        return elements[index]
    return None


def _resolve_node_to_string(node: Node, code_bytes: bytes, resolving: Set[str]) -> Optional[str]:
    """
    统一递归解析入口：将 AST 节点解析为字符串值
    支持：字符串字面量、+拼接、变量引用、对象属性访问、数组索引访问
    """
    if not node:
        return None

    if node.type == 'string':
        return _extract_string_content(code_bytes[node.start_byte:node.end_byte])

    if node.type == 'binary_expression':
        op_node = node.child_by_field_name('operator')
        if op_node and code_bytes[op_node.start_byte:op_node.end_byte] == b'+':
            left = _resolve_node_to_string(node.child_by_field_name('left'), code_bytes, resolving)
            right = _resolve_node_to_string(node.child_by_field_name('right'), code_bytes, resolving)
            if left is not None and right is not None:
                return left + right
        return None

    if node.type == 'identifier':
        var_name = code_bytes[node.start_byte:node.end_byte].decode('utf-8')
        if var_name in resolving:
            return None
        resolving.add(var_name)
        value_node = _find_var_value_node(var_name, node, code_bytes)
        resolving.discard(var_name)
        if not value_node:
            return None
        return _resolve_node_to_string(value_node, code_bytes, resolving)

    if node.type == 'member_expression':
        obj_node = node.child_by_field_name('object')
        prop_node = node.child_by_field_name('property')
        if not obj_node or not prop_node:
            return None
        prop_name = code_bytes[prop_node.start_byte:prop_node.end_byte].decode('utf-8')
        if obj_node.type != 'identifier':
            return None
        obj_var_name = code_bytes[obj_node.start_byte:obj_node.end_byte].decode('utf-8')
        obj_ast_node = _find_var_value_node(obj_var_name, obj_node, code_bytes)
        if not obj_ast_node or obj_ast_node.type != 'object':
            return None
        target_node = _resolve_object_lookup(obj_ast_node, prop_name, code_bytes)
        if not target_node:
            return None
        return _resolve_node_to_string(target_node, code_bytes, resolving)

    if node.type == 'subscript_expression':
        obj_node = node.child_by_field_name('object')
        idx_node = node.child_by_field_name('index')
        if not obj_node or not idx_node:
            return None
        if obj_node.type != 'identifier':
            return None
        obj_var_name = code_bytes[obj_node.start_byte:obj_node.end_byte].decode('utf-8')
        if idx_node.type == 'string':
            prop_name = _extract_string_content(code_bytes[idx_node.start_byte:idx_node.end_byte])
            if prop_name is None:
                return None
            obj_ast_node = _find_var_value_node(obj_var_name, obj_node, code_bytes)
            if not obj_ast_node or obj_ast_node.type != 'object':
                return None
            target_node = _resolve_object_lookup(obj_ast_node, prop_name, code_bytes)
            if not target_node:
                return None
            return _resolve_node_to_string(target_node, code_bytes, resolving)
        elif idx_node.type == 'number':
            try:
                index = int(code_bytes[idx_node.start_byte:idx_node.end_byte].decode('utf-8'))
            except ValueError:
                return None
            obj_ast_node = _find_var_value_node(obj_var_name, obj_node, code_bytes)
            if not obj_ast_node or obj_ast_node.type != 'array':
                return None
            target_node = _resolve_array_lookup(obj_ast_node, index, code_bytes)
            if not target_node:
                return None
            return _resolve_node_to_string(target_node, code_bytes, resolving)

    return None


def _propagate_variables(stmt_node: Node, target_node: Node, code_bytes: bytes,
                         trace: Optional[list] = None) -> str:
    """
    对代码切片内的字符串变量执行传播替换
    在字节层面做精确替换，避免编码偏移问题
    """
    slice_start = stmt_node.start_byte
    slice_end = stmt_node.end_byte
    slice_bytes = code_bytes[slice_start:slice_end]

    def _record(node: Node, original: str, value: str):
        if trace is None:
            return
        trace.append({
            "stage": "propagate",
            "name": original,
            "value": value,
            "line": _line_of(node, code_bytes),
        })

    replacements = []
    resolved_ranges = []

    def _collect(node):
        if node.type in ('member_expression', 'subscript_expression'):
            resolved_ranges.append((node.start_byte, node.end_byte))
        for child in node.children:
            _collect(child)

    _collect(stmt_node)

    def _traverse(node):
        if node.start_byte < slice_start or node.end_byte > slice_end:
            return

        if node.start_byte >= target_node.start_byte and node.end_byte <= target_node.end_byte:
            for child in node.children:
                _traverse(child)
            return

        if node.type == 'identifier':
            for rs, re in resolved_ranges:
                if node.start_byte >= rs and node.end_byte <= re:
                    return
            resolving = set()
            value = _resolve_node_to_string(node, code_bytes, resolving)
            if value is not None:
                original = code_bytes[node.start_byte:node.end_byte].decode('utf-8')
                replacement = f'"{value}"'
                if replacement != original:
                    replacements.append((
                        node.start_byte - slice_start,
                        node.end_byte - slice_start,
                        replacement.encode('utf-8')
                    ))
                    _record(node, original, value)

        elif node.type in ('member_expression', 'subscript_expression'):
            resolving = set()
            value = _resolve_node_to_string(node, code_bytes, resolving)
            if value is not None:
                original = code_bytes[node.start_byte:node.end_byte].decode('utf-8')
                replacement = f'"{value}"'
                if replacement != original:
                    replacements.append((
                        node.start_byte - slice_start,
                        node.end_byte - slice_start,
                        replacement.encode('utf-8')
                    ))
                    _record(node, original, value)
            return

        for child in node.children:
            _traverse(child)

    _traverse(stmt_node)

    if not replacements:
        if trace is not None:
            trace.append({"stage": "propagate_done", "count": 0, "bytes": len(slice_bytes)})
        return slice_bytes.decode('utf-8')

    replacements.sort(key=lambda x: x[0], reverse=True)
    result = bytearray(slice_bytes)
    for start, end, new_bytes in replacements:
        result[start:end] = new_bytes

    if trace is not None:
        trace.append({
            "stage": "propagate_done",
            "count": len(replacements),
            "bytes": len(result),
        })

    return result.decode('utf-8')


# ==================== 变量传播法 END ====================


def _is_declared_in_function(func_node: Node, var_name: str, usage_node: Node, code_bytes: bytes) -> bool:
    """检查变量是否在当前函数作用域内局部声明"""
    target = var_name.encode('utf-8')
    scopes = _build_scope_chain(usage_node, code_bytes)
    for decls in scopes:
        for decl in decls:
            if decl.start_byte < func_node.start_byte or decl.end_byte > func_node.end_byte:
                continue
            if decl.type == 'assignment_expression':
                left = decl.child_by_field_name('left')
                if left and left.type == 'identifier':
                    if code_bytes[left.start_byte:left.end_byte] == target:
                        return True
                continue
            for child in decl.children:
                if child.type != 'variable_declarator':
                    continue
                name_node = child.child_by_field_name('name')
                if name_node and code_bytes[name_node.start_byte:name_node.end_byte] == target:
                    return True
    return False


def _collect_free_var_declarations(func_node: Node, api_node: Node, code_bytes: bytes,
                                   max_decl_bytes: int = 1500,
                                   trace: Optional[list] = None) -> str:
    """
    收集函数内引用的自由变量（在外层作用域定义），将其声明代码提取出来。

    目的：让 AI 看到 data: t 时，不仅看到 t 怎么来的，还能看到 t 所依赖的 r 到底是什么。

    只收集"有实质内容"的定义（object / array / string），跳过函数调用结果（如 webpack import）。
    """
    free_vars = set()
    func_start = func_node.start_byte
    func_end = func_node.end_byte

    param_names = set()
    params_node = func_node.child_by_field_name('parameters')
    if params_node:
        def _walk_params(node):
            if node.type == 'identifier':
                param_names.add(code_bytes[node.start_byte:node.end_byte].decode('utf-8'))
            for child in node.children:
                _walk_params(child)
        _walk_params(params_node)

    def _collect(node):
        if node.type == 'identifier':
            name = code_bytes[node.start_byte:node.end_byte].decode('utf-8')
            if name in param_names or name in free_vars:
                return

            if _is_declared_in_function(func_node, name, node, code_bytes):
                return

            value_node = _find_var_value_node(name, node, code_bytes)
            if value_node and value_node.type in ('object', 'array', 'string'):
                free_vars.add(name)

        for child in node.children:
            _collect(child)

    _collect(func_node)

    if trace is not None:
        trace.append({
            "stage": "free_vars",
            "names": sorted(free_vars),
            "params": sorted(param_names),
        })

    if not free_vars:
        return ""

    dependencies = []
    seen_ranges = set()

    for var_name in free_vars:
        value_node = _find_var_value_node(var_name, api_node, code_bytes)
        if not value_node:
            continue
        if value_node.type not in ('object', 'array', 'string'):
            continue

        decl_size = value_node.end_byte - value_node.start_byte
        if decl_size > max_decl_bytes:
            if trace is not None:
                trace.append({
                    "stage": "free_var_skip",
                    "name": var_name,
                    "reason": f"定义体积 {decl_size} > 上限 {max_decl_bytes}",
                })
            continue

        # 找到 variable_declarator 层级（只取 r = {...} 这一个，不取整个 const r=..., o=...）
        declarator_node = value_node.parent
        while declarator_node and declarator_node.type != 'variable_declarator':
            declarator_node = declarator_node.parent

        if not declarator_node:
            continue

        if func_start <= declarator_node.start_byte < func_end:
            continue

        range_key = (declarator_node.start_byte, declarator_node.end_byte)
        if range_key in seen_ranges:
            continue
        seen_ranges.add(range_key)

        # 从父级 lexical_declaration/variable_declaration 提取声明关键字 (var/let/const)
        decl_parent = declarator_node.parent
        keyword = "var"
        if decl_parent and decl_parent.type in ('variable_declaration', 'lexical_declaration'):
            if decl_parent.children:
                first_child = decl_parent.children[0]
                kw_text = code_bytes[first_child.start_byte:first_child.end_byte].decode('utf-8')
                if kw_text in ('var', 'let', 'const'):
                    keyword = kw_text

        decl_code = code_bytes[declarator_node.start_byte:declarator_node.end_byte].decode('utf-8')
        dependencies.append(f"{keyword} {decl_code};")

        if trace is not None:
            trace.append({
                "stage": "free_var_add",
                "name": var_name,
                "keyword": keyword,
                "bytes": decl_size,
                "line": _line_of(declarator_node, code_bytes),
            })

    if not dependencies:
        return ""

    return "\n".join(dependencies) + "\n"


def _extract_heuristic_slice(api_node: Node, code_bytes: bytes,
                             trace: Optional[list] = None) -> str:

    # 策略1：尝试提取语义边界
    semantic_boundary = _find_semantic_boundary(api_node)
    if semantic_boundary:
        boundary_code = _extract_complete_boundary(semantic_boundary, code_bytes)

        if trace is not None:
            trace.append({
                "stage": "boundary",
                "strategy": "语义边界优先",
                "node_type": semantic_boundary.type,
                "line_range": (semantic_boundary.start_point[0] + 1,
                               semantic_boundary.end_point[0] + 1),
                "bytes": len(boundary_code.encode('utf-8')),
            })

        # 检查大小是否在合理范围内
        if len(boundary_code.encode('utf-8')) <= MAX_CONTEXT_BYTES:
            propagated = _propagate_variables(semantic_boundary, api_node, code_bytes, trace)

            # 收集自由变量声明
            if semantic_boundary.type in _FUNCTION_TYPES:
                free_var_deps = _collect_free_var_declarations(
                    semantic_boundary, api_node, code_bytes, trace=trace)
                if free_var_deps:
                    propagated = free_var_deps + propagated

            if len(propagated.encode('utf-8')) <= MAX_CONTEXT_BYTES:
                return propagated

            if trace is not None:
                trace.append({
                    "stage": "downgrade",
                    "reason": f"传播后 {len(propagated.encode('utf-8'))} 字节 > 上限 "
                              f"{MAX_CONTEXT_BYTES}，丢弃传播结果改用原始边界代码",
                })
            return boundary_code

        if trace is not None:
            trace.append({
                "stage": "boundary_too_big",
                "reason": f"语义边界 {len(boundary_code.encode('utf-8'))} 字节 > 上限 "
                          f"{MAX_CONTEXT_BYTES}，降级到语句级",
            })

    # 策略2：降级到语句级别提取
    stmt_node = api_node
    while stmt_node and not (stmt_node.type.endswith(
            'statement') or stmt_node.type == 'variable_declarator' or stmt_node.type == 'property'):
        stmt_node = stmt_node.parent

    if not stmt_node:
        if trace is not None:
            trace.append({"stage": "fallback", "reason": "找不到任何语句边界，只截取 API 字符串本身"})
        return code_bytes[api_node.start_byte:api_node.end_byte].decode('utf-8')

    if trace is not None:
        trace.append({
            "stage": "boundary",
            "strategy": "语句级降级",
            "node_type": stmt_node.type,
            "line_range": (stmt_node.start_point[0] + 1, stmt_node.end_point[0] + 1),
            "bytes": stmt_node.end_byte - stmt_node.start_byte,
        })

    core_line = _propagate_variables(stmt_node, api_node, code_bytes, trace)

    # 用统一的自由变量回溯收集依赖
    enclosing_func = _find_enclosing_function(api_node)
    dependencies = ""
    if enclosing_func:
        dependencies = _collect_free_var_declarations(enclosing_func, api_node, code_bytes, trace=trace)

    final_slice = dependencies + core_line

    if len(final_slice.encode('utf-8')) > MAX_CONTEXT_BYTES:
        if trace is not None:
            trace.append({
                "stage": "downgrade",
                "reason": f"带依赖 {len(final_slice.encode('utf-8'))} 字节 > 上限 "
                          f"{MAX_CONTEXT_BYTES}，只保留语句本体",
            })
        return core_line

    return final_slice


def _find_enclosing_function(node: Node) -> Optional[Node]:
    """获取函数节点，用于获取函数名"""
    current = node
    while current:
        if current.type in {'function_declaration', 'arrow_function', 'function_expression', 'method_definition'}:
            return current
        current = current.parent
    return None


def _get_function_name(func_node: Node, code_bytes: bytes) -> Optional[str]:
    """获取函数的名称"""
    if not func_node: return None
    if func_node.type == 'function_declaration':
        name_node = func_node.child_by_field_name('name')
        if name_node: return code_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')
    parent = func_node.parent
    if parent:
        if parent.type == 'variable_declarator':
            name_node = parent.child_by_field_name('name')
            if name_node: return code_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')
        elif parent.type == 'assignment_expression':
            left_node = parent.child_by_field_name('left')
            if left_node: return code_bytes[left_node.start_byte:left_node.end_byte].decode('utf-8')
    return None


# ============================================================
# Caller 召回：绑定作用域约束 + 元数校验 + 确定性排序
# ============================================================
#
# 原实现按「被调函数名文本」做全树匹配（call_index），不区分作用域。
# webpack 打包后每个 module 是独立函数作用域，压缩变量名（e/t/n/a/r/o/i/c…）
# 在几十个 module 里反复复用，导致跨 module 同名串台 —— 实测 8 个 caller 全是误报。
#
# 三道过滤，按开销从小到大：
#   1. 绑定作用域：调用点必须落在 wrapper 名字的绑定作用域字节区间内
#   2. 元数校验：实参个数必须落在 [形参下限, 形参上限] 内
#   3. 确定性排序：取代 list(set(...))，消除 Python str hash 随机化导致的顺序抖动
#
# 任一环节无法判定时一律「放行」（宁可多召回，也不误杀），返回 None 即代表放行。
# ============================================================

_CALLER_PARAM_SIGNALS = (
    re.compile(r'''\bparams\s*:'''),
    re.compile(r'''\bdata\s*:'''),
    re.compile(r'''\bbody\s*:'''),
    re.compile(r'''\bquery\s*:'''),
    re.compile(r'''\bpayload\s*:'''),
    re.compile(r'''JSON\.stringify\s*\('''),
    re.compile(r'''URLSearchParams'''),
    re.compile(r'''\bFormData\b'''),
    re.compile(r'''\.append\s*\(\s*["']\w{2,}'''),
    re.compile(r'''Object\.assign\s*\('''),
    re.compile(r'''\.(?:get|post|put|patch|delete|request)\s*\([^)]+,'''),
)


def _nearest_statement_block(node: Node) -> Optional[Node]:
    """最近的 statement_block（含函数体），用于 const/let 的块级作用域判定"""
    cur = node
    while cur is not None:
        if cur.type == 'statement_block':
            return cur
        cur = cur.parent
    return None


def _nearest_function_ancestor(node: Node) -> Optional[Node]:
    """最近的函数祖先，用于 var 的函数级作用域判定"""
    cur = node
    while cur is not None:
        if cur.type in _FUNCTION_TYPES:
            return cur
        cur = cur.parent
    return None


def _binding_scope_of(func_node: Node) -> Optional[Node]:
    """
    wrapper 名字的绑定作用域节点。

        const / let      → 声明所在的最近 statement_block（块级）
        var              → 最近的函数作用域（var 会 hoist，跨块可见）
        function 声明    → 最近 statement_block
        赋值表达式 / 其它 → 最近的函数作用域

    返回 None 表示「顶层」，调用方会退化为整棵树。
    """
    if func_node is None:
        return None

    if func_node.type == 'function_declaration':
        return _nearest_statement_block(func_node)

    parent = func_node.parent
    if parent is not None and parent.type == 'variable_declarator':
        decl = parent.parent
        if decl is not None and decl.type == 'lexical_declaration':
            return _nearest_statement_block(decl)
        return _nearest_function_ancestor(decl if decl is not None else parent)

    if parent is not None and parent.type == 'assignment_expression':
        return _nearest_function_ancestor(parent)

    return _nearest_function_ancestor(func_node)


def _wrapper_arity(func_node: Node) -> Optional[Tuple[int, Optional[int]]]:
    """
    wrapper 可接受的实参个数区间 (min_args, max_args)。

        max_args = None → 不设上限（存在 rest 参数 ...args）
        返回 None       → 无法确定，调用方应放行

    带默认值的形参只抬上限不抬下限（可以不传）。
    """
    if func_node is None:
        return None

    params = func_node.child_by_field_name('parameters')

    # 单参数箭头函数可不写括号：e => ...，字段名是 parameter 而非 parameters
    if params is None:
        single = func_node.child_by_field_name('parameter')
        if single is None:
            return None
        if single.type == 'rest_pattern':
            return (0, None)
        return (1, 1)

    min_args = 0
    max_args = 0
    unbounded = False
    seen_any = False

    for ch in params.children:
        if not ch.is_named:
            continue
        seen_any = True
        if ch.type == 'rest_pattern':
            unbounded = True
            continue
        if ch.type in ('assignment_pattern', 'optional_parameter'):
            max_args += 1
            continue
        min_args += 1
        max_args += 1

    if not seen_any:
        return None
    return (min_args, None if unbounded else max_args)


def _call_arg_count(call_node: Node) -> Optional[int]:
    """
    调用点的实参个数。

    遇到 f(...args) 展平调用时返回 None（放行，不做元数判定）。
    """
    args = call_node.child_by_field_name('arguments')
    if args is None:
        return None

    count = 0
    for ch in args.children:
        if not ch.is_named:
            continue
        if ch.type == 'spread_element':
            return None
        count += 1
    return count


def _has_caller_param_signal(code: str) -> bool:
    """caller 代码里是否存在参数构造痕迹，用于「信息密度优先」排序"""
    return any(p.search(code) for p in _CALLER_PARAM_SIGNALS)


def _find_callers_of_function(root_node: Node, func_name: str, code_bytes: bytes) -> List[str]:
    """遍历 AST，寻找所有调用了 func_name 的地方 (同样采用切片思想截取上下文)"""
    callers_code = []
    target_name_bytes = func_name.encode('utf-8')

    def traverse(node):
        if node.type == 'call_expression':
            callee = node.child_by_field_name('function')
            if callee and callee.type == 'identifier' and _node_text_equals(callee, code_bytes, target_name_bytes):
                # 找到调用点后，不再提取整个外层函数，而是提取这个调用点所在的完整语句
                stmt_node = node
                while stmt_node and not (
                        stmt_node.type.endswith('statement') or stmt_node.type == 'variable_declarator'):
                    stmt_node = stmt_node.parent

                if stmt_node:
                    callers_code.append(code_bytes[stmt_node.start_byte:stmt_node.end_byte].decode('utf-8'))
                else:
                    callers_code.append(code_bytes[node.start_byte:node.end_byte].decode('utf-8'))
        for child in node.children:
            traverse(child)

    traverse(root_node)
    return list(set(callers_code))


def _extract_multiple_apis_from_bytes(code_bytes: bytes, target_apis: list,
                                      trace: Optional[list] = None) -> Dict[str, Dict[str, Any]]:
    _PARSER = get_parser()
    logger = get_logger()

    results = {
        api: {
            "found": False,
            "api_url": api,
            "wrapper_code": "",
            "caller_codes": [],
            "param_score": 0
        } for api in target_apis
    }

    if _PARSER is None:
        logger.error("[-] Parser not initialized.")
        return results

    try:
        tree = _PARSER.parse(code_bytes)
    except Exception as e:
        logger.error(f"[-] Parsing error: {e}")
        return results

    if trace is not None:
        trace.append({
            "stage": "parse",
            "root_type": tree.root_node.type,
            "has_error": tree.root_node.has_error,
            "api_line": _line_of(tree.root_node, code_bytes),
        })

    hit_nodes = []

    target_apis_bytes = [api.encode('utf-8') for api in target_apis]

    call_index = {}

    def _single_pass_traverse(node: Node):
        """仅做一次全树遍历，同时完成所有数据的打标与收集"""

        # 任务 A: 收集目标 API 字符串节点
        if node.type == 'string':
            # 直接在 bytes 层面做包含判断，极速！
            raw_bytes = code_bytes[node.start_byte:node.end_byte]
            for i, api_bytes in enumerate(target_apis_bytes):
                if api_bytes in raw_bytes:
                    hit_nodes.append((target_apis[i], node))
                    break  # 一个节点匹配上就行了

        # 任务 B: 收集所有的函数调用 (为后面找 Caller 做铺垫)
        elif node.type == 'call_expression':
            callee = node.child_by_field_name('function')
            if callee and callee.type == 'identifier':
                # 提取函数名 (以 bytes 形式存)
                func_name_bytes = code_bytes[callee.start_byte:callee.end_byte]
                if func_name_bytes not in call_index:
                    call_index[func_name_bytes] = []
                call_index[func_name_bytes].append(node)

        # 递归下去
        for child in node.children:
            _single_pass_traverse(child)

    _single_pass_traverse(tree.root_node)

    if trace is not None:
        trace.append({
            "stage": "scan",
            "hits": len(hit_nodes),
            "call_index_size": len(call_index),
        })

    for target_api, api_node in hit_nodes:
        result_data = results[target_api]
        result_data["found"] = True

        raw_text = code_bytes[api_node.start_byte:api_node.end_byte].decode('utf-8', errors='replace')
        if trace is not None:
            trace.append({
                "stage": "hit",
                "api": target_api,
                "line": _line_of(api_node, code_bytes),
                "raw_string": raw_text,
                "exact_match": raw_text.strip('"\'`') == target_api,
            })

        # 1. 切片提取 (使用增强版语义边界优先策略)
        result_data["wrapper_code"] = _extract_heuristic_slice(api_node, code_bytes, trace)

        # 2. 寻找调用链 (享受刚才建立的索引带来的极速快感)
        wrapper_func_node = _find_enclosing_function(api_node)

        if trace is not None and wrapper_func_node is not None:
            trace.append({
                "stage": "wrapper_func",
                "name": _get_function_name(wrapper_func_node, code_bytes),
                "node_type": wrapper_func_node.type,
                "line_range": (wrapper_func_node.start_point[0] + 1,
                               wrapper_func_node.end_point[0] + 1),
            })

        # 3. AST 参数信号评分（在完整函数节点上操作，非截取文本）
        result_data["param_score"] = get_param_score(wrapper_func_node, api_node, code_bytes, trace)

        if wrapper_func_node:
            func_name = _get_function_name(wrapper_func_node, code_bytes)
            if func_name:
                func_name_bytes = func_name.encode('utf-8')

                matching_call_nodes = call_index.get(func_name_bytes, [])

                # ---- 过滤 1：绑定作用域（None 表示顶层，退化为整棵树）----
                binding_scope = _binding_scope_of(wrapper_func_node)
                if binding_scope is None:
                    binding_scope = tree.root_node
                scope_start = binding_scope.start_byte
                scope_end = binding_scope.end_byte

                # ---- 过滤 2：元数校验 ----
                arity = _wrapper_arity(wrapper_func_node)

                dropped_scope = 0
                dropped_arity = 0
                groups = {}

                for call_node in matching_call_nodes:
                    if not (scope_start <= call_node.start_byte
                            and call_node.end_byte <= scope_end):
                        dropped_scope += 1
                        continue

                    argc = _call_arg_count(call_node)
                    if arity is not None and argc is not None:
                        lo, hi = arity
                        if argc < lo or (hi is not None and argc > hi):
                            dropped_arity += 1
                            continue

                    # ---- 取调用点所在的外层函数作为 caller 上下文 ----
                    context_node = _find_enclosing_function(call_node)
                    if context_node is None:
                        context_node = call_node
                        while context_node and not (
                                context_node.type.endswith('statement')
                                or context_node.type == 'variable_declarator'):
                            context_node = context_node.parent
                        if context_node is None:
                            context_node = call_node

                    # 按「上下文节点的字节区间」去重并记录命中次数，
                    # 取代原先按代码文本去重的 list(set(...))（后者会丢失调用次数）
                    key = (context_node.start_byte, context_node.end_byte)
                    group = groups.get(key)
                    if group is None:
                        snippet = code_bytes[key[0]:key[1]].decode('utf-8', errors='replace')
                        groups[key] = {
                            "code": snippet,
                            "hits": 1,
                            "line": _line_of(context_node, code_bytes),
                            "size": len(snippet.encode('utf-8')),
                            # 有参数信号的排前
                            "signal": 0 if _has_caller_param_signal(snippet) else 1,
                        }
                    else:
                        group["hits"] += 1

                # ---- 确定性排序：参数信号 → 字节数小 → 行号 ----
                ranked = sorted(
                    groups.values(),
                    key=lambda g: (g["signal"], g["size"], g["line"])
                )

                result_data["caller_codes"] = [g["code"] for g in ranked]

                if trace is not None:
                    trace.append({
                        "stage": "callers",
                        "func_name": func_name,
                        "call_sites": len(matching_call_nodes),
                        "dropped_scope": dropped_scope,
                        "dropped_arity": dropped_arity,
                        "kept_call_sites": sum(g["hits"] for g in ranked),
                        "unique_callers": len(ranked),
                        "scope_range": (binding_scope.start_point[0] + 1,
                                        binding_scope.end_point[0] + 1),
                        "detail": [
                            {
                                "line": g["line"],
                                "size": g["size"],
                                "hits": g["hits"],
                                "signal": g["signal"] == 0,
                            }
                            for g in ranked
                        ],
                    })

    return results


def extract_multiple_apis_from_raw_code(js_code: str, target_apis: list,
                                        trace: Optional[list] = None) -> Dict[str, Dict[str, Any]]:
    if not isinstance(js_code, str) or not isinstance(target_apis, list):
        return {}
    return _extract_multiple_apis_from_bytes(
        js_code.encode('utf-8', errors='replace'), target_apis, trace)

