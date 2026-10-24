from typing import List, Dict, Any
from tree_sitter import Node

from processor.js.context.parse import get_parser
from processor.js.context.context_extractor import (
    _find_enclosing_function,
    _find_semantic_boundary,
    _propagate_variables,
)
from infra.dedup import DuplicateChecker
from config.scanner_rules import is_api_path_blacklisted
from logger import get_logger

logger = get_logger(__name__)


def _is_path_blacklisted(path: str) -> bool:
    if not path or not isinstance(path, str):
        return True

    try:
        from urllib.parse import urlparse
        path_clean = urlparse(path).path.lower()
    except Exception:
        path_clean = path.lower()

    return is_api_path_blacklisted(path_clean)


async def process_scan_result(scan_info, checker: DuplicateChecker, args, seed_url: str = None):
    """
    处理扫描结果（去重 + 提取下一层 URL）

    Args:
        scan_info: 扫描结果信息
        checker: 去重检查器
        args: 命令行参数
        seed_url: 原始种子URL或已验证的baseURL（用于URL拼接基准）
    """
    url = scan_info["url"]
    source = scan_info.get("source_code", "")
    status = scan_info["status"]
    title = scan_info.get("title", "NULL")
    length = scan_info.get("length", 0)

    # 1. 基础过滤
    if not checker.is_within_scope(url):
        return False, set(), []
    if status == 404:
        return False, set(), []
    if not source or length < 200:
        return False, set(), []
    if len(source) > 20 * 1024 * 1024:
        return False, set(), []

    # 2. 内容去重 (仅针对非 JS 文件)
    if ".js" not in url:
        if checker.is_page_duplicate(url, source, title):
            return False, set(), []

    # 3. 标记为已访问
    checker.mark_url_visited(url)

    # 4. 提取下一层 URL
    next_urls = set()
    rex_output = []

    try:
        from processor.analysis.api.api_scan import analysis_by_rex, data_clean
        rex_output = analysis_by_rex(source)

        # ===== BaseURL 直接使用种子地址 =====
        # 已去除 base_url_agent 验证：域名/baseURL 由种子地址提供，
        # 具体 API 的最终路径（含 /security/ 等前缀）由 AI 阶段（reconstruct）直接输出。
        effective_seed = seed_url
        next_urls = set(data_clean(url, rex_output, seed_url=effective_seed))

    except Exception:
        rex_output = []

    # 过滤 next_urls：阻止爬虫访问危险 URL（但不影响 rex_output 进入 AI 分析）
    if next_urls:
        next_urls = {u for u in next_urls if not _is_path_blacklisted(u)}

    # 筛选 rex_output：只过滤基础格式条件，不过滤黑名单（黑名单在请求阶段由 Guard 拦截）
    if rex_output:
        filtered_rex_output = []
        for item in rex_output:
            is_string = isinstance(item, str)
            length_ok = len(item) > 4
            no_dot = "." not in item
            enough_slash = item.count('/') >= 1

            if is_string and length_ok and no_dot and enough_slash:
                filtered_rex_output.append(item)
        rex_output = filtered_rex_output

    return True, next_urls, rex_output


def _is_already_base_url(url: str) -> bool:
    """判断传入的 seed_url 是否已经是一个验证过的 baseURL（含路径前缀）"""
    if not url:
        return False
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path.rstrip('/')
    return bool(path) and path != '/'

BASE_URL_PROPERTY_NAMES = {
    b'baseURL', b'baseUrl', b'base_url', b'BASE_URL',
    b'BASEURL', b'apiBase', b'API_BASE', b'apiUrl', b'API_URL',
    b'apiBaseURL', b'API_BASE_URL',
}

_MAX_SLICE_BYTES = 8000


def _strip_quotes(raw: bytes) -> bytes:
    text = raw.strip()
    if len(text) >= 2 and text[0] in (ord('"'), ord("'")):
        return text[1:-1]
    return text


def _is_base_url_property(name_bytes: bytes) -> bool:
    clean = _strip_quotes(name_bytes)
    return clean in BASE_URL_PROPERTY_NAMES


def _extract_context_slice(context_node: Node, target_node: Node, code_bytes: bytes) -> str:
    raw_text = code_bytes[context_node.start_byte:context_node.end_byte].decode('utf-8', errors='replace')
    if len(raw_text.encode('utf-8')) > _MAX_SLICE_BYTES:
        raw_text = raw_text[:_MAX_SLICE_BYTES]

    try:
        propagated = _propagate_variables(context_node, target_node, code_bytes)
        if len(propagated.encode('utf-8')) <= _MAX_SLICE_BYTES:
            return propagated
    except Exception:
        pass

    return raw_text


def find_base_url_definitions(code_bytes: bytes, tree) -> List[Dict[str, Any]]:
    """
    在 AST 中定位所有 baseURL "写入点"，返回代码切片列表。

    只匹配写入语义：
      1. assignment_expression 左侧是 member_expression 且属性名是 baseURL
         例：e.baseURL = "/api"  或  e.baseURL += "/security/"
      2. 对象字面量 pair 的 key 是 baseURL
         例：axios.create({ baseURL: "/api" })
    """
    write_hits = []

    def traverse(node: Node):

        if node.type == 'assignment_expression':
            left = node.child_by_field_name('left')
            if left and left.type == 'member_expression':
                prop = left.child_by_field_name('property')
                if prop:
                    prop_text = code_bytes[prop.start_byte:prop.end_byte]
                    if _is_base_url_property(prop_text):
                        func = _find_enclosing_function(node)
                        if func and (func.end_byte - func.start_byte) <= _MAX_SLICE_BYTES:
                            write_hits.append(('assignment_func', func, node))
                        else:
                            stmt = node
                            while stmt and not stmt.type.endswith('statement'):
                                stmt = stmt.parent
                            if stmt:
                                write_hits.append(('assignment_stmt', stmt, node))

        elif node.type == 'pair':
            key = node.child_by_field_name('key')
            if key:
                key_text = code_bytes[key.start_byte:key.end_byte]
                if _is_base_url_property(key_text):
                    boundary = _find_semantic_boundary(node)
                    if boundary and (boundary.end_byte - boundary.start_byte) <= _MAX_SLICE_BYTES:
                        write_hits.append(('object_property', boundary, node))
                    else:
                        parent = node
                        for _ in range(5):
                            if parent and parent.parent:
                                parent = parent.parent
                        write_hits.append(('object_property', parent, node))

        for child in node.children:
            traverse(child)

    traverse(tree.root_node)

    results = []
    seen_ranges = set()

    for hit_type, context_node, target_node in write_hits:
        range_key = (context_node.start_byte, context_node.end_byte)
        if range_key in seen_ranges:
            continue
        seen_ranges.add(range_key)

        code_slice = _extract_context_slice(context_node, target_node, code_bytes)
        if not code_slice.strip():
            continue

        results.append({
            "type": hit_type,
            "code": code_slice,
        })

    logger.info(f"🔍 [BaseURL Extractor] 找到 {len(results)} 个 baseURL 写入点")
    return results


def extract_base_url_candidates(js_code: str) -> List[Dict[str, Any]]:
    """
    对外接口：从 JS 源码中提取所有 baseURL 候选定义

    Returns:
        写入点列表，每个元素包含 type、code
        如果找不到任何写入点，返回空列表
    """
    if not js_code or not isinstance(js_code, str):
        return []

    parser = get_parser()
    if not parser:
        logger.warning("⚠️ [BaseURL Extractor] Parser 未初始化")
        return []

    code_bytes = js_code.encode('utf-8', errors='replace')

    try:
        tree = parser.parse(code_bytes)
    except Exception as e:
        logger.error(f"❌ [BaseURL Extractor] AST 解析失败: {e}")
        return []

    return find_base_url_definitions(code_bytes, tree)