# -*- coding: utf-8 -*-
"""
方案 B · 跨 chunk 调用索引

核心：把现有单 chunk 桥接（_build_bridge_index）扩展为全 bundle（所有 chunk）索引。
召回时，单 chunk 查不到 → 查全局表 → 跨文件跳转 → 提取关键片段。

纯增量：现有单 chunk 逻辑完全保留，只在单 chunk 查不到时触发。
"""
import hashlib
import json
import os
import re

try:
    import tree_sitter_javascript as tsj
    from tree_sitter import Language, Parser
    _TS_AVAILABLE = True
except Exception:
    _TS_AVAILABLE = False

# 进程内源码缓存：{(chunk_dir, filename): src}。
# 索引构建/召回阶段反复读同一批 chunk，读盘是主要开销之一，缓存可避免重复 I/O。
# 该缓存不落盘，仅在进程生命周期内有效；chunk 变更时由调用方显式清空。
_SRC_CACHE = {}

# 进程内索引缓存：{chunk_dir: index}。
# 单次扫描内同一 js_url 的 chunk_dir 会被反复 get_bundle_index（跨批次/跨深度、
# API 阶段 + 密钥阶段）。磁盘缓存每次都要对全部 chunk 做 hash 全量校验（读整文件），
# 是主要 I/O 浪费。进程内缓存命中后直接返回，跳过 hash 校验。
# 该缓存不落盘，仅在进程生命周期内有效；chunk 变更时由调用方显式清空。
_INDEX_CACHE = {}


def _clear_src_cache():
    """清空进程内源码缓存（chunk 变更后调用）。"""
    _SRC_CACHE.clear()


def _clear_index_cache():
    """清空进程内索引缓存（chunk 变更后调用）。"""
    _INDEX_CACHE.clear()


def _clear_all_caches():
    """清空全部进程内缓存（源码 + 索引）。"""
    _SRC_CACHE.clear()
    _INDEX_CACHE.clear()

# ---- 复用现有正则（与 context_extractor 一致）----
# webpack 模块工厂：`"0d85": function(e, a, t) {` 或 `a36b:function(t,s,a){`
# 模块 ID 为 4-6 位 hex，引号可有可无（不同产物格式不同）。
# 注意：打包产物常为单行，不能用 ^ 锚点（re.M 下 ^ 只匹配文件开头）。
_MODULE_FACTORY_RE = re.compile(
    r'"?([0-9a-fA-F]{1,8}|[0-9]{1,6})"?\s*:\s*function\s*\(\s*[A-Za-z_$][\w$]*\s*,\s*[A-Za-z_$][\w$]*\s*,\s*[A-Za-z_$][\w$]*\s*\)\s*\{',
)
# webpack 导出名桥接：`t.d(a, "name", () => X)` / `n.d(t, "name", () => X)`
_EXPORT_BRIDGE_RE = re.compile(
    r'([A-Za-z_$][\w$]*)\.d\(\s*[A-Za-z_$][\w$]*\s*,\s*"([^"]+)"\s*,\s*'
    r'(?:\(?\s*function\s*\(\s*\)\s*\)?\s*\{\s*return\s+([A-Za-z_$][\w$]*)\s*;?\s*\}'
    r'|\(?\s*\(\s*\)\s*=>\s*([A-Za-z_$][\w$]*)\s*;?\s*\)?)'
    r'\s*\)'
)
# 全局组件注册：`e.component("PageConfig", mn)`
_COMPONENT_REG_RE = re.compile(
    r'[A-Za-z_$][\w$]*\.component\(\s*"([^"]+)"\s*,\s*([A-Za-z_$][\w$]*)\s*\)'
)
# webpack4 直接赋值导出：`t["a"]=n` / `t["default"]=n` / `t.a=n`
# 出现在未用 .d() 桥接的产物（如 Vue 组件 chunk），导出名即模块导出键。
_WP4_ASSIGN_EXPORT_RE = re.compile(
    r'[A-Za-z_$][\w$]*\["([A-Za-z_$][\w$]*)"\]\s*=\s*'
    r'([A-Za-z_$][\w$]*(?:\s*\([^)]*\))?)'
)
# 模块引用：`a("c5c8")` / `n("c5c8")` / `Object(a["c5c8"])`
_MODULE_REF_RE = re.compile(
    r'[A-Za-z_$][\w$]*\(\s*"([0-9a-f]{4})"\s*\)'
)

# ============================================================
# 打包器探测 + 多形态解析（通用性/健壮性）
# 目标：不依赖单一 webpack4 格式，按产物形态动态选择解析策略。
# 支持：webpack4 / webpack5 / esbuild / 原生 ESM(Vite/Rollup)
# ============================================================

# webpack5 模块工厂：`"0135":(e,t,n)=>{`（箭头函数）或 `"0135":function(e,t,n){`
_MODULE_FACTORY_WP5_RE = re.compile(
    r'"?([0-9a-fA-F]{1,8}|[0-9]{1,6})"?\s*:\s*(?:function\s*)?\(\s*[A-Za-z_$][\w$]*\s*,\s*[A-Za-z_$][\w$]*\s*,\s*[A-Za-z_$][\w$]*\s*\)\s*=>\s*\{',
)
# webpack5 导出桥接（对象形式）：`n.d(t,{导出名:()=>X})` 或 `n.d(t,{导出名:function(){return X}})` 或 `n.d(t,{导出名:()=>X, 导出名2:()=>Y})`
_EXPORT_BRIDGE_WP5_RE = re.compile(
    r'[A-Za-z_$][\w$]*\.d\(\s*[A-Za-z_$][\w$]*\s*,\s*\{([^}]*)\}\s*\)',
)
# 对象形式内的单个导出项：`导出名:()=>X` / `导出名:function(){return X}` / `导出名:X`
_EXPORT_ITEM_RE = re.compile(
    r'"?([A-Za-z_$][\w$]*)"?\s*:\s*'
    r'(?:\(?\s*\)\s*=>\s*([A-Za-z_$][\w$]*)\s*'
    r'|\(?\s*function\s*\(\s*\)\s*\{\s*return\s+([A-Za-z_$][\w$]*)\s*\}'
    r'|([A-Za-z_$][\w$]*))',
)
# esbuild 导出桥接：`__export(target,{导出名:()=>X})` / `__export(target,{导出名:X})` / `__reExport`
_ESBUILD_EXPORT_RE = re.compile(
    r'__export\(\s*[A-Za-z_$][\w$]*\s*,\s*\{([^}]*)\}\s*\)',
)
# 原生 ESM 导出：`export { X as 导出名 }` / `export { X }` / `export const 导出名 = ...`
_ESM_EXPORT_RE = re.compile(
    r'export\s*\{([^}]*)\}',
)
_ESM_EXPORT_ITEM_RE = re.compile(
    r'([A-Za-z_$][\w$]*)\s*(?:as\s+([A-Za-z_$][\w$]*))?',
)
# 原生 ESM 具名导出声明：`export const 导出名 = X` / `export function 导出名(...)`
_ESM_EXPORT_DECL_RE = re.compile(
    r'export\s+(?:const|let|var|function)\s+([A-Za-z_$][\w$]*)',
)

# 打包器探测：根据产物特征判断
def _detect_bundler(src: str) -> str:
    """探测打包器类型。返回 'webpack4' / 'webpack5' / 'esbuild' / 'esm' / 'unknown'"""
    # esbuild：__export / __reExport 辅助函数
    if '__export' in src and '__toCommonJS' in src or re.search(r'__export\(', src):
        return 'esbuild'
    # webpack：n.d 导出桥接 + 模块工厂
    if re.search(r'\.d\(\s*[A-Za-z_$][\w$]*\s*,\s*"', src):
        return 'webpack4'
    if re.search(r'\.d\(\s*[A-Za-z_$][\w$]*\s*,\s*\{', src):
        return 'webpack5'
    # webpack4 运行时特征（webpackJsonp）——即使未用 .d() 桥接（直接赋值导出）
    if 'webpackJsonp' in src or re.search(r'\["webpackJsonp"\]', src):
        return 'webpack4'
    # 原生 ESM：export 或 import 语句
    if re.search(r'\bexport\s+\{', src) or re.search(r'\bexport\s+(?:const|let|var|function)\b', src) \
            or re.search(r'\bimport\s*\{', src) or re.search(r'\bimport\s+[A-Za-z_$]', src):
        return 'esm'
    return 'unknown'

# 按打包器返回模块工厂正则
def _module_factory_re(bundler: str):
    if bundler == 'webpack5':
        return _MODULE_FACTORY_WP5_RE
    return _MODULE_FACTORY_RE  # webpack4 / 其他回退

# 按打包器提取「导出名 → 私有变量」映射
def _extract_exports(bundler: str, src: str) -> dict:
    """返回 {导出名: 私有变量}。不同打包器形态统一归一化。"""
    exports = {}
    if bundler == 'webpack5':
        for m in _EXPORT_BRIDGE_WP5_RE.finditer(src):
            body = m.group(1)
            for item in _EXPORT_ITEM_RE.finditer(body):
                name = item.group(1)
                priv = item.group(2) or item.group(3) or item.group(4)
                if name and priv:
                    exports[name] = priv
    elif bundler == 'esbuild':
        for m in _ESBUILD_EXPORT_RE.finditer(src):
            body = m.group(1)
            for item in _EXPORT_ITEM_RE.finditer(body):
                name = item.group(1)
                priv = item.group(2) or item.group(3) or item.group(4)
                if name and priv:
                    exports[name] = priv
    elif bundler == 'esm':
        # export { X as name } / export { X }
        for m in _ESM_EXPORT_RE.finditer(src):
            body = m.group(1)
            for item in _ESM_EXPORT_ITEM_RE.finditer(body):
                priv = item.group(1)
                name = item.group(2) or priv
                if priv and name:
                    exports[name] = priv
        # export const 导出名 = X / export function 导出名
        for m in _ESM_EXPORT_DECL_RE.finditer(src):
            name = m.group(1)
            exports.setdefault(name, name)
    else:  # webpack4
        for m in _EXPORT_BRIDGE_RE.finditer(src):
            priv = m.group(3) or m.group(4)
            if priv:
                exports[m.group(2)] = priv
        # 直接赋值导出：`t["a"]=n`（未用 .d() 桥接的产物）
        for m in _WP4_ASSIGN_EXPORT_RE.finditer(src):
            name = m.group(1)
            priv = m.group(2).strip()
            if name and priv and name not in exports:
                exports[name] = priv
    return exports


def _export_offsets(bundler: str, src: str) -> list:
    """返回导出桥接位置列表 [(offset, export_name, private_name)]，用于归属模块。"""
    offsets = []
    if bundler == 'webpack5':
        for m in _EXPORT_BRIDGE_WP5_RE.finditer(src):
            for item in _EXPORT_ITEM_RE.finditer(m.group(1)):
                name = item.group(1)
                priv = item.group(2) or item.group(3) or item.group(4)
                if name and priv:
                    offsets.append((m.start(), name, priv))
    elif bundler == 'esbuild':
        for m in _ESBUILD_EXPORT_RE.finditer(src):
            for item in _EXPORT_ITEM_RE.finditer(m.group(1)):
                name = item.group(1)
                priv = item.group(2) or item.group(3) or item.group(4)
                if name and priv:
                    offsets.append((m.start(), name, priv))
    elif bundler == 'esm':
        for m in _ESM_EXPORT_RE.finditer(src):
            for item in _ESM_EXPORT_ITEM_RE.finditer(m.group(1)):
                priv = item.group(1)
                name = item.group(2) or priv
                if priv and name:
                    offsets.append((m.start(), name, priv))
        for m in _ESM_EXPORT_DECL_RE.finditer(src):
            offsets.append((m.start(), m.group(1), m.group(1)))
    else:  # webpack4
        for m in _EXPORT_BRIDGE_RE.finditer(src):
            priv = m.group(3) or m.group(4)
            if priv:
                offsets.append((m.start(), m.group(2), priv))
        # 直接赋值导出：`t["a"]=n`
        for m in _WP4_ASSIGN_EXPORT_RE.finditer(src):
            name = m.group(1)
            priv = m.group(2).strip()
            if name and priv:
                offsets.append((m.start(), name, priv))
    return offsets

_MAX_DEF_LINES = 12   # 定义片段行数上限（复用 _extract_brace_block 语义）


def _file_hash(path):
    """计算文件 MD5（用于缓存键）"""
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _brace_block(src: str, start_off: int, max_lines: int = _MAX_DEF_LINES):
    """从 start_off 起，用花括号配平（引号感知）截取代码块，超行数上限返回 None"""
    i = src.find("{", start_off)
    if i == -1:
        return None
    depth = 0
    in_str = None
    esc = False
    for j in range(i, min(len(src), i + 50000)):
        ch = src[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                block = src[start_off:j + 1]
                return block if block.count("\n") <= max_lines else None
    return None


def _build_single_chunk_index(filepath: str, src: str = None):
    """构建单个 chunk 的模块边界 + 导出映射 + 组件注册。
    返回 {modules: {mod_id: {offset, end, exports}}, components: {name: offset}}

    src 由调用方传入（build_bundle_index 已读一次，避免重复读盘）；
    为 None 时才自行读盘（兼容单文件独立调用）。
    """
    if src is None:
        try:
            src = open(filepath, encoding='utf-8', errors='replace').read()
        except Exception:
            return None

    idx = {"modules": {}, "components": {}, "bundler": "unknown"}

    bundler = _detect_bundler(src)
    idx["bundler"] = bundler

    # 未知打包器：用 tree-sitter 兜底解析（正则主路径无法识别模块边界）
    if bundler == 'unknown':
        ts_idx = _build_single_chunk_index_ts(filepath, src)
        if ts_idx is not None:
            return ts_idx
        # 兜底失败：返回空索引（bundler 仍标记为 unknown），不抛异常
        return idx

    # 模块边界（按打包器选择工厂正则）
    factory_re = _module_factory_re(bundler)
    mod_starts = [(m.group(1), m.start()) for m in factory_re.finditer(src)]
    for i, (mod_id, off) in enumerate(mod_starts):
        end = mod_starts[i + 1][1] if i + 1 < len(mod_starts) else len(src)
        idx["modules"][mod_id] = {"offset": off, "end": end, "exports": {}}

    # 模块内导出映射（按打包器提取，限定在本模块范围内）
    for off, export_name, private_name in _export_offsets(bundler, src):
        # 归属模块：找包含导出桥接位置的模块
        owner = None
        for mod_id, info in idx["modules"].items():
            if info["offset"] <= off < info["end"]:
                owner = mod_id
                break
        if owner:
            idx["modules"][owner]["exports"][export_name] = private_name

    # 组件注册
    for m in _COMPONENT_REG_RE.finditer(src):
        idx["components"][m.group(1)] = m.start()

    return idx


def _ts_node_text(node) -> str:
    """取节点文本并解码为 str。"""
    try:
        return node.text.decode('utf-8', 'replace')
    except Exception:
        return ''


def _ts_string_literal_value(node) -> str:
    """从 string 节点提取字面量值（去引号）。"""
    txt = _ts_node_text(node).strip()
    if len(txt) >= 2 and txt[0] in ('"', "'") and txt[-1] == txt[0]:
        return txt[1:-1]
    return txt


def _ts_identifier_name(node) -> str:
    """从标识符/属性名节点提取名称。"""
    return _ts_node_text(node).strip()


def _ts_module_exports(module_body) -> dict:
    """用 tree-sitter 遍历模块函数体，提取 {导出名: 私有变量名}。

    覆盖两种形态：
      - `exports.name = X` / `exports["name"] = X`（member/subscript 赋值）
      - `t.d(a, "name", () => X)` 桥接（callee 为 member_expression `.d`）
    """
    exports = {}
    if module_body is None:
        return exports
    stack = list(module_body.children)
    while stack:
        node = stack.pop()
        if node.type == 'assignment_expression':
            left = node.child_by_field_name('left')
            right = node.child_by_field_name('right')
            if left is not None and right is not None:
                name = None
                if left.type in ('member_expression', 'subscript_expression'):
                    # exports.name / exports["name"]：取属性名
                    # member_expression 用 property 字段，subscript_expression 用 index 字段
                    prop = (left.child_by_field_name('property')
                            or left.child_by_field_name('index'))
                    if prop is not None:
                        if prop.type == 'string':
                            name = _ts_string_literal_value(prop)
                        elif prop.type == 'property_identifier':
                            name = _ts_identifier_name(prop)
                if name:
                    priv = _ts_identifier_name(right) if right.type == 'identifier' else None
                    if priv:
                        exports.setdefault(name, priv)
        elif node.type == 'call_expression':
            callee = node.child_by_field_name('function')
            if callee is not None and callee.type == 'member_expression':
                prop = callee.child_by_field_name('property')
                if prop is not None and _ts_identifier_name(prop) == 'd':
                    # t.d(a, "name", () => X) 或 t.d(a, {name: () => X, ...})
                    args = node.child_by_field_name('arguments')
                    if args is not None:
                        arg_nodes = [c for c in args.children
                                     if c.type not in ('(', ')', ',')]
                        if len(arg_nodes) >= 2:
                            name_node = arg_nodes[1]
                            if name_node.type == 'string':
                                name = _ts_string_literal_value(name_node)
                                if name:
                                    priv = _ts_arrow_return_ident(arg_nodes[2])
                                    if priv:
                                        exports.setdefault(name, priv)
                            elif name_node.type == 'object':
                                # 对象形式：{导出名: () => X, 导出名2: ...}
                                for pair in name_node.children:
                                    if pair.type != 'pair':
                                        continue
                                    k = pair.child_by_field_name('key')
                                    v = pair.child_by_field_name('value')
                                    if k is None or v is None:
                                        continue
                                    if k.type == 'string':
                                        name = _ts_string_literal_value(k)
                                    elif k.type == 'property_identifier':
                                        name = _ts_identifier_name(k)
                                    else:
                                        name = None
                                    if name:
                                        priv = _ts_arrow_return_ident(v)
                                        if priv:
                                            exports.setdefault(name, priv)
        # 继续下钻子节点（不进入嵌套函数体，避免把子函数内导出误归本模块）
        for c in node.children:
            if c.type in ('function', 'function_declaration',
                          'arrow_function', 'method_definition'):
                continue
            stack.append(c)
    return exports


def _ts_arrow_return_ident(fn_node) -> str:
    """从箭头函数/函数节点提取 return 的标识符名。"""
    if fn_node is None:
        return None
    if fn_node.type == 'arrow_function':
        body = fn_node.child_by_field_name('body')
        if body is None:
            return None
        if body.type == 'identifier':
            return _ts_identifier_name(body)
        if body.type == 'statement_block':
            return _ts_block_return_ident(body)
    elif fn_node.type in ('function', 'function_expression'):
        body = fn_node.child_by_field_name('body')
        if body is not None and body.type == 'statement_block':
            return _ts_block_return_ident(body)
    return None


def _ts_block_return_ident(block) -> str:
    """从语句块中找 `return X` 的标识符名。"""
    for c in block.children:
        if c.type == 'return_statement':
            # 不同 tree-sitter-javascript 版本对 return 的实参 field 命名不同
            # （有的用 argument，有的无命名 field），直接遍历子节点找标识符更稳。
            for rc in c.children:
                if rc.type == 'identifier':
                    return _ts_identifier_name(rc)
    return None


def _ts_component_regs(tree) -> dict:
    """找 `X.component("Name", Y)` 调用，记录 {Name: 调用起点字节偏移}。"""
    comps = {}
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == 'call_expression':
            callee = node.child_by_field_name('function')
            if callee is not None and callee.type == 'member_expression':
                prop = callee.child_by_field_name('property')
                if prop is not None and _ts_identifier_name(prop) == 'component':
                    args = node.child_by_field_name('arguments')
                    if args is not None:
                        arg_nodes = [c for c in args.children
                                     if c.type not in ('(', ')', ',')]
                        if arg_nodes and arg_nodes[0].type == 'string':
                            name = _ts_string_literal_value(arg_nodes[0])
                            if name:
                                comps.setdefault(name, node.start_byte)
        for c in node.children:
            if c.type in ('function', 'function_declaration',
                          'arrow_function', 'method_definition'):
                continue
            stack.append(c)
    return comps


def _ts_call_sites(tree, src, fn):
    """tree-sitter 兜底：遍历成员访问节点，提取 {导出名: [(fn, offset)]}。

    覆盖两种形态（与正则路径一致）：
      - 下标访问：`X["name"]`
      - 点访问：`X.name`
    offset 指向成员访问起点（node.start_byte），供 find_api_callers 查表定位。
    """
    sites = {}
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in ('member_expression', 'subscript_expression'):
            # member_expression 用 property 字段，subscript_expression 用 index 字段
            prop = (node.child_by_field_name('property')
                    or node.child_by_field_name('index'))
            if prop is not None:
                name = None
                if prop.type == 'string':
                    name = _ts_string_literal_value(prop)
                elif prop.type == 'property_identifier':
                    name = _ts_identifier_name(prop)
                if name:
                    if name in _GENERIC_PROP_NAMES:
                        continue
                    sites.setdefault(name, []).append((fn, node.start_byte))
        for c in node.children:
            stack.append(c)
    return sites


def _build_single_chunk_index_ts(filepath: str, src: str = None):
    """tree-sitter 兜底解析（打包器探测为 unknown 时）。

    用 tree-sitter 提取模块边界/导出映射/组件注册，返回与
    _build_single_chunk_index 相同的 dict。解析失败或结构不符返回 None。
    """
    if not _TS_AVAILABLE:
        return None
    try:
        if src is None:
            src = open(filepath, encoding='utf-8', errors='replace').read()
        lang = Language(tsj.language())
        parser = Parser(lang)
        tree = parser.parse(src.encode('utf-8'))
        root = tree.root_node

        # 找顶层对象字面量（webpack 形态 `window["app"]={ "modId": function(e,t,n){...} }`）
        obj_node = None
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == 'object':
                obj_node = node
                break
            for c in node.children:
                if c.type in ('function', 'function_declaration',
                              'arrow_function', 'method_definition'):
                    continue
                stack.append(c)
        if obj_node is None:
            return None

        idx = {"modules": {}, "components": {}, "bundler": "unknown"}

        pairs = [c for c in obj_node.children if c.type == 'pair']
        if not pairs:
            return None

        obj_end = obj_node.end_byte
        for i, pair in enumerate(pairs):
            key = pair.child_by_field_name('key')
            value = pair.child_by_field_name('value')
            if key is None or value is None:
                continue
            if key.type != 'string':
                continue
            mod_id = _ts_string_literal_value(key)
            if value.type not in ('function', 'function_expression', 'arrow_function'):
                continue
            end = pairs[i + 1].start_byte if i + 1 < len(pairs) else obj_end
            body = value.child_by_field_name('body')
            exports = _ts_module_exports(body)
            idx["modules"][mod_id] = {
                "offset": pair.start_byte, "end": end, "exports": exports,
            }

        idx["components"] = _ts_component_regs(tree)
        return idx
    except Exception:
        return None


# 过泛属性名黑名单：JS 内置对象/数组/字符串的通用属性或高频噪声名。
# 这些几乎不可能是 API 导出名，索引进 call_sites 只会膨胀体积、污染召回。
# 若某真实 API 导出名恰好命中，可在此移除（黑名单可配置）。
_GENERIC_PROP_NAMES = frozenset({
    # 内置对象/数组/字符串通用属性
    "length", "prototype", "constructor", "toString", "valueOf", "hasOwnProperty",
    "call", "apply", "bind", "push", "pop", "shift", "unshift", "splice", "slice",
    "concat", "join", "indexOf", "lastIndexOf", "includes", "find", "findIndex",
    "map", "forEach", "filter", "reduce", "reduceRight", "some", "every", "keys",
    "values", "entries", "flat", "flatMap", "fill", "copyWithin", "reverse", "sort",
    # Promise / 异步
    "then", "catch", "finally", "resolve", "reject", "all", "race", "allSettled",
    # 模块系统 / 全局对象
    "default", "exports", "module", "require", "window", "document", "console",
    "Object", "Array", "String", "Number", "Boolean", "Promise", "JSON", "Math",
    "Date", "RegExp", "Error", "undefined", "null", "globalThis", "self",
    # console 方法（webpack 产物高频噪声）
    "log", "error", "warn", "info", "debug", "trace", "assert", "dir", "table",
    # 高频通用词（几乎不可能是 API 导出名）
    "name", "value", "type", "id", "key", "data", "url", "status", "code", "msg",
})


def _build_call_sites(src: str, fn: str, bundler: str = 'unknown'):
    """预扫描单个文件的所有成员访问点，按导出名倒排。

    覆盖两种形态：
      - 下标访问：`X["name"]`（含 `Object(X["name"])(...)` 调用）
      - 点访问：`X.name`
    返回 {export_name: [(fn, offset), ...]}。offset 指向成员访问起点，
    供 find_api_callers 直接查表定位候选调用点，避免每次全量正则扫描。

    过泛属性名（JS 内置/数组/对象通用属性）会被过滤，避免索引体积膨胀
    和召回噪声。未知打包器（unknown）时优先用 tree-sitter 兜底遍历成员
    访问节点；解析失败或提取为空时降级回正则路径（尽力而为，不抛异常）。
    """
    if bundler == 'unknown' and _TS_AVAILABLE:
        try:
            lang = Language(tsj.language())
            parser = Parser(lang)
            tree = parser.parse(src.encode('utf-8'))
            ts_sites = _ts_call_sites(tree, src, fn)
            if ts_sites:
                return ts_sites
        except Exception:
            pass
    sites = {}
    # 下标访问：`X["name"]`，name 为任意标识符/数字
    for m in re.finditer(r'([A-Za-z_$][\w$]*)\s*\[\s*"([^"]+)"\s*\]', src):
        host, name = m.group(1), m.group(2)
        if name in _GENERIC_PROP_NAMES:
            continue
        sites.setdefault(name, []).append((fn, m.start()))
    # 点访问：`X.name`（name 为标识符）
    for m in re.finditer(r'([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)', src):
        host, name = m.group(1), m.group(2)
        if name in _GENERIC_PROP_NAMES:
            continue
        sites.setdefault(name, []).append((fn, m.start()))
    return sites


def build_bundle_index(chunk_dir: str):
    """构建全 bundle 索引。
    返回 {files: {filename: {hash, modules, components}}, modules: {mod_id: {file, offset}},
           components: {name: {file, offset}}, cache_key: str}"""
    files = {}
    call_sites = {}
    for fn in sorted(os.listdir(chunk_dir)):
        if not fn.endswith('.js'):
            continue
        fp = os.path.join(chunk_dir, fn)
        # 单次读盘：src 同时用于建索引和 call_sites，避免每文件读 2 次
        src = _read_file_src(chunk_dir, fn)
        if src is None:
            continue
        idx = _build_single_chunk_index(fp, src)
        if idx is None:
            continue
        files[fn] = {
            "hash": _file_hash(fp),
            "modules": idx["modules"],
            "components": idx["components"],
            "bundler": idx.get("bundler", "unknown"),
        }
        # 调用点预索引：按导出名倒排，供 find_api_callers 查表
        for name, sites in _build_call_sites(
                src, fn, idx.get("bundler", "unknown")).items():
            call_sites.setdefault(name, []).extend(sites)

    # 全局模块表：mod_id → (file, offset)
    modules = {}
    for fn, finfo in files.items():
        for mod_id, minfo in finfo["modules"].items():
            # 冲突时保留第一个（webpack 模块 ID 全局唯一，冲突极少）
            if mod_id not in modules:
                modules[mod_id] = {"file": fn, "offset": minfo["offset"]}

    # 全局组件表：name → (file, offset)
    components = {}
    for fn, finfo in files.items():
        for name, off in finfo["components"].items():
            if name not in components:
                components[name] = {"file": fn, "offset": off}

    cache_key = hashlib.md5(
        json.dumps({fn: finfo["hash"] for fn, finfo in files.items()},
                   sort_keys=True).encode()).hexdigest()

    return {
        "files": files,
        "modules": modules,
        "components": components,
        "call_sites": call_sites,
        "cache_key": cache_key,
    }


# ---- 缓存读写 ----

def _cache_path(chunk_dir):
    return os.path.join(chunk_dir, ".bundle_index.json")


def load_cache(chunk_dir: str):
    """加载缓存。缓存键（chunk hash 列表）一致才返回，否则 None"""
    cp = _cache_path(chunk_dir)
    if not os.path.exists(cp):
        return None
    try:
        with open(cp, encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return None
    # 校验缓存键：当前 chunk 列表 hash 是否与缓存一致
    current = {}
    for fn in sorted(os.listdir(chunk_dir)):
        if not fn.endswith('.js'):
            continue
        fp = os.path.join(chunk_dir, fn)
        current[fn] = _file_hash(fp)
    current_key = hashlib.md5(json.dumps(current, sort_keys=True).encode()).hexdigest()
    if data.get("cache_key") != current_key:
        return None
    # 旧缓存无调用点索引 → 视为失效，触发重建
    if "call_sites" not in data:
        return None
    return data


def save_cache(chunk_dir: str, index: dict):
    """保存索引到缓存"""
    cp = _cache_path(chunk_dir)
    try:
        with open(cp, 'w', encoding='utf-8') as f:
            json.dump(index, f, ensure_ascii=False)
    except Exception:
        pass


def get_bundle_index(chunk_dir: str):
    """获取索引：进程内缓存命中直接返回，否则重建并缓存。

    单次扫描内同一 chunk_dir 会被反复调用（跨批次/跨深度、API+密钥两阶段）。
    优先命中进程内 _INDEX_CACHE，跳过磁盘缓存的全量 hash 校验（读整文件算 md5），
    避免每次取索引都全量读盘。磁盘缓存仅作为进程内未命中时的兜底。
    """
    if chunk_dir in _INDEX_CACHE:
        return _INDEX_CACHE[chunk_dir]

    cached = load_cache(chunk_dir)
    if cached:
        _INDEX_CACHE[chunk_dir] = cached
        return cached

    index = build_bundle_index(chunk_dir)
    _INDEX_CACHE[chunk_dir] = index
    save_cache(chunk_dir, index)
    return index


# ---- 跨文件召回 ----

def _read_file_src(chunk_dir: str, filename: str):
    """读取 chunk 文件源码，优先命中进程内缓存避免重复读盘。"""
    key = (chunk_dir, filename)
    if key in _SRC_CACHE:
        return _SRC_CACHE[key]
    try:
        src = open(os.path.join(chunk_dir, filename), encoding='utf-8',
                   errors='replace').read()
    except Exception:
        return None
    _SRC_CACHE[key] = src
    return src


def _module_def_snippet(src: str, offset: int):
    """提取模块定义片段（从模块工厂头到函数体闭合）"""
    # 模块工厂头：`"c5c8":function(e,t,n){`
    head = src[offset:offset + 200]
    brace = src.find("{", offset)
    if brace == -1:
        return None
    return _brace_block(src, brace - 1)  # 从 { 前开始，取整个函数体


def _func_body_end(src: str, body_open_off: int):
    """从函数体 `{` 起点配平，返回闭合 `}` 的偏移（引号感知）。找不到返回 None。"""
    depth = 0
    in_str = None
    esc = False
    for j in range(body_open_off, min(len(src), body_open_off + 50000)):
        ch = src[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j
    return None


def _expr_body_end(src: str, expr_start: int, max_scan: int = 20000):
    """表达式体箭头函数（无 `{}`）的结束偏移。

    函数体为单个表达式，结束于下一个**顶层** `,`（const 链分隔）或模块闭合 `}`。
    用括号/花括号配平（引号感知）跳过表达式内部的嵌套结构。
    找不到返回 None。"""
    depth_p = 0
    depth_b = 0
    in_str = None
    esc = False
    for j in range(expr_start, min(len(src), expr_start + max_scan)):
        ch = src[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
        elif ch == "(":
            depth_p += 1
        elif ch == ")":
            depth_p -= 1
        elif ch == "{":
            depth_b += 1
        elif ch == "}":
            depth_b -= 1
            if depth_b < 0:
                # 模块闭合 `}`：表达式体到此结束
                return j
        elif ch == "," and depth_p == 0 and depth_b == 0:
            return j
    return None


def resolve_export_name(chunk_dir: str, index: dict, api_path: str):
    """反查 API 路径对应的导出函数名（跨 chunk）。

    逻辑（与 _build_bridge_index 一致）：
      1. 定位 api_path 所在模块源码与偏移。
      2. 从 api_path 偏移向前找**最近的、其函数体确实包含 api_path** 的函数体变量名
         （`function X(e){...}` / `X=e=>...` / `X=function(e){...}`）。
         关键：用花括号配平验证该函数体的闭合 `}` 落在 api_path 之后，
         从而避免在大模块内命中前一个函数导致错位。
      3. 用 _EXPORT_BRIDGE_RE 反查该变量对应的导出名。
    返回导出名（str）或 None。大模块内多 API 时仍可能错位，调用方可人工校正。
    """
    for fn in sorted(index["files"]):
        src = _read_file_src(chunk_dir, fn)
        if src is None:
            continue
        bundler = index["files"][fn].get("bundler", "unknown")
        for m in re.finditer(re.escape(api_path), src):
            off = m.start()
            owner = None
            for mod_id, minfo in index["files"][fn]["modules"].items():
                if minfo["offset"] <= off < minfo["end"]:
                    owner = mod_id
                    break
            # esbuild/esm 无模块工厂：整文件即一模块
            if not owner:
                mod_src = src
                rel = off
            else:
                minfo = index["files"][fn]["modules"][owner]
                mod_src = src[minfo["offset"]:minfo["end"]]
                rel = off - minfo["offset"]

            # 1) 向前找最近的、函数体覆盖 api_path 的函数体变量名
            head = mod_src[:rel]
            # 形态：`function X(` / `X=function(` / `X=e=>` / `X=()=>` / `X=>`
            #        `X=async e=>` / `X=async()=>` / `X=async(e)=>`（async 箭头函数）
            # 排除普通赋值 `X=`（后非 function/箭头）与箭头参数名（`s=e=>` 里的 `e`）
            var = None
            for vm in reversed(list(re.finditer(
                    r'function\s+([A-Za-z_$][\w$]*)\s*\('
                    r'|([A-Za-z_$][\w$]*)\s*=\s*function\s*\('
                    r'|([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>'
                    r'|(?<!=)([A-Za-z_$][\w$]*)\s*=>', head))):
                cand = vm.group(1) or vm.group(2) or vm.group(3) or vm.group(4)
                if not cand:
                    continue
                # 判断形态：函数声明/函数表达式（块体）vs 箭头函数（块体或表达式体）
                is_arrow = vm.group(3) is not None or vm.group(4) is not None
                if not is_arrow:
                    # 函数声明/函数表达式：体必为块 `{...}`
                    body_open = head.find("{", vm.start())
                    if body_open == -1:
                        continue
                    body_abs = body_open
                    end = _func_body_end(mod_src, body_abs)
                    if end is not None and end > rel:
                        var = cand
                        break
                    continue
                # 箭头函数：判断是块体（`=> {`）还是表达式体（`=> expr`）
                arrow = head.find("=>", vm.start())
                if arrow == -1:
                    continue
                # 跳过 `=>` 后的空白，看是否紧跟 `{`
                k = arrow + 2
                while k < len(head) and head[k] in " \t\r\n":
                    k += 1
                if k < len(head) and head[k] == "{":
                    # 块体：定位函数体 `{`，配平找闭合 `}`
                    body_open = k
                    body_abs = body_open
                    end = _func_body_end(mod_src, body_abs)
                    if end is not None and end > rel:
                        var = cand
                        break
                else:
                    # 表达式体箭头函数（无 `{}`）：`X=async()=>await fn(...)`
                    # 函数体为单个表达式，结束于下一个顶层 `,` 或模块闭合 `}`
                    end = _expr_body_end(mod_src, arrow + 2)
                    if end is not None and end > rel:
                        var = cand
                        break
            if not var:
                continue

            # 2) 反查导出名（按打包器形态）
            bundler = index["files"][fn].get("bundler", "unknown")
            for _, export_name, private_name in _export_offsets(bundler, mod_src):
                if private_name == var:
                    return export_name
            return None
    return None


def _api_def_snippet(src: str, api_off: int):
    """提取 API 定义片段（通用版）。

    不依赖具体 API 封装形态（e=>Object(a["a"])(...) / axios.get / request({...})），
    只依赖一个通用事实：任何 API 定义里必然写出 `url: "/api/xxx"` 字段。

    策略：
      1. 从 api_path 位置向前回溯，找最近的包含 `url:` 的赋值/调用起点
         （`xxx = ...({` 或 `xxx({`，即 `=` 后跟 `(` 或 `{`）。
      2. 从该起点用花括号配平截取整个参数对象，把 url/method/data 骨架带出。
      3. 若找不到含 url 的骨架，退回：从 api_path 自身向前找最近的 `{` 配平。
    """
    # 1) 向前找最近的含 `url:` 的赋值/调用骨架
    head = src[max(0, api_off - 800):api_off]
    # 匹配 `xxx = fn({` 或 `xxx({` 或 `xxx: ({` 这类"定义起点"，且其后的对象含 url:
    for m in reversed(list(re.finditer(
            r'[A-Za-z_$][\w$]*\s*[:=]\s*(?:[A-Za-z_$][\w$]*\.?[A-Za-z_$]*\()?\s*\{', head))):
        start = api_off - len(head) + m.start()
        block = _brace_block(src, start, max_lines=8)
        if block and 'url:' in block:
            return block
    # 2) 退回：从 api_path 向前找最近的 `{` 配平
    head2 = src[max(0, api_off - 400):api_off]
    brace = head2.rfind('{')
    if brace != -1:
        start = api_off - len(head2) + brace
        block = _brace_block(src, start, max_lines=8)
        if block and 'url:' in block:
            return block
    # 3) 再退回：位置参数形态（axios.get("/api/...", {...}) / fetch("/api/...", {...})）
    #    URL 不是 `url:` 字段，而是函数第一个参数。从 api_path 向前配平到最近调用括号。
    head3 = src[max(0, api_off - 300):api_off]
    paren = head3.rfind('(')
    if paren != -1:
        start = api_off - len(head3) + paren
        block = _paren_block(src, start, max_lines=8)
        if block:
            return block
    return None


def _paren_block(src: str, start_off: int, max_lines: int = 8):
    """从 start_off 起，用圆括号配平（引号感知）截取调用，超行数上限返回 None"""
    i = src.find("(", start_off)
    if i == -1:
        return None
    depth = 0
    in_str = None
    esc = False
    for j in range(i, min(len(src), i + 50000)):
        ch = src[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                block = src[start_off:j + 1]
                return block if block.count("\n") <= max_lines else None
    return None


def _extract_call_arg(src: str, open_off: int, max_lines: int = 8):
    """从 '(' 之后提取第一个实参（对象字面量/数组/标量）。
    用括号+花括号配平（引号感知）截取。返回 (arg_str, end_off) 或 (None, None)。
    若实参是 `{...}` 对象字面量，arg_str 即该对象源码。"""
    i = src.find("(", open_off)
    if i == -1:
        return None, None
    depth_p = 0
    depth_b = 0
    in_str = None
    esc = False
    for j in range(i, min(len(src), i + 20000)):
        ch = src[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
        elif ch == "(":
            depth_p += 1
        elif ch == ")":
            depth_p -= 1
            if depth_p == 0:
                arg = src[i + 1:j]
                return arg, j
        elif ch == "{":
            depth_b += 1
        elif ch == "}":
            depth_b -= 1
    return None, None


def _object_fields(arg: str):
    """从对象字面量源码提取顶层字段名（去重、保序）。
    支持 `{a:1,b:2}` / `{...spread}`（spread 记为 *spread*）。"""
    if not arg or not arg.strip().startswith("{"):
        return []
    fields = []
    seen = set()
    depth = 0
    in_str = None
    esc = False
    # 跳过外层 { }
    i = arg.find("{")
    j = arg.rfind("}")
    body = arg[i + 1:j] if i != -1 and j != -1 else arg
    # 在顶层逗号切分
    parts = []
    cur = []
    for ch in body:
        if in_str:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    for p in parts:
        p = p.strip()
        if p.startswith("..."):
            name = "*spread*"
        else:
            m = re.match(r'([A-Za-z_$][\w$]*)\s*:', p)
            name = m.group(1) if m else None
        if name and name not in seen:
            seen.add(name)
            fields.append(name)
    return fields


def _trace_var_fields(src: str, call_off: int, var: str, back_win: int = 800):
    """变量实参回溯：当实参是裸标识符（如 `t`、`e`）时，向前回溯该变量
    被赋字段的语句（`t.field = ...`），收集字段名。用于 `data:t` 透传 API
    在调用方以"先建对象再传"形态出现时的参数识别。"""
    if not var or not re.match(r'[A-Za-z_$][\w$]*$', var):
        return []
    head = src[max(0, call_off - back_win):call_off]
    fields = []
    seen = set()
    # 匹配 `var.field = ...` 或 `var.field=...`
    for m in re.finditer(
            r'\b' + re.escape(var) + r'\s*\.\s*([A-Za-z_$][\w$]*)\s*=', head):
        name = m.group(1)
        if name not in seen:
            seen.add(name)
            fields.append(name)
    return fields


def _find_api_def_module(chunk_dir: str, index: dict, api_path: str):
    """定位 API 路径定义所在文件与模块 id。

    返回 (def_file, def_module_id) 或 (None, None)。
    用于 find_api_callers 按「导入该模块的文件」限定调用方搜索范围，
    避免单字母导出名（c/i/n/p/o/k/l/a/b/d/g 等）在数百个模块间撞名导致误报。
    """
    for fn in sorted(index["files"]):
        src = _read_file_src(chunk_dir, fn)
        if src is None:
            continue
        for m in re.finditer(re.escape(api_path), src):
            off = m.start()
            for mod_id, minfo in index["files"][fn]["modules"].items():
                if minfo["offset"] <= off < minfo["end"]:
                    return fn, mod_id
    return None, None


def _file_imports_module(src: str, mod_id: str) -> bool:
    """文件源码是否 import 了模块 mod_id（webpack 形态 `n("mod_id")` / `n.n("mod_id")`）。

    用字符串 find 定位 `"mod_id"`，再向前检查是否为 `X("mod_id")` 调用形态，
    避免对超大单行 webpack 产物做慢速正则 search（贪婪回溯）。
    """
    if not mod_id:
        return True
    needle = '"' + mod_id + '"'
    start = 0
    while True:
        idx = src.find(needle, start)
        if idx == -1:
            return False
        # 向前检查：`X("mod_id")` —— 前一个非空白字符是 `(`
        j = idx - 1
        while j >= 0 and src[j] in ' \t\n\r':
            j -= 1
        if j >= 0 and src[j] == '(':
            return True
        start = idx + 1


def _module_bind_vars(src: str, mod_id: str):
    """返回文件中绑定到模块 mod_id 的命名空间变量名列表。

    webpack 形态：
      - `var a=n("mod")` / `a=n("mod")` / `const a=n.n("mod")`
      - 逗号表达式：`_e=(c("ab43"),c("4af0"))`（RHS 为 `(X("m1"),X("mod"))`）
      - 直接调用：`a=o("mod")`（无 var/const/let 前缀）
    用于 find_api_callers 精确限定：仅匹配 `a["export"]`（a 为绑定变量），
    避免同文件内其它命名空间（w/s/o 等）的同名单字母导出造成误报。
    """
    if not mod_id:
        return []
    # 用字符串 find 定位 `"mod_id"`，再向前解析绑定变量，
    # 避免对超大单行 webpack 产物做慢速正则 findall（贪婪回溯）。
    needle = '"' + mod_id + '"'
    vars_ = []
    start = 0
    while True:
        idx = src.find(needle, start)
        if idx == -1:
            break
        # 向前找 `X("mod_id")`：`(` 前的标识符 X
        j = idx - 1
        while j >= 0 and src[j] in ' \t\n\r':
            j -= 1
        if j >= 0 and src[j] == '(':
            # 提取调用函数名 X（可含 `.`，如 `n.n("mod")`），再向前找绑定变量
            k = j - 1
            while k >= 0 and (src[k].isalnum() or src[k] in '_$.'):
                k -= 1
            # 向前找 `var X =` / `X =` / `(X("m1"),X("mod"))`
            # seg 覆盖到 `"mod_id")` 之后，确保正则能匹配完整的 `X("mod_id")`
            seg = src[max(0, k - 80):idx + len(needle) + 2]
            # 形态1/3：`var X =` 或 `X =`（含逗号表达式 `_e=(c("m1"),X("mod"))`）
            m = re.search(
                r'(?:var\s+|const\s+|let\s+)?([A-Za-z_$][\w$]*)\s*=\s*'
                r'(?:\(\s*[^()]*\s*)?[A-Za-z_$][\w$]*\s*\(\s*["\']'
                + re.escape(mod_id) + r'["\']\s*\)',
                seg,
            )
            if m:
                vars_.append(m.group(1))
        start = idx + 1
    return list(dict.fromkeys(vars_))


def find_api_callers(chunk_dir: str, index: dict, export_name: str,
                     max_callers: int = 8, def_module_id: str = None):
    """定位导出函数名的真实调用点，并提取传参字段。

    解决三类问题：
      1. 噪声：导出名撞上 Vue 渲染字段（如 `a.pushData` 作为数据属性）或
         模块路径字符串（`"./accessControl/pushData"`）。仅当导出名以
         `["name"]` / `.name` 成员访问且紧跟 `(`（直接调用），或以
         `field: X["name"]` 引用赋值（Vue CRUD mixin）时才算真实调用点。
      2. `data:t` 透传：从调用点提取真实传参对象字段名。
      3. 单字母导出名跨模块撞名：当导出名为单字母（c/i/n/p/o/k/l/a/b/d/g 等）
         时，同名导出在数百个模块中复用，全文件搜索会命中大量无关模块的
         同名单字母调用。通过 def_module_id 限定：
         a) 只搜索「import 了定义模块」的文件；
         b) 只匹配「绑定到定义模块的命名空间变量」（如 `a=n("mod")` 后的
            `a["export"]`），而非同文件内其它命名空间的同名单字母导出。
         从而大幅提升精度。

    返回 {callers: [{file, kind, field, params, code}]}
      kind: direct（直接调用）/ ref（引用赋值，经 this.field 调用）
      params: 提取到的字段名列表（含 '*spread*' 表示展开对象）
    """
    callers = []
    seen = set()
    esc = re.escape(export_name)

    # 直接调用形态：成员访问后紧跟 `(`（含 `Object(X["name"])(...)` 的 `)(`）
    # 从候选点 off 锚定匹配：`X["name"]` 或 `X.name` 后紧跟调用括号。
    direct_re = re.compile(
        r'[A-Za-z_$][\w$]*\s*(?:\["' + esc + r'"\]|\.' + esc + r')\s*(?:\)\s*)?\(')
    # 引用赋值形态：field: X["name"] 或 field = X["name"]
    ref_re = re.compile(
        r'([A-Za-z_$][\w$]*)\s*[:=]\s*(?:Object\s*\([A-Za-z_$][\w$]*\s*\)\s*)?'
        r'[A-Za-z_$][\w$]*\["' + esc + r'"\]')

    # 从调用点预索引查表，按 export_name 精确过滤候选调用点，避免全量正则扫描
    candidates = index.get("call_sites", {}).get(export_name, [])
    # 按文件分组，每文件只读一次源码、算一次绑定变量
    by_file = {}
    for fn, off in candidates:
        by_file.setdefault(fn, []).append(off)

    for fn in sorted(by_file):
        src = _read_file_src(chunk_dir, fn)
        if src is None:
            continue
        # 限定搜索范围：仅搜索 import 了定义模块的文件，避免单字母导出名跨模块撞名误报
        if def_module_id and not _file_imports_module(src, def_module_id):
            continue
        # 精确限定命名空间：绑定到定义模块的变量名集合（如 `a=n("mod")` 的 a）
        bound_vars = _module_bind_vars(src, def_module_id) if def_module_id else []
        # 若指定了定义模块但未能识别任何绑定变量，则保守跳过该文件的宽松匹配，
        # 避免同文件内其它命名空间的同名单字母导出造成误报。
        if def_module_id and not bound_vars:
            continue

        # 1) 直接调用：从候选点锚定匹配成员访问 + 调用括号
        for off in by_file[fn]:
            tail = src[off:off + 80]
            dm = direct_re.match(tail)
            if not dm:
                continue
            # 若指定了定义模块，要求成员访问的宿主变量是绑定变量
            if bound_vars:
                host = dm.group(0).split('[')[0].split('.')[0].strip()
                if host not in bound_vars:
                    continue
            open_off = off + dm.start()
            arg, _ = _extract_call_arg(src, open_off)
            params = _object_fields(arg) if arg is not None else []
            # 实参是裸标识符（先建对象再传）→ 回溯字段赋值
            if not params and arg is not None:
                var = arg.strip()
                params = _trace_var_fields(src, open_off, var)
            key = ("direct", fn, open_off)
            if key in seen:
                continue
            seen.add(key)
            callers.append({
                "file": fn, "kind": "direct", "field": None,
                "params": params,
                "code": src[max(0, open_off - 60):min(len(src), open_off + 200)],
            })
            if len(callers) >= max_callers:
                return {"callers": callers}

        # 2) 引用赋值（Vue CRUD mixin：apiAdd/apiDelete/...）
        for off in by_file[fn]:
            seg_start = max(0, off - 60)
            seg = src[seg_start:off + 40]
            rm = ref_re.search(seg)
            if not rm:
                continue
            # 若指定了定义模块，要求被引用的宿主变量是绑定变量
            if bound_vars:
                hm = re.search(r'([A-Za-z_$][\w$]*)\["' + esc + r'"\]', rm.group(0))
                host = hm.group(1) if hm else None
                if host not in bound_vars:
                    continue
            field = rm.group(1)
            key = ("ref", fn, field)
            if key in seen:
                continue
            seen.add(key)
            # 收集 this.field(...) 调用点的实参
            params = []
            this_re = re.compile(r'this\.' + re.escape(field) + r'\s*\(')
            for tm in this_re.finditer(src):
                arg, _ = _extract_call_arg(src, tm.start())
                if arg is not None:
                    fields = _object_fields(arg)
                    if not fields:
                        fields = _trace_var_fields(src, tm.start(), arg.strip())
                    params.extend(fields)
            # 去重保序
            uniq = []
            for p in params:
                if p not in uniq:
                    uniq.append(p)
            rm_abs = seg_start + rm.start()
            callers.append({
                "file": fn, "kind": "ref", "field": field,
                "params": uniq,
                "code": src[max(0, rm_abs - 60):min(len(src), rm_abs + 40)],
            })
            if len(callers) >= max_callers:
                return {"callers": callers}

    return {"callers": callers}


# ==================== 密钥跨 chunk 调用方召回 ====================
# 背景：密钥值本身是字符串字面量，跨 chunk 引用它的是持有该值的变量/属性
# （如 `const KEY="sk_..."` → 其他 chunk 引用 `KEY`；`{secret:"..."}` → 引用 `secret`）。
# 单文件密钥扫描（SenInfoContextExtractor）只能找到定义文件内部的调用者；
# 当内部调用者为空时，用本函数经调用点索引按宿主变量名反查其他 chunk 的引用点。
# 与 API 召回（find_api_callers）的区别：密钥没有明确的定义模块 id，无法用
# _module_bind_vars 精确限定命名空间，因此噪声控制依赖「过滤过泛变量名 + 过滤定义文件自身」。

# 过泛的通用变量名：跨 chunk 反查会命中大量无关点，跳过以控噪声。
_GENERIC_HOST_VARS = {
    'key', 'secret', 'token', 'id', 'value', 'data', 'url', 'name', 'type',
    'code', 'msg', 'status', 'config', 'options', 'params', 'headers', 'body',
    'result', 'res', 'req', 'list', 'item', 'obj', 'object', 'info', 'detail',
    'e', 't', 'n', 'r', 'a', 'b', 'c', 'd', 'i', 'o', 'p', 'k', 'l', 'g',
}


def _is_generic_host_var(host_var: str) -> bool:
    """宿主变量名是否过泛（过泛则跨 chunk 反查噪声过大，跳过）。"""
    if not host_var:
        return True
    name = host_var.split('.')[-1].strip()
    if not name:
        return True
    if name in _GENERIC_HOST_VARS:
        return True
    if len(name) <= 1:
        return True
    return False


def find_secret_callers(chunk_dir: str, index: dict, host_var: str,
                        def_file: str = None, max_callers: int = 8):
    """跨 chunk 召回引用某密钥宿主变量的调用点。

    密钥值本身是字符串字面量，跨 chunk 引用它的是持有该值的变量/属性。本函数
    用调用点预索引反查其他 chunk 的引用点，过滤掉定义文件自身与过泛变量名。

    锚点解析（两种场景）：
      - 配置对象属性：`{secret:"..."}` → 其他 chunk 直接引用 `X["secret"]`，
        用 host_var 最后一段（secret）查 call_sites。
      - 导出桥接：`const KEY="sk_..."; n.d(t,"apiKey",()=>KEY)` → 其他 chunk
        用 `X["apiKey"]` 引用，需先反查 host_var（KEY）的导出名（apiKey）再查表。

    返回 {callers: [{file, kind, code}]}；无法识别/过泛时返回空列表。
    """
    if not host_var:
        return {"callers": []}
    # 过泛变量名（key/secret/token 等）跨 chunk 反查噪声过大，跳过
    if _is_generic_host_var(host_var):
        return {"callers": []}

    # 候选锚点：host_var 最后一段（配置对象属性形态）
    anchors = [host_var.split('.')[-1].strip()]
    # 导出桥接：反查 host_var 在定义文件中被导出的名字（导出形态）
    if def_file:
        def_src = _read_file_src(chunk_dir, def_file)
        if def_src:
            bundler = _detect_bundler(def_src)
            exports = _extract_exports(bundler, def_src)
            for exp_name, priv in exports.items():
                if priv == host_var or priv == host_var.split('.')[-1].strip():
                    anchors.append(exp_name)
    anchors = [a for a in anchors if a and not _is_generic_host_var(a)]

    callers = []
    seen = set()
    for name in anchors:
        call_sites = index.get("call_sites", {}).get(name, [])
        # 按文件分组，过滤定义文件自身
        by_file = {}
        for fn, off in call_sites:
            if def_file and fn == def_file:
                continue
            by_file.setdefault(fn, []).append(off)
        if not by_file:
            continue
        esc = re.escape(name)
        # 成员访问形态：X["name"] 或 X.name
        direct_re = re.compile(r'[A-Za-z_$][\w$]*\s*(?:\["' + esc + r'"\]|\.' + esc + r')')
        for fn in sorted(by_file):
            src = _read_file_src(chunk_dir, fn)
            if src is None:
                continue
            for off in by_file[fn]:
                seg = src[max(0, off - 80):off + 120]
                if not direct_re.search(seg):
                    continue
                key = (fn, off)
                if key in seen:
                    continue
                seen.add(key)
                callers.append({"file": fn, "kind": "ref", "code": seg})
                if len(callers) >= max_callers:
                    return {"callers": callers}
    return {"callers": callers}


def cross_chunk_recall(chunk_dir: str, index: dict, api_path: str,
                       max_snippets: int = 4):
    """跨文件召回：给定 API 路径，找出定义它的模块，并提取关键片段。
    返回 {snippets: [{file, kind, module, code}], chain: [...]}
    kind: api_def（具体 API 定义）/ module_def（模块头）"""
    snippets = []
    chain = []
    seen = set()

    # 1) 在所有 chunk 源码中找 api_path 字符串，定位定义模块
    for fn in sorted(index["files"]):
        src = _read_file_src(chunk_dir, fn)
        if src is None:
            continue
        for m in re.finditer(re.escape(api_path), src):
            off = m.start()
            # 归属模块
            owner = None
            for mod_id, minfo in index["files"][fn]["modules"].items():
                if minfo["offset"] <= off < minfo["end"]:
                    owner = mod_id
                    break
            # 无 module 映射的文件（如 UMD 库、独立脚本）用文件名作为归属标识，
            # 否则 API 字符串即使命中也会被跳过，导致跨 chunk 召回失效。
            if not owner:
                owner = fn

            # 优先提取具体 API 定义（url/method/data 骨架）
            api_snip = _api_def_snippet(src, off)
            if api_snip and api_snip not in seen:
                seen.add(api_snip)
                snippets.append({
                    "file": fn, "kind": "api_def", "module": owner,
                    "code": api_snip,
                })
                chain.append(f"{owner}@{fn}")

            # 补充模块头（含导出名映射）；仅当文件有真实 module 映射时才有模块头
            mods = index["files"][fn]["modules"]
            if owner in mods:
                mod_off = mods[owner]["offset"]
                mod_snip = _module_def_snippet(src, mod_off)
                if mod_snip and mod_snip not in seen:
                    seen.add(mod_snip)
                    snippets.append({
                        "file": fn, "kind": "module_def", "module": owner,
                        "code": mod_snip,
                    })

            if len(snippets) >= max_snippets:
                return {"snippets": snippets[:max_snippets], "chain": chain}

    return {"snippets": snippets[:max_snippets], "chain": chain}
