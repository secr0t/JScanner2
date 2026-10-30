# -*- coding: utf-8 -*-
"""
方案 B · 阶段1：chunk 采集器

从入口 JS 提取 webpack chunk 映射表，批量下载全部 chunk 到本地目录。
复用 httpx_crawler.fetch_urls_async 异步下载。

流程：
  1. 抓首页 HTML → 提取入口 JS URL
  2. 下载入口 JS → 正则提取 chunk 名→hash 映射表 → 生成全部 chunk URL
  3. fetch_urls_async 批量下载 → 存原始 JS 到 chunk_dir
"""
import asyncio
import os
import re

# webpack chunk 运行时：`s.p+"static/js/"+({chunk名:chunk名}[e]||e)+"."+{chunk名:"hash"}[e]+".js"`
# 提取第二个映射表（chunk名 -> hash）
_CHUNK_HASH_MAP_RE = re.compile(
    r'\+"\."\s*\+\s*\{([^}]*?[0-9a-f]{8}[^}]*?)\}\s*\[[A-Za-z_$][\w$]*\]'
)
# 单个条目：chunk名:"hash"
_CHUNK_ENTRY_RE = re.compile(r'"?([A-Za-z_~][\w~-]*)"?\s*:\s*"([0-9a-f]{8})"')

# 入口 JS 引用：<script src="...app.xxx.js">
_ENTRY_SCRIPT_RE = re.compile(r'<script[^>]+src="([^"]+\.js)"')


def extract_chunk_map(entry_js: str):
    """从入口 JS 提取 chunk 名→hash 映射表。
    返回 {chunk名: hash}，取第一个含 hash 的映射表（当前版本）。"""
    for m in _CHUNK_HASH_MAP_RE.finditer(entry_js):
        body = m.group(1)
        entries = dict(_CHUNK_ENTRY_RE.findall(body))
        if entries:
            return entries
    return {}


def build_chunk_urls(base_url: str, entry_js: str):
    """根据入口 JS 和站点 base_url，生成全部 chunk 的完整 URL。
    URL = base + "static/js/" + chunk名 + "." + hash + ".js"
    返回 (chunk_urls, chunk_map)"""
    chunk_map = extract_chunk_map(entry_js)
    if not chunk_map:
        return [], {}
    base = base_url.rstrip('/')
    urls = []
    for name, h in chunk_map.items():
        urls.append(f"{base}/static/js/{name}.{h}.js")
    return urls, chunk_map


def _extract_entry_js_url(html: str):
    """从首页 HTML 提取入口 JS URL（含 app/入口 chunk 的 script 引用）"""
    scripts = _ENTRY_SCRIPT_RE.findall(html)
    # 优先选含 app 或入口特征的，否则选最后一个（通常是入口）
    for s in scripts:
        if re.search(r'/(app|index|main|entry)[^/]*\.js', s):
            return s
    return scripts[-1] if scripts else None


def _resolve_url(base_url: str, ref: str):
    """把相对/绝对 script 引用解析成完整 URL"""
    if ref.startswith('http'):
        return ref
    base = base_url.rstrip('/')
    if ref.startswith('/'):
        return base + ref
    # 相对路径：取 base 的目录
    if '/' in base:
        base = base[:base.rfind('/')]
    return base + '/' + ref


async def collect_chunks(base_url: str, chunk_dir: str,
                         fetch_urls_async=None, thread_num=50,
                         headers=None, cookies=None, timeout=30,
                         extra_chunks=None, extra_js_urls=None):
    """采集全部 chunk 到本地目录。

    Args:
        base_url: 站点首页 URL（如 https://e.csot.tcl.com:8092/#/login）
        chunk_dir: 保存 chunk 的本地目录
        fetch_urls_async: 复用 httpx_crawler.fetch_urls_async；None 时延迟导入
        thread_num/headers/cookies/timeout: 透传给 fetch_urls_async
        extra_chunks: 可选，手动补充公共 chunk 文件名列表（如 ["chunk-libs.xxx.js"]）。
            公共 chunk 的 hash 由 webpack 运行时计算，无法从入口 JS 静态提取，
            需从浏览器 Network 面板或 HTML 引用手动补充。
        extra_js_urls: 可选，额外下载的独立 JS 文件 URL 列表（如 UMD 库、非 webpack
            chunk 的脚本）。这些文件不在首页入口 JS 的 chunk 映射表里，需显式传入，
            否则跨 chunk 索引无法覆盖它们。

    Returns:
        {"entry_js": 入口JS文件名, "chunk_map": {chunk名: hash},
         "downloaded": 成功下载数, "failed": 失败数}
    """
    os.makedirs(chunk_dir, exist_ok=True)

    if fetch_urls_async is None:
        from crawler.httpx_crawler import fetch_urls_async

    # 1. 抓首页 HTML
    home_results = await fetch_urls_async(
        [base_url], thread_num=thread_num, headers=headers,
        cookies=cookies, timeout=timeout)
    home = home_results[0] if home_results else {}
    if home.get("error") or not home.get("response_content"):
        raise RuntimeError(f"首页抓取失败: {home.get('error')}")

    html = home["response_content"]
    entry_ref = _extract_entry_js_url(html)
    if not entry_ref:
        raise RuntimeError("首页未找到入口 JS 引用")

    entry_url = _resolve_url(base_url, entry_ref)

    # 2. 下载入口 JS
    entry_results = await fetch_urls_async(
        [entry_url], thread_num=thread_num, headers=headers,
        cookies=cookies, timeout=timeout)
    entry = entry_results[0] if entry_results else {}
    if entry.get("error") or not entry.get("response_content"):
        raise RuntimeError(f"入口 JS 下载失败: {entry.get('error')}")

    entry_js = entry["response_content"]
    entry_name = os.path.basename(entry_url)
    with open(os.path.join(chunk_dir, entry_name), 'w', encoding='utf-8') as f:
        f.write(entry_js)

    # 3. 提取 chunk 映射表，生成 URL
    chunk_urls, chunk_map = build_chunk_urls(base_url, entry_js)

    # 3b. 补充公共 chunk（手动指定）
    if extra_chunks:
        base = base_url.rstrip('/')
        for name in extra_chunks:
            if not name.endswith('.js'):
                name += '.js'
            url = f"{base}/static/js/{name}"
            if url not in chunk_urls:
                chunk_urls.append(url)

    downloaded = 0
    failed = 0

    # 4. 批量下载 chunk（无 chunk 映射表时跳过，不阻断 extra_js_urls 下载）
    if chunk_urls:
        results = await fetch_urls_async(
            chunk_urls, thread_num=thread_num, headers=headers,
            cookies=cookies, timeout=timeout)
        for res in results:
            if res.get("error") or not res.get("response_content"):
                failed += 1
                continue
            name = os.path.basename(res["url"])
            with open(os.path.join(chunk_dir, name), 'w', encoding='utf-8') as f:
                f.write(res["response_content"])
            downloaded += 1

    # 5. 额外下载独立 JS 文件（非 webpack chunk，如 UMD 库），确保跨 chunk 索引覆盖。
    #    独立于 chunk 映射表提取，即使站点无 webpack chunk 也会下载。
    if extra_js_urls:
        extra_results = await fetch_urls_async(
            extra_js_urls, thread_num=thread_num, headers=headers,
            cookies=cookies, timeout=timeout)
        for res in extra_results:
            if res.get("error") or not res.get("response_content"):
                failed += 1
                continue
            name = os.path.basename(res["url"])
            if not name.endswith('.js'):
                continue
            with open(os.path.join(chunk_dir, name), 'w', encoding='utf-8') as f:
                f.write(res["response_content"])
            downloaded += 1

    if downloaded == 0:
        return {"entry_js": entry_name, "chunk_map": chunk_map,
                "downloaded": 0, "failed": failed, "error": "未提取到 chunk 映射表且无额外 JS 可下载"}

    return {"entry_js": entry_name, "chunk_map": chunk_map,
            "downloaded": downloaded, "failed": failed}


def collect_chunks_sync(base_url: str, chunk_dir: str, **kwargs):
    """同步包装：方便非 async 环境调用"""
    return asyncio.run(collect_chunks(base_url, chunk_dir, **kwargs))
