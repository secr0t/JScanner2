import asyncio
import atexit
import logging
import os
import time
import uuid
import warnings
from traceback import print_exc
from urllib.parse import urlparse

import psutil
from user_agent import generate_user_agent

from config.scanner_rules import UNAUTHORIZED_PAGE_KEYWORDS, \
    HTTPX_STATIC_EXTENSIONS, STATIC_RESOURCE_EXTENSIONS
from config.scanner_rules import is_api_path_blacklisted
from config.config import WHITE_SCOPE_PATH, db_filename, MEMORY_LIMIT, OVERFLOW_DIR
from crawler.browser_crawler import get_source_async
from crawler.httpx_crawler import fetch_urls_with_dedup, fetch_urls_async
from crawler.response_process import process_scan_result
from infra.ai_client import client
from infra.dedup import DuplicateChecker
from infra import watchdog
from infra.feishu import send_feishu_notify
from parse_args import parse_args
from processor.analysis import AISecurityAuditor
from processor.analysis.api.api_scan import get_root_domain
from processor.analysis.secret.js_sensitive_rex import find_all_info_by_rex
from processor.analysis.secret.secret_scanner import SensitiveInfoScanner, cleanup_bloom_filters, remove_html_tags, \
    SQLiteStorage
from processor.analysis.api.request_executor import batch_execute_requests
from storage.api_state import ApiStatus
from storage.filerw import read

warnings.filterwarnings("ignore")
from colorama import init

BATCH_SIZE = 200
BATCH_SLEEP = 0.2
API_MIN_LENGTH = 4
HTML_EXTS = {'.html', '.htm', '.xhtml'}


def _build_bundle_context(js_url: str, seed_url: str, collect_if_missing: bool = True):
    """为入口 JS 构建跨 chunk 召回上下文；失败/非 webpack 时返回 None（优雅降级）。

    策略：
      1. chunk 缓存目录 = Result/bundle_chunks/<md5(js_url)>，按入口 URL 隔离。
      2. 目录已存在（含入口 JS）→ 直接构建索引（走缓存，不重新下载）。
      3. 目录不存在 → 若 collect_if_missing 则尝试用 bundle_collector 采集；
         否则（密钥扫描阶段）直接返回 None，避免对 chunk 文件重复采集。
    返回 {"chunk_dir", "index", "cross_chunk_recall",
           "find_api_callers", "resolve_export_name", "find_secret_callers"} 或 None。
    """
    try:
        from processor.js.context import bundle_index as bi
        from processor.js.context.bundle_collector import collect_chunks_sync

        import hashlib
        chunk_dir = os.path.join(
            "Result", "bundle_chunks", hashlib.md5(js_url.encode()).hexdigest()[:16])

        # 目录已有入口 JS（上次采集过）→ 直接构建索引
        if not (os.path.isdir(chunk_dir) and os.listdir(chunk_dir)):
            if not collect_if_missing:
                return None
            # 额外下载 js_url 指向的独立 JS 文件（非 webpack chunk，如 UMD 库），
            # 确保跨 chunk 索引能覆盖它（collect_chunks 默认只采首页入口 JS + webpack chunk）
            collect_chunks_sync(seed_url, chunk_dir, extra_js_urls=[js_url] if js_url else None)

        index = bi.get_bundle_index(chunk_dir)
        if not index or not index.get("files"):
            return None
        return {
            "chunk_dir": chunk_dir,
            "index": index,
            "js_url": js_url,
            "cross_chunk_recall": bi.cross_chunk_recall,
            "find_api_callers": bi.find_api_callers,
            "resolve_export_name": bi.resolve_export_name,
            "find_secret_callers": bi.find_secret_callers,
        }
    except Exception:
        return None


def _assemble_bundle_context(js_url: str, chunk_dir: str, index: dict):
    """把 chunk_dir + index 组装成 _build_bundle_context 的返回结构（含函数引用）。

    并行构建时，子进程只产出纯数据 index；函数引用（cross_chunk_recall /
    find_api_callers / resolve_export_name / find_secret_callers）在主进程组装，
    避免把不可 pickle 的模块函数传入子进程。
    """
    from processor.js.context import bundle_index as bi
    return {
        "chunk_dir": chunk_dir,
        "index": index,
        "js_url": js_url,
        "cross_chunk_recall": bi.cross_chunk_recall,
        "find_api_callers": bi.find_api_callers,
        "resolve_export_name": bi.resolve_export_name,
        "find_secret_callers": bi.find_secret_callers,
    }


async def _build_bundle_contexts_many(js_urls, seed_url: str, collect_if_missing: bool = True):
    """并行构建多个 js_url 的跨 chunk 召回上下文。返回 {js_url: context_or_None}。

    方案 B：把串行的"采集 + 建索引"并行化。
      1. 采集（I/O 密集）：对缺失的 chunk_dir 用原生 collect_chunks 并发下载，
         在 async 上下文里 asyncio.gather，不阻塞主事件循环。
      2. 建索引（CPU 密集）：用 ProcessPoolExecutor 并行 build_bundle_index，
         子进程产出纯数据 index，主进程写入 _INDEX_CACHE 并组装 context。
    单个 js_url 失败只影响它自己（返回 None），不影响其他 js_url。
    """
    import hashlib
    from concurrent.futures import ProcessPoolExecutor
    from processor.js.context import bundle_index as bi
    from processor.js.context.bundle_collector import collect_chunks

    chunk_dir_map = {}
    for js_url in js_urls:
        chunk_dir = os.path.join(
            "Result", "bundle_chunks", hashlib.md5(js_url.encode()).hexdigest()[:16])
        chunk_dir_map[js_url] = chunk_dir

    # 1) 并发采集缺失的 chunk_dir
    to_collect = [(js_url, cd) for js_url, cd in chunk_dir_map.items()
                  if not (os.path.isdir(cd) and os.listdir(cd))]
    if to_collect and collect_if_missing:
        # 每个 js_url 额外下载其指向的独立 JS 文件（非 webpack chunk，如 UMD 库），
        # 确保跨 chunk 索引能覆盖它（collect_chunks 默认只采首页入口 JS + webpack chunk）
        await asyncio.gather(
            *(collect_chunks(seed_url, cd, extra_js_urls=[js_url] if js_url else None)
              for js_url, cd in to_collect),
            return_exceptions=True)

    # 2) 并行建索引（CPU 密集）
    ready = [js_url for js_url, cd in chunk_dir_map.items()
             if os.path.isdir(cd) and os.listdir(cd)]
    results = {}
    if ready:
        ready_dirs = [chunk_dir_map[js_url] for js_url in ready]
        workers = min(os.cpu_count() or 1, len(ready))
        with ProcessPoolExecutor(max_workers=workers) as ex:
            indexes = list(ex.map(bi.build_bundle_index, ready_dirs))
        for js_url, index in zip(ready, indexes):
            if not index or not index.get("files"):
                continue
            cd = chunk_dir_map[js_url]
            bi._INDEX_CACHE[cd] = index  # 进程内缓存，供后续 get_bundle_index 命中
            results[js_url] = _assemble_bundle_context(js_url, cd, index)
    return results


def _is_more_specific(new_url: str, old_url: str) -> bool:
    """新 baseURL 的路径前缀比旧的更长，说明更精确"""
    from urllib.parse import urlparse
    new_path = urlparse(new_url).path.rstrip('/')
    old_path = urlparse(old_url).path.rstrip('/')
    return len(new_path) > len(old_path)


def _is_already_base_url(url: str) -> bool:
    """判断 URL 是否已经是一个验证过的 baseURL（含路径前缀）"""
    if not url:
        return False
    parsed = urlparse(url)
    path = parsed.path.rstrip('/')
    return bool(path) and path != '/'


def _get_first_level_prefix(api_path):
    path = api_path.strip().lstrip('/')
    parts = path.split('/')
    return parts[0] if parts else ""


# 初始化日志
logger = logging.getLogger(__name__)


def _is_static_url(url: str) -> bool:
    """判断是否是静态资源"""
    url_lower = url.lower().split('?')[0]
    return any(url_lower.endswith(ext) for ext in HTTPX_STATIC_EXTENSIONS)


def _is_html_url(url: str) -> bool:
    """判断是否是 HTML 页面"""
    url_lower = url.lower().split('?')[0]
    return any(url_lower.endswith(ext) for ext in HTML_EXTS)


def _is_skip_ext(url: str) -> bool:
    """判断是否是需要跳过的扩展名"""
    url_lower = url.lower().split('?')[0]
    return any(url_lower.endswith(ext) for ext in STATIC_RESOURCE_EXTENSIONS)


def classify_url(url, is_seed=False):
    """URL 分类（极简版）"""
    if is_seed:
        return 'dynamic'

    parsed = urlparse(url)
    path = parsed.path
    has_dot = "." in path

    if has_dot:
        if _is_static_url(url):
            return 'static'
        elif _is_html_url(url):
            return 'dynamic'
        return 'dynamic'
    return 'api'


# ==================== Scanner 类 ====================

class Scanner:
    def __init__(self, args, db_handler):
        self.args = args
        self.db_handler = db_handler
        self.initial_urls = []
        self.checker = None
        self.whiteList = read(WHITE_SCOPE_PATH)
        self.domain_base_urls = {}

        # 站点维度 scan_id（P0-1：API 状态按站点隔离）与本次运行 run_id（P0-2：中断恢复）
        self.scan_id = None
        self.run_id = uuid.uuid4().hex

        self.ai_auditor = None
        if self.args.findparam:
            try:
                self.ai_auditor = AISecurityAuditor(request_validation=self.args.request_validation)
            except Exception as e:
                # P0-3：初始化失败必须打出完整栈，不能只留一句话后静默关闭 AI 分析
                import traceback
                traceback.print_exc()
                logger.error(f"[AI] AI 安全审计器初始化失败（本次扫描不会产出 API 分析结果）：{e}")
                print(f"[AI] AI 安全审计器初始化失败：{e}")

        self.sensitive_scanner = None
        if self.args.analyzeSensitiveInfoAI:
            try:
                self.sensitive_scanner = SensitiveInfoScanner(
                    client=client,
                    db=self.db_handler,
                    max_ast_analysis=50,
                    max_llm=80
                )
            except Exception as e:
                import traceback
                traceback.print_exc()
                logger.error(f"[Scanner] 敏感信息扫描器初始化失败：{e}")
                print(f"[Scanner] 敏感信息扫描器初始化失败：{e}")

        atexit.register(self._cleanup_resources)

    def _cleanup_resources(self):
        try:
            try:
                cleanup_bloom_filters()
            except Exception:
                pass
            if self.db_handler:
                self.db_handler.close()
        except Exception as e:
            print(f"[Cleanup] 清理失败：{e}")

    @staticmethod
    def _is_api_path_blacklisted(api_path: str) -> bool:
        """
        检查 API path 是否匹配黑名单正则

        Args:
            api_path: API 路径

        Returns:
            bool: 如果匹配黑名单返回 True，否则返回 False
        """
        return is_api_path_blacklisted(api_path)

    async def _quick_scan_filter(self, url, status_code, snippet):
        """快速扫描过滤器"""
        url_lower = url.lower()
        snippet_lower = snippet.lower() if snippet else ""

        if status_code == 401:
            return "0"
        if _is_skip_ext(url):
            return "0"
        if (200 <= status_code <= 300) or (500 <= status_code < 600):
            if any(kw in snippet_lower for kw in UNAUTHORIZED_PAGE_KEYWORDS):
                return "0"
            if "<!doctype" in snippet_lower or "<html" in snippet_lower or "<head" in snippet_lower:
                return "0"
        return "1"

    async def run(self):
        """主运行逻辑"""
        os.makedirs("Result", exist_ok=True)
        watchdog.beat("startup", self.args.url)
        watchdog.start()                       # 启动心跳广播（daemon 线程）
        self.initial_urls = self._load_initial_urls()

        # P0-1：以站点为单位分配 scan_id，不同站点的 API 状态互不影响
        root_domain = get_root_domain(self.args.url) if self.args.url else "unknown"
        self.scan_id = self.db_handler.get_or_create_scan_id(root_domain)
        print(f"🎯 [Scan] scan_id={self.scan_id} | 站点={root_domain} | run_id={self.run_id}")

        # P0-2：把上一轮没跑完的 API 重新排队，支持从中断位置恢复
        resumed = self.db_handler.reset_stale_in_progress(self.scan_id, self.run_id)
        if resumed:
            print(f"♻️ [Resume] {resumed} 个 API 从中断位置重新排队")

        self.checker = DuplicateChecker(db_handler=self.db_handler, initial_root_domain=self.initial_urls,
                                        scan_id=self.scan_id)
        self.args.initial_urls = self.initial_urls

        raw_seed_urls = self.load_url()
        scan_seed_urls = []
        for url in raw_seed_urls:
            url = url.strip()
            if not url:
                continue
            if not self.checker.visited_urls.contains(url):
                self.checker.visited_urls.add(url)
                scan_seed_urls.append(url)
            else:
                print(f"初始 URL 已在历史记录中，跳过：{url}")

        if not scan_seed_urls:
            return

        start_time = time.time()
        await self._scan_recursive(scan_seed_urls, 0, is_seed=True)
        watchdog.beat("finished")
        print(f"🏁 任务结束 | 总耗时：{time.time() - start_time:.2f}秒")

    def load_url(self):
        if self.args.url and self.args.url.strip():
            return [self.args.url.strip()]
        return []

    def _load_initial_urls(self):
        white_list_domains = read(WHITE_SCOPE_PATH)
        if self.args.url and self.args.url.strip():
            try:
                seed_root_domain = get_root_domain(self.args.url.strip())
                if seed_root_domain and seed_root_domain not in white_list_domains:
                    white_list_domains.append(seed_root_domain)
            except Exception:
                pass
        return list(set(filter(None, white_list_domains)))

    async def _process_ai_batch(self, batch_all_next_paths_with_source, batch_scan_info_list, batch_next_urls):
        if not self.ai_auditor:
            return

        if not getattr(self.args, 'findparam', False):
            return

        effective_seed = self._get_effective_seed()
        base_prefix = effective_seed.rstrip('/') if effective_seed else None
        origin_url = self.args.url

        # 已去除 prefix_agent 前缀验证：API 最终路径（含前缀）由 AI 阶段（reconstruct）
        # 直接输出，此处不再做前缀聚类判定。verified_clusters 保留为空，默认全量用 base_prefix。
        verified_clusters = {}

        qualified_api_paths = set()
        if getattr(self.args, 'fastscan', False) and batch_next_urls:
            print("⚡ [FastScan] 快速扫描模式已启用")

            urls_to_scan = []
            path_to_url_map = {}
            for item in batch_all_next_paths_with_source:
                source_url = item.get("sourceURL", "").strip()
                next_paths = item.get("next_paths", [])
                if not source_url or not next_paths:
                    continue

                for api_path in next_paths:
                    api_path = api_path.strip()
                    if not api_path or len(api_path) < API_MIN_LENGTH:
                        continue
                    if self._is_api_path_blacklisted(api_path):
                        continue

                    cluster = _get_first_level_prefix(api_path)
                    use_prefix = verified_clusters.get(cluster, True)

                    if use_prefix and base_prefix and _is_already_base_url(base_prefix):
                        full_url = f"{base_prefix}/{api_path.lstrip('/')}"
                    else:
                        parsed = urlparse(source_url)
                        domain_prefix = f"{parsed.scheme}://{parsed.netloc}"
                        full_url = api_path if api_path.startswith("http") else f"{domain_prefix}{api_path}"

                    full_url = full_url.strip()
                    if full_url and full_url not in path_to_url_map:
                        path_to_url_map[full_url] = api_path
                        if not _is_skip_ext(full_url):
                            urls_to_scan.append(full_url)

            if urls_to_scan:
                unique_results, dup_count, stats = await fetch_urls_with_dedup(
                    urls=urls_to_scan, thread_num=50,
                    headers={"User-Agent": generate_user_agent()}, cookies=None, timeout=10)
                url_scan_results = {}
                for result in unique_results:
                    url = result["url"].strip()
                    url_scan_results[url] = {
                        "status_code": result["status_code"], "length": result["length"],
                        "response_content": result["response_content"], "fingerprint": result.get("fingerprint"),
                    }
                filter_count = 0
                for full_url, api_path in path_to_url_map.items():
                    if full_url in url_scan_results:
                        scan_result = url_scan_results[full_url]
                        should_test = await self._quick_scan_filter(
                            url=full_url, status_code=scan_result["status_code"],
                            snippet=scan_result["response_content"][:600])
                        if should_test == "1":
                            qualified_api_paths.add(api_path)
                        else:
                            filter_count += 1

                print(
                    f"🌐 [Quick Scan] {len(urls_to_scan)} URLs → {dup_count} duplicates → {len(qualified_api_paths)} qualified")
                print(f"🔍 [Filter Stats] Filtered: {filter_count}, Passed: {len(qualified_api_paths)}")
        else:
            print("ℹ️  [FastScan] 快速扫描模式未启用，将分析所有 API")

        source_map = {}
        for info in batch_scan_info_list:
            if info.get("source_code") and info.get("url") and ".js" in info["url"]:
                try:
                    clean_code = remove_html_tags(info["source_code"])
                    source_map[info["url"]] = clean_code
                except:
                    source_map[info["url"]] = info["source_code"]

        processed_count = 0
        skipped_dup_count = 0

        # (api_path, js_url) 全量保留：
        # 不同 JS 文件里的同名路径上下文可能不同，不能在分析前按 path 丢掉
        api_pairs = []
        seen_pairs = set()

        for item in batch_all_next_paths_with_source:
            js_url = item.get("sourceURL")
            found_apis = item.get("next_paths", [])

            if not js_url or js_url not in source_map:
                continue

            for api_path in found_apis:
                api_path = api_path.strip()

                if len(api_path) < API_MIN_LENGTH:
                    continue
                if api_path.startswith("http") or api_path.startswith("//"):
                    continue
                if any(api_path.lower().endswith(ext) for ext in ['.png', '.jpg', '.css', '.woff', '.ico']):
                    continue
                if self._is_api_path_blacklisted(api_path):
                    continue

                pair = (api_path, js_url)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    api_pairs.append(pair)

        # 去重范围 = (scan_id, api_path)；去重判据 = 状态机
        all_paths_in_batch = list(dict.fromkeys(p for p, _ in api_pairs))
        analyzable_paths = [p for p in all_paths_in_batch if self.checker.should_analyze_api(p)]
        analyzable_set = set(analyzable_paths)
        skipped_dup_count = len(all_paths_in_batch) - len(analyzable_paths)

        apis_to_scan = [(api_path, js_url) for api_path, js_url in api_pairs if api_path in analyzable_set]

        if skipped_dup_count > 0:
            print(f"⏭️ [Path Dedup] Skipped {skipped_dup_count} duplicate API paths in this batch")

        if not apis_to_scan:
            print(f"✅ [Batch] All APIs already processed, skipping AI analysis...")
            return

        # P0-2：分析前只登记"发现"，不标记完成；后续失败仍会重新进入分析
        self.checker.mark_apis_discovered([(api_path, js_url) for api_path, js_url in apis_to_scan])
        print(f"📝 [State] Marked {len(analyzable_paths)} API paths as DISCOVERED (分析完成前不算 processed)")

        js_groups = {}
        for api_path, js_url in apis_to_scan:
            if js_url not in js_groups:
                js_groups[js_url] = []

            cluster = _get_first_level_prefix(api_path)
            use_prefix = verified_clusters.get(cluster, True)

            if use_prefix and base_prefix and _is_already_base_url(base_prefix):
                full_url = f"{base_prefix}/{api_path.lstrip('/')}"
            else:
                from processor.analysis.api.api_scan import data_clean
                cleaned_urls = data_clean(js_url, [api_path], seed_url=effective_seed)
                if cleaned_urls and len(cleaned_urls) > 0:
                    full_url = cleaned_urls[0]
                else:
                    parsed = urlparse(js_url)
                    domain_prefix = f"{parsed.scheme}://{parsed.netloc}"
                    full_url = api_path if api_path.startswith("http") else f"{domain_prefix}{api_path}"

            js_groups[js_url].append((api_path, full_url))

        vuln_records_for_request = []

        # 方案 B：并行构建本批次所有 js_url 的跨 chunk 召回上下文。
        # 采集（I/O 密集）用 asyncio.gather 并发，建索引（CPU 密集）用
        # ProcessPoolExecutor 并行；返回 {js_url: context_or_None}。
        bundle_contexts = {}
        try:
            bundle_contexts = await _build_bundle_contexts_many(
                list(js_groups.keys()),
                effective_seed.strip() if effective_seed else self.args.url.strip(),
            )
        except Exception:
            print_exc()
            logger.error("❌ [AI] 并行构建 bundle context 失败，降级为逐个构建")

        for js_url, api_data_list in js_groups.items():
            js_source = source_map.get(js_url, "")
            if not js_source:
                continue

            api_paths = [item[0] for item in api_data_list]
            print(f"🧩 [AI] 开始分析 {js_url} | API 数: {len(api_paths)} | JS 大小: {len(js_source)} 字符")

            # 进入 AI 前推进状态并累加尝试次数
            self.checker.mark_api_status_batch(
                api_paths, ApiStatus.AI_PENDING, js_url=js_url,
                run_id=self.run_id, increment_attempt=True
            )

            try:
                # 跨 chunk 召回上下文（webpack 入口 JS 才有效；失败自动降级为 None）
                bundle_context = bundle_contexts.get(js_url)
                if bundle_context is None:
                    # 并行构建未覆盖（如采集/建索引失败）→ 回退到原串行逻辑
                    bundle_context = _build_bundle_context(
                        js_url,
                        effective_seed.strip() if effective_seed else self.args.url.strip(),
                    )
                batch_ai_advisories = self.ai_auditor.scan_multiple_apis(
                    js_code=js_source,
                    api_paths=api_paths,
                    target_url=effective_seed.strip() if effective_seed else self.args.url.strip(),
                    bundle_context=bundle_context,
                )
            except Exception as e:
                print_exc()
                logger.error(f"❌ [AI] Failed to analyze APIs from {js_url}: {e}")
                self.checker.mark_api_status_batch(
                    api_paths, ApiStatus.AI_FAILED, js_url=js_url,
                    last_error=str(e), run_id=self.run_id
                )
                continue

            # 上下文召回结果（用于区分"没上下文"和"AI 失败"）
            context_types = getattr(self.ai_auditor, "last_context_types", {}) or {}
            context_found = getattr(self.ai_auditor, "last_context_found", {}) or {}

            for api_path in api_paths:
                advisory_report = batch_ai_advisories.get(api_path)

                if not advisory_report:
                    if not context_found.get(api_path, False):
                        fail_status = ApiStatus.NO_CONTEXT
                        reason = "AST 上下文未命中"
                    elif context_types.get(api_path) == "FRONTEND_ROUTE":
                        fail_status = ApiStatus.NO_CONTEXT
                        reason = "前端路由上下文，非 HTTP API"
                    else:
                        fail_status = ApiStatus.AI_FAILED
                        reason = "AI 未产出可用结果（超时/JSON 解析失败/空返回）"

                    # 失败态不等于完成，下次扫描仍会重新处理
                    self.checker.mark_api_status(
                        api_path, fail_status, js_url=js_url,
                        last_error=reason, run_id=self.run_id
                    )
                    continue

                print(f"🤖 [AI Advisor] Generated Advisory for {api_path}")
                print(advisory_report)
                processed_count += 1

                full_url = next((item[1] for item in api_data_list if item[0] == api_path), "")

                # 已去除 base_url/prefix Agent：直接使用 AI 输出的最终 path 组装完整 URL
                # （AI path 已含 /security/ 等拦截器前缀；域名取种子地址 origin）
                ai_path = advisory_report.get("path", "")
                if ai_path:
                    if ai_path.startswith(("http://", "https://")):
                        full_url = ai_path
                    else:
                        parsed = urlparse(origin_url or js_url)
                        full_url = f"{parsed.scheme}://{parsed.netloc}{ai_path}"

                record_id = self.db_handler.save_ai_result_with_id(
                    js_url=js_url,
                    full_url=full_url,
                    advisory_report=advisory_report,
                    scan_id=self.scan_id
                )

                if record_id:
                    vuln_records_for_request.append({
                        "id": record_id,
                        "api_path": api_path,
                        "full_url": full_url,
                        "http_method": advisory_report.get("method", ""),
                        "params": advisory_report.get("params", ""),
                        "path": advisory_report.get("path", "")
                    })
                    self.checker.mark_api_status(
                        api_path, ApiStatus.AI_DONE, js_url=js_url, run_id=self.run_id
                    )
                else:
                    # 写库失败同样不能算完成
                    self.checker.mark_api_status(
                        api_path, ApiStatus.AI_FAILED, js_url=js_url,
                        last_error="结果写入数据库失败", run_id=self.run_id
                    )

        if processed_count > 0:
            print(f"🤖 [AI Advisor] Batch completed. Generated {processed_count} Advisories.")

        if vuln_records_for_request:
            if not self.args.request_validation:
                print(f"ℹ️  [Request Validation] 未开启请求验证，{len(vuln_records_for_request)} 条记录仅存档")
                # 未开启验证：AI 阶段即为本轮终点，推进到终态
                self.checker.mark_api_status_batch(
                    [r["api_path"] for r in vuln_records_for_request],
                    ApiStatus.VALIDATED, run_id=self.run_id
                )
            else:
                print(f"🏷️ [Classifier] Starting operation type classification for {len(vuln_records_for_request)} records...")

                read_records = []
                write_records = []

                for record in vuln_records_for_request:
                    op_type = self.ai_auditor.classify_operation_type(
                        path=record.get("path", ""),
                        method=record.get("http_method", ""),
                        params=record.get("params", "")
                    )

                    if op_type == "READ":
                        read_records.append(record)
                    else:
                        write_records.append(record)
                        print(f"🚫 [{record.get('path', '')}] 分类: {op_type} → 需人工确认")

                if write_records:
                    self.db_handler.batch_mark_needs_manual_review([r["id"] for r in write_records])
                    print(f"📋 [Classifier] {len(write_records)} records marked as needs_manual_review")
                    # 自动化链路到此结束，转入人工确认
                    self.checker.mark_api_status_batch(
                        [r["api_path"] for r in write_records],
                        ApiStatus.VALIDATED, run_id=self.run_id
                    )

                if read_records:
                    print(f"🚀 [Request Validation] Starting {len(read_records)} READ requests...")
                    self.checker.mark_api_status_batch(
                        [r["api_path"] for r in read_records],
                        ApiStatus.VALIDATION_PENDING, run_id=self.run_id
                    )
                    try:
                        request_results = await batch_execute_requests(read_records)

                        updated_count = self.db_handler.batch_update_ai_vuln_request_results(request_results)
                        print(f"✅ [Request Validation] Completed. Updated {updated_count} records.")

                        id_to_path = {r["id"]: r["api_path"] for r in read_records}
                        validated_paths = []
                        failed_paths = []
                        for result in request_results:
                            api_path = id_to_path.get(result.get("id"))
                            if not api_path:
                                continue
                            if result.get("status_code", -1) > 0:
                                validated_paths.append(api_path)
                            else:
                                failed_paths.append(api_path)

                        if validated_paths:
                            self.checker.mark_api_status_batch(
                                validated_paths, ApiStatus.VALIDATED, run_id=self.run_id
                            )
                        if failed_paths:
                            self.checker.mark_api_status_batch(
                                failed_paths, ApiStatus.VALIDATION_FAILED,
                                last_error="请求验证未拿到有效响应", run_id=self.run_id
                            )

                    except Exception as e:
                        print_exc()
                        logger.error(f"❌ [Request Validation] Batch request failed: {e}")
                        print(f"❌ [Request Validation] 批量请求失败: {e}")
                        self.checker.mark_api_status_batch(
                            [r["api_path"] for r in read_records],
                            ApiStatus.VALIDATION_FAILED,
                            last_error=str(e), run_id=self.run_id
                        )
                else:
                    print(f"ℹ️  [Request Validation] No READ records to validate.")
        else:
            print(f"ℹ️  [Request Validation] No records to validate.")

    async def parallel_fetch(self, batch_dynamic, batch_static, effective_seed=None):
        """异步并行请求：静态 + 动态"""
        tasks = []
        task_order = []
        seed = effective_seed if effective_seed else self.args.url
        if batch_dynamic:
            dynamic_task = get_source_async(urls=batch_dynamic, thread_num=self.args.thread_num, args=self.args,
                                            checker=self.checker, effective_seed=seed)
            tasks.append(dynamic_task)
            task_order.append('dynamic')
        if batch_static:
            static_task = fetch_urls_async(urls=batch_static, thread_num=min(self.args.thread_num, 50),
                                           headers={"User-Agent": generate_user_agent()}, timeout=10)
            tasks.append(static_task)
            task_order.append('static')
        if not tasks:
            return ([], [], set(), []), []
        results = await asyncio.gather(*tasks)
        dynamic_result = ([], [], set(), [])
        static_result = []
        for i, task_type in enumerate(task_order):
            if task_type == 'dynamic':
                dynamic_result = results[i]
            elif task_type == 'static':
                static_result = results[i]
        return dynamic_result, static_result

    def _get_effective_seed(self) -> str:
        """获取当前域名已缓存的 baseURL，如果没有则返回原始 seed_url"""
        if not self.args.url:
            return self.args.url
        root_domain = get_root_domain(self.args.url)
        return self.domain_base_urls.get(root_domain, self.args.url)

    def _collect_base_urls_from_batch(self, scan_info_list):
        """从本批次的 scan_info 中收集已验证的 baseURL，存入域名级缓存"""
        root_domain = get_root_domain(self.args.url) if self.args.url else None
        if not root_domain:
            return
        for info in scan_info_list:
            detected = info.get("detected_base_url")
            if detected:
                existing = self.domain_base_urls.get(root_domain)
                if not existing or _is_more_specific(detected, existing):
                    self.domain_base_urls[root_domain] = detected
                    print(f"🎯 [BaseURL] 域名 {root_domain} → {detected}")

    async def _process_single_batch(self, batch_urls: list, depth: int) -> dict:
        """处理单个批次（提取自 _scan_recursive）"""
        batch_dynamic = [u for u in batch_urls if classify_url(u, is_seed=(depth == 0)) == 'dynamic']
        batch_static = [u for u in batch_urls if classify_url(u, is_seed=(depth == 0)) == 'static']

        effective_seed = self._get_effective_seed()
        dynamic_result, static_result = await self.parallel_fetch(batch_dynamic=batch_dynamic,
                                                                  batch_static=batch_static,
                                                                  effective_seed=effective_seed)

        batch_all_next_urls_with_source = []
        batch_scan_info_list = []
        batch_next_urls = set()
        batch_all_next_paths_with_source = []

        if dynamic_result:
            batch_all_next_urls_with_source, batch_scan_info_list, batch_next_urls, batch_all_next_paths_with_source = dynamic_result

        if static_result:
            for static_resp in static_result:
                if not static_resp.get("error"):
                    parsed = urlparse(static_resp["url"])
                    static_info = {
                        "domain": parsed.hostname, "url": static_resp["url"], "path": parsed.path,
                        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                        "status": static_resp["status_code"], "title": "Static Resource",
                        "length": static_resp["length"], "source_code": static_resp["response_content"],
                        "is_valid": 0, "redirect_count": static_resp.get("redirect_count", 0),
                        "redirect_locations": [], "original_url": static_resp["url"]
                    }
                    try:
                        is_valid, next_urls, next_paths = await process_scan_result(static_info, self.checker,
                                                                                    self.args,
                                                                                    seed_url=effective_seed)
                        if is_valid:
                            static_info["is_valid"] = 1
                            batch_scan_info_list.append(static_info)
                            if next_urls:
                                batch_next_urls.update(next_urls)
                                batch_all_next_urls_with_source.append(
                                    {"next_urls": list(next_urls), "sourceURL": static_resp["url"]})
                                batch_all_next_paths_with_source.append(
                                    {"next_paths": next_paths, "sourceURL": static_resp["url"]})
                        else:
                            batch_scan_info_list.append(static_info)
                    except Exception as e:
                        print(f"⚠️ 静态资源处理失败 {static_resp['url']}: {e}")
                        batch_scan_info_list.append(static_info)
        return {
            "next_urls": batch_next_urls,
            "scan_info_list": batch_scan_info_list,
            "all_next_urls_with_source": batch_all_next_urls_with_source,
            "all_next_paths_with_source": batch_all_next_paths_with_source
        }

    def _check_memory_and_handle(self, depth: int, next_urls: set, remaining_urls: list) -> bool:
        """检查内存并处理溢出，返回是否继续"""
        try:
            mem = psutil.virtual_memory()
            if mem.percent > MEMORY_LIMIT:
                print(f"\n⚠️  内存告警：{mem.percent}% > {MEMORY_LIMIT}% | 触发熔断保护.")
                os.makedirs(OVERFLOW_DIR, exist_ok=True)
                file_id = uuid.uuid4().hex[:8]
                rem_height_children = self.args.height - (depth + 1)
                final_children = [u for u in next_urls if self.checker.should_scan(u)]
                if final_children and rem_height_children >= 0:
                    with open(f"{OVERFLOW_DIR}/overflow_depth_{rem_height_children}_{file_id}_children.txt", "w") as f:
                        f.write("\n".join(final_children))
                rem_height_siblings = self.args.height - depth
                if remaining_urls and rem_height_siblings >= 0:
                    with open(f"{OVERFLOW_DIR}/overflow_depth_{rem_height_siblings}_{file_id}_siblings.txt", "w") as f:
                        f.write("\n".join([u for u in remaining_urls if ".js" in u]))
                self.db_handler.close()
                print(f"🛑 进程主动退出 (Memory Safety)")
                return False
            return True
        except Exception:
            return True

    async def _scan_recursive(self, urls, depth, is_seed=False):
        """递归扫描主流程"""
        if depth > self.args.height:
            return
        raw_urls_list = [url.strip() for url in urls if url.strip()]
        urls_list = []
        if depth > 0:
            for u in raw_urls_list:
                if self.checker.should_scan(u):
                    self.checker.visited_urls.add(u)
                    urls_list.append(u)
        else:
            for u in raw_urls_list:
                if self.checker.is_within_scope(u):
                    urls_list.append(u)
        if not urls_list:
            return
        print(f"🔍 深度 {depth} 扫描开始 | URL 数：{len(urls_list)}")

        static_urls = [u for u in urls_list if classify_url(u, is_seed=(depth == 0)) == 'static']
        dynamic_urls = [u for u in urls_list if classify_url(u, is_seed=(depth == 0)) == 'dynamic']
        api_urls = [u for u in urls_list if classify_url(u, is_seed=(depth == 0)) == 'api']

        if static_urls: print(f"   📦 静态资源：{len(static_urls)} 个（使用 httpx 快速请求）")
        if dynamic_urls: print(f"   🚀 动态页面：{len(dynamic_urls)} 个（使用 Playwright）")
        if api_urls: print(f"   ⏭️ API 路径：{len(api_urls)} 个（不请求，从 JS 分析）")

        batch_size = BATCH_SIZE
        total_batches = (len(urls_list) + batch_size - 1) // batch_size
        all_scan_info_list = []
        all_next_urls = set()

        for batch_idx in range(0, len(urls_list), batch_size):
            batch_urls = urls_list[batch_idx:batch_idx + batch_size]
            current_batch = batch_idx // batch_size + 1
            print(f"\n[D{depth}] 批次 {current_batch}/{total_batches} (Size: {len(batch_urls)})")
            watchdog.beat("batch", f"D{depth} 批次 {current_batch}/{total_batches}")

            try:
                batch_result = await asyncio.wait_for(
                    self._process_single_batch(batch_urls, depth),
                    timeout=BATCH_SIZE * 5
                )

                all_scan_info_list.extend(batch_result["scan_info_list"])

                self._collect_base_urls_from_batch(batch_result["scan_info_list"])

                for n_url in batch_result["next_urls"]:
                    if self.checker.should_scan(n_url):
                        all_next_urls.add(n_url)
                if batch_result["all_next_urls_with_source"]:
                    try:
                        self.db_handler.append_data_batch(batch_result["all_next_urls_with_source"], depth=depth)
                        print(f"✅ [DB] 基础数据已存入")
                    except Exception as e:
                        print(f"❌ [DB] 基础数据存储失败：{e}")
                if self.args.findparam and self.ai_auditor:
                    print(f"🤖 [AI] 正在进行 API 逻辑审计...")
                    watchdog.beat("ai_batch", f"D{depth} B{current_batch}")
                    await self._process_ai_batch(
                        batch_result["all_next_paths_with_source"],
                        batch_result["scan_info_list"],
                        batch_result["next_urls"]
                    )
            except Exception as e:
                logger.error(f"❌ [Fetch Error] 批次 {current_batch}/{total_batches} 请求失败：{e}")
                import traceback
                traceback.print_exc()
                continue

            logger.info(f"[D{depth}] 批次 {current_batch}/{total_batches} 扫描完成")
            if current_batch < total_batches:
                await asyncio.sleep(BATCH_SLEEP)

            # 内存熔断检查
            remaining = urls_list[batch_idx + batch_size:]
            if not self._check_memory_and_handle(depth, all_next_urls, remaining):
                return

        if self.args.analyzeSensitiveInfoRex or self.args.analyzeSensitiveInfoAI:
            print(f"🔍 正在提取敏感信息 (Regex/Qwen)...")
            await self._extract_sensitive_info(all_scan_info_list)

        if all_next_urls:
            logger.info(f"➡️  进入深度 {depth + 1} | 待扫描 URL：{len(all_next_urls)}")
            await self._scan_recursive(all_next_urls, depth + 1, is_seed=False)
        else:
            logger.info(f"✅ 深度 {depth} 完成")

    async def _extract_sensitive_info(self, scan_info_list):
        source_map_results = []
        for scan_info in scan_info_list:
            url = scan_info["url"]
            watchdog.beat("sensitive_loop", url)   # 逐文件推进都算进展
            if not (scan_info["is_valid"] == 1 or url in self.initial_urls):
                continue
            if ".js" not in scan_info["url"]:
                continue

            source_code = scan_info.get("source_code", "")
            tail = source_code[-300:] if len(source_code) > 300 else source_code
            has_source_map = "Y" if "sourceMappingURL=" in tail else "N"
            source_map_results.append((url, has_source_map))
            if has_source_map == "Y":
                print(f"🗺️ [SourceMap] 发现 SourceMap 暴露：{url}")

            combined_sensitive_info = set()
            if self.args.analyzeSensitiveInfoAI and self.sensitive_scanner:
                try:
                    # 跨 chunk 密钥召回：复用 API 阶段已采集的 chunk 缓存（不重新采集）
                    bundle_context = _build_bundle_context(
                        url,
                        self._get_effective_seed() or (self.args.url.strip() if self.args.url else ""),
                        collect_if_missing=False,
                    )
                    js_file = url.rsplit("/", 1)[-1]
                    ai_results = self.sensitive_scanner.scan(
                        js_code=scan_info["source_code"], js_url=url,
                        bundle_context=bundle_context, js_file=js_file)
                    if ai_results:
                        for item in ai_results:
                            combined_sensitive_info.add(item.get("value", ""))
                        high_risk = [r for r in ai_results if r.get("risk_level") == "High"]
                        if high_risk:
                            print(f"🔥 [High Risk] URL: {url}")
                            for hr in high_risk[:5]:
                                value_preview = hr.get('value', '')[:50]
                                print(f"   └─ {value_preview}...")
                                print(f"      类型：{hr.get('secret_type', 'unknown')}")
                                suggestion = hr.get('test_suggestion', '')[:50]
                                print(f"      建议：{suggestion}...")
                except Exception as e:
                    print_exc()
                    logger.error(f"❌ [AI Scan] 分析失败 {url}: {e}")
                    print(f"❌ [AI Scan] 分析失败 {url}: {e}")
            if self.args.analyzeSensitiveInfoRex:
                try:
                    rex_results = find_all_info_by_rex(scan_info["source_code"])
                    if rex_results:
                        combined_sensitive_info.update(rex_results)
                except Exception:
                    pass

        if source_map_results:
            self.db_handler.batch_save_source_map_results(source_map_results)
            yes_count = sum(1 for _, flag in source_map_results if flag == "Y")
            print(f"🗺️ [SourceMap] 检测完成：{len(source_map_results)} 个JS文件，{yes_count} 个暴露了 SourceMap")



if __name__ == '__main__':
    init(autoreset=True)
    args = parse_args()
    start_time = time.time()
    os.makedirs("Result", exist_ok=True)
    target_url = args.url.strip() if args.url else "unknown"
    print(f"📂 扫描结果将存入数据库：{db_filename}")
    db_handler = SQLiteStorage(db_filename)
    scanner = Scanner(args, db_handler)
    try:
        asyncio.run(scanner.run())
        run_time = round(time.time() - start_time, 2)
        print(f"本次扫描耗时：{run_time}s")
    except Exception as e:
        run_time = round(time.time() - start_time, 2)
        error_content = f"❌ 错误：{str(e)}\n⏱️ 耗时：{run_time}s"
        send_feishu_notify("【扫描任务报警】", error_content)
        print_exc()
    finally:
        scanner._cleanup_resources()