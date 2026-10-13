import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from playwright.async_api import Request, async_playwright, Page, BrowserContext
from rich.markup import escape
from tqdm.asyncio import tqdm_asyncio
from user_agent import generate_user_agent

from config.scanner_rules import PLAYWRIGHT_BLOCKED_RESOURCES
from config.config import GLOBAL_TIMEOUT, MAX_REDIRECT_COUNT
from infra.dedup import DuplicateChecker
from crawler.httpx_crawler import fetch_urls_async
from crawler.response_process import process_scan_result
from logger import get_logger
from infra import watchdog

logger = get_logger(__name__)

@asynccontextmanager
async def get_playwright_page(context: BrowserContext):
    """异步上下文管理器：创建和自动关闭页面"""
    page = await context.new_page()
    try:
        yield page
    finally:
        try:
            # 强制超时关闭，防止僵尸页面占用内存
            await asyncio.wait_for(page.close(), timeout=3.0)
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass


async def fetch_page_async(page: Page, url: str, progress: tqdm_asyncio):
    """
    Args:
        page: Playwright Page 对象
        url: 目标 URL
        progress: 进度条
    """
    captured_resources = set()
    redirect_count = 0  # 跳转次数计数器
    redirect_locations = []  # 记录所有跳转目标
    final_status = None
    final_url = url

    try:
        # 路由拦截：过滤图片字体等无用资源
        await page.route("**/*", lambda route: route.abort()
        if route.request.resource_type in PLAYWRIGHT_BLOCKED_RESOURCES
        else route.continue_())

        # 监听请求：捕获动态加载的 JS 文件
        def handle_request(request: Request):
            res_url = request.url
            res_type = request.resource_type

            if res_type == "script" or res_url.split('?')[0].endswith('.js'):
                captured_resources.add(res_url)
            elif res_type == "document" and res_url != "about:blank":
                captured_resources.add(res_url)

        page.on("request", handle_request)

        # 监听响应：统计 302 跳转次数
        def handle_response(response):
            nonlocal redirect_count, final_url
            if response.status in [301, 302, 303, 307, 308]:
                location = response.headers.get('location')
                redirect_count += 1
                redirect_locations.append(location)
                final_url = response.url

        page.on("response", handle_response)

        # 访问页面，超时 30s
        timeout_ms = GLOBAL_TIMEOUT * 1000
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

        # 获取最终状态和 URL
        if response:
            final_status = response.status
            final_url = response.url

        if redirect_count > MAX_REDIRECT_COUNT:
            return {
                "type": "redirect_loop",
                "redirect_count": redirect_count,
                "redirect_locations": redirect_locations,
                "url": url,
                "status": final_status
            }, url, final_status

        # 获取页面内容
        html_content = await asyncio.wait_for(page.content(), timeout=10.0)

        # 将捕获到的动态资源拼接到 HTML 尾部
        if captured_resources:
            append_html = "\n<!-- JScanner Captured Resources (Dynamic) -->\n"
            for res in captured_resources:
                safe_res = escape(res)
                append_html += f'<script src="{safe_res}"></script>\n'
            html_content += append_html

        return {
            "type": "success",
            "html": html_content,
            "url": final_url,
            "status": final_status,
            "redirect_count": redirect_count,
            "redirect_locations": redirect_locations
        }, final_url, final_status

    except Exception as e:
        error_msg = str(e)
        if "timeout" in error_msg.lower():
            print(f"⚠️ 抓取超时（30s）：{url}")
        else:
            print(f"❌ 抓取失败：{url} - {error_msg}")

        return {
            "type": "error",
            "error": error_msg,
            "url": url,
            "status": None
        }, url, None
    finally:
        progress.update(1)
        watchdog.beat("page_done", url)      # 每抓完一页=一次真进展


async def get_source_async(urls, thread_num, args, checker: DuplicateChecker,
                           storage_state: str = None, effective_seed: str = None):
    """
    Playwright 异步批量请求入口

    Args:
        urls: URL 列表
        thread_num: 并发线程数
        args: 命令行参数
        checker: 去重检查器
        storage_state: Cookie 存储文件路径 (用于保持登录状态)
        effective_seed: 已验证的 baseURL（如果有），否则使用 args.url

    Returns:
        all_next_urls_with_source: 来源 URL -> 子 URL 关系
        scan_info_list: 扫描详情列表
        all_next_urls: 下一层待爬取的纯 URL 集合
        all_next_paths_with_source: 来源 URL -> 子路径关系
    """
    progress = tqdm_asyncio(total=len(urls), desc="🕷️ Crawling", unit="url", ncols=100)

    # 局部变量，避免全局状态污染
    request_failed_urls = set()
    redirect_stats = {
        "total": 0,
        "success": 0,
        "error": 0,
        "redirect_0": 0,  # 0 次跳转
        "redirect_1": 0,  # 1 次跳转 (允许)
        "redirect_loop": 0  # 多次跳转 (禁止)
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=not getattr(args, 'visible', False),
            proxy={"server": args.proxy} if getattr(args, 'proxy', None) else None,
            args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"]
        )

        # 创建全局上下文
        context_kwargs = {
            "user_agent": generate_user_agent(),
            "ignore_https_errors": True,
            "java_script_enabled": True,
        }

        if storage_state:
            try:
                context_kwargs["storage_state"] = storage_state
                print(f"📦 加载 Cookie 状态：{storage_state}")
            except Exception as e:
                print(f"⚠️ 加载 Cookie 状态失败：{e}")

        global_context = await browser.new_context(**context_kwargs)

        try:
            semaphore = asyncio.Semaphore(thread_num)

            async def bounded_fetch(url):
                async with semaphore:
                    async with get_playwright_page(global_context) as page:
                        return await fetch_page_async(page, url, progress)

            results = await asyncio.gather(*[bounded_fetch(url) for url in urls])

        finally:
            # 关闭必须有超时：浏览器无响应时，外层 wait_for 取消会卡在这里造成永久死锁
            try:
                await asyncio.wait_for(global_context.close(), timeout=5.0)
            except Exception:
                pass
            try:
                await asyncio.wait_for(browser.close(), timeout=5.0)
            except Exception:
                pass
            progress.close()

    # 处理失败 URL 的 fallback (使用 httpx)
    for scan_result, url, status in results:
        if scan_result and scan_result.get("type") == "error":
            request_failed_urls.add(url)

    if request_failed_urls:
        print(f"🔄 尝试使用 httpx 补救 {len(request_failed_urls)} 个失败的 URL...")
        fallback_results = await fetch_urls_async(
            urls=list(request_failed_urls),
            thread_num=min(thread_num, 10),
            headers=None,
            cookies=None,
            timeout=10
        )
        # 更新结果
        updated_count = 0
        for i, (scan_result, url, status) in enumerate(results):
            if scan_result and scan_result.get("type") == "error":
                for fb_result in fallback_results:
                    if fb_result["url"] == url and not fb_result.get("error"):
                        results[i] = (
                            {
                                "type": "success",
                                "html": fb_result["response_content"],
                                "url": url,
                                "status": fb_result["status_code"],
                                "redirect_count": fb_result.get("redirect_count", 0),
                                "redirect_locations": []
                            },
                            url,
                            fb_result["status_code"]
                        )
                        updated_count += 1
                        break
        print(f"✅ 成功补救 {updated_count} 个 URL")

    # 处理结果
    all_next_urls_with_source = []
    scan_info_list = []
    all_next_urls = set()
    all_next_paths_with_source = []

    seed_url = effective_seed if effective_seed else getattr(args, 'url', None)

    for scan_result, url, final_status in results:
        if not scan_result or scan_result.get("type") != "success":
            continue

        html = scan_result.get("html", "")
        final_url = scan_result.get("url", url)
        redirect_count = scan_result.get("redirect_count", 0)

        if not html:
            continue

        # 统计跳转次数
        redirect_stats["total"] += 1
        if final_status and 200 <= final_status < 400:
            redirect_stats["success"] += 1
            if redirect_count == 0:
                redirect_stats["redirect_0"] += 1
            elif redirect_count == 1:
                redirect_stats["redirect_1"] += 1
            else:
                redirect_stats["redirect_loop"] += 1
        else:
            redirect_stats["error"] += 1

        parsed = urlparse(final_url)

        scan_info = {
            "domain": parsed.hostname,
            "url": final_url,
            "path": parsed.path,
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "status": final_status,
            "length": len(html),
            "source_code": html,
            "is_valid": 0,
            "redirect_count": redirect_count,
            "redirect_locations": scan_result.get("redirect_locations", []),
            "original_url": url
        }

        is_valid, next_urls_without_source, next_paths_without_source = \
            await process_scan_result(scan_info, checker, args, seed_url=seed_url)

        if is_valid:
            scan_info["is_valid"] = 1

            next_urls_with_source = {
                "next_urls": next_urls_without_source,
                "sourceURL": final_url
            }
            all_next_urls_with_source.append(next_urls_with_source)
            all_next_urls.update(next_urls_without_source)

            next_paths_with_source = {
                "next_paths": next_paths_without_source,
                "sourceURL": final_url
            }
            all_next_paths_with_source.append(next_paths_with_source)

        scan_info_list.append(scan_info)

    return (
        all_next_urls_with_source,
        scan_info_list,
        all_next_urls,
        all_next_paths_with_source
    )



