import os
import threading
from urllib.parse import urlparse

from infra.bloom import DiskBloomFilter
from logger import get_logger
from storage.api_state import ApiStatus

logger = get_logger(__name__)


class DuplicateChecker:
    """
    去重管理器（v3.0 - 站点隔离 + 状态机）

    双层去重架构：
    ├── Layer 1: DiskBloomFilter（内存缓存，快速检查）
    └── Layer 2: SQLite 数据库（持久化存储，重启续扫）

    API 去重维度（P0-1）：
        (scan_id, api_path)
    不同站点的相同 path 互不影响，只有同一站点同一路径才允许去重。

    API 去重判据（P0-2）：
        只有状态机的成功终态（VALIDATED）才算"处理完成"；
        AI / Context / 验证失败的状态在重试次数内仍会重新进入分析。
    """

    def __init__(self, db_handler=None, initial_root_domain: list = None, scan_id: str = None):
        """
        初始化去重管理器

        :param db_handler: SQLiteStorage 实例（用于持久化）
        :param initial_root_domain: 目标根域名列表（用于 URL 有效性检查）
        :param scan_id: 当前扫描任务的站点 scan_id
        """
        # Layer 1: 内存缓存 key = "{scan_id}|{api_path}"（最快，O(1) 查询）
        self.api_state_cache = {}

        # Layer 2: 磁盘布隆过滤器（快速，低内存）
        # 注意：key 同样带 scan_id，避免跨站点互相误判
        self.visited_urls = DiskBloomFilter("Result/global_dedup.bloom", capacity=10000000)
        self.visited_api_paths = DiskBloomFilter("Result/api_path_dedup.bloom", capacity=1000000)

        # Layer 3: 数据库持久化（重启续扫核心）
        self.db_handler = db_handler

        # 站点维度：API 去重范围
        self.scan_id = scan_id or "unknown"

        # 标题去重缓存
        self.title_map = dict()
        self.target_root = initial_root_domain if initial_root_domain else []
        self.title_lock = threading.Lock()
        self.MAX_TITLE_PER_DOMAIN = 3000
        self.MAX_DOMAIN_CACHE = 200

        # 从数据库加载历史记录到缓存
        if db_handler:
            self._load_visited_urls_from_db()
            self._load_api_states_from_db()

        logger.info(
            f"✅ [Dedup] 去重管理器初始化完成 | 目标域名：{len(self.target_root)} 个 | scan_id：{self.scan_id}"
        )

    def set_scan_id(self, scan_id: str):
        """设置/切换站点 scan_id（切换后需要重新加载缓存）"""
        if not scan_id or scan_id == self.scan_id:
            return
        self.scan_id = scan_id
        self.api_state_cache.clear()
        self._load_api_states_from_db()

    def _load_visited_urls_from_db(self):
        """
        从数据库加载历史已访问 URL（重启续扫核心）
        """
        try:
            historical_urls = self.db_handler.get_all_visited_urls()
            count = 0
            for url in historical_urls:
                self.visited_urls.add(url)
                count += 1
            logger.info(f"📚 [Dedup] 从数据库加载 {count} 个历史 URL")
        except Exception as e:
            logger.error(f"⚠️ [Dedup] 加载历史 URL 失败：{e}")

    def _load_api_states_from_db(self):
        """
        从数据库加载本站点（scan_id）的历史 API 分析状态（重启续扫核心）
        """
        if not self.db_handler:
            return
        try:
            states = self.db_handler.get_api_states(self.scan_id)
            for state in states:
                self.api_state_cache[self._state_key(state["api_path"])] = {
                    "status": state.get("status"),
                    "attempt_count": state.get("attempt_count", 0),
                }
            logger.info(
                f"📚 [Dedup] 从数据库加载 {len(states)} 个历史 API 状态（scan_id={self.scan_id}）"
            )
        except Exception as e:
            logger.error(f"⚠️ [Dedup] 加载历史 API 状态失败：{e}")

    def is_valid_url(self, url: str) -> bool:
        """
        [兼容旧接口] 只检查域名范围，不检查是否已访问
        """
        return self.is_within_scope(url)

    def is_within_scope(self, url: str) -> bool:
        """检查 URL 是否在目标域名范围内"""
        if not isinstance(url, str) or len(url.strip()) == 0:
            return False
        try:
            parsed = urlparse(url)
            for root in self.target_root:
                if root in parsed.netloc:
                    return True
            return False
        except Exception as e:
            return False

    def should_scan(self, url: str) -> bool:
        """
        判断 URL 是否应该扫描

        检查顺序：
        1. 是否在目标域名范围内
        2. 是否已访问（内存 + 数据库）
        3. 是否是有效文件类型
        """
        # 1. 检查域名范围
        if not self.is_within_scope(url):
            return False

        # 2. 检查是否已访问（先查内存布隆过滤器）
        if self.visited_urls.contains(url):
            if self.db_handler and self.db_handler.is_url_visited(url):
                return False

        # 3. 检查文件类型
        url_lower = url.lower().split('?')[0]
        allowed_extensions = ['.js', '.html', '.htm']

        has_allowed_ext = any(url_lower.endswith(ext) for ext in allowed_extensions)
        no_ext = '.' not in url_lower.split('/')[-1]

        if has_allowed_ext or no_ext:
            return True

        return False

    def mark_url_visited(self, url: str):
        """
        标记 URL 为已访问（同步写入内存 + 数据库）

        :param url: 目标 URL
        """
        if not isinstance(url, str) or len(url.strip()) == 0:
            return

        # Layer 1: 写入内存布隆过滤器
        self.visited_urls.add(url)

        # Layer 2: 写入数据库（持久化）
        if self.db_handler:
            try:
                self.db_handler.mark_url_visited(url)
            except Exception as e:
                logger.error(f"⚠️ [Dedup] 数据库写入失败：{e}")

    def mark_urls_visited_batch(self, urls: list):
        """
        批量标记 URL 为已访问

        :param urls: URL 列表
        """
        if not urls:
            return

        # Layer 1: 写入内存
        for url in urls:
            self.visited_urls.add(url)

        # Layer 2: 批量写入数据库
        if self.db_handler:
            try:
                self.db_handler.mark_urls_visited_batch(urls)
            except Exception as e:
                logger.error(f"⚠️ [Dedup] 批量数据库写入失败：{e}")

    def is_url_visited(self, url: str) -> bool:
        """
        检查 URL 是否已访问（内存 + 数据库双重检查）

        :param url: 目标 URL
        :return: 是否已访问
        """
        # 先查内存布隆过滤器（快速）
        if not self.visited_urls.contains(url):
            return False

        # 再查数据库确认（准确）
        if self.db_handler:
            return self.db_handler.is_url_visited(url)

        return True

    def _limit_set_size(self, target_set: set, max_size: int):
        """限制集合大小"""
        if len(target_set) > max_size:
            del_list = list(target_set)[:len(target_set) - max_size]
            for val in del_list:
                target_set.remove(val)

    def _limit_domain_cache(self, target_dict: dict, max_domain: int):
        """限制域名字典大小"""
        if len(target_dict) > max_domain:
            del_domain = list(target_dict.keys())[:len(target_dict) - max_domain]
            for domain in del_domain:
                del target_dict[domain]

    def check_duplicate_by_title(self, title: str, url: str) -> bool:
        """按"域名 + 标题"去重"""
        if not isinstance(title, str):
            return False
        title_norm = title.strip().lower()
        if ".js" in url:
            return False
        if len(title_norm) <= 7:
            return False

        try:
            domain = urlparse(url).netloc
            with self.title_lock:
                if domain not in self.title_map:
                    self.title_map[domain] = set()
                if title_norm in self.title_map[domain]:
                    return True
                self.title_map[domain].add(title_norm)
                self._limit_set_size(self.title_map[domain], self.MAX_TITLE_PER_DOMAIN)
                self._limit_domain_cache(self.title_map, self.MAX_DOMAIN_CACHE)
            return False
        except Exception:
            return False

    def is_page_duplicate(self, url: str, html: str, title: str = "", enable_title_check: bool = True):
        """
        页面去重主入口

        :param url: 页面 URL
        :param html: 页面 HTML 内容
        :param title: 页面标题
        :param enable_title_check: 是否启用标题去重
        :return: 是否重复
        """
        if ".js" in url:
            return False
        if not isinstance(html, str) or not html.lower().startswith("<!doctype html>"):
            return False
        if "jquery" in html.lower():
            return False
        if len(html) > 712000:
            return False

        if enable_title_check and title and len(title.strip()) > 0:
            if self.check_duplicate_by_title(title, url):
                return True
        return False

    def clear_visited_urls(self):
        """
        清空已访问 URL 记录（用于重新开始扫描）
        """
        # 清空内存布隆过滤器（重新创建）
        self.visited_urls.close()
        if os.path.exists(self.visited_urls.filepath):
            os.remove(self.visited_urls.filepath)
        self.visited_urls = DiskBloomFilter("Result/global_dedup.bloom", capacity=10000000)

        # 清空数据库记录
        if self.db_handler:
            try:
                self.db_handler.clear_visited_urls()
            except Exception as e:
                logger.warning(f"⚠️ [Dedup] 清空数据库记录失败：{e}")

        logger.info("🗑️ [Dedup] 已清空所有已访问 URL 记录")

    def get_visited_count(self) -> int:
        """
        获取已访问 URL 数量

        :return: 已访问 URL 数量
        """
        if self.db_handler:
            try:
                stats = self.db_handler.get_stats()
                return stats.get("visited_urls", {}).get("total", 0)
            except:
                pass
        return 0

    def close(self):
        """关闭资源"""
        try:
            self.visited_urls.close()
            self.visited_api_paths.close()
        except:
            pass
        logger.info("🔒 [Dedup] 去重管理器已关闭")

    # ==================== API 去重（站点隔离 + 状态机） ====================

    def _state_key(self, api_path: str) -> str:
        """API 去重键：scan_id + api_path（P0-1：跨站点不再互相覆盖）"""
        return f"{self.scan_id}|{api_path}"

    def refresh_api_state(self, api_path: str):
        """从数据库刷新单个 API 的状态到缓存"""
        if not self.db_handler:
            return None
        try:
            state = self.db_handler.get_api_state(self.scan_id, api_path)
        except Exception as e:
            logger.error(f"⚠️ [Dedup] 读取 API 状态失败：{e}")
            return None

        key = self._state_key(api_path)
        if state:
            self.api_state_cache[key] = {
                "status": state.get("status"),
                "attempt_count": state.get("attempt_count", 0),
            }
        else:
            self.api_state_cache.pop(key, None)
        return state

    def get_api_state(self, api_path: str):
        """读取 API 状态（缓存 → Bloom → DB）"""
        if not isinstance(api_path, str) or len(api_path.strip()) == 0:
            return None

        key = self._state_key(api_path)
        cached = self.api_state_cache.get(key)
        if cached:
            return cached

        # Bloom 里没有 → 肯定没处理过
        if not self.visited_api_paths.contains(key):
            return None

        # Bloom 命中（可能假阳性）→ 查数据库确认
        if self.db_handler:
            return self.refresh_api_state(api_path)

        return None

    def should_analyze_api(self, api_path: str) -> bool:
        """
        判断某 API 是否需要进入本轮分析。

        - 从未出现过                    → True
        - 成功终态（VALIDATED）          → False（真正完成，才允许去重）
        - 进行中                        → False（本轮已在处理）
        - 失败态且重试次数未超上限       → True（可重试，避免静默漏扫）
        """
        if not isinstance(api_path, str) or len(api_path.strip()) == 0:
            return False

        state = self.get_api_state(api_path)
        if not state:
            return True

        status = state.get("status")
        if ApiStatus.is_terminal_success(status):
            return False
        if ApiStatus.is_in_progress(status):
            return False
        return ApiStatus.should_retry(status, state.get("attempt_count", 0))

    def is_api_path_processed(self, api_path: str) -> bool:
        """
        【兼容旧接口】是否真正分析完成（只有 VALIDATED 算完成）
        """
        state = self.get_api_state(api_path)
        if not state:
            return False
        return ApiStatus.is_terminal_success(state.get("status"))

    def mark_apis_discovered(self, paths_data: list):
        """
        登记发现的 API（状态 = DISCOVERED，不代表处理完成）

        :param paths_data: [(api_path, js_url), ...]
        """
        if not paths_data:
            return

        items = [(p, js) for p, js in paths_data if isinstance(p, str) and p.strip()]
        if not items:
            return

        for api_path, _ in items:
            self._remember(api_path, ApiStatus.DISCOVERED, 0)

        if self.db_handler:
            try:
                self.db_handler.mark_apis_discovered(self.scan_id, items)
            except Exception as e:
                logger.error(f"⚠️ [Dedup] API 状态数据库写入失败：{e}")

    def mark_api_status(self, api_path: str, status: str, js_url: str = None,
                        last_error: str = None, run_id: str = None,
                        increment_attempt: bool = False):
        """推进单个 API 的分析状态"""
        if not isinstance(api_path, str) or len(api_path.strip()) == 0:
            return

        if self.db_handler:
            try:
                self.db_handler.mark_api_status(
                    self.scan_id, api_path, status,
                    js_url=js_url, last_error=last_error, run_id=run_id,
                    increment_attempt=increment_attempt,
                )
            except Exception as e:
                logger.error(f"⚠️ [Dedup] API 状态更新失败：{e}")

        self.refresh_api_state(api_path)

    def mark_api_status_batch(self, api_paths: list, status: str, js_url: str = None,
                              last_error: str = None, run_id: str = None,
                              increment_attempt: bool = False):
        """批量推进 API 分析状态"""
        if not api_paths:
            return

        valid = [p for p in api_paths if isinstance(p, str) and p.strip()]
        if not valid:
            return

        if self.db_handler:
            try:
                self.db_handler.mark_api_status_batch(
                    self.scan_id, valid, status,
                    js_url=js_url, last_error=last_error, run_id=run_id,
                    increment_attempt=increment_attempt,
                )
            except Exception as e:
                logger.error(f"⚠️ [Dedup] API 状态批量更新失败：{e}")

        for api_path in valid:
            self.refresh_api_state(api_path)

    def _remember(self, api_path: str, status: str, attempt_count: int):
        """写入本地缓存 + Bloom（仅作快速过滤，准确判据仍在数据库）"""
        key = self._state_key(api_path)
        self.api_state_cache[key] = {
            "status": status,
            "attempt_count": attempt_count,
        }
        self.visited_api_paths.add(key)

    def clear_api_paths(self):
        """
        清空本站点已处理 API path 记录
        """
        # 清空内存布隆过滤器
        self.visited_api_paths.close()
        if os.path.exists(self.visited_api_paths.filepath):
            os.remove(self.visited_api_paths.filepath)
        self.visited_api_paths = DiskBloomFilter("Result/api_path_dedup.bloom", capacity=1000000)

        self.api_state_cache.clear()

        # 清空数据库记录（仅当前站点）
        if self.db_handler:
            try:
                self.db_handler.clear_api_state(scan_id=self.scan_id)
            except Exception as e:
                logger.warning(f"⚠️ [Dedup] 清空 API path 数据库记录失败：{e}")

        logger.info(f"🗑️ [Dedup] 已清空 scan_id={self.scan_id} 的 API 分析状态记录")
