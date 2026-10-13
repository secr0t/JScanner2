import hashlib
import json
import os
import sqlite3
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

from config.scanner_rules import VALID_HTTP_METHODS
from logger import get_logger
from storage.api_state import ApiStatus, MAX_ATTEMPTS

logger = get_logger(__name__)

# 当前代码期望的数据库结构版本（每次结构变更 +1）
SCHEMA_VERSION = 2

# ai_vulns 风险等级：由请求验证结论推导，不再依赖 AI 自由发挥
RISK_HIGH = "High"
RISK_MED = "Med"
RISK_LOW = "Low"
RISK_INFO = "Info"

# 请求验证结论 → 风险等级
VERDICT_TO_RISK = {
    "success_with_data": RISK_HIGH,   # 未鉴权即返回业务数据
    "success_no_data": RISK_MED,
    "needs_human_review": RISK_MED,
    "param_error": RISK_LOW,
    "auth_denied": RISK_LOW,
    "method_not_allowed": RISK_LOW,
    "not_found": RISK_INFO,
    "unknown": RISK_INFO,
    "failed": RISK_INFO,
    "dangerous_blocked": RISK_INFO,
    "blocked_by_blacklist": RISK_INFO,
    "needs_manual_review": RISK_LOW,
}

# 本扫描器关注的核心问题：接口未授权访问
DEFAULT_VULNERABILITY_TYPE = "unauthorized_access"


class SQLiteStorage:

    def __init__(self, db_path: str):
        db_dir = os.path.dirname(os.path.abspath(db_path))
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self):
        """初始化数据库：开启 WAL 模式以获得极速写入性能"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()

            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA temp_store=MEMORY;")
            cursor.execute("PRAGMA cache_size=-64000;")

            self._create_tables(cursor)
            self._ensure_columns(cursor)
            # 索引必须在补列之后创建，否则旧库会因字段不存在而报错
            self._create_indexes(cursor)
            self._run_migrations(cursor)

            self.conn.commit()
            logger.info(
                f"✅ [DB] 数据库初始化成功：{self.db_path} (schema v{SCHEMA_VERSION})"
            )

        except Exception as e:
            logger.error(f"❌ [DB] 数据库初始化失败：{e}")
            raise

    # ==================== Schema / 迁移 ====================

    @staticmethod
    def _table_exists(cursor, table: str) -> bool:
        try:
            cursor.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
                (table,),
            )
            return cursor.fetchone() is not None
        except Exception:
            return False

    @staticmethod
    def _column_exists(cursor, table: str, column: str) -> bool:
        try:
            cursor.execute(f"PRAGMA table_info({table})")
            return any(row[1] == column for row in cursor.fetchall())
        except Exception:
            return False

    @staticmethod
    def _scan_id_for_domain(root_domain: str) -> str:
        """由根域名推导出稳定的 scan_id（同一站点多次扫描共用）"""
        domain = (root_domain or "").strip().lower()
        if not domain:
            return "unknown"
        return hashlib.sha1(domain.encode("utf-8")).hexdigest()[:16]

    def _create_tables(self, cursor):
        """建表（全部使用 IF NOT EXISTS，兼容已有数据库）"""

        # 1. 基础爬虫结果表
        create_scan_table_sql = """
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            domain TEXT,
            path TEXT,
            source_url TEXT,
            scan_depth INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor.execute(create_scan_table_sql)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain ON scan_results(domain);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_depth ON scan_results(scan_depth);")

        # 2. AI 渗透建议表（统一数据模型）
        #    request_status 即验证状态（validation_status），保留字段名以免破坏历史数据
        create_ai_table_sql = """
        CREATE TABLE IF NOT EXISTS ai_vulns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            js_url TEXT NOT NULL,
            api_endpoint TEXT NOT NULL,
            http_method TEXT DEFAULT 'UNKNOWN',
            path TEXT,
            params JSON,
            operation_type TEXT,
            risk_level TEXT DEFAULT 'Low',
            vulnerability_type TEXT DEFAULT 'unauthorized_access',
            evidence JSON,
            request_status TEXT,
            response_code INTEGER,
            response_length INTEGER,
            response_body_preview TEXT,
            scan_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(js_url, api_endpoint)
        );
        """
        cursor.execute(create_ai_table_sql)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_endpoint ON ai_vulns(api_endpoint);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_js_url ON ai_vulns(js_url);")

        # 3. 敏感信息硬编码表
        create_sensitive_table_sql = """
        CREATE TABLE IF NOT EXISTS sensitive_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            js_url TEXT NOT NULL,
            sensitive_value TEXT NOT NULL,
            context_code TEXT,
            caller_codes JSON,
            risk_level TEXT DEFAULT 'Low',
            secret_type TEXT,
            test_suggestion TEXT,
            ai_raw_analysis JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(js_url, sensitive_value)
        );
        """
        cursor.execute(create_sensitive_table_sql)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_risk ON sensitive_info(risk_level);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_js ON sensitive_info(js_url);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_type ON sensitive_info(secret_type);")

        # 4. 已访问 URL 记录表（支持重启续扫）
        create_visited_table_sql = """
        CREATE TABLE IF NOT EXISTS visited_urls (
            url TEXT PRIMARY KEY,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor.execute(create_visited_table_sql)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_visited_url ON visited_urls(url);")

        # 5. 扫描目标表（站点维度，P0-1：跨站点隔离）
        create_scan_targets_sql = """
        CREATE TABLE IF NOT EXISTS scan_targets (
            scan_id TEXT PRIMARY KEY,
            root_domain TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor.execute(create_scan_targets_sql)

        # 6. API 分析状态机表（P0-2：替代旧的 processed_api_paths 布尔去重）
        #    主键 = (scan_id, api_path)，同一站点同一路径才允许去重
        create_api_state_sql = """
        CREATE TABLE IF NOT EXISTS api_analysis_state (
            scan_id TEXT NOT NULL,
            api_path TEXT NOT NULL,
            js_url TEXT,
            status TEXT NOT NULL DEFAULT 'DISCOVERED',
            attempt_count INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            run_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (scan_id, api_path)
        );
        """
        cursor.execute(create_api_state_sql)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_state_status ON api_analysis_state(status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_state_scan ON api_analysis_state(scan_id);")

        # 7. Schema 版本表
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """)

        create_source_map_table_sql = """
        CREATE TABLE IF NOT EXISTS js_source_maps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            js_url TEXT NOT NULL UNIQUE,
            is_sourceMap TEXT NOT NULL DEFAULT 'N',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor.execute(create_source_map_table_sql)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sourcemap_js ON js_source_maps(js_url);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sourcemap_flag ON js_source_maps(is_sourceMap);")

    def _create_indexes(self, cursor):
        """建索引（只在字段确认存在之后执行）"""
        index_statements = [
            "CREATE INDEX IF NOT EXISTS idx_risk ON ai_vulns(risk_level);",
            "CREATE INDEX IF NOT EXISTS idx_scan_id ON ai_vulns(scan_id);",
        ]
        for sql in index_statements:
            try:
                cursor.execute(sql)
            except Exception as e:
                logger.warning(f"⚠️ [DB] 创建索引失败（可忽略）：{sql} | {e}")

    def _ensure_columns(self, cursor):
        """
        兼容历史数据库：缺失字段自动补齐。

        注意：
        旧代码用 `ALTER TABLE ... DROP COLUMN risk_level` 做迁移，
        但 SQLite 3.35 以下不支持 DROP COLUMN（本项目 venv 为 3.31），
        导致旧库保留 risk_level、新库没有 risk_level —— 字段模型不一致。
        这里改为"只增不删"，保证新旧库字段一致。
        """
        required_columns = [
            ("ai_vulns", "operation_type", "TEXT"),
            ("ai_vulns", "request_status", "TEXT"),
            ("ai_vulns", "response_code", "INTEGER"),
            ("ai_vulns", "response_length", "INTEGER"),
            ("ai_vulns", "response_body_preview", "TEXT"),
            ("ai_vulns", "risk_level", "TEXT DEFAULT 'Low'"),
            ("ai_vulns", "vulnerability_type", "TEXT DEFAULT 'unauthorized_access'"),
            ("ai_vulns", "evidence", "JSON"),
            ("ai_vulns", "scan_id", "TEXT"),
        ]

        for table, column, ddl in required_columns:
            if not self._table_exists(cursor, table):
                continue
            if self._column_exists(cursor, table, column):
                continue
            try:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
                logger.info(f"🔄 [DB] 迁移：已补充 {table}.{column}")
            except Exception as e:
                logger.warning(f"⚠️ [DB] 补充 {table}.{column} 失败：{e}")

    def _run_migrations(self, cursor):
        """按版本顺序执行数据迁移"""
        current_version = self._get_schema_version(cursor)

        if current_version >= SCHEMA_VERSION:
            self._set_schema_version(cursor, current_version)
            return

        if current_version < 2:
            self._migrate_v1_to_v2(cursor)

        self._set_schema_version(cursor, SCHEMA_VERSION)
        logger.info(f"🔄 [DB] Schema 迁移完成：v{current_version} → v{SCHEMA_VERSION}")

    def _get_schema_version(self, cursor) -> int:
        try:
            cursor.execute("SELECT value FROM schema_meta WHERE key='schema_version'")
            row = cursor.fetchone()
            if row and str(row[0]).isdigit():
                return int(row[0])
        except Exception:
            pass

        # 没有版本记录：旧库（存在 processed_api_paths）视为 v1，全新库视为 v0
        if self._table_exists(cursor, "processed_api_paths"):
            return 1
        return 0

    def _set_schema_version(self, cursor, version: int):
        try:
            cursor.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', ?)",
                (str(version),),
            )
        except Exception as e:
            logger.warning(f"⚠️ [DB] 写入 schema_version 失败：{e}")

    def _migrate_v1_to_v2(self, cursor):
        """
        v1 → v2：
        processed_api_paths(api_path 主键) → api_analysis_state(scan_id + api_path)
        旧表的 scan_id 由 js_url 所在域名推导。
        """
        if not self._table_exists(cursor, "processed_api_paths"):
            return

        try:
            cursor.execute("SELECT api_path, js_url FROM processed_api_paths")
            rows = cursor.fetchall()
        except Exception as e:
            logger.warning(f"⚠️ [DB] 读取旧 processed_api_paths 失败：{e}")
            rows = []

        migrated = 0
        for api_path, js_url in rows:
            if not api_path:
                continue
            domain = self._extract_domain(js_url or "")
            scan_id = self._scan_id_for_domain(domain)
            try:
                cursor.execute(
                    "INSERT OR IGNORE INTO scan_targets (scan_id, root_domain) VALUES (?, ?)",
                    (scan_id, domain or "unknown"),
                )
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO api_analysis_state
                    (scan_id, api_path, js_url, status, attempt_count)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (scan_id, api_path, js_url, ApiStatus.VALIDATED, MAX_ATTEMPTS),
                )
                migrated += 1
            except Exception:
                continue

        try:
            cursor.execute("DROP TABLE IF EXISTS processed_api_paths")
        except Exception as e:
            logger.warning(f"⚠️ [DB] 删除旧表 processed_api_paths 失败：{e}")

        logger.info(f"🔄 [DB] 迁移 v1→v2：{migrated} 条历史记录转入 api_analysis_state")

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception as e:
                logger.warning(f"⚠️ [DB] 关闭连接时出错：{e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ==================== 工具方法 ====================

    def _extract_domain(self, url: str) -> str:
        try:
            return urlparse(url).netloc
        except Exception:
            return ""

    def _extract_path(self, url: str) -> str:
        try:
            return urlparse(url).path
        except Exception:
            return ""

    def _normalize_method(self, method: str) -> str:
        if not method:
            return "UNKNOWN"
        method = method.upper().strip()
        if method in VALID_HTTP_METHODS:
            return method
        return "UNKNOWN"

    def _parse_params(self, params_str: str) -> Dict[str, str]:
        if not params_str:
            return {}

        try:
            params_str = params_str.strip()
            if params_str.startswith("[") and params_str.endswith("]"):
                params_str = params_str[1:-1]
            if not params_str:
                return {}

            params = {}
            for item in params_str.split(","):
                item = item.strip()
                if not item:
                    continue

                if "=" in item:
                    key, value = item.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    params[key] = value
                else:
                    params[item] = ""

            return params
        except Exception as e:
            logger.warning(f"⚠️ [DB] params 解析失败：{e}")
            return {}

    def get_all_visited_urls(self) -> List[str]:
        """
        获取所有已访问的 URL（用于重启后续扫）

        Returns:
            已访问 URL 列表
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT url FROM visited_urls")
            urls = [row[0] for row in cursor.fetchall()]
            logger.info(f"📚 [DB] 从数据库加载 {len(urls)} 个历史 URL")
            return urls
        except Exception as e:
            logger.warning(f"⚠️ [DB] 获取已访问 URL 失败：{e}")
            return []

    def mark_url_visited(self, url: str) -> bool:
        """
        标记 URL 为已访问（同步写入数据库）

        Args:
            url: 目标 URL

        Returns:
            是否成功标记
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO visited_urls (url) VALUES (?)",
                (url,)
            )
            self.conn.commit()
            return True
        except Exception as e:
            logger.warning(f"⚠️ [DB] 标记 URL 失败：{e}")
            return False

    def mark_urls_visited_batch(self, urls: List[str]) -> int:
        """
        批量标记 URL 为已访问

        Args:
            urls: URL 列表

        Returns:
            成功标记的数量
        """
        if not urls:
            return 0

        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")

            data = [(url,) for url in urls if url and isinstance(url, str)]
            cursor.executemany(
                "INSERT OR IGNORE INTO visited_urls (url) VALUES (?)",
                data
            )

            self.conn.commit()
            logger.debug(f"📝 [DB] 批量标记 {len(data)} 个 URL 为已访问")
            return len(data)
        except Exception as e:
            self.conn.rollback()
            logger.warning(f"⚠️ [DB] 批量标记 URL 失败：{e}")
            return 0

    def is_url_visited(self, url: str) -> bool:
        """
        检查 URL 是否已访问

        Args:
            url: 目标 URL

        Returns:
            是否已访问
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT 1 FROM visited_urls WHERE url = ? LIMIT 1", (url,))
            return cursor.fetchone() is not None
        except Exception as e:
            logger.warning(f"⚠️ [DB] 检查 URL 状态失败：{e}")
            return False

    def clear_visited_urls(self) -> int:
        """
        清空已访问 URL 记录（用于重新开始扫描）

        Returns:
            清空的记录数
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM visited_urls")
            count = cursor.rowcount
            self.conn.commit()
            logger.info(f"🗑️ [DB] 已清空 {count} 条已访问 URL 记录")
            return count
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] 清空已访问 URL 失败：{e}")
            return 0

    # ==================== 扫描目标（站点维度） ====================

    def get_scan_id(self, root_domain: str) -> Optional[str]:
        """获取站点已有 scan_id，不存在返回 None"""
        domain = (root_domain or "").strip().lower() or "unknown"
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT scan_id FROM scan_targets WHERE root_domain = ?", (domain,))
            row = cursor.fetchone()
            return row[0] if row else None
        except Exception as e:
            logger.warning(f"⚠️ [DB] 查询 scan_id 失败：{e}")
            return None

    def get_or_create_scan_id(self, root_domain: str) -> str:
        """
        获取（或创建）站点维度的 scan_id。

        同一根域名复用同一个 scan_id，保证：
        - 跨站点（不同 root_domain）API 状态互相隔离
        - 同一站点重复扫描可以续扫
        """
        domain = (root_domain or "").strip().lower() or "unknown"
        scan_id = self._scan_id_for_domain(domain)

        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO scan_targets (scan_id, root_domain) VALUES (?, ?)",
                (scan_id, domain),
            )
            self.conn.commit()
        except Exception as e:
            logger.warning(f"⚠️ [DB] 注册扫描目标失败：{e}")

        return scan_id

    # ==================== API 分析状态机（P0-2） ====================

    def mark_apis_discovered(self, scan_id: str, items: List[tuple]) -> int:
        """
        登记发现的 API（状态 = DISCOVERED）。

        注意：DISCOVERED 不代表处理完成，后续失败仍可重试。

        Args:
            scan_id: 站点 scan_id
            items: [(api_path, js_url), ...]

        Returns:
            新增登记的数量
        """
        if not scan_id or not items:
            return 0

        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
            cursor.executemany(
                """
                INSERT OR IGNORE INTO api_analysis_state
                (scan_id, api_path, js_url, status, attempt_count)
                VALUES (?, ?, ?, ?, 0)
                """,
                [(scan_id, api_path, js_url, ApiStatus.DISCOVERED)
                 for api_path, js_url in items if api_path],
            )
            self.conn.commit()
            return len(items)
        except Exception as e:
            self.conn.rollback()
            logger.warning(f"⚠️ [DB] 登记 DISCOVERED 失败：{e}")
            return 0

    def mark_api_status(
        self,
        scan_id: str,
        api_path: str,
        status: str,
        js_url: str = None,
        last_error: str = None,
        run_id: str = None,
        increment_attempt: bool = False,
        force: bool = False,
    ) -> bool:
        """
        推进单个 API 的分析状态。

        Args:
            scan_id: 站点 scan_id
            api_path: API 路径
            status: 新状态（见 storage/api_state.py）
            js_url: 来源 JS URL
            last_error: 失败原因（失败态必填）
            run_id: 本次运行的 run_id（用于中断恢复）
            increment_attempt: 是否累加 attempt_count
            force: 跳过状态机校验（仅用于迁移/重置）

        Returns:
            是否更新成功
        """
        if not scan_id or not api_path:
            return False

        current = self.get_api_state(scan_id, api_path)
        if current and not force and not ApiStatus.can_transition(current["status"], status):
            logger.warning(
                f"⚠️ [DB] 非法状态转移，已拒绝：{api_path} "
                f"{current['status']} → {status}"
            )
            return False

        sets = ["status = ?", "updated_at = CURRENT_TIMESTAMP"]
        params = [status]

        if js_url:
            sets.append("js_url = ?")
            params.append(js_url)
        if last_error is not None:
            sets.append("last_error = ?")
            params.append(str(last_error)[:500])
        if run_id:
            sets.append("run_id = ?")
            params.append(run_id)
        if increment_attempt:
            sets.append("attempt_count = attempt_count + 1")

        params.extend([scan_id, api_path])

        try:
            cursor = self.conn.cursor()
            if current is None:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO api_analysis_state
                    (scan_id, api_path, js_url, status, attempt_count, last_error, run_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (scan_id, api_path, js_url or "", status,
                     1 if increment_attempt else 0,
                     str(last_error)[:500] if last_error else None, run_id),
                )
            else:
                cursor.execute(
                    f"UPDATE api_analysis_state SET {', '.join(sets)} "
                    f"WHERE scan_id = ? AND api_path = ?",
                    params,
                )
            self.conn.commit()
            return True
        except Exception as e:
            self.conn.rollback()
            logger.warning(f"⚠️ [DB] 更新 API 状态失败：{e}")
            return False

    def mark_api_status_batch(
        self,
        scan_id: str,
        api_paths: List[str],
        status: str,
        js_url: str = None,
        last_error: str = None,
        run_id: str = None,
        increment_attempt: bool = False,
        force: bool = False,
    ) -> int:
        """批量推进 API 分析状态，返回成功数量"""
        if not api_paths:
            return 0
        ok = 0
        for api_path in api_paths:
            if self.mark_api_status(
                scan_id, api_path, status,
                js_url=js_url, last_error=last_error, run_id=run_id,
                increment_attempt=increment_attempt, force=force,
            ):
                ok += 1
        return ok

    def get_api_state(self, scan_id: str, api_path: str) -> Optional[Dict[str, Any]]:
        """读取单个 API 的状态记录"""
        if not scan_id or not api_path:
            return None
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT scan_id, api_path, js_url, status, attempt_count,
                       last_error, run_id, created_at, updated_at
                FROM api_analysis_state WHERE scan_id = ? AND api_path = ?
                """,
                (scan_id, api_path),
            )
            row = cursor.fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))
        except Exception as e:
            logger.warning(f"⚠️ [DB] 读取 API 状态失败：{e}")
            return None

    def get_api_states(self, scan_id: str, statuses: List[str] = None) -> List[Dict[str, Any]]:
        """读取某站点全部（或指定状态）的 API 状态记录"""
        if not scan_id:
            return []
        try:
            cursor = self.conn.cursor()
            if statuses:
                placeholders = ",".join("?" * len(statuses))
                cursor.execute(
                    f"""
                    SELECT scan_id, api_path, js_url, status, attempt_count,
                           last_error, run_id, created_at, updated_at
                    FROM api_analysis_state
                    WHERE scan_id = ? AND status IN ({placeholders})
                    """,
                    [scan_id] + list(statuses),
                )
            else:
                cursor.execute(
                    """
                    SELECT scan_id, api_path, js_url, status, attempt_count,
                           last_error, run_id, created_at, updated_at
                    FROM api_analysis_state WHERE scan_id = ?
                    """,
                    (scan_id,),
                )
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            logger.warning(f"⚠️ [DB] 读取 API 状态列表失败：{e}")
            return []

    def should_process_api(self, scan_id: str, api_path: str) -> bool:
        """
        判断某 API 是否还需要进入分析。

        - 无记录                       → 需要
        - VALIDATED（成功终态）         → 不需要
        - 进行中                        → 不需要（本轮已在处理）
        - 失败态且 attempt < 上限       → 需要（可重试）
        """
        if not scan_id or not api_path:
            return False

        state = self.get_api_state(scan_id, api_path)
        if not state:
            return True

        status = state.get("status")
        if ApiStatus.is_terminal_success(status):
            return False
        if ApiStatus.is_in_progress(status):
            return False
        return ApiStatus.should_retry(status, state.get("attempt_count", 0))

    def is_api_path_processed(self, api_path: str, scan_id: str = None) -> bool:
        """
        【兼容旧接口】判断 API 是否真正处理完成。

        只有 VALIDATED 才算完成 —— 失败/进行中都不算。
        """
        if not scan_id:
            return False
        state = self.get_api_state(scan_id, api_path)
        if not state:
            return False
        return ApiStatus.is_terminal_success(state.get("status"))

    def reset_stale_in_progress(self, scan_id: str, current_run_id: str) -> int:
        """
        中断恢复：把上一轮没跑完（run_id != 当前）的进行中状态重置为可重试。

        这样进程被杀 / Ctrl+C 后重新扫描，可以从中断位置继续。
        """
        if not scan_id or not current_run_id:
            return 0

        placeholders = ",".join("?" * len(ApiStatus.IN_PROGRESS))
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                f"""
                UPDATE api_analysis_state
                SET status = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP
                WHERE scan_id = ?
                  AND status IN ({placeholders})
                  AND (run_id IS NULL OR run_id != ?)
                """,
                [ApiStatus.AI_FAILED, "interrupted: 上一轮未完成，重新排队", scan_id]
                + list(ApiStatus.IN_PROGRESS)
                + [current_run_id],
            )
            count = cursor.rowcount
            self.conn.commit()
            if count:
                logger.info(f"♻️ [DB] 中断恢复：{count} 个 API 重新排队")
            return count
        except Exception as e:
            self.conn.rollback()
            logger.warning(f"⚠️ [DB] 中断状态重置失败：{e}")
            return 0

    def get_api_state_stats(self, scan_id: str = None) -> Dict[str, int]:
        """按状态统计 API 数量"""
        try:
            cursor = self.conn.cursor()
            if scan_id:
                cursor.execute(
                    "SELECT status, COUNT(*) FROM api_analysis_state WHERE scan_id = ? GROUP BY status",
                    (scan_id,),
                )
            else:
                cursor.execute("SELECT status, COUNT(*) FROM api_analysis_state GROUP BY status")
            return dict(cursor.fetchall())
        except Exception as e:
            logger.warning(f"⚠️ [DB] 统计 API 状态失败：{e}")
            return {}

    def clear_api_state(self, scan_id: str = None) -> int:
        """清空 API 分析状态（重新开始扫描时使用）"""
        try:
            cursor = self.conn.cursor()
            if scan_id:
                cursor.execute("DELETE FROM api_analysis_state WHERE scan_id = ?", (scan_id,))
            else:
                cursor.execute("DELETE FROM api_analysis_state")
            count = cursor.rowcount
            self.conn.commit()
            logger.info(f"🗑️ [DB] 已清空 {count} 条 API 分析状态记录")
            return count
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] 清空 API 分析状态失败：{e}")
            return 0

    # ==================== 基础数据写入方法 ====================

    def append_data_batch(self, input_data: list, depth: int = 0, show_progress: bool = False) -> None:
        if not input_data:
            return

        rows_to_insert = []
        for item in input_data:
            if not isinstance(item, dict):
                continue
            source_url = str(item.get("sourceURL", "")).strip()
            next_urls = item.get("next_urls", [])
            if not next_urls:
                continue

            for url in next_urls:
                if not isinstance(url, str) or not url.strip():
                    continue
                url_str = url.strip()
                if self._is_static_resource(url_str):
                    continue
                domain = self._extract_domain(url_str)
                path = self._extract_path(url_str)
                rows_to_insert.append((url_str, domain, path, source_url, depth))

        if not rows_to_insert:
            return

        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
            sql = """
                INSERT OR IGNORE INTO scan_results
                (url, domain, path, source_url, scan_depth)
                VALUES (?, ?, ?, ?, ?)
            """
            cursor.executemany(sql, rows_to_insert)

            visited_urls = [(row[0],) for row in rows_to_insert]
            cursor.executemany(
                "INSERT OR IGNORE INTO visited_urls (url) VALUES (?)",
                visited_urls
            )

            self.conn.commit()
            if show_progress:
                print(f"💾 [DB] 基础数据写入：{len(rows_to_insert)} 条")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] 基础数据写入异常：{e}")
            raise

    def _is_static_resource(self, url: str) -> bool:
        static_extensions = [
            ".js", ".vue", ".css", ".ts", ".jsx", ".tsx",
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
            ".woff", ".woff2", ".ttf", ".eot",
            ".mp4", ".mp3", ".wav", ".webm"
        ]
        url_lower = url.lower()
        url_without_query = url_lower.split("?")[0]
        for ext in static_extensions:
            if url_without_query.endswith(ext):
                return True
        return False

    @staticmethod
    def _derive_risk_level(verdict: str = None, request_status: str = None) -> str:
        """
        由请求验证结论推导风险等级。

        未验证 / 无法判定时保持 Low（只是候选接口，不是已确认漏洞）。
        """
        for key in (verdict, request_status):
            if key and key in VERDICT_TO_RISK:
                return VERDICT_TO_RISK[key]
        return RISK_LOW

    def _build_ai_row(self, advisory_report: Dict[str, Any], scan_id: str = None) -> tuple:
        """把 AI advisory 转换成统一的 ai_vulns 行数据"""
        raw_method = advisory_report.get("method", "")
        http_method = self._normalize_method(raw_method)
        path = advisory_report.get("path", "")
        params_raw = advisory_report.get("params", "")
        params_parsed = self._parse_params(params_raw)
        params_json = json.dumps(params_parsed, ensure_ascii=False) if params_parsed else None

        # evidence：JS 侧证据（AI 原始输出），与服务端响应摘要互不重复
        evidence_json = None
        try:
            evidence_json = json.dumps(
                {
                    "advisory": advisory_report,
                    "dangerous": advisory_report.get("dangerous", False),
                    "danger_reason": advisory_report.get("danger_reason", ""),
                },
                ensure_ascii=False,
            )
        except Exception:
            evidence_json = None

        return (
            http_method,
            path,
            params_json,
            RISK_LOW,
            DEFAULT_VULNERABILITY_TYPE,
            evidence_json,
            scan_id,
        )

    def save_ai_result(self, js_url: str, api_endpoint: str, advisory_report: Dict[str, Any],
                       scan_id: str = None):
        """保存 AI 渗透建议（不返回 ID，用于不需要后续请求验证的场景）"""
        if not advisory_report or not isinstance(advisory_report, dict):
            logger.warning("⚠️ [DB] advisory_report 为空或格式错误")
            return

        if not js_url or not api_endpoint:
            logger.warning("⚠️ [DB] js_url 或 api_endpoint 为空")
            return

        try:
            cursor = self.conn.cursor()
            row = self._build_ai_row(advisory_report, scan_id)

            sql = """
                INSERT OR REPLACE INTO ai_vulns
                (js_url, api_endpoint, http_method, path, params,
                 risk_level, vulnerability_type, evidence, scan_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """

            cursor.execute(sql, (js_url, api_endpoint) + row)

            self.conn.commit()

            logger.info(f"💾 [DB] 渗透建议已存档：{row[0]} {api_endpoint}")

        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] AI 渗透建议写入失败：{e}")
            raise

    def save_ai_result_with_id(self, js_url: str, full_url: str, advisory_report: Dict[str, Any],
                               scan_id: str = None) -> Optional[int]:
        """保存 AI 分析结果并返回记录 ID"""
        if not advisory_report or not isinstance(advisory_report, dict):
            logger.warning("⚠️ [DB] advisory_report 为空或格式错误")
            return None

        if not js_url or not full_url:
            logger.warning("⚠️ [DB] js_url 或 full_url 为空")
            return None

        try:
            cursor = self.conn.cursor()
            row = self._build_ai_row(advisory_report, scan_id)

            sql = """
                INSERT OR REPLACE INTO ai_vulns
                (js_url, api_endpoint, http_method, path, params,
                 risk_level, vulnerability_type, evidence, scan_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """

            cursor.execute(sql, (js_url, full_url) + row)

            self.conn.commit()

            record_id = cursor.lastrowid

            logger.info(f"💾 [DB] 渗透建议已存档：{row[0]} {full_url}")

            return record_id

        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] AI 渗透建议写入失败：{e}")
            return None

    def batch_mark_needs_manual_review(self, record_ids: List[int]) -> int:
        """批量标记需要人工审核的记录（create/update/delete 操作类型）"""
        if not record_ids:
            return 0
        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
            cursor.executemany(
                "UPDATE ai_vulns SET request_status = 'needs_manual_review' WHERE id = ?",
                [(rid,) for rid in record_ids]
            )
            self.conn.commit()
            count = cursor.rowcount
            logger.info(f"📋 [DB] 批量标记 {count} 条记录为需人工审核")
            return count
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] 批量标记人工审核失败：{e}")
            return 0

    def batch_update_ai_vuln_request_results(self, request_results: List[Dict[str, Any]]) -> int:
        """批量更新 AI 漏洞记录的请求验证结果"""
        if not request_results:
            return 0

        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")

            sql = """
                UPDATE ai_vulns
                SET request_status = ?, risk_level = ?, response_code = ?,
                    response_length = ?, response_body_preview = ?
                WHERE id = ?
            """

            updated_count = 0
            for result in request_results:
                record_id = result.get("id")
                if not record_id:
                    continue

                verdict = result.get("verdict", "")
                status_code = result.get("status_code", -1)
                content_summary = result.get("content_summary", "")

                if verdict == "dangerous_blocked":
                    request_status = "dangerous_blocked"
                elif status_code > 0:
                    request_status = "success"
                else:
                    request_status = "failed"

                # 风险等级由验证结论推导，保证 risk_level 永远是真实存在的字段
                risk_level = self._derive_risk_level(verdict=verdict, request_status=request_status)

                response_length = len(content_summary) if content_summary else 0

                cursor.execute(sql, (
                    request_status,
                    risk_level,
                    status_code,
                    response_length,
                    content_summary,
                    record_id
                ))
                updated_count += 1

            self.conn.commit()
            logger.info(f"💾 [DB] 批量更新请求验证结果：{updated_count} 条")
            return updated_count

        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] 批量更新请求结果失败：{e}")
            return 0

    def save_sensitive_info(self, js_url: str, sensitive_items: List[Dict[str, Any]]):
        if not js_url:
            logger.warning("⚠️ [DB] js_url 为空")
            return
        if not sensitive_items or not isinstance(sensitive_items, list):
            return

        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")

            sql = """
                INSERT OR REPLACE INTO sensitive_info
                (js_url, sensitive_value, context_code, caller_codes, risk_level,
                 secret_type, test_suggestion, ai_raw_analysis)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """

            inserted_count = 0
            high_risk_count = 0

            for item in sensitive_items:
                if not isinstance(item, dict):
                    continue
                value = item.get("value", "")
                if not value:
                    continue

                context = item.get("context", "")
                callers = item.get("callers", [])
                risk_level = item.get("risk_level", "Low")
                secret_type = item.get("secret_type", "unknown")
                test_suggestion = item.get("test_suggestion", "")
                ai_raw = item.get("ai_raw_analysis", {})

                callers_json = json.dumps(callers, ensure_ascii=False)
                ai_raw_json = json.dumps(ai_raw, ensure_ascii=False)

                cursor.execute(sql, (
                    js_url, value, context, callers_json,
                    risk_level, secret_type, test_suggestion, ai_raw_json
                ))

                inserted_count += 1
                if risk_level == "High":
                    high_risk_count += 1

            self.conn.commit()

            if high_risk_count > 0:
                logger.info(f"🔥 [DB] 敏感信息写入：{inserted_count} 条 (高危：{high_risk_count})")
            else:
                logger.info(f"💾 [DB] 敏感信息写入：{inserted_count} 条")

        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] 敏感信息写入失败：{e}")
            raise


    def get_sensitive_by_js(self, js_url: str) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM sensitive_info WHERE js_url = ? ORDER BY created_at DESC"
            cursor.execute(sql, (js_url,))
            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                for field in ["caller_codes", "ai_raw_analysis"]:
                    if record.get(field):
                        try:
                            record[field] = json.loads(record[field])
                        except json.JSONDecodeError:
                            pass
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 按 JS URL 读取敏感信息失败：{e}")
            return []

    def get_sensitive_by_risk(self, risk_level: str) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM sensitive_info WHERE risk_level = ? ORDER BY created_at DESC"
            cursor.execute(sql, (risk_level,))
            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                for field in ["caller_codes", "ai_raw_analysis"]:
                    if record.get(field):
                        try:
                            record[field] = json.loads(record[field])
                        except json.JSONDecodeError:
                            pass
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 按风险等级读取敏感信息失败：{e}")
            return []

    def get_sensitive_by_type(self, secret_type: str) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM sensitive_info WHERE secret_type = ? ORDER BY created_at DESC"
            cursor.execute(sql, (secret_type,))
            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                for field in ["caller_codes", "ai_raw_analysis"]:
                    if record.get(field):
                        try:
                            record[field] = json.loads(record[field])
                        except json.JSONDecodeError:
                            pass
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 按秘密类型读取敏感信息失败：{e}")
            return []

    def get_all_sensitive(self) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM sensitive_info ORDER BY created_at DESC"
            cursor.execute(sql)
            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                for field in ["caller_codes", "ai_raw_analysis"]:
                    if record.get(field):
                        try:
                            record[field] = json.loads(record[field])
                        except json.JSONDecodeError:
                            pass
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 读取所有敏感信息失败：{e}")
            return []


    def get_linked_report(self, js_url: str) -> Dict[str, Any]:
        try:
            ai_vulns = self.get_vulns_by_js(js_url)
            sensitive_info = self.get_sensitive_by_js(js_url)
            high_risk_vulns = sum(1 for v in ai_vulns if v.get("risk_level") == "High")
            high_risk_sensitive = sum(1 for s in sensitive_info if s.get("risk_level") == "High")

            return {
                "js_url": js_url,
                "ai_vulns": {
                    "total": len(ai_vulns),
                    "high_risk": high_risk_vulns,
                    "items": ai_vulns
                },
                "sensitive_info": {
                    "total": len(sensitive_info),
                    "high_risk": high_risk_sensitive,
                    "items": sensitive_info
                },
                "summary": {
                    "total_findings": len(ai_vulns) + len(sensitive_info),
                    "total_high_risk": high_risk_vulns + high_risk_sensitive
                }
            }
        except Exception as e:
            logger.error(f"❌ [DB] 获取关联报告失败：{e}")
            return {}


    def get_all_vulns(self, risk_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            if risk_filter:
                sql = "SELECT * FROM ai_vulns WHERE risk_level = ? ORDER BY created_at DESC"
                cursor.execute(sql, (risk_filter,))
            else:
                sql = "SELECT * FROM ai_vulns ORDER BY created_at DESC"
                cursor.execute(sql)

            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                if record.get("params"):
                    try:
                        record["params"] = json.loads(record["params"])
                    except json.JSONDecodeError:
                        pass
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 读取漏洞记录失败：{e}")
            return []

    def get_vulns_by_js(self, js_url: str) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM ai_vulns WHERE js_url = ? ORDER BY created_at DESC"
            cursor.execute(sql, (js_url,))
            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                if record.get("params"):
                    try:
                        record["params"] = json.loads(record["params"])
                    except json.JSONDecodeError:
                        pass
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 按 JS URL 读取失败：{e}")
            return []

    def get_vuln_by_endpoint(self, api_endpoint: str) -> Optional[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM ai_vulns WHERE api_endpoint = ? LIMIT 1"
            cursor.execute(sql, (api_endpoint,))
            row = cursor.fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                record = dict(zip(columns, row))
                if record.get("params"):
                    try:
                        record["params"] = json.loads(record["params"])
                    except json.JSONDecodeError:
                        pass
                return record
            return None
        except Exception as e:
            logger.error(f"❌ [DB] 按端点读取失败：{e}")
            return None

    def get_stats(self) -> Dict[str, Any]:
        try:
            cursor = self.conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM ai_vulns")
            total_vulns = cursor.fetchone()[0]

            cursor.execute("SELECT risk_level, COUNT(*) FROM ai_vulns GROUP BY risk_level")
            risk_distribution_vulns = dict(cursor.fetchall())

            cursor.execute("SELECT COUNT(*) FROM sensitive_info")
            total_sensitive = cursor.fetchone()[0]

            cursor.execute("SELECT risk_level, COUNT(*) FROM sensitive_info GROUP BY risk_level")
            risk_distribution_sensitive = dict(cursor.fetchall())

            cursor.execute("SELECT secret_type, COUNT(*) FROM sensitive_info GROUP BY secret_type")
            type_distribution = dict(cursor.fetchall())

            cursor.execute("SELECT COUNT(*) FROM scan_results")
            total_urls = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM visited_urls")
            total_visited = cursor.fetchone()[0]

            return {
                "ai_vulns": {
                    "total": total_vulns,
                    "by_risk": risk_distribution_vulns
                },
                "sensitive_info": {
                    "total": total_sensitive,
                    "by_risk": risk_distribution_sensitive,
                    "by_type": type_distribution
                },
                "scan_results": {
                    "total_urls": total_urls
                },
                "visited_urls": {
                    "total": total_visited
                },
                "api_analysis_state": {
                    "by_status": self.get_api_state_stats()
                }
            }
        except Exception as e:
            logger.error(f"❌ [DB] 获取统计信息失败：{e}")
            return {}

    def export_high_risk(self) -> List[Dict[str, Any]]:
        return self.get_all_vulns(risk_filter="High")

    def export_high_risk_sensitive(self) -> List[Dict[str, Any]]:
        return self.get_sensitive_by_risk("High")

    def export_for_burp(self, output_path: str) -> bool:
        """导出高危漏洞为 Burp Suite 可导入的 CSV 格式"""
        try:
            high_risks = self.export_high_risk()
            if not high_risks:
                logger.warning("⚠️ [DB] 没有高危漏洞可导出")
                return False

            with open(output_path, "w", encoding="utf-8") as f:
                f.write("URL,Method,Risk Level,Path,Params\n")

                for vuln in high_risks:
                    url = vuln.get("api_endpoint", "")
                    method = vuln.get("http_method", "UNKNOWN")
                    risk = vuln.get("risk_level", "Low")

                    path = vuln.get("path", "")
                    path = path.replace(",", ";").replace("\n", " ") if path else ""

                    params = vuln.get("params", {})
                    if isinstance(params, dict):
                        params_str = ",".join(f"{k}={v}" for k, v in params.items())
                    else:
                        params_str = str(params)
                    params_str = params_str.replace(",", ";") if params_str else ""

                    f.write(f'"{url}","{method}","{risk}","{path}","{params_str}"\n')

            logger.info(f"✅ [DB] 已导出 {len(high_risks)} 条高危漏洞到：{output_path}")
            return True
        except Exception as e:
            logger.error(f"❌ [DB] 导出 Burp 格式失败：{e}")
            return False

    def save_source_map_result(self, js_url: str, is_source_map: str) -> bool:
        try:
            cursor = self.conn.cursor()
            sql = """
                INSERT OR REPLACE INTO js_source_maps (js_url, is_sourceMap)
                VALUES (?, ?)
            """
            cursor.execute(sql, (js_url, is_source_map))
            self.conn.commit()
            return True
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] SourceMap 结果写入失败：{e}")
            return False

    def batch_save_source_map_results(self, results: list) -> int:
        if not results:
            return 0
        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
            sql = """
                INSERT OR REPLACE INTO js_source_maps (js_url, is_sourceMap)
                VALUES (?, ?)
            """
            cursor.executemany(sql, results)
            self.conn.commit()
            logger.info(f"💾 [DB] SourceMap 检测结果写入：{len(results)} 条")
            return len(results)
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] SourceMap 批量写入失败：{e}")
            return 0

    def get_source_map_results(self) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM js_source_maps ORDER BY created_at DESC"
            cursor.execute(sql)
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"❌ [DB] 读取 SourceMap 结果失败：{e}")
            return []
