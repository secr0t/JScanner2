import difflib
import hashlib
import re
import time
import traceback
from typing import Any, Dict, Iterable, Optional, List, Tuple

import json_repair

from config.scanner_rules import is_api_path_blacklisted
from infra import watchdog
from infra.ai_client import client
from infra.bloom import DiskBloomFilter
from logger import get_logger
from processor.analysis.params.param_pre_filter import pre_filter_has_params
from processor.analysis.prompts import (
    SYSTEM_PROMPT_ADVISORY,
    SYSTEM_PROMPT_JUDGE,
    SYSTEM_PROMPT_OPERATION_CLASSIFY,
)
from processor.js.context.context_extractor import extract_multiple_apis_from_raw_code

logger = get_logger(__name__)


class AISecurityAuditor:
    """
    AI 参数安全审计器

    核心流程：

        API 提取
          ↓
        上下文语义过滤
          ↓
        Level 2：判断是否存在参数
          ↓
        Level 3：参数值补充 + 请求构建

    本版本重点修复：

    1. $router.push / $router.replace 等前端路由被错误识别为 HTTP API
    2. router query 被错误识别为 HTTP Query 参数
    3. 普通字符串 / route path / 页面跳转代码进入 AI
    4. wrapper_code 存在 ≠ 一定是 HTTP wrapper
    """

    # 代码最大长度阈值
    CODE_MAX_LENGTH = 12000

    # ============================================================
    # 参数结果复用缓存（精确层 + 模糊层）
    # ============================================================

    # 模糊层：相似度达到该阈值才允许复用（difflib ratio）
    PARAM_CACHE_SIMILARITY_THRESHOLD = 0.97

    # 模糊层：差异片段若触及这些「参数承载键」，说明参数定义可能不同，
    # 宁可多调一次 LLM 也不复用（避免漏报）
    PARAM_BEARER_KEYS = frozenset({
        "data", "params", "body", "query", "payload",
    })

    # ============================================================
    # 前端导航 / 路由语义
    # ============================================================

    # 这些语义本身并不能证明发生了 HTTP 请求
    FRONTEND_NAVIGATION_PATTERNS = [
        r"\$router\s*\.\s*push\s*\(",
        r"\$router\s*\.\s*replace\s*\(",
        r"\brouter\s*\.\s*push\s*\(",
        r"\brouter\s*\.\s*replace\s*\(",
        r"\bnavigate\s*\(",
        r"\bnavigateTo\s*\(",
        r"\bgo\s*\(",
        r"\blocation\s*\.\s*(?:href|assign|replace)\s*=",
        r"\bwindow\s*\.\s*location\b",
        r"\bwindow\s*\.\s*open\s*\(",
        r"\bhistory\s*\.\s*(?:pushState|replaceState)\s*\(",
    ]

    # ============================================================
    # HTTP 发包语义
    # ============================================================

    # 明确的网络请求信号
    HTTP_REQUEST_PATTERNS = [
        # Fetch
        r"\bfetch\s*\(",

        # Axios
        r"\baxios\s*\(",
        r"\baxios\s*\.\s*(?:get|post|put|delete|patch|request|head|options)\s*\(",

        # jQuery AJAX
        r"\$\s*\.\s*ajax\s*\(",
        r"\$\s*\.\s*get\s*\(",
        r"\$\s*\.\s*post\s*\(",

        # XMLHttpRequest
        r"\bXMLHttpRequest\s*\(",
        r"\.\s*open\s*\(\s*['\"](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['\"]",

        # 常见 request 封装
        r"\brequest\s*\(",
        r"\brequest\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(",

        # 常见 http 封装
        r"\bhttp\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(",
        r"\bhttps?\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(",

        # 常见 api 封装
        r"\bapi\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(",
        r"\bapiRequest\s*\(",
        r"\bhttpRequest\s*\(",
        r"\bajaxRequest\s*\(",

        # HTTP 请求配置对象结构：同时包含 url + method + (data|params)
        r"""(?:url\s*:\s*["'/][^"']{3,}["'])\s*[^}]{0,200}(?:method\s*:\s*["'](?:get|post|put|delete|patch)["'])""",
        r"""(?:method\s*:\s*["'](?:get|post|put|delete|patch)["'])\s*[^}]{0,200}(?:url\s*:\s*["'/][^"']{3,}["'])""",
    ]

    # 明确属于“路由对象”的字段
    ROUTER_ONLY_PATTERNS = [
        r"\bpath\s*:",
        r"\bquery\s*:",
        r"\bparams\s*:",
        r"\bname\s*:",
    ]

    def __init__(self, request_validation: bool = False, code_max_length: int = None):
        """
        Args:
            request_validation: 是否开启请求验证（影响 Level 3 的参数值生成策略）
            code_max_length: 单次送入大模型的代码最大长度，None 表示使用类默认值

        注意：
        这里只保留主流程真正使用的参数。
        旧版本遗留的 client / db / bloom 等参数已全部删除，
        避免调用方与构造函数定义不一致导致 TypeError。
        """
        self.request_validation = bool(request_validation)

        if code_max_length and code_max_length > 0:
            self.CODE_MAX_LENGTH = code_max_length

        self._no_param_bloom = DiskBloomFilter(
            "Result/no_param_cache.bloom",
            capacity=500000,
            error_rate=0.001,
        )

        # 参数结果复用缓存：key=剥离 api_path 后的规范化 wrapper → LLM 提取结果。
        # 与 _no_param_bloom 的区别：key 去掉路径（同结构异路径可复用），
        # 且 has_value=0/1 都缓存（进程内精确 dict，不落盘、无假阳性）。
        self._param_cache: Dict[str, Dict[str, Any]] = {}

        # Level 3 参数值复用缓存：
        # key   = 剥离 api_path 后的规范化 wrapper
        # value = 同一 wrapper 下按 callers / param_keys / 取值策略区分的条目列表。
        # 与 Level 2 分开存放：值结果 schema 不同，且复用条件额外要求
        # callers 精确一致（业务调用点可能携带真实传参值，不能模糊）。
        self._value_cache: Dict[str, List[Dict[str, Any]]] = {}

        # 最近一次 scan_multiple_apis 的上下文召回结果，供主流程推进状态机使用
        self.last_context_found = {}
        self.last_context_types = {}

    # ============================================================
    # 基础 JSON 解析
    # ============================================================

    def _clean_json_response(self, content: str) -> str:
        """
        强壮的 JSON 剥壳器（用于 Level 2 和 Level 3）
        """
        if not content:
            return ""

        content = content.strip()

        if content.startswith("{") or content.startswith("["):
            if content.endswith("```"):
                content = content[:-3].strip()
            return content

        match = re.search(
            r"```(?:json)?\s*(.*?)\s*```",
            content,
            flags=re.DOTALL | re.IGNORECASE,
        )

        if match:
            return match.group(1).strip()

        start_idx = content.find("{")
        end_idx = content.rfind("}")

        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            return content[start_idx:end_idx + 1].strip()

        return ""

    def _parse_level2_result(self, content: str) -> Dict[str, Any]:
        """
        解析 Level 2 的 JSON 输出。

        返回：
            {
                "has_value": 0/1,
                "param_keys": [...]
            }
        """

        if not content:
            return {
                "has_value": 1,
                "param_keys": [],
            }

        if isinstance(content, dict):
            has_value = content.get("has_value", 1)
            param_keys = content.get("param_keys", [])

            if not isinstance(param_keys, list):
                param_keys = []

            param_keys = [
                k
                for k in param_keys
                if isinstance(k, str)
                and (len(k) > 1 or k.lower() in ["id", "ip", "os"])
            ]

            return {
                "has_value": has_value,
                "param_keys": param_keys,
            }

        if isinstance(content, list):
            logger.warning(
                f"⚠️ Level 2 返回了列表而非字典：{content}，默认 has_value=1"
            )

            return {
                "has_value": 1,
                "param_keys": [],
            }

        content = content.strip()

        try:
            parsed = json_repair.loads(content)

            if isinstance(parsed, list):
                logger.warning(
                    f"⚠️ Level 2 JSON 解析后为列表：{parsed}，默认 has_value=1"
                )

                return {
                    "has_value": 1,
                    "param_keys": [],
                }

            if isinstance(parsed, dict):
                has_value = parsed.get("has_value", 1)
                param_keys = parsed.get("param_keys", [])

                if not isinstance(param_keys, list):
                    param_keys = []

                param_keys = [
                    k
                    for k in param_keys
                    if isinstance(k, str)
                    and (len(k) > 1 or k.lower() in ["id", "ip", "os"])
                ]

                return {
                    "has_value": has_value,
                    "param_keys": param_keys,
                }

            logger.warning(
                f"⚠️ Level 2 JSON 解析后为未知类型：{type(parsed)}，默认 has_value=1"
            )

            return {
                "has_value": 1,
                "param_keys": [],
            }

        except Exception as e:
            logger.warning(
                f"⚠️ Level 2 JSON 解析失败：{e}，默认 has_value=1"
            )

            return {
                "has_value": 1,
                "param_keys": [],
            }

    # ============================================================
    # 代码压缩
    # ============================================================

    def _aggressive_minify(
        self,
        code: str,
        max_chars: int = None,
    ) -> str:
        """
        纯代码级压缩（删除对安全分析无用的代码）
        """

        if not code:
            return ""

        original_length = len(code)

        # Base64 图片
        code = re.sub(
            r'["\']image/[a-zA-Z]*;base64,[^"\']*["\']',
            '"[IMG]"',
            code,
        )

        # CSS
        code = re.sub(
            r'["\'][^"\']*[\.#][a-zA-Z0-9_-]+\s*\{[^}]*:[^}]*\}[^"\']*["\']',
            '"[CSS]"',
            code,
        )

        # HTML
        code = re.sub(
            r'["\'][^"\']*<[a-z][^>]*>[^"\']*["\']',
            '"[HTML]"',
            code,
        )

        # 超大数组
        code = re.sub(
            r'\[(\s*["\'][a-zA-Z0-9]{2,}["\']\s*,?){50,}\]',
            '"[ARRAY]"',
            code,
        )

        # 注释
        code = re.sub(
            r"/\*.*?\*/",
            "",
            code,
            flags=re.DOTALL,
        )

        code = re.sub(
            r"//.*?$",
            "",
            code,
            flags=re.MULTILINE,
        )

        # 空白字符
        code = re.sub(
            r"\s+",
            " ",
            code,
        )

        # console
        code = re.sub(
            r"console\.[a-zA-Z]+\([^)]*\)",
            "",
            code,
        )

        # logger
        code = re.sub(
            r"logger\.[a-zA-Z]+\([^)]*\)",
            "",
            code,
        )

        compressed_length = len(code)

        total_saved = original_length - compressed_length

        compression_rate = (
            (total_saved / original_length) * 100
            if original_length > 0
            else 0
        )

        logger.info(
            f"[Minify] 压缩：{original_length} → "
            f"{compressed_length} 字符 "
            f"(节省：{total_saved} 字符，"
            f"{compression_rate:.1f}%)"
        )

        return code

    def _compress_code_loop(
        self,
        code: str,
        max_chars: int,
    ) -> str:
        """
        代码压缩（规则压缩 + 结构截断）
        """

        if not code:
            return ""

        original_length = len(code)

        current_code = self._aggressive_minify(
            code,
            max_chars,
        )

        if len(current_code) <= max_chars:
            logger.info(
                f"[Compress] Rule-based sufficient: "
                f"{original_length} → {len(current_code)}"
            )

            return current_code

        logger.warning(
            f"[Compress] Rule-based not enough "
            f"({len(current_code)} > {max_chars}), "
            f"using structural truncate"
        )

        current_code = self._structural_truncate(
            current_code,
            max_chars,
        )

        logger.info(
            f"[Compress] Final: "
            f"{original_length} → {len(current_code)}"
        )

        return current_code

    def _structural_truncate(
        self,
        code: str,
        max_chars: int,
    ) -> str:
        """
        结构截断：尽量在 function 边界处截断
        """

        if len(code) <= max_chars:
            return code

        function_pattern = (
            r"(?:function\s+\w+"
            r"|\w+\s*=\s*(?:async\s+)?function"
            r"|\w+\s*:\s*(?:async\s+)?function)"
        )

        function_matches = list(
            re.finditer(
                function_pattern,
                code,
            )
        )

        if not function_matches:
            return (
                code[:max_chars]
                + "\n\n/*...[代码截断]...*/\n\n"
            )

        protected_keywords = [
            "params",
            "data",
            "body",
            "payload",
            "query",
            "fetch",
            "axios",
            "request",
            "http",
            "post",
            "get",
            "token",
            "sign",
            "auth",
            "permission",
            "key",
            "secret",
        ]

        protected_functions = []

        for i, match in enumerate(function_matches):
            start = match.start()

            end = (
                function_matches[i + 1].start()
                if i + 1 < len(function_matches)
                else len(code)
            )

            function_code = code[start:end]

            if any(
                kw in function_code
                for kw in protected_keywords
            ):
                protected_functions.append(
                    (start, end)
                )

        result_parts = []
        current_pos = 0
        total_length = 0

        for start, end in protected_functions:
            if total_length + (end - start) > max_chars * 0.8:
                break

            result_parts.append(
                code[current_pos:start]
            )

            result_parts.append(
                code[start:end]
            )

            total_length += end - current_pos
            current_pos = end

        if (
            total_length < max_chars
            and current_pos < len(code)
        ):
            remaining = max_chars - total_length

            result_parts.append(
                code[
                    current_pos:
                    current_pos + remaining
                ]
            )

            total_length += remaining

        result = "".join(result_parts)

        if len(result) < len(code):
            result += (
                "\n\n/*..."
                "[代码截断 - 保留关键函数]"
                "...*/\n\n"
            )

        return result[:max_chars + 100]

    # ============================================================
    # 新增：上下文语义判定
    # ============================================================

    @classmethod
    def _regex_any(
        cls,
        code: str,
        patterns: List[str],
    ) -> bool:
        """
        判断代码是否命中任意正则。
        """

        if not code:
            return False

        for pattern in patterns:
            try:
                if re.search(
                    pattern,
                    code,
                    flags=re.IGNORECASE,
                ):
                    return True
            except re.error:
                continue

        return False

    @classmethod
    def _contains_http_request_signal(
        cls,
        code: str,
    ) -> bool:
        """
        判断代码是否存在明确的 HTTP 发包语义。

        注意：
        这里故意不把 query / params / path 当成 HTTP 信号。
        """

        if not code:
            return False

        return cls._regex_any(
            code,
            cls.HTTP_REQUEST_PATTERNS,
        )

    @classmethod
    def _contains_frontend_navigation_signal(
        cls,
        code: str,
    ) -> bool:
        """
        判断代码是否属于前端导航 / 路由跳转。
        """

        if not code:
            return False

        return cls._regex_any(
            code,
            cls.FRONTEND_NAVIGATION_PATTERNS,
        )

    @classmethod
    def _is_navigation_only_code(
        cls,
        code: str,
    ) -> bool:
        """
        判断一段代码是否本质上只是前端导航，而不是 HTTP 请求。

        核心规则：

            有导航
            且
            没有任何明确 HTTP 发包信号

        => 导航代码
        """

        if not code:
            return False

        has_navigation = cls._contains_frontend_navigation_signal(
            code
        )

        if not has_navigation:
            return False

        has_http = cls._contains_http_request_signal(
            code
        )

        return not has_http

    @classmethod
    def _classify_context_type(
        cls,
        context_data: Dict[str, Any],
    ) -> str:
        """
        对 extractor 返回的上下文做二次语义判定。

        返回：

            HTTP_REQUEST
            FRONTEND_ROUTE
            UNKNOWN
        """

        if not context_data:
            return "UNKNOWN"

        # 如果未来 extractor 已经提供 context_type，
        # 优先相信明确结果。
        explicit_type = context_data.get(
            "context_type"
        )

        if explicit_type:
            explicit_type = str(
                explicit_type
            ).upper()

            if explicit_type in {
                "HTTP_REQUEST",
                "FRONTEND_ROUTE",
                "UNKNOWN",
            }:
                return explicit_type

        wrapper_code = context_data.get(
            "wrapper_code",
            "",
        )

        caller_codes = context_data.get(
            "caller_codes",
            [],
        )

        if not isinstance(caller_codes, list):
            caller_codes = []

        # --------------------------------------------------------
        # 第一优先级：wrapper
        # --------------------------------------------------------

        wrapper_has_http = (
            cls._contains_http_request_signal(
                wrapper_code
            )
        )

        wrapper_is_navigation_only = (
            cls._is_navigation_only_code(
                wrapper_code
            )
        )

        if wrapper_has_http:
            return "HTTP_REQUEST"

        if wrapper_is_navigation_only:
            return "FRONTEND_ROUTE"

        # --------------------------------------------------------
        # 第二优先级：caller
        #
        # wrapper 不明确的时候，如果 caller 中存在明确 HTTP
        # 发包语义，也允许继续。
        # --------------------------------------------------------

        for caller in caller_codes:
            if cls._contains_http_request_signal(
                caller
            ):
                return "HTTP_REQUEST"

        # --------------------------------------------------------
        # 第三优先级：未知
        # --------------------------------------------------------

        return "UNKNOWN"

    @classmethod
    def _filter_caller_codes(
        cls,
        caller_codes: List[str],
    ) -> List[str]:
        """
        清理 caller：

        纯 router/navigation caller 不再进入 AI。
        """

        if not caller_codes:
            return []

        filtered = []

        for caller in caller_codes:
            if not caller:
                continue

            if cls._is_navigation_only_code(
                caller
            ):
                continue

            filtered.append(caller)

        return filtered

    @staticmethod
    def _normalize_cache_key(
        raw_wrapper: str,
        api_path: str,
    ) -> str:
        """
        剥离 api_path 后的规范化 wrapper → 参数结果缓存 key。

        空 wrapper 返回 ""，调用方须跳过（不参与缓存）。
        只替换「引号包裹的完整路径」，避免 /a/b/c 这种前缀误伤；
        拼接形式（"/a" + "/b"）剥不干净 → key 不同 → 自然 miss，安全回退原逻辑。
        """

        if not raw_wrapper:
            return ""

        code = raw_wrapper

        for q in ('"', "'", "`"):
            code = code.replace(
                f"{q}{api_path}{q}",
                '"__P__"',
            )

        return re.sub(
            r"\s+",
            " ",
            code,
        )

    @staticmethod
    def _find_similar_key(
        candidate_key: str,
        cached_keys: Iterable[str],
    ) -> Optional[str]:
        """
        模糊层共用核心（Level 2 / Level 3）：
        在 cached_keys 中找一个与 candidate_key 足够相似的 key，
        且差异片段不触及参数承载键 → 返回该 key，否则返回 None。

        设计要点：
            1. 相似度只是「捞」候选，diff 承载键校验才是「判」是否安全；
            2. 非空白差异落在参数承载键附近（±60 字符窗口）就放弃复用，
               走 LLM（宁可多花一次调用，不能漏报）；
            3. 纯空白差异（空格/换行/缩进风格）不影响参数，直接跳过；
            4. 取最相似的一条；多条同样相似时按缓存插入序取第一条。
        """

        if not candidate_key:
            return None

        best_key = None
        best_ratio = 0.0

        for cached_key in cached_keys:
            ratio = difflib.SequenceMatcher(
                None,
                candidate_key,
                cached_key,
            ).ratio()

            if ratio > best_ratio:
                best_ratio = ratio
                best_key = cached_key

        if (
            best_key is None
            or best_ratio
            < AISecurityAuditor.PARAM_CACHE_SIMILARITY_THRESHOLD
        ):
            return None

        # 差异片段校验：列出两侧不匹配的文本块，
        # 非空白差异若落在参数承载键附近（±60 字符窗口），则放弃复用。
        # 理由：params/data/body 等承载键通常紧邻其参数对象，
        # 在窗口内出现说明差异可能改写了参数名/值 → 不能复用。
        matcher = difflib.SequenceMatcher(
            None,
            candidate_key,
            best_key,
        )

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                continue

            cand_diff = candidate_key[i1:i2]
            cached_diff = best_key[j1:j2]

            # 纯空白差异（空格/换行/缩进风格）不影响参数，跳过
            if (
                cand_diff.strip() == ""
                and cached_diff.strip() == ""
            ):
                continue

            window = (
                candidate_key[max(0, i1 - 60):i2 + 60]
                + best_key[max(0, j1 - 60):j2 + 60]
            )

            if any(
                key in window
                for key in AISecurityAuditor.PARAM_BEARER_KEYS
            ):
                return None

        logger.info(
            f"[FuzzyCache] ratio={best_ratio:.3f}，"
            f"差异片段未触及参数承载键，允许复用"
        )

        return best_key

    def _find_similar_cache_match(
        self,
        candidate_key: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Level 2 模糊层：返回通过校验的缓存结果。
        相似度 + 承载键护栏逻辑见共用方法 _find_similar_key。

        返回:
            命中 → 缓存的结果 dict {has_value, param_keys}
            未命中 → None
        """

        best_key = self._find_similar_key(
            candidate_key,
            self._param_cache.keys(),
        )

        if best_key is None:
            return None

        return self._param_cache[best_key]

    # ============================================================
    # Level 3 参数值复用缓存
    # ============================================================

    def _normalize_callers(
        self,
        caller_codes: List[str],
        api_path: str,
    ) -> str:
        """
        规范化业务调用点（已过滤，≤3 个）：
        逐个剥离 api_path + 折叠空白，用单元分隔符拼接。

        callers 是真实调用点，可能携带真实传参值，
        因此在 Level 3 值缓存里只允许精确一致，不做模糊。
        """

        if not caller_codes:
            return ""

        parts = []

        for code in caller_codes[:3]:
            if not isinstance(code, str):
                code = str(code)

            parts.append(
                self._normalize_cache_key(code, api_path)
            )

        return "\x1f".join(parts)

    @staticmethod
    def _match_value_entry(
        entries: List[Dict[str, Any]],
        callers_key: str,
        param_keys: Tuple[str, ...],
        value_mode: bool,
    ) -> Optional[Dict[str, Any]]:
        """
        在同一 wrapper 的条目列表里，
        找 callers / param_keys / 取值策略全等的一条。
        """

        for entry in entries:
            if (
                entry["callers_key"] == callers_key
                and tuple(entry["param_keys"]) == param_keys
                and entry["value_mode"] == value_mode
            ):
                return entry["result"]

        return None

    def _lookup_value_cache(
        self,
        wrapper_norm: str,
        callers_key: str,
        param_keys: Tuple[str, ...],
        value_mode: bool,
    ) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """
        Level 3 两层查找。

        精确层：wrapper 归一化串等值；
        模糊层：wrapper 相似度达标且差异不触承载键。
        两层都要求 callers / param_keys / 取值策略精确一致。

        返回:
            ("exact" | "fuzzy", result)；未命中返回 (None, None)。
        """

        if not wrapper_norm:
            return None, None

        # ---- 精确层 ----
        entries = self._value_cache.get(wrapper_norm)

        if entries:
            result = self._match_value_entry(
                entries,
                callers_key,
                param_keys,
                value_mode,
            )

            if result is not None:
                return "exact", result

        # ---- 模糊层（只模糊 wrapper，其余条件仍须精确）----
        best_key = self._find_similar_key(
            wrapper_norm,
            self._value_cache.keys(),
        )

        if best_key is not None:
            result = self._match_value_entry(
                self._value_cache[best_key],
                callers_key,
                param_keys,
                value_mode,
            )

            if result is not None:
                return "fuzzy", result

        return None, None

    def _store_value_cache(
        self,
        wrapper_norm: str,
        callers_key: str,
        param_keys: Tuple[str, ...],
        value_mode: bool,
        result: Dict[str, Any],
    ) -> None:
        """
        写回 Level 3 值缓存（result 不含 path，path 命中时各自回填）。
        等价条目已存在则跳过。
        """

        if not wrapper_norm:
            return

        entries = self._value_cache.setdefault(
            wrapper_norm,
            [],
        )

        for entry in entries:
            if (
                entry["callers_key"] == callers_key
                and tuple(entry["param_keys"]) == param_keys
                and entry["value_mode"] == value_mode
            ):
                return

        entries.append(
            {
                "callers_key": callers_key,
                "param_keys": tuple(param_keys),
                "value_mode": value_mode,
                "result": result,
            }
        )

    # ============================================================
    # Level 2
    # ============================================================

    def _analyze_multiple_api_values(
        self,
        candidates: List[Dict[str, Any]],
    ) -> Dict[str, Dict]:
        """
        Level 2：逐个判断多个 API 是否有参数值。

        三层过滤漏斗：

            AST评分
              ↓
            Bloom缓存
              ↓
            正则参数预过滤
              ↓
            上下文语义过滤
              ↓
            AI
        """

        strategy_results = {}

        for candidate in candidates:
            api_path = candidate["api_path"]
            context_data = candidate["context_data"]

            raw_wrapper = context_data.get(
                "wrapper_code",
                "",
            )

            caller_codes = context_data.get(
                "caller_codes",
                [],
            )

            if not isinstance(caller_codes, list):
                caller_codes = []

            # ----------------------------------------------------
            # NEW：上下文语义二次过滤
            # 只拦截明确的前端路由，UNKNOWN 放行
            # ----------------------------------------------------

            context_type = self._classify_context_type(
                context_data
            )

            if context_type == "FRONTEND_ROUTE":
                strategy_results[api_path] = {
                    "decision": 0,
                    "param_keys": [],
                }

                logger.info(
                    f"[{api_path}] 🚫 "
                    f"前端路由上下文，"
                    f"跳过 Level 2 AI"
                )

                continue

            # ----------------------------------------------------
            # Layer 1: AST
            # ----------------------------------------------------

            ast_score = context_data.get(
                "param_score",
                0,
            )

            # ----------------------------------------------------
            # Layer 2: Bloom
            # ----------------------------------------------------

            wrapper_hash = hashlib.md5(
                raw_wrapper.encode("utf-8")
            ).hexdigest()

            if (
                raw_wrapper
                and self._no_param_bloom.contains(
                    wrapper_hash
                )
            ):
                strategy_results[api_path] = {
                    "decision": 0,
                    "param_keys": [],
                }

                logger.info(
                    f"[{api_path}] ⚡ "
                    f"Bloom 缓存命中 (no-param)，跳过 AI"
                )

                continue

            # ----------------------------------------------------
            # 清理 caller
            # ----------------------------------------------------

            caller_codes = self._filter_caller_codes(
                caller_codes
            )

            context_data["caller_codes"] = caller_codes

            # ----------------------------------------------------
            # Layer 3:
            # AST + 正则参数预过滤
            # ----------------------------------------------------

            regex_hit = pre_filter_has_params(
                raw_wrapper,
                caller_codes,
                api_path,
            )

            if (
                ast_score <= 0
                and not regex_hit
            ):
                strategy_results[api_path] = {
                    "decision": 0,
                    "param_keys": [],
                }

                if ast_score == -1:
                    logger.info(
                        f"[{api_path}] ⏭️ "
                        f"无 enclosing function "
                        f"且正则无信号，保守跳过"
                    )
                else:
                    logger.info(
                        f"[{api_path}] 🔇 "
                        f"AST评分=0 + 正则无信号，"
                        f"跳过 AI"
                    )

                continue

            if ast_score >= 1:
                logger.info(
                    f"[{api_path}] 🌳 "
                    f"AST评分={ast_score}，送 AI"
                )
            else:
                logger.info(
                    f"[{api_path}] 📝 "
                    f"正则命中(AST=0)，送 AI"
                )

            # ----------------------------------------------------
            # Layer 4: 参数结果复用缓存
            # 同结构异路径的 wrapper（剥离 api_path 后逐字节等价）
            # 参数提取结果必然一致，直接复用，跳过压缩 + LLM
            # ----------------------------------------------------

            cache_key = self._normalize_cache_key(
                raw_wrapper,
                api_path,
            )

            cached_result = None

            # ---- 精确层：剥离路径后逐字节等价 ----
            if cache_key and cache_key in self._param_cache:
                cached_result = self._param_cache[cache_key]

                logger.info(
                    f"[{api_path}] ♻️ "
                    f"参数结果缓存命中，复用 LLM 结果（跳过调用）"
                )

            # ---- 模糊层：相似度足够高 + 差异不触承载键 ----
            elif cache_key:
                fuzzy = self._find_similar_cache_match(
                    cache_key
                )

                if fuzzy is not None:
                    cached_result = fuzzy

                    logger.info(
                        f"[{api_path}] ♻️ "
                        f"参数结果缓存模糊命中，复用 LLM 结果（跳过调用）"
                    )

            if cached_result is not None:
                strategy_results[api_path] = {
                    "decision": cached_result["has_value"],
                    "param_keys": cached_result["param_keys"],
                }

                continue

            # ----------------------------------------------------
            # 压缩代码
            # ----------------------------------------------------

            wrapper_code = self._compress_code_loop(
                raw_wrapper,
                self.CODE_MAX_LENGTH // 2,
            )

            processed_callers = [
                self._compress_code_loop(
                    c,
                    self.CODE_MAX_LENGTH // 6,
                )
                for c in caller_codes[:3]
            ]

            callers_str = "\n\n".join(
                [
                    f"--- 业务调用点 {i + 1} ---\n{c}"
                    for i, c in enumerate(
                        processed_callers
                    )
                ]
            )

            full_desc = (
                f"目标 API: {api_path}\n\n"
                f"[JS 底层发包函数]:\n"
                f"{wrapper_code}\n\n"
                f"[JS 业务调用点]:\n"
                f"{callers_str}"
            )

            messages = [
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT_JUDGE,
                },
                {
                    "role": "user",
                    "content": (
                        "请对该单一 API 的全量源码进行审查，"
                        "提取 HTTP 参数名：\n\n"
                        f"{full_desc}"
                    ),
                },
            ]

            result = client.chat(
                messages=messages,
                max_tokens=1000,
                require_json=True,
            )

            try:
                level2_result = self._parse_level2_result(
                    result
                )

                strategy_results[api_path] = {
                    "decision": level2_result[
                        "has_value"
                    ],
                    "param_keys": level2_result[
                        "param_keys"
                    ],
                }

                # 写回缓存（has_value=0/1 都写，复用无参数结论可省掉 Bloom 依赖）
                if cache_key:
                    self._param_cache[cache_key] = {
                        "has_value": level2_result[
                            "has_value"
                        ],
                        "param_keys": level2_result[
                            "param_keys"
                        ],
                    }

                # AI 返回无参数
                if (
                    level2_result["has_value"] == 0
                    and raw_wrapper
                ):
                    self._no_param_bloom.add(
                        wrapper_hash
                    )

            except Exception as e:
                exc = traceback.format_exc()

                logger.error(
                    f"[-] Level 2 单点 "
                    f"({api_path}) 解析异常："
                    f"{exc}，默认 has_value=1"
                )

                strategy_results[api_path] = {
                    "decision": 1,
                    "param_keys": [],
                }

        return strategy_results

    # ============================================================
    # Level 3
    # ============================================================

    def analyze(
        self,
        context_data: Dict[str, Any],
        param_keys: List[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Level 3：参数值补充 + 请求构建
        """

        if (
            not context_data
            or not context_data.get("found")
        ):
            return None

        api_url = context_data.get(
            "api_url",
            "",
        )

        try:
            raw_wrapper = context_data.get(
                "wrapper_code",
                "",
            )

            caller_codes = context_data.get(
                "caller_codes",
                [],
            )

            if not isinstance(caller_codes, list):
                caller_codes = []

            # ----------------------------------------------------
            # NEW：Level 3 最终保险
            # 只拦截明确的前端路由
            # ----------------------------------------------------

            context_type = self._classify_context_type(
                context_data
            )

            if context_type == "FRONTEND_ROUTE":
                logger.info(
                    f"[{api_url}] 🚫 "
                    f"Level 3 上下文类型="
                    f"{context_type}，"
                    f"前端路由，拒绝分析"
                )

                return None

            caller_codes = self._filter_caller_codes(
                caller_codes
            )

            context_data["caller_codes"] = caller_codes

            # ----------------------------------------------------
            # Level 3 参数值复用缓存
            # 同结构异路径 wrapper（剥路径后等价/高度相似）
            # 且 callers / param_keys / 取值策略一致
            # → 参数值结果必然一致，跳过压缩 + LLM。
            # 查询异常时 fail-open 回退正常 LLM 流程。
            # ----------------------------------------------------

            wrapper_norm = ""
            callers_key = ""

            try:
                wrapper_norm = self._normalize_cache_key(
                    raw_wrapper,
                    api_url,
                )

                callers_key = self._normalize_callers(
                    caller_codes,
                    api_url,
                )

                (
                    hit_type,
                    cached_value,
                ) = self._lookup_value_cache(
                    wrapper_norm,
                    callers_key,
                    tuple(param_keys or ()),
                    self.request_validation,
                )

                if hit_type is not None:
                    reused_value = dict(cached_value)
                    reused_value["path"] = api_url

                    logger.info(
                        f"[{api_url}] ♻️ "
                        f"Level 3 参数值缓存"
                        f"{'模糊' if hit_type == 'fuzzy' else ''}"
                        f"命中，跳过压缩与 LLM"
                    )

                    return reused_value

            except Exception as cache_err:
                logger.warning(
                    f"[{api_url}] Level 3 值缓存查询异常，"
                    f"回退 LLM：{cache_err}"
                )

            wrapper_code = self._compress_code_loop(
                raw_wrapper,
                self.CODE_MAX_LENGTH // 2,
            )

            processed_callers = [
                self._compress_code_loop(
                    c,
                    self.CODE_MAX_LENGTH // 6,
                )
                for c in caller_codes[:3]
            ]

            callers_str = "\n\n".join(
                [
                    f"--- 业务调用点 {i + 1} ---\n{c}"
                    for i, c in enumerate(
                        processed_callers
                    )
                ]
            )

            full_code = (
                f"[底层发包函数 (Wrapper)]\n"
                f"{wrapper_code}\n\n"
                f"[高层业务调用点 (Callers)]\n"
                f"{callers_str}"
            )

        except Exception as e:
            logger.error(
                f"[-] 构建上下文数据失败：{e}"
            )

            return None

        # --------------------------------------------------------
        # Level 2 参数名线索
        # --------------------------------------------------------

        param_keys_hint = ""

        if param_keys and len(param_keys) > 0:
            param_keys_hint = (
                f"Level 2 检测到的参数名线索："
                f"{param_keys}\n"
                f"（仅供参考，以代码实际内容为准）\n\n"
            )

        # --------------------------------------------------------
        # 参数值策略
        # --------------------------------------------------------

        if self.request_validation:
            value_hint = (
                "参数值要求：禁止使用代码中的真实值，"
                "必须生成同类型但不可能存在的测试值"
                "（如 orderId→999999999, "
                "userId→-1, "
                "phone→10000000000）"
            )
        else:
            value_hint = (
                "参数值要求：从代码中提取真实参数值，"
                "无法确定时根据参数语义给出合理默认值"
            )

        # --------------------------------------------------------
        # Prompt
        # --------------------------------------------------------

        user_prompt = f"""
{param_keys_hint}=== 【前端 JS 代码证据】 ===
{full_code}

目标 API: {api_url}

{value_hint}

请严格按照 Prompt 要求提取请求信息。
"""

        messages = [
            {
                "role": "system",
                "content": SYSTEM_PROMPT_ADVISORY,
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ]

        result = client.chat(
            messages=messages,
            max_tokens=2000,
            temperature=0.2,
        )

        cleaned_content = self._clean_json_response(
            result
        )

        if not cleaned_content:
            return None

        try:
            parsed = json_repair.loads(
                cleaned_content
            )

            if not isinstance(parsed, dict):
                logger.warning(
                    f"[-] AI 返回不是字典："
                    f"{type(parsed)}"
                )

                return None

            parsed["path"] = api_url

            if "dangerous" not in parsed:
                parsed["dangerous"] = False

            if "danger_reason" not in parsed:
                parsed["danger_reason"] = ""

            logger.info(
                f"[VULN-AUDIT] [{api_url}]\n"
                f"  ┌─ context_type "
                f"={self._classify_context_type(context_data)} "
                f"─┐\n"
                f"  └─ context_type END ─┘\n"
                f"  ┌─ wrapper_code "
                f"(len={len(wrapper_code)}) ─┐\n"
                f"{wrapper_code}\n"
                f"  └─ wrapper_code END ─┘\n"
                f"  ┌─ callers "
                f"(数量={len(processed_callers)}) ─┐\n"
                f"{callers_str}\n"
                f"  └─ callers END ─┘\n"
                f"  AI原始返回: {result}\n"
                f"  最终解析: {parsed}"
            )

            # 写回 Level 3 值缓存（path 不缓存，命中时各自回填）
            self._store_value_cache(
                wrapper_norm,
                callers_key,
                tuple(param_keys or ()),
                self.request_validation,
                {
                    key: value
                    for key, value in parsed.items()
                    if key != "path"
                },
            )

            return parsed

        except Exception as e:
            logger.error(
                f"[-] AI JSON 解析失败：{e}"
            )

            return None

    # ============================================================
    # 基础 API Path 黑名单
    # ============================================================

    @staticmethod
    def _is_blacklisted(
        api_path: str,
    ) -> bool:
        return is_api_path_blacklisted(
            api_path
        )

    # ============================================================
    # 操作类型分类
    # ============================================================

    def classify_operation_type(
        self,
        path: str,
        method: str,
        params: str,
    ) -> str:

        if not path:
            return "UNKNOWN"

        user_prompt = (
            f"API Path: {path}\n"
            f"HTTP Method: {method or '未知'}\n"
            f"Params: {params or '无'}"
        )

        try:
            result = client.chat(
                messages=[
                    {
                        "role": "system",
                        "content": SYSTEM_PROMPT_OPERATION_CLASSIFY,
                    },
                    {
                        "role": "user",
                        "content": user_prompt,
                    },
                ],
                require_json=True,
                temperature=0.1,
            )

            if isinstance(result, dict):
                op_type = result.get(
                    "operation",
                    "UNKNOWN",
                ).upper()

                confidence = result.get(
                    "confidence",
                    0.0,
                )

                if op_type in (
                    "READ",
                    "WRITE",
                    "UNKNOWN",
                ):
                    logger.info(
                        f"🏷️ [{path}] "
                        f"操作分类: {op_type} "
                        f"(confidence: {confidence})"
                    )

                    return op_type

                logger.warning(
                    f"⚠️ [{path}] "
                    f"未知操作类型: {op_type}，"
                    f"默认为 UNKNOWN"
                )

        except Exception as e:
            logger.warning(
                f"⚠️ [{path}] "
                f"操作分类失败: {e}"
            )

        return "UNKNOWN"

    # ============================================================
    # 主扫描流程
    # ============================================================

    def scan_multiple_apis(
        self,
        js_code: str,
        api_paths: list,
        target_url: str,
    ) -> Dict[
        str,
        Optional[Dict[str, Any]]
    ]:
        """
        主流程漏斗：

            API 提取
              ↓
            上下文类型过滤
              ↓
            Level 2
              ↓
            Level 3
        """

        results = {}

        # 上下文召回快照（供主流程区分"没上下文"与"AI 失败"）
        self.last_context_found = {}
        self.last_context_types = {}

        # --------------------------------------------------------
        # Step 1：API Path 黑名单
        # --------------------------------------------------------

        api_paths = [
            p
            for p in api_paths
            if not self._is_blacklisted(p)
        ]

        try:
            extract_start = time.time()

            logger.info(
                f"🔬 开始 AST 上下文提取："
                f"JS大小={len(js_code)} 字符, "
                f"目标API={len(api_paths)} 个"
            )

            all_contexts = (
                extract_multiple_apis_from_raw_code(
                    js_code,
                    api_paths,
                )
            )

            logger.info(
                f"🔬 AST 上下文提取完成，"
                f"耗时 {time.time() - extract_start:.1f}s"
            )

        except Exception as e:
            logger.error(
                f"[-] 批量提取上下文数据失败：{e}"
            )

            # Context Recall 异常：主流程据此把 API 标记为 CONTEXT_FAILED，而不是完成
            for api in api_paths:
                self.last_context_found[api] = False

            return {
                api: None
                for api in api_paths
            }

        level_2_candidates = []

        # --------------------------------------------------------
        # Step 2：上下文过滤
        # --------------------------------------------------------

        for api_path, context_data in all_contexts.items():

            self.last_context_found[api_path] = bool(
                context_data
                and context_data.get("found")
            )

            if (
                not context_data
                or not context_data.get("found")
            ):
                continue

            wrapper_code = context_data.get(
                "wrapper_code",
                "",
            )

            caller_codes = context_data.get(
                "caller_codes",
                [],
            )

            if not isinstance(caller_codes, list):
                caller_codes = []

            # ----------------------------------------------------
            # NEW：
            # 对 caller 先做纯导航过滤
            # ----------------------------------------------------

            filtered_callers = (
                self._filter_caller_codes(
                    caller_codes
                )
            )

            context_data["caller_codes"] = (
                filtered_callers
            )

            # ----------------------------------------------------
            # NEW：
            # 判断上下文类型
            # ----------------------------------------------------

            context_type = (
                self._classify_context_type(
                    context_data
                )
            )

            context_data["context_type"] = (
                context_type
            )

            self.last_context_types[api_path] = context_type

            has_wrapper = bool(
                wrapper_code
            )

            has_callers = bool(
                filtered_callers
            )

            has_http_wrapper = (
                self._contains_http_request_signal(
                    wrapper_code
                )
            )

            has_http_caller = any(
                self._contains_http_request_signal(
                    caller
                )
                for caller in filtered_callers
            )

            # ----------------------------------------------------
            # 关键修复：
            #
            # 只过滤明确的前端路由跳转
            # UNKNOWN 类型继续走原来的漏斗（AST + 正则 + AI）
            # ----------------------------------------------------

            if context_type == "FRONTEND_ROUTE":
                results[api_path] = None

                logger.info(
                    f"[{api_path}] 🚫 "
                    f"前端路由跳转上下文，跳过："
                    f"has_wrapper={has_wrapper} "
                    f"has_callers={has_callers}"
                )

                continue

            level_2_candidates.append(
                {
                    "api_path": api_path,
                    "context_data": context_data,
                }
            )

        logger.info(
            f"📋 候选 API: "
            f"{len(level_2_candidates)} / "
            f"{len(all_contexts)}"
        )

        # --------------------------------------------------------
        # Step 3：Level 2
        # --------------------------------------------------------

        if level_2_candidates:
            ai_judgements = (
                self._analyze_multiple_api_values(
                    level_2_candidates
                )
            )

        else:
            ai_judgements = {}

            logger.info(
                "⚠️ 无候选 API，跳过 Level 2"
            )

        # --------------------------------------------------------
        # Step 4：Level 3
        # --------------------------------------------------------

        for candidate in level_2_candidates:
            watchdog.beat("param_l3", candidate["api_path"])   # 每个候选一次进展
            api_path = candidate[
                "api_path"
            ]

            context_data = candidate[
                "context_data"
            ]

            judgement = ai_judgements.get(
                api_path
            )

            # ----------------------------------------------------
            # Level 2 没结果
            # ----------------------------------------------------

            if not judgement:
                logger.warning(
                    f"⚠️ [{api_path}] "
                    f"Level 2 无结果，跳过"
                )

                results[api_path] = None
                continue

            # ----------------------------------------------------
            # Level 2 判断无参数
            # ----------------------------------------------------

            if judgement.get(
                "decision",
                1,
            ) == 0:

                logger.info(
                    f"[{api_path}] "
                    f"AI确认无参数，记录空结果"
                )

                results[api_path] = {
                    "path": api_path,
                    "method": "",
                    "params": "",
                }
                continue

            logger.info(
                f"✅ [{api_path}] "
                f"进入 Level 3"
            )

            context_data[
                "target_host"
            ] = target_url

            context_data[
                "api_url"
            ] = api_path

            # ----------------------------------------------------
            # Level 2 参数名
            # ----------------------------------------------------

            param_keys = judgement.get(
                "param_keys",
                [],
            )

            analysis_result = self.analyze(
                context_data=context_data,
                param_keys=param_keys,
            )

            results[api_path] = (
                analysis_result
            )

        # --------------------------------------------------------
        # Step 5：统计
        # --------------------------------------------------------

        total = len(results)

        success = sum(
            1
            for r in results.values()
            if r is not None
        )

        logger.info(
            f"📈 扫描完成："
            f"{success} / {total} API 有数据"
        )

        return results