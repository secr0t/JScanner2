import json
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import httpx

from config.scanner_rules import (
    REQUEST_HEADERS,
    REQUEST_TIMEOUT,
    CONTENT_SUMMARY_MAX_LENGTH,
    SUPPORTED_REQUEST_METHODS,
    DEFAULT_REQUEST_METHOD,
    BUSINESS_AUTH_DENIED_CODES,
    BUSINESS_AUTH_DENIED_MESSAGES,
    JSON_CODE_FIELDS,
    JSON_MESSAGE_FIELDS,
    JSON_DATA_FIELDS,
    MAX_RETRY_PER_API,
    METHOD_SWITCH_MAP,
    is_api_path_blacklisted
)
from logger import get_logger

logger = get_logger(__name__)


def _strip_html_tags(text: str) -> str:
    """
    去除文本中的所有 HTML 标签

    Args:
        text: 包含 HTML 标签的文本

    Returns:
        去除 HTML 标签后的纯文本
    """
    if not text:
        return ""

    clean_text = re.sub(r'<[^>]+>', '', text)
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()

    return clean_text


def _parse_params_string(params_str: str) -> Dict[str, Any]:
    """
    解析参数字符串为字典

    支持格式：
    - "key1=value1,key2=value2"
    - "key1=value1&key2=value2"
    - JSON 字符串（兼容）

    Args:
        params_str: 参数字符串

    Returns:
        解析后的参数字典
    """
    if not params_str or not isinstance(params_str, str):
        return {}

    params_str = params_str.strip()
    if not params_str:
        return {}

    if params_str.startswith('{'):
        try:
            parsed = json.loads(params_str)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    params = {}
    separator = ',' if ',' in params_str else '&'

    for item in params_str.split(separator):
        item = item.strip()
        if not item:
            continue

        if '=' in item:
            key, value = item.split('=', 1)
            params[key.strip()] = value.strip()
        else:
            params[item] = ""

    return params


def _normalize_method(method: str) -> str:
    """
    标准化 HTTP 方法

    Args:
        method: 原始方法字符串

    Returns:
        标准化的方法（GET/POST/PUT），无效方法降级为 GET
    """
    if not method or not isinstance(method, str):
        return DEFAULT_REQUEST_METHOD

    method_upper = method.upper().strip()

    if method_upper in SUPPORTED_REQUEST_METHODS:
        return method_upper

    logger.debug(f"⚠️ [Request] 不支持的方法 '{method}'，降级为 GET")
    return DEFAULT_REQUEST_METHOD


def _parse_response_body(response: httpx.Response) -> Dict[str, Any]:
    """
    智能解析响应体，提取结构化判断字段

    - JSON 响应：解析 code/message/data 字段，body_summary 仍走 HTML 清理
    - HTML 响应：剥除 HTML 标签后截取摘要
    - 其他：直接截取原文

    Returns:
        {
            "content_type": str,
            "body_summary": str,
            "json_code": Any,
            "json_message": str,
            "has_data": bool,
            "is_business_denied": bool,
        }
    """
    result = {
        "content_type": "unknown",
        "body_summary": "",
        "json_code": None,
        "json_message": "",
        "has_data": False,
        "is_business_denied": False,
    }

    response_text = response.text
    if not response_text or not response_text.strip():
        result["content_type"] = "empty"
        result["body_summary"] = ""
        return result

    content_type_header = response.headers.get("content-type", "").lower()
    stripped = response_text.strip()

    if "json" in content_type_header or stripped.startswith("{") or stripped.startswith("["):
        result["content_type"] = "json"
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                for field in JSON_CODE_FIELDS:
                    if field in data:
                        result["json_code"] = data[field]
                        break

                for field in JSON_MESSAGE_FIELDS:
                    if field in data:
                        result["json_message"] = str(data[field])[:200]
                        break

                for field in JSON_DATA_FIELDS:
                    if field in data and data[field] not in (None, "", [], {}, 0):
                        result["has_data"] = True
                        break

                if result["json_code"] in BUSINESS_AUTH_DENIED_CODES:
                    result["is_business_denied"] = True
                elif result["json_message"]:
                    msg_lower = result["json_message"].lower()
                    if any(kw in msg_lower for kw in BUSINESS_AUTH_DENIED_MESSAGES):
                        result["is_business_denied"] = True

        except (json.JSONDecodeError, TypeError):
            pass

    elif "html" in content_type_header or stripped.startswith("<"):
        result["content_type"] = "html"
        summary_lower = _strip_html_tags(response_text)[:CONTENT_SUMMARY_MAX_LENGTH].lower()
        if any(kw in summary_lower for kw in BUSINESS_AUTH_DENIED_MESSAGES):
            result["is_business_denied"] = True

    else:
        result["content_type"] = "text"

    result["body_summary"] = _strip_html_tags(response_text)[:CONTENT_SUMMARY_MAX_LENGTH]

    return result


# ==================== 底层 HTTP 请求 ====================

def _send_http_request(full_url: str, method: str, params_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    发送单次原始 HTTP 请求并解析响应

    Returns:
        {
            "status_code": int,
            "content_type": str,
            "content_summary": str,
            "json_code": Any,
            "json_message": str,
            "has_data": bool,
            "is_business_denied": bool,
        }
    """
    result = {
        "status_code": -1,
        "content_type": "unknown",
        "content_summary": "",
        "json_code": None,
        "json_message": "",
        "has_data": False,
        "is_business_denied": False,
    }

    try:
        headers = REQUEST_HEADERS.copy()

        with httpx.Client(timeout=REQUEST_TIMEOUT, follow_redirects=False) as client:
            if method == "POST":
                response = client.post(full_url, headers=headers, json=params_dict if params_dict else None)
            elif method == "PUT":
                response = client.put(full_url, headers=headers, json=params_dict if params_dict else None)
            else:
                response = client.get(full_url, headers=headers, params=params_dict if params_dict else None)

        parsed = _parse_response_body(response)
        result["status_code"] = response.status_code
        result.update(parsed)

        logger.info(f"📡 [Raw] {method} {full_url} → {result['status_code']}")

    except httpx.TimeoutException:
        result["content_summary"] = "Request Failed: timeout"
        logger.warning(f"⏱️ [Raw] 超时: {full_url}")

    except httpx.NetworkError as e:
        result["content_summary"] = "Request Failed: connection error"
        logger.warning(f"🌐 [Raw] 网络错误: {full_url} | {e}")

    except Exception as e:
        result["content_summary"] = f"Request Failed: {str(e)[:100]}"
        logger.error(f"❌ [Raw] 未知错误: {full_url} | {e}")

    return result


# ==================== AI 响应分析 ====================

def _ai_analyze_response(full_url: str, method: str, params_dict: dict,
                         status_code: int, content_summary: str) -> Dict[str, Any]:
    """
    调用 AI 分析 API 响应（第二层）

    Returns:
        {
            "verdict": str,
            "next_action": str,
            "retry_hint": dict | None
        }
    """
    from infra.ai_client import client
    from processor.analysis.prompts import SYSTEM_PROMPT_RESPONSE_ANALYSIS

    user_prompt = (
        f"API: {full_url}\n"
        f"Method: {method}\n"
        f"Params: {json.dumps(params_dict, ensure_ascii=False) if params_dict else 'none'}\n"
        f"Status Code: {status_code}\n"
        f"Response Body:\n{content_summary}"
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT_RESPONSE_ANALYSIS},
        {"role": "user", "content": user_prompt}
    ]

    try:
        result = client.chat(messages=messages, require_json=True, max_tokens=500)

        if isinstance(result, dict):
            verdict = result.get("verdict", "unknown")
            next_action = result.get("next_action", "done")
            retry_hint = result.get("retry_hint")

            if next_action == "retry" and not retry_hint:
                next_action = "done"

            return {
                "verdict": verdict,
                "next_action": next_action,
                "retry_hint": retry_hint,
            }

    except Exception as e:
        logger.error(f"❌ [AI Analysis] AI 分析失败: {full_url} | {e}")

    return {"verdict": "unknown", "next_action": "done", "retry_hint": None}


# ==================== 结果构建 ====================

def _build_result(status_code=-1, verdict="unknown", action="", content_type="unknown",
                  content_summary="", json_code=None, json_message="",
                  has_data=False, is_business_denied=False,
                  retry_count=0, all_responses=None) -> Dict[str, Any]:
    """构建统一的返回结果字典"""
    return {
        "status_code": status_code,
        "verdict": verdict,
        "action": action,
        "content_type": content_type,
        "content_summary": content_summary,
        "json_code": json_code,
        "json_message": json_message,
        "has_data": has_data,
        "is_business_denied": is_business_denied,
        "retry_count": retry_count,
        "all_responses": all_responses or [],
    }


# ==================== 危险 API 请求拦截 ====================

def _is_dangerous_write_url(full_url: str) -> bool:
    """
    检查 URL 路径是否匹配黑名单正则（子串匹配）

    Args:
        full_url: 完整 URL

    Returns:
        True 表示该 URL 匹配黑名单，应拦截请求
    """
    if not full_url:
        return False
    try:
        path = urlparse(full_url).path.lower()
    except Exception:
        return False

    return is_api_path_blacklisted(path)


# ==================== 三层漏斗主入口 ====================

def execute_api_request(
        full_url: str,
        method: str,
        params_json: Optional[str] = None
) -> Dict[str, Any]:
    """
    执行 API 请求，经过三层漏斗判定

    三层漏斗：
      Layer 1   - 状态码机械初筛（401/403/404/405/500+/超时/网络错误）
      Layer 1.5 - 关键词过滤（仅 2xx，检测假 200）
      Layer 2   - AI 深度分析（2xx 通过关键词过滤 + 500+）

    Args:
        full_url: 完整的 API URL
        method: HTTP 方法（GET/POST/PUT，其他方法会降级为 GET）
        params_json: 参数串（格式为 "key=value,key2=value2" 或 JSON）

    Returns:
        {
            "status_code": int,
            "verdict": str,
            "action": str,
            "content_type": str,
            "content_summary": str,
            "json_code": Any,
            "json_message": str,
            "has_data": bool,
            "is_business_denied": bool,
            "retry_count": int,
            "all_responses": list,
        }
    """
    retry_count = 0
    current_method = method
    current_params_json = params_json
    method_switched = False
    all_responses = []

    params_dict = {}
    if params_json:
        try:
            params_dict = _parse_params_string(params_json)
        except Exception as e:
            logger.warning(f"⚠️ [Funnel] 参数解析失败: {full_url} | Error: {e}")
            return _build_result(
                status_code=-2, verdict="failed", action=current_method,
                content_summary=f"Params Parse Exception: {str(e)}"
            )

    while True:
        normalized_method = _normalize_method(current_method)

        # ===== 发送请求 =====
        raw_result = _send_http_request(full_url, normalized_method, params_dict)
        all_responses.append({
            "method": normalized_method,
            "status_code": raw_result["status_code"],
            "content_summary": raw_result["content_summary"][:200],
        })

        status_code = raw_result["status_code"]
        current_result = raw_result

        # ===== Layer 1: 状态码机械初筛 =====
        if status_code in (401, 403):
            return _build_result(**current_result, verdict="auth_denied",
                                 action=normalized_method, retry_count=retry_count, all_responses=all_responses)

        if status_code == -1 or status_code == -2:
            return _build_result(**current_result, verdict="failed",
                                 action=normalized_method, retry_count=retry_count, all_responses=all_responses)

        if status_code == 404:
            return _build_result(**current_result, verdict="not_found",
                                 action=normalized_method, retry_count=retry_count, all_responses=all_responses)

        # 405: 方法切换（只允许一次）
        if status_code == 405:
            if not method_switched and normalized_method in METHOD_SWITCH_MAP:
                current_method = METHOD_SWITCH_MAP[normalized_method]
                method_switched = True
                retry_count += 1
                if retry_count > MAX_RETRY_PER_API:
                    return _build_result(**current_result, verdict="needs_human_review",
                                         action=normalized_method, retry_count=retry_count, all_responses=all_responses)
                logger.info(f"🔄 [Funnel] 405 → 切换 {normalized_method} → {current_method}，重试 {retry_count}/{MAX_RETRY_PER_API}")
                continue
            else:
                return _build_result(**current_result, verdict="method_not_allowed",
                                     action=normalized_method, retry_count=retry_count, all_responses=all_responses)

        # ===== Layer 1.5: 关键词过滤（仅 2xx）=====
        if 200 <= status_code < 300:
            if current_result.get("is_business_denied"):
                return _build_result(**current_result, verdict="auth_denied",
                                     action=normalized_method, retry_count=retry_count, all_responses=all_responses)
            # 通过 1.5 层，进入 Layer 2

        # ===== Layer 2: AI 深度分析（2xx 通过关键词过滤 + 500+）=====
        if (200 <= status_code < 300) or (500 <= status_code < 600):
            ai_result = _ai_analyze_response(
                full_url, normalized_method, params_dict,
                status_code, current_result["content_summary"]
            )

            verdict = ai_result["verdict"]
            next_action = ai_result["next_action"]
            retry_hint = ai_result.get("retry_hint")

            # AI 建议重试
            if next_action == "retry" and retry_hint:
                retry_count += 1
                if retry_count <= MAX_RETRY_PER_API:
                    if "method" in retry_hint and retry_hint["method"]:
                        current_method = retry_hint["method"]
                    if "params" in retry_hint and retry_hint["params"]:
                        params_dict = retry_hint["params"]
                    logger.info(f"🔄 [Funnel] AI retry {retry_count}/{MAX_RETRY_PER_API} | "
                                f"method={current_method} | {full_url}")
                    continue
                else:
                    logger.warning(f"🛑 [Funnel] 达到最大重试次数({MAX_RETRY_PER_API})，强制停止 | {full_url}")
                    return _build_result(**current_result, verdict="needs_human_review",
                                         action=normalized_method, retry_count=retry_count, all_responses=all_responses)

            # AI 给出最终判定
            return _build_result(**current_result, verdict=verdict,
                                 action=normalized_method, retry_count=retry_count, all_responses=all_responses)

        # ===== 兜底：其他状态码（3xx 等）=====
        return _build_result(**current_result, verdict="unknown",
                             action=normalized_method, retry_count=retry_count, all_responses=all_responses)


# ==================== 批量执行 ====================

async def batch_execute_requests(
        vuln_records: list
) -> list:
    """
    批量执行请求（异步版本，提高并发效率）

    Args:
        vuln_records: AI 漏洞记录列表，每个记录包含:
            - id: 数据库记录 ID
            - full_url: 完整 URL
            - http_method: HTTP 方法
            - params: JSON 格式的参数

    Returns:
        结果列表，每个元素包含:
            - id: 记录 ID
            - status_code: 状态码
            - verdict: 判定结果
            - content_summary: 内容摘要
    """
    import asyncio

    safe_records = [r for r in vuln_records if r.get("id")]

    final_results = []
    exec_records = []
    for record in safe_records:
        if _is_dangerous_write_url(record.get("full_url", "")):
            logger.warning(f"🛑 [Batch Request] 命中黑名单，拦截请求: {record.get('full_url')}")
            final_results.append({
                "id": record["id"],
                "status_code": -3,
                "verdict": "blocked_by_blacklist",
                "content_summary": "Blocked: URL matched dangerous blacklist"
            })
        else:
            exec_records.append(record)

    if not exec_records:
        return final_results

    async def single_request(record: Dict[str, Any]) -> Dict[str, Any]:
        """单个请求的异步包装"""
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            execute_api_request,
            record["full_url"],
            record["http_method"],
            record.get("params")
        )
        result["id"] = record["id"]
        return result

    tasks = [single_request(record) for record in exec_records]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"❌ [Batch Request] 任务 {i} 执行失败: {result}")
            final_results.append({
                "id": exec_records[i]["id"],
                "status_code": -1,
                "verdict": "failed",
                "content_summary": f"Request Failed: {str(result)[:100]}"
            })
        else:
            final_results.append(result)

    return final_results
