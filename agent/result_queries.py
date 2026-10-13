# -*- coding: utf-8 -*-
"""
结果查询封装层。

直接复用 SQLiteStorage 的查询方法，按 task_id 定位任务级数据库，
为 MCP / HTTP 接口提供结构化结果拉取能力。
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from .schemas import TaskInfo, TaskStatus


# 任务级数据库的默认存放目录
_TASKS_DB_DIR = "Result/tasks"


def _get_db_path(task: TaskInfo) -> Optional[str]:
    """获取任务对应的 SQLite 数据库路径。"""
    if task.result_db_path:
        return task.result_db_path
    # 回退推导
    return os.path.join(_TASKS_DB_DIR, task.task_id, "result.db")


def _open_db(db_path: str):
    """
    打开只读 DB 连接。

    复用项目的 SQLiteStorage，但以只读模式打开（不触发迁移/建表）。
    """
    from storage.db import SQLiteStorage

    if not os.path.exists(db_path):
        return None
    # SQLiteStorage.__init__ 会执行 _init_db（建表 + 迁移）。
    # 对已存在的库，IF NOT EXISTS / 空迁移是安全的幂等操作。
    return SQLiteStorage(db_path)


def _try_query(task: TaskInfo, query_fn) -> Any:
    """安全执行查询：DB 不存在或查询异常时返回空结果。"""
    db_path = _get_db_path(task)
    if not db_path:
        return _empty_result()

    try:
        db = _open_db(db_path)
        if db is None:
            return _empty_result()
        try:
            return query_fn(db)
        finally:
            db.close()
    except Exception as e:
        return {"error": str(e), **_empty_result()}


def _empty_result() -> Dict[str, Any]:
    return {"total": 0, "items": []}


# ---------------------------------------------------------------------------
# 公开查询接口
# ---------------------------------------------------------------------------

def get_apis(task: TaskInfo, page: int = 1, page_size: int = 20,
             status_filter: Optional[str] = None) -> Dict[str, Any]:
    """
    拉取任务发现的 API 列表（从 api_analysis_state 表）。

    Args:
        task: 任务信息
        page: 页码（1-based）
        page_size: 每页条数
        status_filter: 按状态过滤（DISCOVERED / AI_DONE / VALIDATED 等）
    """
    def _query(db):
        states = db.get_api_states(statuses=[status_filter] if status_filter else None)
        total = len(states)
        start = (page - 1) * page_size
        end = start + page_size
        items = states[start:end]
        return {"total": total, "page": page, "page_size": page_size, "items": items}

    return _try_query(task, _query)


def get_vulnerabilities(task: TaskInfo, risk_level: Optional[str] = None,
                        limit: int = 50) -> Dict[str, Any]:
    """
    拉取漏洞/未授权访问结果（从 ai_vulns 表）。

    Args:
        task: 任务信息
        risk_level: 风险等级过滤（High / Med / Low / Info）
        limit: 最多返回条数
    """
    def _query(db):
        vulns = db.get_all_vulns(risk_filter=risk_level)
        total = len(vulns)
        items = vulns[:limit]
        return {"total": total, "limit": limit, "items": items}

    return _try_query(task, _query)


def get_sensitive_info(task: TaskInfo, risk_level: Optional[str] = None,
                       limit: int = 50) -> Dict[str, Any]:
    """
    拉取敏感信息命中（从 sensitive_info 表）。

    Args:
        task: 任务信息
        risk_level: 风险等级过滤（High / Med / Low）
        limit: 最多返回条数
    """
    def _query(db):
        if risk_level:
            items = db.get_sensitive_by_risk(risk_level)
        else:
            items = db.get_all_sensitive()
        total = len(items)
        items = items[:limit]
        return {"total": total, "limit": limit, "items": items}

    return _try_query(task, _query)


def get_sourcemaps(task: TaskInfo) -> Dict[str, Any]:
    """拉取 SourceMap 暴露结果。"""
    def _query(db):
        items = db.get_source_map_results()
        return {"total": len(items), "items": items}

    return _try_query(task, _query)


def get_task_stats(task: TaskInfo) -> Dict[str, Any]:
    """拉取任务的全量统计摘要。"""
    def _query(db):
        stats = db.get_stats()
        # 简化嵌套结构
        return {
            "ai_vulns_total": stats.get("ai_vulns", {}).get("total", 0),
            "ai_vulns_by_risk": stats.get("ai_vulns", {}).get("by_risk", {}),
            "sensitive_total": stats.get("sensitive_info", {}).get("total", 0),
            "sensitive_by_risk": stats.get("sensitive_info", {}).get("by_risk", {}),
            "sensitive_by_type": stats.get("sensitive_info", {}).get("by_type", {}),
            "urls_scanned": stats.get("scan_results", {}).get("total_urls", 0),
            "api_analysis_by_status": stats.get("api_analysis_state", {}).get("by_status", {}),
        }

    return _try_query(task, _query)


def refresh_task_progress(task: TaskInfo) -> None:
    """
    从 DB 查询最新统计，更新 TaskInfo 的进度字段。

    在 TaskManager 轮询进度时调用。
    """
    db_path = _get_db_path(task)
    if not db_path or not os.path.exists(db_path):
        return

    try:
        db = _open_db(db_path)
        if db is None:
            return
        try:
            stats = db.get_stats()

            task.urls_found = stats.get("scan_results", {}).get("total_urls", 0)
            task.vulns_count = stats.get("ai_vulns", {}).get("total", 0)
            task.sensitive_count = stats.get("sensitive_info", {}).get("total", 0)

            vuln_by_risk = stats.get("ai_vulns", {}).get("by_risk", {})
            task.high_risk_vulns = vuln_by_risk.get("High", 0)

            sensitive_by_risk = stats.get("sensitive_info", {}).get("by_risk", {})
            task.high_risk_sensitive = sensitive_by_risk.get("High", 0)

            api_state = stats.get("api_analysis_state", {}).get("by_status", {})
            task.apis_found = sum(api_state.values())
            # 已完成 = VALIDATED
            task.apis_analyzed = api_state.get("VALIDATED", 0)

            # SourceMap
            sm_results = db.get_source_map_results()
            task.sourcemap_count = sum(1 for r in sm_results if r.get("is_sourceMap") == "Y")

        finally:
            db.close()
    except Exception:
        pass  # 进度查询失败不中断主流程
