# -*- coding: utf-8 -*-
"""
Agent 调用层的数据结构定义。

ScanOptions  ——  Agent 发起扫描时传入的参数（与 CLI argparse 解耦）
TaskInfo     ——  任务运行状态与进度快照
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# 任务状态枚举
# ---------------------------------------------------------------------------

class TaskStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


# ---------------------------------------------------------------------------
# 扫描参数
# ---------------------------------------------------------------------------

@dataclass
class ScanOptions:
    """
    Agent 发起扫描所需的全部参数。

    字段名与 CLI argparse 保持语义一致，但不依赖 argparse.Namespace，
    因此 Service 层可以在没有命令行的环境（MCP / HTTP）中使用。
    """

    url: str = ""
    height: int = 2
    thread_num: int = 10
    findparam: bool = True          # 默认开启 API 参数解析（对齐 run_scan.sh 的 BASE_PYTHON_ARGS）
    fastscan: bool = True           # 快速扫描模式
    analyze_sensitive_info_ai: bool = False   # AI 敏感信息分析（省 token，默认关）
    analyze_sensitive_info_rex: bool = False  # 正则敏感信息分析
    request_validation: bool = False           # 请求验证
    proxy: Optional[str] = None
    visible: bool = False                      # 浏览器可见模式
    use_shared_db: bool = False                # True=使用全局共享 DB（保留跨次去重）

    # ------------------------------------------------------------------
    # 转换为 Scanner 所需的 argparse.Namespace
    # ------------------------------------------------------------------

    def to_namespace(self):
        """
        构造一个与 parse_args() 返回值兼容的 Namespace 对象。

        Scanner.__init__ / Scanner.run 访问的 args 属性：
        url, height, thread_num, proxy, visible,
        findparam, fastscan, analyzeSensitiveInfoAI, analyzeSensitiveInfoRex,
        request_validation, no_request, initial_urls
        """
        from argparse import Namespace

        return Namespace(
            url=self.url,
            height=self.height,
            thread_num=self.thread_num,
            proxy=self.proxy,
            visible=self.visible,
            findparam=self.findparam,
            fastscan=self.fastscan,
            analyzeSensitiveInfoAI=self.analyze_sensitive_info_ai,
            analyzeSensitiveInfoRex=self.analyze_sensitive_info_rex,
            request_validation=self.request_validation,
            no_request=not self.request_validation,   # 语义取反
            initial_urls=[],                           # run() 中会覆盖
        )


# ---------------------------------------------------------------------------
# 任务信息
# ---------------------------------------------------------------------------

@dataclass
class TaskInfo:
    """单个扫描任务的全量状态快照。"""

    task_id: str
    url: str
    options: ScanOptions
    status: TaskStatus = TaskStatus.QUEUED

    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None

    # 进度
    phase: str = ""                # startup / crawling / ai_analysis / sensitive / finished
    depth: int = 0
    current_batch: int = 0
    total_batches: int = 0

    # 统计快照（从 DB 查询）
    urls_found: int = 0
    apis_found: int = 0
    apis_analyzed: int = 0
    vulns_count: int = 0
    sensitive_count: int = 0
    sourcemap_count: int = 0
    high_risk_vulns: int = 0
    high_risk_sensitive: int = 0

    error: Optional[str] = None
    result_db_path: Optional[str] = None

    # 内部：asyncio.Task 引用（不序列化）
    _asyncio_task: Optional[Any] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        """转为可 JSON 序列化的字典（排除内部字段）。"""
        elapsed = None
        if self.started_at:
            end = self.finished_at if self.finished_at else time.time()
            elapsed = round(end - self.started_at, 2)

        return {
            "task_id": self.task_id,
            "url": self.url,
            "options": {
                "height": self.options.height,
                "thread_num": self.options.thread_num,
                "findparam": self.options.findparam,
                "fastscan": self.options.fastscan,
                "analyze_sensitive_info_ai": self.options.analyze_sensitive_info_ai,
                "analyze_sensitive_info_rex": self.options.analyze_sensitive_info_rex,
                "request_validation": self.options.request_validation,
                "proxy": self.options.proxy,
                "use_shared_db": self.options.use_shared_db,
            },
            "status": self.status.value,
            "phase": self.phase,
            "depth": self.depth,
            "current_batch": self.current_batch,
            "total_batches": self.total_batches,
            "progress": {
                "urls_found": self.urls_found,
                "apis_found": self.apis_found,
                "apis_analyzed": self.apis_analyzed,
                "vulns_count": self.vulns_count,
                "sensitive_count": self.sensitive_count,
                "sourcemap_count": self.sourcemap_count,
                "high_risk_vulns": self.high_risk_vulns,
                "high_risk_sensitive": self.high_risk_sensitive,
            },
            "error": self.error,
            "result_db_path": self.result_db_path,
            "elapsed_seconds": elapsed,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


def new_task_id() -> str:
    """生成短任务 ID（8 位 hex）。"""
    return uuid.uuid4().hex[:8]
