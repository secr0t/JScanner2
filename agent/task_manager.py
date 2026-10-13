# -*- coding: utf-8 -*-
"""
任务管理器。

负责：
1. 创建并跟踪扫描任务
2. 有界并发控制（默认并发 1，可通过环境变量配置）
3. 进度轮询（后台定时从 DB 刷新进度到 TaskInfo）
4. 任务取消
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List, Optional

from . import result_queries, scan_service
from .schemas import ScanOptions, TaskInfo, TaskStatus, new_task_id

# 最大并发扫描数（Chromium 资源重，默认 1）
_MAX_CONCURRENCY = int(os.environ.get("JSCANNER_CONCURRENCY", "1"))

# 进度刷新间隔（秒）
_PROGRESS_REFRESH_INTERVAL = 5.0


class TaskManager:
    """全局任务管理器单例。"""

    def __init__(self, max_concurrency: int = _MAX_CONCURRENCY):
        self._tasks: Dict[str, TaskInfo] = {}
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._max_concurrency = max_concurrency
        self._lock = asyncio.Lock()
        self._progress_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # 任务生命周期
    # ------------------------------------------------------------------

    async def start_task(self, options: ScanOptions) -> TaskInfo:
        """
        创建扫描任务并立即返回。

        任务进入队列后异步执行，不等扫描完成。
        """
        task_id = new_task_id()
        task = TaskInfo(
            task_id=task_id,
            url=options.url,
            options=options,
            status=TaskStatus.QUEUED,
            phase="queued",
        )

        async with self._lock:
            self._tasks[task_id] = task

        # 创建 asyncio 后台任务
        task._asyncio_task = asyncio.create_task(self._run_task(task))

        # 启动进度刷新器（首次创建任务时启动）
        self._ensure_progress_refresher()

        return task

    async def _run_task(self, task: TaskInfo) -> None:
        """实际执行扫描任务（受信号量限制）。"""
        async with self._semaphore:
            try:
                await scan_service.run_scan_async(task)
            except asyncio.CancelledError:
                task.status = TaskStatus.CANCELLED
            except Exception as e:
                task.status = TaskStatus.FAILED
                task.error = str(e)

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------

    async def get_task(self, task_id: str) -> Optional[TaskInfo]:
        """查询单个任务状态。"""
        task = self._tasks.get(task_id)
        if task is None:
            return None

        # 刷新进度
        result_queries.refresh_task_progress(task)
        return task

    async def list_tasks(self, status_filter: Optional[str] = None,
                         limit: int = 20) -> List[TaskInfo]:
        """列出任务（按创建时间倒序）。"""
        tasks = list(self._tasks.values())
        # 按创建时间倒序
        tasks.sort(key=lambda t: t.created_at, reverse=True)

        if status_filter:
            tasks = [t for t in tasks if t.status.value == status_filter]

        return tasks[:limit]

    # ------------------------------------------------------------------
    # 控制
    # ------------------------------------------------------------------

    async def stop_task(self, task_id: str) -> bool:
        """停止任务。返回 True 表示已发送取消信号。"""
        task = self._tasks.get(task_id)
        if task is None:
            return False
        return scan_service.stop_scan(task)

    # ------------------------------------------------------------------
    # 进度刷新
    # ------------------------------------------------------------------

    def _ensure_progress_refresher(self):
        """启动后台进度刷新协程（只启动一次）。"""
        if self._progress_task is not None and not self._progress_task.done():
            return

        self._progress_task = asyncio.create_task(self._refresh_loop())

    async def _refresh_loop(self):
        """后台定时刷新所有运行中任务的进度。"""
        while True:
            await asyncio.sleep(_PROGRESS_REFRESH_INTERVAL)
            for task in self._tasks.values():
                if task.status == TaskStatus.RUNNING:
                    result_queries.refresh_task_progress(task)
