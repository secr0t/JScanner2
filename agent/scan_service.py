# -*- coding: utf-8 -*-
"""
扫描服务层。

把 JScanner2 的 Scanner 引擎封装为可被 Agent 异步调用的 async 函数。
不修改 Scanner / main.py 任何现有代码，仅做实例化 + 调用 + 资源清理。
"""

from __future__ import annotations

import asyncio
import atexit
import os
import time
from typing import Optional

from .schemas import ScanOptions, TaskInfo, TaskStatus
from . import result_queries

# 任务级数据库的默认存放目录
_TASKS_DB_DIR = "Result/tasks"

# 全局共享数据库路径（与 CLI 一致）
_SHARED_DB_PATH = "Result/JScanner_Result.db"


def _resolve_db_path(task_id: str, use_shared_db: bool) -> str:
    """决定本次扫描使用哪个数据库文件。"""
    if use_shared_db:
        return _SHARED_DB_PATH
    return os.path.join(_TASKS_DB_DIR, task_id, "result.db")


async def run_scan_async(task: TaskInfo) -> TaskInfo:
    """
    执行单个扫描任务。

    在当前事件循环中运行 Scanner.run()，任务取消时传播 CancelledError
    并确保资源清理。

    Args:
        task: 已初始化的 TaskInfo（status 会被更新）

    Returns:
        更新后的 TaskInfo
    """
    from main import Scanner
    from storage.db import SQLiteStorage

    options = task.options
    db_path = _resolve_db_path(task.task_id, options.use_shared_db)
    task.result_db_path = db_path

    # 确保目录存在
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

    # 构造与 CLI 完全兼容的 Namespace
    args = options.to_namespace()

    db_handler = SQLiteStorage(db_path)
    scanner = Scanner(args, db_handler)

    task.status = TaskStatus.RUNNING
    task.started_at = time.time()

    try:
        await scanner.run()

        # 扫描完成，刷新进度
        result_queries.refresh_task_progress(task)
        task.status = TaskStatus.SUCCEEDED
        task.phase = "finished"

    except asyncio.CancelledError:
        task.status = TaskStatus.CANCELLED
        task.phase = "cancelled"
        raise

    except Exception as e:
        task.status = TaskStatus.FAILED
        task.phase = "error"
        task.error = str(e)
        import traceback
        traceback.print_exc()

    finally:
        task.finished_at = time.time()
        # 确保资源清理（Scanner.__init__ 注册了 atexit，但进程不退出时不会触发）
        try:
            scanner._cleanup_resources()
            # 反注册 atexit 处理器，避免长驻服务中 atexit 列表无限增长
            atexit.unregister(scanner._cleanup_resources)
        except Exception:
            pass

    return task


def stop_scan(task: TaskInfo) -> bool:
    """
    通过取消 asyncio.Task 来停止扫描。

    返回 True 表示已发送取消信号。
    实际取消会在下一个 await 点生效。
    """
    if task._asyncio_task is None:
        return False

    if task.status in (TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.CANCELLED):
        return False

    task._asyncio_task.cancel()
    return True
