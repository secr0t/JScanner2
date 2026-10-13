# -*- coding: utf-8 -*-
"""JScanner2 MCP server（stdio transport，零依赖）。

面向其他 Agent 的标准接入点：任何支持 MCP 协议的客户端（Claude Code、
Cline、自定义红队 agent 等）都能通过 tools/list / tools/call 调用 JScanner2，
不用拼命令行、不用解析控制台日志。

实现说明：
* 纯 stdio + JSON-RPC 2.0，newline-delimited —— 不引入 mcp SDK，零运行时依赖；
* 只实现本服务需要的四个方法：initialize / tools/list / tools/call / ping，
  其余方法（resources / prompts / notifications）安全忽略；
* 日志一律走 stderr，stdout 只承载协议帧，避免污染 JSON-RPC 流；
* 扫描是长任务：每个任务一个后台 daemon 线程（线程内跑 asyncio 事件循环），
  start_scan 立即返回 task_id，由 get_task 轮询进度，stop_task 取消。

启动：
    python -m agent.mcp_server

客户端配置示例（.trae/mcp.json 或任意 MCP 客户端）：
    "mcpServers": {
      "jscanner2": { "command": "<python>", "args": ["-m", "agent.mcp_server"], "cwd": "<项目根目录>" }
    }
"""

from __future__ import annotations

import json
import sys
import threading
from typing import Any, Dict, List, Optional

# 绝对导入：以 `python -m agent.mcp_server` 从项目根目录运行时，agent 是顶层包
from agent.schemas import ScanOptions, TaskInfo, TaskStatus, new_task_id
from agent import result_queries

# MCP 协议版本：取最广泛兼容的 2024-11-05
PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "jscanner2-mcp", "version": "2.0.0"}

_MAX_CONCURRENCY = 1  # Chromium 资源重，默认并发 1（任务在后台排队串行）

# ---------------------------------------------------------------- 任务存储
_tasks: Dict[str, TaskInfo] = {}
_tasks_lock = threading.Lock()
_worker_slots = threading.BoundedSemaphore(_MAX_CONCURRENCY)


def _run_task_in_thread(task: TaskInfo) -> None:
    """后台线程：在线程内跑一个独立事件循环执行扫描任务。"""
    import asyncio

    from agent.scan_service import run_scan_async

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        future = asyncio.ensure_future(run_scan_async(task), loop=loop)
        task._loop = loop  # 供 stop_task 跨线程取消
        loop.run_until_complete(future)
    except asyncio.CancelledError:
        task.status = TaskStatus.CANCELLED
        task.phase = "cancelled"
    except Exception as exc:  # 兜底：确保任务不悬挂
        task.status = TaskStatus.FAILED
        task.phase = "error"
        task.error = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            loop.close()
        except Exception:
            pass
        _worker_slots.release()


def _spawn_scan(task: TaskInfo) -> None:
    """有界并发：排队等待信号量后启动后台线程。"""
    _worker_slots.acquire()
    t = threading.Thread(target=_run_task_in_thread, args=(task,), daemon=True, name=f"scan-{task.task_id}")
    t.start()


def _get_task(task_id: str) -> Optional[TaskInfo]:
    with _tasks_lock:
        task = _tasks.get(task_id)
    if task is not None:
        result_queries.refresh_task_progress(task)
    return task


def _task_summary(task: TaskInfo) -> Dict[str, Any]:
    d = task.to_dict()
    return {
        "task_id": d["task_id"],
        "url": d["url"],
        "status": d["status"],
        "phase": d["phase"],
        "depth": d["depth"],
        "elapsed_seconds": d["elapsed_seconds"],
        "progress": d["progress"],
        "error": d["error"],
        "result_db_path": d["result_db_path"],
    }


# ---------------------------------------------------------------- 工具定义
_START_SCAN_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "目标站点 URL（必填，含 http/https）"},
        "height": {"type": "integer", "default": 2, "description": "扫描深度"},
        "thread_num": {"type": "integer", "default": 10, "description": "并发线程数"},
        "findparam": {"type": "boolean", "default": True, "description": "自动解析 API 参数"},
        "fastscan": {"type": "boolean", "default": True, "description": "快速扫描模式"},
        "analyze_sensitive_info_ai": {"type": "boolean", "default": False, "description": "AI 分析敏感信息（省 token，默认关）"},
        "analyze_sensitive_info_rex": {"type": "boolean", "default": False, "description": "正则收集敏感信息"},
        "request_validation": {"type": "boolean", "default": False, "description": "请求验证。开启后填充响应字段并推导真实 risk_level；关闭时这些字段为 null，risk_level 恒为 Low"},
        "proxy": {"type": "string", "description": "代理，如 http://127.0.0.1:7890"},
        "use_shared_db": {"type": "boolean", "default": False, "description": "使用全局共享 DB（保留跨次去重）"},
    },
    "required": ["url"],
}

_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "jscanner_start_scan",
        "description": (
            "发起一个 JScanner2 站点安全扫描任务，立即返回 task_id（后台异步执行）。"
            "参数 request_validation 开启后会对 READ 类接口发验证请求，ai_vulns 结果将填充 "
            "request_status/response_code/response_length/response_body_preview 并推导真实 risk_level；"
            "关闭时这些字段为 null、risk_level 恒为 Low（仅 AI 候选）。仅扫描已授权目标。"
        ),
        "inputSchema": _START_SCAN_SCHEMA,
    },
    {
        "name": "jscanner_get_task",
        "description": "查询扫描任务的状态与进度（QUEUED/RUNNING/SUCCEEDED/FAILED/CANCELLED）。",
        "inputSchema": {"type": "object", "properties": {"task_id": {"type": "string"}}, "required": ["task_id"]},
    },
    {
        "name": "jscanner_list_tasks",
        "description": "列出扫描任务（按创建时间倒序），可按状态过滤。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "description": "QUEUED/RUNNING/SUCCEEDED/FAILED/CANCELLED"},
                "limit": {"type": "integer", "default": 20},
            },
        },
    },
    {
        "name": "jscanner_stop_task",
        "description": "停止一个运行中的扫描任务（尽力而为，已扫描结果保留在数据库中）。",
        "inputSchema": {"type": "object", "properties": {"task_id": {"type": "string"}}, "required": ["task_id"]},
    },
    {
        "name": "jscanner_get_apis",
        "description": "拉取任务发现的 API 列表（分页，按分析状态过滤）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "page": {"type": "integer", "default": 1},
                "page_size": {"type": "integer", "default": 20},
                "status": {"type": "string", "description": "DISCOVERED/AI_DONE/VALIDATED 等"},
            },
            "required": ["task_id"],
        },
    },
    {
        "name": "jscanner_get_vulnerabilities",
        "description": (
            "拉取漏洞/未授权访问结果。注意：字段随发起扫描时 request_validation 变化——"
            "开启时有 response_code/response_length/response_body_preview/request_status 且 risk_level 为验证后真实等级；"
            "关闭时这些字段为 null、risk_level 恒为 Low。operation_type 字段恒为 null。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "risk_level": {"type": "string", "description": "High/Med/Low/Info"},
                "limit": {"type": "integer", "default": 50},
            },
            "required": ["task_id"],
        },
    },
    {
        "name": "jscanner_get_sensitive_info",
        "description": "拉取 JS 中发现的敏感信息（密钥/Token 等）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "risk_level": {"type": "string", "description": "High/Med/Low"},
                "limit": {"type": "integer", "default": 50},
            },
            "required": ["task_id"],
        },
    },
    {
        "name": "jscanner_get_sourcemaps",
        "description": "拉取 SourceMap 暴露检测结果（is_sourceMap=Y 表示暴露）。",
        "inputSchema": {"type": "object", "properties": {"task_id": {"type": "string"}}, "required": ["task_id"]},
    },
    {
        "name": "jscanner_get_task_logs",
        "description": "拉取扫描任务尾部的控制台日志（便于排查）。",
        "inputSchema": {
            "type": "object",
            "properties": {"task_id": {"type": "string"}, "lines": {"type": "integer", "default": 50}},
            "required": ["task_id"],
        },
    },
]


# ---------------------------------------------------------------- 工具实现
def _jscanner_start_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return _tool_error("url 不能为空")
    if not (url.startswith("http://") or url.startswith("https://")):
        return _tool_error("url 必须以 http:// 或 https:// 开头")

    options = ScanOptions(
        url=url,
        height=int(args.get("height", 2)),
        thread_num=int(args.get("thread_num", 10)),
        findparam=bool(args.get("findparam", True)),
        fastscan=bool(args.get("fastscan", True)),
        analyze_sensitive_info_ai=bool(args.get("analyze_sensitive_info_ai", False)),
        analyze_sensitive_info_rex=bool(args.get("analyze_sensitive_info_rex", False)),
        request_validation=bool(args.get("request_validation", False)),
        proxy=(str(args["proxy"]).strip() or None) if args.get("proxy") else None,
        use_shared_db=bool(args.get("use_shared_db", False)),
    )

    task = TaskInfo(task_id=new_task_id(), url=url, options=options, status=TaskStatus.QUEUED, phase="queued")
    with _tasks_lock:
        _tasks[task.task_id] = task
    _spawn_scan(task)

    return {
        "task_id": task.task_id,
        "status": task.status.value,
        "url": url,
        "message": f"扫描任务已创建，task_id={task.task_id}。使用 jscanner_get_task 查询进度。",
    }


def _jscanner_get_task(args: Dict[str, Any]) -> Dict[str, Any]:
    task = _get_task(str(args.get("task_id", "")))
    if task is None:
        return _tool_error(f"任务 {args.get('task_id')} 不存在")
    return _task_summary(task)


def _jscanner_list_tasks(args: Dict[str, Any]) -> Dict[str, Any]:
    status_filter = args.get("status") or None
    limit = int(args.get("limit", 20))
    with _tasks_lock:
        tasks = list(_tasks.values())
    tasks.sort(key=lambda t: t.created_at, reverse=True)
    if status_filter:
        tasks = [t for t in tasks if t.status.value == status_filter]
    return {"total": len(tasks), "items": [_task_summary(t) for t in tasks[:limit]]}


def _jscanner_stop_task(args: Dict[str, Any]) -> Dict[str, Any]:
    task = _get_task(str(args.get("task_id", "")))
    if task is None:
        return _tool_error(f"任务 {args.get('task_id')} 不存在")
    if task.status in (TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.CANCELLED):
        return {"task_id": task.task_id, "stopped": False, "message": "任务已结束，无需停止。"}

    loop = getattr(task, "_loop", None)
    if loop is not None and loop.is_running():
        def _cancel_all():
            for fut in asyncio_all_tasks(loop):
                fut.cancel()
        loop.call_soon_threadsafe(_cancel_all)
        return {"task_id": task.task_id, "stopped": True, "message": "取消信号已发送，已扫描结果会保留。"}

    # 线程尚未启动事件循环：直接标记取消
    task.status = TaskStatus.CANCELLED
    task.phase = "cancelled"
    return {"task_id": task.task_id, "stopped": True, "message": "任务已标记为取消。"}


def asyncio_all_tasks(loop):
    """线程安全获取 loop 上的任务集合。"""
    import asyncio

    return asyncio.all_tasks(loop)


def _jscanner_get_apis(args: Dict[str, Any]) -> Dict[str, Any]:
    task = _get_task(str(args.get("task_id", "")))
    if task is None:
        return _tool_error(f"任务 {args.get('task_id')} 不存在")
    return result_queries.get_apis(
        task,
        page=int(args.get("page", 1)),
        page_size=int(args.get("page_size", 20)),
        status_filter=args.get("status") or None,
    )


def _jscanner_get_vulnerabilities(args: Dict[str, Any]) -> Dict[str, Any]:
    task = _get_task(str(args.get("task_id", "")))
    if task is None:
        return _tool_error(f"任务 {args.get('task_id')} 不存在")
    return result_queries.get_vulnerabilities(
        task,
        risk_level=args.get("risk_level") or None,
        limit=int(args.get("limit", 50)),
    )


def _jscanner_get_sensitive_info(args: Dict[str, Any]) -> Dict[str, Any]:
    task = _get_task(str(args.get("task_id", "")))
    if task is None:
        return _tool_error(f"任务 {args.get('task_id')} 不存在")
    return result_queries.get_sensitive_info(
        task,
        risk_level=args.get("risk_level") or None,
        limit=int(args.get("limit", 50)),
    )


def _jscanner_get_sourcemaps(args: Dict[str, Any]) -> Dict[str, Any]:
    task = _get_task(str(args.get("task_id", "")))
    if task is None:
        return _tool_error(f"任务 {args.get('task_id')} 不存在")
    return result_queries.get_sourcemaps(task)


def _jscanner_get_task_logs(args: Dict[str, Any]) -> Dict[str, Any]:
    task = _get_task(str(args.get("task_id", "")))
    if task is None:
        return _tool_error(f"任务 {args.get('task_id')} 不存在")
    lines = int(args.get("lines", 50))

    def _tail(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return "".join(f.readlines()[-lines:])
        except Exception as e:
            return f"(读取失败: {e})"

    return {
        "task_id": task.task_id,
        "log_tail": _tail("logs/scanner.log"),
        "error_log_tail": _tail("logs/scanner_error.log"),
    }


_TOOL_IMPL = {
    "jscanner_start_scan": _jscanner_start_scan,
    "jscanner_get_task": _jscanner_get_task,
    "jscanner_list_tasks": _jscanner_list_tasks,
    "jscanner_stop_task": _jscanner_stop_task,
    "jscanner_get_apis": _jscanner_get_apis,
    "jscanner_get_vulnerabilities": _jscanner_get_vulnerabilities,
    "jscanner_get_sensitive_info": _jscanner_get_sensitive_info,
    "jscanner_get_sourcemaps": _jscanner_get_sourcemaps,
    "jscanner_get_task_logs": _jscanner_get_task_logs,
}


def _tool_ok(data: Any) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}], "isError": False}


def _tool_error(message: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


# ---------------------------------------------------------------- 协议层
def _rpc_error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _handle(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = msg.get("method", "")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": _TOOLS}}
    if method == "tools/call":
        name = params.get("name")
        impl = _TOOL_IMPL.get(name)
        if impl is None:
            return _rpc_error(req_id, -32602, f"未知工具: {name!r}")
        result = impl(params.get("arguments") or {})
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    # notifications/initialized、notifications/cancelled、resources/* 等：安全忽略
    if req_id is None:
        return None
    return _rpc_error(req_id, -32601, f"不支持的 method: {method!r}")


def run() -> int:
    """主循环：逐行读 stdin，处理 JSON-RPC 帧，响应写 stdout。"""
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            sys.stderr.write(f"[jscanner2-mcp] 丢弃无法解析的帧: {exc}\n")
            sys.stderr.flush()
            continue
        try:
            response = _handle(msg)
        except Exception as exc:  # 协议层兜底：绝不因单帧异常退出
            sys.stderr.write(f"[jscanner2-mcp] 处理帧异常: {type(exc).__name__}: {exc}\n")
            sys.stderr.flush()
            if "id" in msg and msg["id"] is not None:
                response = _rpc_error(msg["id"], -32603, str(exc))
            else:
                response = None
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
