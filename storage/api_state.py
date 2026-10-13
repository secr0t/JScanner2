# -*- coding: utf-8 -*-
"""
API 分析状态机（P0-2）

背景
----
旧实现里 "发现 API → 立刻写入 processed → 再做 AI/分析"，
一旦 AI 超时、JSON 解析失败、Context Recall 异常或进程被杀，
该 API 依然被记为 processed，下次扫描不会再处理 —— 静默漏扫。

现在改为显式状态机：

    DISCOVERED
        ↓
    CONTEXT_READY
        ↓
    AI_PENDING
        ↓
    AI_DONE
        ↓
    VALIDATION_PENDING
        ↓
    VALIDATED          （唯一成功终态）

异常状态（可重试，绝不等于 DONE）：

    AI_FAILED          AI 调用/解析失败
    CONTEXT_FAILED     Context Recall 抛异常
    VALIDATION_FAILED  请求验证批次失败
    NO_CONTEXT         Context Recall 正常结束但没有取到 HTTP 上下文

规则
----
1. 只有 VALIDATED 算"处理完成"，可以被去重跳过。
2. 失败状态在 attempt_count < MAX_ATTEMPTS 时允许重新进入分析。
3. 中断恢复靠 run_id：上一轮未跑完的 IN_PROGRESS 状态会被重置为可重试。
"""

# 单个 API 的最大尝试次数（超过后不再重试，避免无限循环）
MAX_ATTEMPTS = 3


class ApiStatus:
    """API 分析状态机状态定义"""

    # ---------------- 正常链路 ----------------
    DISCOVERED = "DISCOVERED"
    CONTEXT_READY = "CONTEXT_READY"
    AI_PENDING = "AI_PENDING"
    AI_DONE = "AI_DONE"
    VALIDATION_PENDING = "VALIDATION_PENDING"
    VALIDATED = "VALIDATED"

    # ---------------- 异常链路 ----------------
    AI_FAILED = "AI_FAILED"
    CONTEXT_FAILED = "CONTEXT_FAILED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    NO_CONTEXT = "NO_CONTEXT"

    # ---------------- 分组 ----------------
    # 成功终态：允许去重跳过
    TERMINAL_SUCCESS = frozenset({VALIDATED})

    # 进行中：本轮已经在处理，不允许重复进入
    IN_PROGRESS = frozenset({
        DISCOVERED,
        CONTEXT_READY,
        AI_PENDING,
        AI_DONE,
        VALIDATION_PENDING,
    })

    # 失败态：attempt_count 未超上限时可重试
    FAILURE = frozenset({
        AI_FAILED,
        CONTEXT_FAILED,
        VALIDATION_FAILED,
        NO_CONTEXT,
    })

    ALL = frozenset({
        DISCOVERED, CONTEXT_READY, AI_PENDING, AI_DONE,
        VALIDATION_PENDING, VALIDATED,
        AI_FAILED, CONTEXT_FAILED, VALIDATION_FAILED, NO_CONTEXT,
    })

    # ---------------- 合法状态转移 ----------------
    TRANSITIONS = {
        DISCOVERED: {CONTEXT_READY, AI_PENDING, CONTEXT_FAILED, NO_CONTEXT},
        CONTEXT_READY: {AI_PENDING, CONTEXT_FAILED, NO_CONTEXT},
        AI_PENDING: {AI_DONE, AI_FAILED, CONTEXT_FAILED, NO_CONTEXT},
        AI_DONE: {VALIDATION_PENDING, VALIDATED, VALIDATION_FAILED},
        VALIDATION_PENDING: {VALIDATED, VALIDATION_FAILED},
        VALIDATED: frozenset(),

        # 失败态允许重新排队
        AI_FAILED: {AI_PENDING, CONTEXT_READY},
        CONTEXT_FAILED: {AI_PENDING, CONTEXT_READY},
        VALIDATION_FAILED: {VALIDATION_PENDING, VALIDATED, AI_DONE},
        NO_CONTEXT: {AI_PENDING, CONTEXT_READY},
    }

    # ---------------- 判定方法 ----------------

    @classmethod
    def is_terminal_success(cls, status: str) -> bool:
        return status in cls.TERMINAL_SUCCESS

    @classmethod
    def is_in_progress(cls, status: str) -> bool:
        return status in cls.IN_PROGRESS

    @classmethod
    def is_failure(cls, status: str) -> bool:
        return status in cls.FAILURE

    @classmethod
    def can_transition(cls, old_status: str, new_status: str) -> bool:
        """是否允许从 old_status 转移到 new_status"""
        if not old_status:
            # 无历史状态，直接进入任意状态
            return True
        if old_status == new_status:
            return True
        allowed = cls.TRANSITIONS.get(old_status)
        if allowed is None:
            # 未知的历史状态（旧数据），不做阻拦
            return True
        return new_status in allowed

    @classmethod
    def should_retry(cls, status: str, attempt_count: int) -> bool:
        """失败态是否还允许再试一次"""
        if not cls.is_failure(status):
            return False
        try:
            attempt_count = int(attempt_count or 0)
        except (TypeError, ValueError):
            attempt_count = 0
        return attempt_count < MAX_ATTEMPTS
