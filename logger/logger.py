import hashlib
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler

from config.config import (
    FEISHU_WEBHOOK,
    FEISHU_ALERT_LEVELS,
    FEISHU_RATE_LIMIT_SECONDS
)
from infra.feishu import send_feishu_notify

LOG_DIR = "logs"
LOG_FILENAME = "scanner.log"
LOG_ERROR_FILENAME = "scanner_error.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5

CONSOLE_LOG_LEVEL = logging.INFO

# 强制日志用北京时间，避免服务器/容器为 UTC 时比本地慢 8 小时
_CN_TZ = timezone(timedelta(hours=8))
def _cn_converter(timestamp):
    return datetime.fromtimestamp(timestamp, _CN_TZ).timetuple()
logging.Formatter.converter = staticmethod(_cn_converter)

_initialized = False
_feishu_sent_time: dict = {}
_feishu_lock = threading.Lock()

def _should_send_feishu(content: str) -> bool:
    if not FEISHU_WEBHOOK:
        return False

    content_hash = hashlib.md5(content.encode()).hexdigest()
    current_time = time.time()

    with _feishu_lock:
        if content_hash in _feishu_sent_time:
            last_sent = _feishu_sent_time[content_hash]
            if current_time - last_sent < FEISHU_RATE_LIMIT_SECONDS:
                return False

        _feishu_sent_time[content_hash] = current_time
        cutoff = current_time - 3600
        expired_keys = [k for k, v in _feishu_sent_time.items() if v <= cutoff]
        for key in expired_keys:
            del _feishu_sent_time[key]

    return True

def _send_feishu_alert(level: str, message: str, logger_name: str):
    title = f"🚨【JScanner 告警】{level}"
    content = (
        f"• 级别：{level}\n"
        f"• 模块：{logger_name}\n"
        f"• 时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"{message}"
    )

    def send_async():
        try:
            send_feishu_notify(title, content)
        except Exception:
            pass

    thread = threading.Thread(target=send_async, daemon=True)
    thread.start()

class FeishuAlertHandler(logging.Handler):
    def __init__(self, levels: list = None):
        super().__init__()
        level_names = levels or FEISHU_ALERT_LEVELS
        self.alert_levels = set()
        for level in level_names:
            if isinstance(level, str):
                self.alert_levels.add(getattr(logging, level))
            else:
                self.alert_levels.add(level)

    def emit(self, record: logging.LogRecord):
        if record.levelno not in self.alert_levels:
            return
        message = record.getMessage()
        if not _should_send_feishu(message):
            return
        _send_feishu_alert(
            level=record.levelname,
            message=message,
            logger_name=record.name
        )

def _ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)

def _create_console_handler() -> logging.Handler:
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(CONSOLE_LOG_LEVEL)
    formatter = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT)
    handler.setFormatter(formatter)
    return handler

def _create_file_handler(filename: str, level: int) -> logging.Handler:
    filepath = os.path.join(LOG_DIR, filename)
    handler = RotatingFileHandler(
        filepath,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    handler.setLevel(level)
    formatter = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT)
    handler.setFormatter(formatter)
    return handler


def _init_global_logging():
    """全局初始化一次，所有logger自动继承配置"""
    global _initialized
    if _initialized:
        return
    _ensure_log_dir()

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # 清空默认handler，避免重复打印
    root_logger.handlers.clear()

    # 添加所有handler
    root_logger.addHandler(_create_console_handler())
    root_logger.addHandler(_create_file_handler(LOG_FILENAME, logging.DEBUG))
    root_logger.addHandler(_create_file_handler(LOG_ERROR_FILENAME, logging.ERROR))
    root_logger.addHandler(FeishuAlertHandler())

    # 压制第三方库的 DEBUG 日志
    for noisy_logger in ("httpcore", "httpx", "chardet", "filelock", "asyncio", "urllib3", "hpack",
                         "openai", "dashscope", "litellm", "aiosqlite"):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)

    _initialized = True


def get_logger(name: str = "JScanner") -> logging.Logger:
    """获取logger，全局统一配置，任意名称都能打印"""
    _init_global_logging()
    return logging.getLogger(name)

def shutdown_logger():
    logging.shutdown()