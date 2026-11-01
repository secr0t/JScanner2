# ===== 此文件由 setup.sh 自动生成，如需自定义请直接编辑此文件 =====
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_dotenv(path):
    """读取项目根目录 .env（KEY=VALUE），不覆盖已存在的环境变量。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except FileNotFoundError:
        pass


_load_dotenv(os.path.join(PROJECT_ROOT, ".env"))


def _abs(path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(PROJECT_ROOT, path)


# 本地/私有化大模型服务地址
BASE_URL = os.environ.get("JSCANNER_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")

# API Key（优先读环境变量 / .env；真实密钥不要写进仓库）
API_KEY = os.environ.get("JSCANNER_API_KEY", "")

DEFAULT_CONFIG_PATH = _abs("config/models_config.json")  # 模型配置文件路径

WHITE_SCOPE_PATH = _abs("config/whiteList.txt")   # 白名单路径（仅扫描指定路径）
MEMORY_LIMIT = 80                            # 内存占用阈值（%），超限时会进行内存释放

proxies = {
    "http": "",           # 示例: "http://127.0.0.1:7890"
    "https": "",          # 示例: "http://127.0.0.1:7890"
    "no_proxy": "*"       # 不走代理的域名，* 表示全部走代理
}

# ------------------------------
# 🔔 飞书告警通知
# ------------------------------
FEISHU_WEBHOOK = os.environ.get("JSCANNER_FEISHU_WEBHOOK", "")
FEISHU_ALERT_LEVELS = ["ERROR", "CRITICAL"]       # 触发告警的日志级别
FEISHU_RATE_LIMIT_SECONDS = 60                    # 相同告警内容60秒内只发一次

# ------------------------------
# 📁 输出路径配置
# ------------------------------
db_filename = _abs("Result/JScanner_Result.db")    # 扫描结果数据库路径
OVERFLOW_DIR = _abs("Overflow_Queue")              # 溢出队列暂存目录
LOG_DIR = _abs("logs")                             # 日志输出目录

# ------------------------------
# 🎯 扫描范围与性能控制
# ------------------------------
GLOBAL_TIMEOUT = 30                          # 单页面最大等待时间（秒）
MAX_REDIRECT_COUNT = 1                       # 最大允许跳转次数

CODE_MAX_LENGTH = 12000  # 单次送入大模型的代码最大长度（避免 token 超限）

# ------------------------------
# 📋 日志系统配置
# ------------------------------
LOG_FILENAME = "scanner.log"
LOG_ERROR_FILENAME = "scanner_error.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES = 10 * 1024 * 1024  # 单文件最大10MB
LOG_BACKUP_COUNT = 5              # 保留5个历史日志
CONSOLE_LOG_LEVEL = "INFO"        # 控制台输出级别

# ------------------------------
# 📦 NLTK 数据路径
# ------------------------------
NLTK_DIR = "config/nltk_data"
