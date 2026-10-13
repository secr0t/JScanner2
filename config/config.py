# ===== 此文件由 setup.sh 自动生成，如需自定义请直接编辑此文件 =====

# 本地/私有化大模型服务地址
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

# API Key（请替换为您自己的密钥）
API_KEY = "sk-ws-H.EXLEYXX.cBc8."

# 🔧 提示词缓存配置（阿里云 DashScope）
ENABLE_PROMPT_CACHE = True  # 是否启用提示词缓存
CACHE_CONTROL_TYPE = "ephemeral"  # 缓存类型：ephemeral（临时缓存，5分钟有效期）
MIN_CACHE_TOKENS = 1024  # 最小缓存 token 数（约等于字符数）
MAX_CACHE_MARKERS = 4  # 单次请求最多缓存标记数

DEFAULT_CONFIG_PATH = "config/models_config.json"  # 模型配置文件路径

WHITE_SCOPE_PATH = "config/whiteList.txt"   # 白名单路径（仅扫描指定路径）
MEMORY_LIMIT = 80                            # 内存占用阈值（%），超限时会进行内存释放

proxies = {
    "http": "",           # 示例: "http://127.0.0.1:7890"
    "https": "",          # 示例: "http://127.0.0.1:7890"
    "no_proxy": "*"       # 不走代理的域名，* 表示全部走代理
}

# ------------------------------
# 🔔 飞书告警通知
# ------------------------------
FEISHU_WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/1412ed79--4e29-adb9-"
FEISHU_ALERT_LEVELS = ["ERROR", "CRITICAL"]       # 触发告警的日志级别
FEISHU_RATE_LIMIT_SECONDS = 60                    # 相同告警内容60秒内只发一次

# ------------------------------
# 📁 输出路径配置
# ------------------------------
db_filename = "Result/JScanner_Result.db"         # 扫描结果数据库路径
OVERFLOW_DIR = "Overflow_Queue"                   # 溢出队列暂存目录
LOG_DIR = "logs"                                  # 日志输出目录

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
