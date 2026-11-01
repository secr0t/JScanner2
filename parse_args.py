import argparse


def str_to_float(value):
    """将字符串转为浮点数，并验证范围 (0.0-1.0)"""
    try:
        val = float(value)
        if not 0.0 <= val <= 1.0:
            raise argparse.ArgumentTypeError("阈值必须在 0.0 到 1.0 之间")
        return val
    except ValueError:
        raise argparse.ArgumentTypeError("必须输入有效的浮点数")


def parse_args():
    parser = argparse.ArgumentParser(description="网站扫描工具 - 支持URL扫描、批量处理及结果导出")

    # 核心目标参数（必选其一）
    parser.add_argument('-u', '--url', type=lambda x: x.strip().rstrip('\r'),
                        help="输入带有http/https的单个网站URL（如：https://example.com）")
    # 扫描配置参数
    parser.add_argument('-H', '--depth', '--height', dest='height', type=int, default=2,
                        help="扫描深度（默认：2；-H/--depth 推荐，--height 为兼容别名）")
    parser.add_argument('-t', '--thread_num', type=int, default=10, help="并发线程数（默认：10）")

    # 网络与浏览器参数
    parser.add_argument('-p', '--proxy', type=str,
                        help="代理服务器（格式：http://127.0.0.1:12335 或 socks5://127.0.0.1:1080）")

    parser.add_argument('-v', '--visible', action='store_true', default=False,
                        help="显示浏览器窗口（默认：无头模式，不显示窗口）")

    parser.add_argument('-fp', '--findparam', action='store_true', default=False,
                        help="自动解析api参数")

    parser.add_argument('-fs','--fastscan', action='store_true', default=False, help="是否使用快速扫描模式")

    parser.add_argument('-asia','--analyzeSensitiveInfoAI', action='store_true', default=False, help="是否使用AI模型分析敏感信息")

    parser.add_argument('-rv', '--request-validation', action='store_true', default=False,
                        help="AI分析完成后，自动发起请求验证结果")

    # Agent 召回（主动决策式深召回，LLM 密集，默认关闭）
    parser.add_argument('-ar', '--agent-recall', action='store_true', default=False,
                        help="启用 Agent 召回：普通/跨chunk召回不足时，用 LLM 工具循环深度召回补充上下文")

    args = parser.parse_args()

    # 无目标时不要静默跑空扫描：明确报错并以退出码 2 结束（argparse 约定）
    if not (args.url and args.url.strip()):
        parser.error("必须提供扫描目标：-u/--url https://example.com")

    return args