# -*- coding: utf-8 -*-
"""生产侧加载 test/template_recall 的桥接层。

`-ar`（Agent 召回）的实现位于 test/template_recall，不属于生产包。
本模块负责三件事：

1. 把项目的 test/ 目录加入 sys.path，使 `template_recall` 可导入；
2. 阻止 recall_agent 导入时的 os.chdir 副作用（生产进程的 CWD 很关键）；
3. 用项目自己的 config/config.py + config/models_config.json 构造 AI 客户端，
   不依赖 test 里硬编码的 ARTEX llm.json。
"""

from __future__ import annotations

import os
import sys

_NO_CHDIR_ENV = "JSCANNER_RECALL_NO_CHDIR"


def _project_root() -> str:
    # processor/js/context/agent_recall_bridge.py -> 项目根
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def ensure_importable() -> None:
    """把 test/ 放进 sys.path，并确保真实 config/infra 模块先于 stub 被导入。"""
    test_dir = os.path.join(_project_root(), "test")
    if os.path.isdir(test_dir) and test_dir not in sys.path:
        sys.path.insert(0, test_dir)

    # recall_agent 在导入时会 chdir 到临时目录；生产里必须关掉。
    os.environ.setdefault(_NO_CHDIR_ENV, "1")

    # recall_agent 用 sys.modules.setdefault 放 stub；先把真实模块导入好。
    import config.config  # noqa: F401
    try:
        import infra.feishu  # noqa: F401
    except Exception:
        pass


def load_recall_agent():
    """返回 RecallAgent 类；调用方负责捕获异常并降级。"""
    ensure_importable()
    from template_recall.recall_agent import RecallAgent
    return RecallAgent


def build_recall_client():
    """用项目配置构造独立 AI 客户端（与扫描主流程同一套模型配置）。"""
    import config.config as cfg
    from infra.ai_client import AIHubClient

    config_file = getattr(cfg, "DEFAULT_CONFIG_PATH", "config/models_config.json")
    models = None
    if not os.path.exists(config_file):
        config_file = None
        models = ["qwen3.7-flash"]  # 兜底：至少给一个可用模型，避免空模型列表

    return AIHubClient(
        api_key=cfg.API_KEY,
        base_url=cfg.BASE_URL,
        models=models,
        config_file=config_file,
        timeout=180,
    )
