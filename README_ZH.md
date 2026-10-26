# JScanner2 - AI驱动的JavaScript安全分析工具

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

[中文版](https://github.com/hmx222/JScanner2/blob/master/README_ZH.md) | [English](https://github.com/hmx222/JScanner2/blob/master/README.md)

---

## 🚀 快速开始

### 环境要求

- Docker & Docker Compose
- AI模型API访问权限（推荐：**Qwen 3.5-flash**）
- 推荐配置：**4核CPU + 4GB内存**

### 安装与使用

```bash
# 1. 克隆项目
git clone https://github.com/hmx222/JScanner2.git
cd JScanner2

# 2. 初始化配置
vim setup.sh  # 配置AI API密钥等
docker compose run --rm scanner /app/setup.sh

# 3. 准备目标URL列表
# 必需：将需要扫描的URL添加到urls.txt中

# 4. 添加白名单
# 可选：将白名单域名添加到config/whiteList.txt中

# 5. 开始扫描
docker compose run --rm scanner /app/run_scan.sh urls.txt
```

---

## ⌨️ 命令行参数

### 单站点扫描（CLI）

```bash
python main.py -u https://target.com -H 2 -t 10 -fp -fs
```

### 批量扫描（run_scan.sh）

```bash
bash run_scan.sh urls.txt          # 以文件路径作为参数
echo urls.txt | bash run_scan.sh   # 或通过管道输入
```

`run_scan.sh` 自带：内存熔断续跑（溢出队列接力）、心跳看门狗（判定卡死自动重启）、飞书通知。

### 参数速查表

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-u`, `--url` | 必填 | 目标网站 URL（需含 http/https） |
| `-H`, `--height` | 2 | 扫描深度 |
| `-t`, `--thread_num` | 10 | 并发线程数 |
| `-p`, `--proxy` | 空 | 代理，如 `http://127.0.0.1:7890` |
| `-v`, `--visible` | False | 显示浏览器窗口（默认无头模式） |
| `-fp`, `--findparam` | False | 自动解析 API 参数（推荐开启） |
| `-fs`, `--fastscan` | False | 快速扫描模式：先 HTTP 探测过滤再送 AI（推荐开启） |
| `-asir`, `--analyzeSensitiveInfoRex` | False | 正则收集 JS 敏感信息 |
| `-asia`, `--analyzeSensitiveInfoAI` | False | AI 分析敏感信息 |
| `-rv`, `--request-validation` | False | AI 分析后自动发起请求验证 |
| `-nr`, `--no-request` | False | 仅存档 AI 结果，不发验证请求 |

推荐组合（与 `run_scan.sh` 默认一致）：

```bash
python main.py -u https://target.com -H 5 -fp -fs -asia
```

### 配置文件

| 文件 | 作用 |
| --- | --- |
| `config/config.py` | AI 模型地址、API Key、白名单路径、内存阈值、飞书告警、输出路径 |
| `config/models_config.json` | 模型列表配置 |
| `config/whiteList.txt` | 白名单域名（仅扫描白名单路径） |
| `setup.sh` | 初始化（配置 API Key、下载 NLTK 数据） |

> **注意**：AI 相关功能（`-fp` / `-asia`）依赖 `config/config.py` 中配置有效的 API Key。未配置时扫描仍可运行，但 AI 功能不可用。

---

## 📖 概述

**JScanner2** 是一款结合 **AST（抽象语法树）解析** 与 **AI大语言模型** 的智能化JavaScript安全扫描工具，用于发现JavaScript文件中的敏感信息和未授权访问漏洞。

与传统的基于正则表达式的工具不同，JScanner2能够理解代码语义，自动提取API参数，并提供AI驱动的漏洞利用指导。

### ✨ 核心特性

- 🔍 **智能参数发现** - 基于AST提取API端点及参数
- 🤖 **AI驱动分析** - 上下文感知的硬编码密钥检测，附带利用建议
- 🔄 **断点续扫** - 支持暂停/恢复扫描任务

---

## 🔐 密钥识别算法

JScanner2 的 AI 密钥识别链路采用基于**熵与分词特征的候选评分方法**，并结合 AST 上下文分析与大语言模型复核，对 JavaScript 源码中的潜在密钥进行识别与风险判定。

相关算法思路与技术细节见：[先知社区技术文章](https://xz.aliyun.com/news/91962)。本项目在密钥识别流程中使用了该公开技术方案。

---

## 💡 为什么选择JScanner2

###  传统工具的局限性

传统的JavaScript扫描工具（findsomething、JSFinder等）依赖 **正则表达式匹配**，存在以下问题：

1. **仅能获取API路径** - 无法提取触发漏洞所需的参数
2. **误报率高** - 正则无法理解上下文（例如：`s=qcfvg28@4a`）
3. **需要大量人工分析** - 每个发现都需要人工验证
4. **缺乏业务逻辑理解** - 无法区分安全和可 exploited 的密钥

---

## 📊 结果分析

扫描结果以 SQLite 数据库形式存储在 `Result/` 目录中（默认路径：`Result/JScanner_Result.db`）。

| 表 | 内容 |
| --- | --- |
| `scan_results` | 爬取的 URL 基础数据 |
| `api_analysis_state` | API 分析状态机（DISCOVERED → AI_PENDING → AI_DONE → VALIDATED） |
| `ai_vulns` | 漏洞/未授权访问结果（风险等级 High/Med/Low/Info） |
| `sensitive_info` | 敏感信息命中（含风险等级与类型） |
| `js_source_maps` | SourceMap 暴露检测结果 |
| `visited_urls` | 已访问 URL（去重用） |

查询示例：

```bash
python -c "import sqlite3; c=sqlite3.connect('Result/JScanner_Result.db'); [print(r) for r in c.execute('SELECT api_endpoint,http_method,risk_level FROM ai_vulns WHERE risk_level=\"High\"')]"
```

## 📈 实战成果

对 **29个国内SRC**（安全应急响应中心）的部分网站进行测试，成果如下：

| 漏洞等级 | 数量 |
| -------- | ---- |
| 🔴 **高危** | 10   |
|  **中危** | 4    |
| 🟢 **低危** | 1    |

**说明：**
- ✅ 已去重（不包含重复漏洞）
- ✅ WAF检测率低（不发起攻击性payload）
- ✅ 适合攻防演练场景使用
- ✅ 仅包含独立运营的SRC（不包括公益SRC）

---

## 💰 成本与性能

### Token消耗

- 扫描 **1,600-2,000个网站** 约需 **1亿tokens**（仅指urls.txt中的URL数量）
- 包含递归JS文件发现

### 扫描时长

- 2,000个网站：数小时（取决于JS文件数量）
- 建议使用服务器配合screen/tmux运行

### 推荐配置

| 资源 | 最低配置 | 推荐配置 |
| ---- | -------- | -------- |
| **CPU** | 2核 | 4核及以上 |
| **内存** | 2GB | 4GB及以上 |
| **网络** | 稳定连接 | 高带宽 |
| **存储** | 1GB | 5GB及以上（用于存储结果） |

---

##  高级用法

### 白名单配置

防止扫描特定域名：

```bash
# config/whiteList.txt
google.com
facebook.com
analytics.example.com
```

---

## 🤖 Agent 使用指南

JScanner2 可被 AI Agent（Trae / Claude / Cursor 等）以编程方式调用。项目内置 **MCP Server**（`agent/mcp_server.py`，基于官方 FastMCP SDK），让 Agent 可以发起扫描、轮询进度、拉取结果。

### 启动 MCP Server

```bash
# stdio 传输（默认，供 TraeCode / Claude Desktop 等 MCP 客户端接入）
python agent/mcp_server.py

# HTTP 传输（streamable-http）
python agent/mcp_server.py --transport http --port 9000
```

MCP 工具：`jscanner_start_scan`、`jscanner_get_task`、`jscanner_list_tasks`、`jscanner_stop_task`、`jscanner_get_apis`、`jscanner_get_vulnerabilities`、`jscanner_get_sensitive_info`、`jscanner_get_sourcemaps`、`jscanner_get_task_logs`。

### Agent 使用工作流

1. **确认授权**：只扫描用户明确授权/有权限的目标。
2. **明确目标**：拿到具体 URL（带 http/https），确定扫描深度与参数。
3. **发起扫描**：优先推荐 `-fp -fs`（快速 + 参数解析）；需要敏感信息时加 `-asia` 或 `-asir`。
4. **查看结果**：查询 `ai_vulns`（重点 High 风险）、`sensitive_info`、`js_source_maps`。

### 注意事项

- 深度越大耗时越长，AI 分析消耗 token，控制目标范围。
- 大站点可能数小时，批量任务建议用 `run_scan.sh` 后台运行。
- 若配置了飞书 webhook，异常会收到告警。

---

## 🤝 致谢

本项目使用以下技术构建：
- [Playwright](https://playwright.dev/) - 浏览器自动化
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP探测
- [NLTK](https://www.nltk.org/) - 自然语言处理
- [阿里云](https://www.aliyun.com/) - AI模型服务

---

##  支持与反馈

- **问题反馈**: [GitHub Issues](https://github.com/hmx222/JScanner2/issues)
- **技术文章**: [中文技术文章](https://xz.aliyun.com/news/91962)
- **讨论区**: [GitHub Discussions](https://github.com/hmx222/JScanner2/discussions)

---

**为安全社区用心制作 ❤️**
