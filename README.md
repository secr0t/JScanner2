# JScanner2 - AI-Powered JavaScript Security Analysis Tool

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

[中文版](https://github.com/hmx222/JScanner2/blob/master/README_ZH.md) | [English](https://github.com/hmx222/JScanner2/blob/master/README.md)

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- AI Model API access (Recommended: **Qwen 3.5-flash**)
- Recommended specs: **4 CPU cores + 4GB RAM**

### Installation & Usage

```bash
# 1. Clone the repository
git clone https://github.com/hmx222/JScanner2.git
cd JScanner2

# 2. Configure and initialize
vim setup.sh  # Configure your AI API keys etc
docker compose run --rm scanner /app/setup.sh

# 3. Prepare target URLs
# Required: Add URLs to scan in urls.txt

# 4. Add WhiteList
# Optional: Add whitelist domains in config/whiteList.txt

# 5. Start scanning
docker compose run --rm scanner /app/run_scan.sh urls.txt
```

---

## ⌨️ Command Line Options

### Single-site scan (CLI)

```bash
python main.py -u https://target.com -H 2 -t 10 -fp -fs
```

### Batch scan (run_scan.sh)

```bash
bash run_scan.sh urls.txt          # pass the URL file as an argument
echo urls.txt | bash run_scan.sh   # or pipe it via stdin
```

`run_scan.sh` includes: memory-safety resumable scanning (overflow queue), heartbeat watchdog with auto-restart on hang, and Feishu notifications.

### Option reference

| Option | Default | Description |
| --- | --- | --- |
| `-u`, `--url` | required | Target website URL (must include http/https) |
| `-H`, `--height` | 2 | Scan depth |
| `-t`, `--thread_num` | 10 | Concurrent thread count |
| `-p`, `--proxy` | empty | Proxy, e.g. `http://127.0.0.1:7890` |
| `-v`, `--visible` | False | Show the browser window (headless by default) |
| `-fp`, `--findparam` | False | Auto-parse API parameters (recommended) |
| `-fs`, `--fastscan` | False | Fast-scan mode: HTTP-probe filter before AI analysis (recommended) |
| `-asir`, `--analyzeSensitiveInfoRex` | False | Collect sensitive info from JS with regex |
| `-asia`, `--analyzeSensitiveInfoAI` | False | Analyze sensitive info with AI |
| `-rv`, `--request-validation` | False | Auto-send validation requests after AI analysis |
| `-nr`, `--no-request` | False | Store AI results only, skip validation requests |

Recommended combination (matches `run_scan.sh` defaults):

```bash
python main.py -u https://target.com -H 5 -fp -fs -asia
```

### Configuration

| File | Purpose |
| --- | --- |
| `config/config.py` | AI model endpoint, API keys, whitelist path, memory threshold, Feishu alerts, output paths |
| `config/models_config.json` | Model list configuration |
| `config/whiteList.txt` | Whitelisted domains (only whitelisted paths are scanned) |
| `setup.sh` | One-time setup (API keys, NLTK data download) |

> **Note**: AI features (`-fp` / `-asia`) require a valid API key in `config/config.py`. Scanning still runs without it, but AI features are unavailable.

---

## 📖 Overview

**JScanner2** is an intelligent JavaScript security scanning tool that combines **AST (Abstract Syntax Tree) parsing** with **AI large language models** to discover sensitive information and unauthorized access vulnerabilities in JavaScript files.

Unlike traditional regex-based tools, JScanner2 understands code semantics, extracts API parameters automatically, and provides AI-powered exploit guidance.

### ✨ Key Features

- 🔍 **Intelligent Parameter Discovery** - AST-based extraction of API endpoints AND parameters
- 🤖 **AI-Driven Analysis** - Context-aware hardcoded secret detection with exploit suggestions  
- 🔄 **Resumable Scanning** - Support for pause/resume operations

---

## 💡 Why JScanner2

### ❌ Limitations of Traditional Tools

Traditional JavaScript scanning tools (findsomething, JSFinder, etc.) rely on **regex matching** and suffer from:

1. **API Paths Only** - Cannot extract parameters needed to trigger vulnerabilities
2. **High False Positives** - Regex cannot understand context (e.g., `s=qcfvg28@4a`)
3. **Manual Analysis Required** - Every finding needs human verification
4. **No Business Logic** - Cannot distinguish between safe and exploitable secrets

---

## 📊 Results Analysis

Scan results are stored as SQLite databases in the `Result/` directory (default: `Result/JScanner_Result.db`).

| Table | Content |
| --- | --- |
| `scan_results` | Crawled URL base data |
| `api_analysis_state` | API analysis state machine (DISCOVERED → AI_PENDING → AI_DONE → VALIDATED) |
| `ai_vulns` | Vulnerability / unauthorized-access findings (risk: High / Med / Low / Info) |
| `sensitive_info` | Sensitive info findings (risk level & type) |
| `js_source_maps` | SourceMap exposure detection results |
| `visited_urls` | Visited URLs (deduplication) |

Query example:

```bash
python -c "import sqlite3; c=sqlite3.connect('Result/JScanner_Result.db'); [print(r) for r in c.execute('SELECT api_endpoint,http_method,risk_level FROM ai_vulns WHERE risk_level=\"High\"')]"
```

## 📈 Real-World Results

Tested against **29 domestic SRCs** (Security Response Centers) with the following findings:

| Severity     | Count |
| ------------ | ----- |
| 🔴 **High**   | 10    |
| 🟡 **Medium** | 4     |
| 🟢 **Low**    | 1     |

**Notes:**
- ✅ Deduplicated (no repeated vulnerabilities)
- ✅ Low WAF detection rate (no attack payloads)
- ✅ Suitable for red team/blue team exercises
- ✅ Includes only independent SRCs (not public bug bounty platforms)

---

## 💰 Cost & Performance

### Token Consumption

- **~100 million tokens** for scanning 1,600-2,000 websites (URLs in urls.txt only)
- Recursive JS file discovery included in count

### Scan Duration

- 2,000 websites: Several hours (depends on JS file count)
- Recommended: Run on server with screen/tmux

### Recommended Configuration

| Resource    | Minimum           | Recommended        |
| ----------- | ----------------- | ------------------ |
| **CPU**     | 2 cores           | 4+ cores           |
| **RAM**     | 2GB               | 4GB+               |
| **Network** | Stable connection | High bandwidth     |
| **Storage** | 1GB               | 5GB+ (for results) |

---

## 🔧 Advanced Usage

### Whitelist Configuration

Prevent scanning of specific domains:

```bash
# config/whiteList.txt
google.com
facebook.com
analytics.example.com
```

---

## 🤖 Agent Usage Guide

JScanner2 can be driven by AI agents (Trae / Claude / Cursor, etc.). The project ships an **MCP server** at `agent/mcp_server.py` (built on the official FastMCP SDK) that lets agents start scans, poll progress, and fetch results programmatically.

### Start the MCP server

```bash
# stdio transport (default, for TraeCode / Claude Desktop / MCP clients)
python agent/mcp_server.py

# HTTP transport (streamable-http)
python agent/mcp_server.py --transport http --port 9000
```

MCP tools: `jscanner_start_scan`, `jscanner_get_task`, `jscanner_list_tasks`, `jscanner_stop_task`, `jscanner_get_apis`, `jscanner_get_vulnerabilities`, `jscanner_get_sensitive_info`, `jscanner_get_sourcemaps`, `jscanner_get_task_logs`.

### Agent workflow

1. **Confirm authorization** — only scan targets the user explicitly authorizes.
2. **Identify the target** — get a concrete URL (with http/https), decide scan depth and options.
3. **Start the scan** — prefer `-fp -fs` (fast-scan + parameter parsing); add `-asia` / `-asir` when sensitive-info scanning is needed.
4. **Collect results** — query `ai_vulns` (focus on High risk), `sensitive_info`, `js_source_maps`.

### Operational notes

- Deeper scans take longer and consume more AI tokens — keep the target scope tight.
- Large sites can take hours; prefer `run_scan.sh` in the background for batch jobs.
- If a Feishu webhook is configured, failures trigger alerts.

---

## 🤝 Acknowledgments

Built with:
- [Playwright](https://playwright.dev/) - Browser automation
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP probing
- [NLTK](https://www.nltk.org/) - Natural language processing
- [阿里云](https://www.aliyun.com/) - AI model services

---

## 📧 Support & Feedback

- **Issues**: [GitHub Issues](https://github.com/hmx222/JScanner2/issues)
- **Technical Details**: [Article (Chinese)](https://xz.aliyun.com/news/91962)
- **Discussions**: [GitHub Discussions](https://github.com/hmx222/JScanner2/discussions)

---

**Made with ❤️ for the security community**
