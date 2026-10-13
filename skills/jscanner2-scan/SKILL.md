---
name: jscanner2-scan
description: Scan a website end-to-end for JavaScript security issues with JScanner2. Use when the user asks to scan a target site or URL for API endpoints, request parameters, hardcoded secrets, sensitive info, source map exposure, or unauthorized access (扫描网站/JS/API/参数/敏感信息/未授权访问). Do not use for analyzing a single JS snippet pasted in chat or for non-security web crawling.
---

# JScanner2 Scan

> **Deployment note (not Trae-specific):** this skill is a platform-agnostic instruction
> bundle. Copy this folder (`jscanner2-scan/`) into the skills directory of whichever agent
> you use — Claude Code `~/.claude/skills/`, Cline, a red-team agent's custom skills
> directory, etc. The commands and contract below are plain CLI facts; they do not depend
> on any particular agent framework.

JScanner2 is a website-wide JavaScript security scanner. Given a target site URL it crawls
the site, extracts requestable APIs and parameters from JS via AST + AI, detects hardcoded
secrets and source-map exposure, and optionally validates unauthorized access by sending
verification requests. Results are stored in a SQLite database, **not** printed to stdout.

## 1. Confirm authorization first

JScanner2 can send requests to the target (when `-rv` is on) and consumes AI tokens.
Only run it against targets the user explicitly authorizes.

## 2. Decide parameters

| Need | Command |
| --- | --- |
| Default recommended | `python main.py -u <url> -H 5 -fp -fs` |
| + sensitive info via AI | add `-asia` |
| + sensitive info via regex | add `-asir` |
| + request validation (real requests) | add `-rv` |
| Keep it fast | `-H 2 -t 10` (lower depth / fewer threads) |

Full parameter table: [references/cli-contract.md](references/cli-contract.md).

## 3. Invocation templates

```bash
# Single site
python main.py -u https://example.com -H 5 -fp -fs

# Fast scan + request validation
python main.py -u https://example.com -H 2 -fp -fs -rv

# Batch (urls.txt, one URL per line) — handles memory-safety resume + watchdog
bash run_scan.sh urls.txt

# Docker
docker compose run --rm scanner /app/run_scan.sh urls.txt
```

## 4. Output contract (where results live)

Results are **not** on stdout. They are stored in SQLite:

- Default DB: `Result/JScanner_Result.db`
- Tables:
  | Table | Content |
  | --- | --- |
  | `scan_results` | Crawled URL base data |
  | `api_analysis_state` | Per-API analysis state machine (DISCOVERED → AI_PENDING → AI_DONE → VALIDATED) |
  | `ai_vulns` | Unauthorized-access / vulnerability findings |
  | `sensitive_info` | Hardcoded secret findings |
  | `js_source_maps` | Source-map exposure (is_sourceMap = Y/N) |
  | `visited_urls` | Deduplication |
- Query example:
  ```bash
  python -c "import sqlite3;c=sqlite3.connect('Result/JScanner_Result.db');[print(r) for r in c.execute('SELECT api_endpoint,http_method,risk_level FROM ai_vulns WHERE risk_level=\"High\"')]"
  ```

## 5. The `-rv` option changes what `ai_vulns` contains

| | `-rv` ON | `-rv` OFF (default) |
| --- | --- | --- |
| Behavior | Sends verification requests for READ-class APIs | No requests, results stored only |
| `request_status` | `success` / `failed` / `dangerous_blocked` / `needs_manual_review` | `null` |
| `response_code` / `response_length` / `response_body_preview` | populated (body is a truncated summary) | `null` |
| `risk_level` | Derived from the verification verdict (High/Med/Low/Info) | Always `Low` (candidate only, unconfirmed) |
| Write-class (POST/PUT...) | Marked `needs_manual_review`, no request sent | Unchanged |

Decide `-rv` with the user/agent; do not silently enable it.

## 6. Interpretation pitfalls

- **`risk_level = Low` without `-rv` does NOT mean safe** — it means "unverified candidate".
- **`response_body_preview` is a truncated HTML-stripped summary**, not the raw response body.
- **`ai_vulns.operation_type` is always `null`** — used only for internal READ/WRITE routing, never persisted.
- `api_analysis_state.status` is the analysis pipeline state; do not confuse it with `ai_vulns.request_status`.
- A scan can take minutes to hours; poll or use `run_scan.sh` in the background.
- AI features (`-fp`, `-asia`) need a valid API key in `config/config.py`; without one the scan still runs but those features degrade or are skipped.

## 7. Boundaries

- JScanner2 is a scanner, not an exploiter: it extracts attack surface and (with `-rv`) verifies unauthorized access, but does not craft exploits.
- Only scan targets the operator owns or is authorized to test.
- Deep scans and AI analysis consume tokens and network traffic — keep scope tight.

Reference: [CLI contract and full parameter table](references/cli-contract.md)
