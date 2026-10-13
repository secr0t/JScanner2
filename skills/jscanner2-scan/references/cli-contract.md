# JScanner2 CLI contract and parameter reference

Loaded on demand when exact flags, exit semantics, or output-shape details are needed.
Keep the skill body (`SKILL.md`) as the primary reading; this file is the source of truth
for exact values. Verified against `parse_args.py`, `main.py`, `storage/db.py`.

## CLI usage

```
python main.py -u <url> [options]
```

Batch entry point: `bash run_scan.sh <urls.txt>` (or pipe the file via stdin).
Docker entry: `docker compose run --rm scanner /app/run_scan.sh urls.txt`.

## Parameters (verified against parse_args.py)

| Flag | Type / default | Purpose |
| --- | --- | --- |
| `-u, --url` | str, required | Target site URL (must include http/https) |
| `-H, --height` | int, default 2 | Recursive scan depth |
| `-t, --thread_num` | int, default 10 | Concurrent threads |
| `-p, --proxy` | str | Proxy, e.g. `http://127.0.0.1:7890` |
| `-v, --visible` | flag | Show the browser window (default headless) |
| `-fp, --findparam` | flag | Auto-parse API parameters (recommended) |
| `-fs, --fastscan` | flag | Fast-scan: HTTP-probe filter before AI analysis (recommended) |
| `-asir, --analyzeSensitiveInfoRex` | flag | Collect sensitive info from JS via regex |
| `-asia, --analyzeSensitiveInfoAI` | flag | Analyze sensitive info with AI |
| `-rv, --request-validation` | flag | Auto-send validation requests after AI analysis |
| `-nr, --no-request` | flag | Store AI results only, skip validation requests |

Recommended combo (matches `run_scan.sh` defaults): `-H 5 -fp -fs -asia`.

## Configuration

| File | Purpose |
| --- | --- |
| `config/config.py` | AI model endpoint, API keys, whitelist path, memory threshold, Feishu alerts, output paths |
| `config/models_config.json` | Model list configuration |
| `config/whiteList.txt` | Whitelisted domains |
| `setup.sh` | One-time setup (API keys, NLTK data) |

AI features (`-fp` / `-asia`) need a valid API key in `config/config.py`. Without one the
scan still runs but those features are unavailable.

## Database schema (verified against storage/db.py)

Default DB: `Result/JScanner_Result.db`.

### scan_results
Crawled URL base data: `id`, `url` (unique), `domain`, `path`, `source_url`, `scan_depth`, `created_at`.

### api_analysis_state
Per-API state machine, primary key `(scan_id, api_path)`:
`scan_id`, `api_path`, `js_url`, `status`, `attempt_count`, `last_error`, `run_id`, `created_at`, `updated_at`.

Valid `status` values: `DISCOVERED`, `CONTEXT_READY`, `AI_PENDING`, `AI_DONE`,
`VALIDATION_PENDING`, `VALIDATED` (only terminal success), plus retryable failures
`AI_FAILED`, `CONTEXT_FAILED`, `VALIDATION_FAILED`, `NO_CONTEXT`.

### ai_vulns
Vulnerability / unauthorized-access findings:
`id`, `js_url`, `api_endpoint`, `http_method`, `path`, `params` (JSON), `operation_type`
(**always null — never persisted**), `risk_level`, `vulnerability_type`, `evidence` (JSON),
`request_status`, `response_code`, `response_length`, `response_body_preview`, `scan_id`, `created_at`.

Field semantics:

| Field | When populated |
| --- | --- |
| `js_url` / `api_endpoint` / `http_method` / `path` / `params` / `evidence` / `scan_id` | AI analysis stage |
| `risk_level` | `Low` at insert; derived from verdict only after `-rv` validation |
| `request_status` | only after validation: `success` / `failed` / `dangerous_blocked`, or `needs_manual_review` for write-class APIs |
| `response_code` / `response_length` / `response_body_preview` | only after validation; body is a truncated HTML-stripped summary |
| `operation_type` | never (null) |

`evidence` JSON shape: `{"advisory": {...}, "dangerous": bool, "danger_reason": "..."}`.

### sensitive_info
`id`, `js_url`, `sensitive_value`, `context_code`, `caller_codes` (JSON), `risk_level`,
`secret_type`, `test_suggestion`, `ai_raw_analysis` (JSON), `created_at`.

### js_source_maps
`id`, `js_url` (unique), `is_sourceMap` (`Y`/`N`), `created_at`.

### visited_urls
`url` (primary key), `created_at`. Deduplication across runs.

## Query examples

```bash
# High-risk vulnerabilities
python -c "import sqlite3;c=sqlite3.connect('Result/JScanner_Result.db');[print(r) for r in c.execute('SELECT api_endpoint,http_method,risk_level FROM ai_vulns WHERE risk_level=\"High\"')]"

# Source map exposure
python -c "import sqlite3;c=sqlite3.connect('Result/JScanner_Result.db');[print(r) for r in c.execute('SELECT js_url,is_sourceMap FROM js_source_maps WHERE is_sourceMap=\"Y\"')]"

# API analysis state summary
python -c "import sqlite3;c=sqlite3.connect('Result/JScanner_Result.db');print(c.execute('SELECT status,COUNT(*) FROM api_analysis_state GROUP BY status').fetchall())"
```

## run_scan.sh behavior (batch mode)

- Reads URLs from the file (hot-reloadable; comments `#` and blanks skipped; deduped).
- Tracks done/failed URLs in `logs/scan_done_urls.txt` / `logs/scan_fail_urls.txt`.
- Heartbeat watchdog (`Result/heartbeat.json`): kills + resumes a URL that stalls
  (default 180 s, tunable via `STALL_TIMEOUT` env).
- Memory-safety overflow queue in `Overflow_Queue/` resumes remaining depth.
- Sends a Feishu notification when the whole batch finishes.
