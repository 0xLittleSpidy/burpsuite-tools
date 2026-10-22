---
name: sqlmap
description: >
  Comprehensive guide and technical reference for SQLMap command-line usage, options, techniques, and REST API integration. Use whenever generating SQLMap commands, configuring scan options, debugging SQLMap API issues, or implementing SQL injection testing with SQLMap.
---
# SQLMap Reference Skill

This skill provides comprehensive instructions, option mappings, injection techniques, and REST API references for sqlmap, the automated SQL injection and database takeover tool.

## Core Directives

1. **Option Formatting Standard**:
   - **CLI Flags**: In command-line invocations, flags use hyphenated lowercase format (e.g. `--time-sec`, `--no-cast`, `--hex`, `--force-ssl`, `--timeless`).
   - **REST API Keys**: In `sqlmapapi.py` (`/option/<taskid>/set` and `/scan/<taskid>/start`), option names use strict camelCase matching `optDict` (e.g. `timeSec`, `noCast`, `hexConvert`, `forceSSL`, `timeless`).
   - **CLI-Only vs API Options**: Some options are rejected by the REST API (e.g. `wizard`, `sqlShell`, `evalCode`, `alert`). Always verify that options submitted to `/option/<taskid>/set` exist in `/option/<taskid>/list`.

2. **Shell Quoting & Escaping**:
   - In generated CLI commands, all double-quoted arguments (such as `--data="..."`, `--cookie="..."`, `--headers="..."`) MUST have inner double quotes (`"`) escaped as `\"`.
   - Inner backslashes (`\`) MUST be escaped as `\\` before quotes are escaped.
   - Multiline request bodies or JSON strings MUST have literal carriage returns and newlines converted to whitespace so the command can be pasted and executed on a single line in terminal shells (bash, zsh, cmd.exe, PowerShell).

3. **Techniques Reference**:
   - **B**: Boolean-based blind
   - **E**: Error-based
   - **U**: UNION query-based
   - **S**: Stacked queries
   - **T**: Time-based blind
   - **Q**: Inline queries

4. **HTTP/2 Timeless Timing**:
   - On HTTP/2 targets that process concurrent streams, `--timeless` replaces artificial `SLEEP` delays with a jitter-immune concurrency oracle.
   - In CLI: `--timeless`
   - In REST API (supported engines): `"timeless": true`

## Detailed Documentation References

Detailed upstream documentation is stored in the `references/` directory:
- [usage.md](references/usage.md): Full official usage guide covering all command-line arguments, targets, request manipulation, injection boundaries, techniques, fingerprinting, enumeration, and takeover options.
- [rest-api.md](references/rest-api.md): Full REST API specification (`sqlmapapi.py`), including server administration, authentication, task creation, option inspection, scanning, status polling, and log retrieval.
- [techniques.md](references/techniques.md): Overview and mechanics of the supported SQL injection exploitation techniques.
- [faq.md](references/faq.md): Frequently asked questions, troubleshooting tips, and common operational scenarios.

## Common Option Mapping Table

| Feature / Category | CLI Switch | REST API Option Name | Value Type |
| --- | --- | --- | --- |
| Target URL | `-u URL` | `url` | string |
| HTTP Method | `--method=METHOD` | `method` | string |
| POST Data | `--data=DATA` | `data` | string |
| Cookie Header | `--cookie=COOKIE` | `cookie` | string |
| User-Agent | `--user-agent=AGENT` | `agent` | string |
| Referer | `--referer=REFERER` | `referer` | string |
| Extra Headers | `--headers=HEADERS` | `headers` | string |
| Test Parameter | `-p PARAM` | `testParameter` | string |
| Detection Level | `--level=LEVEL` (1-5) | `level` | integer |
| Risk Level | `--risk=RISK` (1-3) | `risk` | integer |
| Techniques | `--technique=TECH` | `technique` | string |
| Time Delay | `--time-sec=SECONDS` | `timeSec` | integer |
| Timeless Timing | `--timeless` | `timeless` | boolean |
| Disable Casting | `--no-cast` | `noCast` | boolean |
| Hex Conversion | `--hex` | `hexConvert` | boolean |
| Force SSL / HTTPS | `--force-ssl` | `forceSSL` | boolean |
| Batch Mode | `--batch` | `batch` | boolean |
| Proxy | `--proxy=URL` | `proxy` | string |
| Tor Socks5 | `--tor` | `tor` | boolean |
| Tor Port | `--tor-port=PORT` | `torPort` | integer |
| Tor Type | `--tor-type=TYPE` | `torType` | string |
| HTTP Param Pollution | `--hpp` | `hpp` | boolean |
| Threads | `--threads=NUM` | `threads` | integer |
| Delay Between Reqs | `--delay=SECONDS` | `delay` | float |
| Timeout | `--timeout=SECONDS` | `timeout` | float |
| Retries | `--retries=RETRIES` | `retries` | integer |
| Database Target | `-D DB` | `db` | string |
| Table Target | `-T TBL` | `tbl` | string |
| Column Target | `-C COL` | `col` | string |
| Dump Data | `--dump` | `dumpTable` | boolean |
| Get Banner | `-b` | `getBanner` | boolean |
| Current User | `--current-user` | `getCurrentUser` | boolean |
| Current Database | `--current-db` | `getCurrentDb` | boolean |
| Hostname | `--hostname` | `getHostname` | boolean |
| Is DBA Check | `--is-dba` | `isDba` | boolean |
