# CSP Inspector (Burp Suite Extension)

**Author**: littlespidy  
*Created with the help of an AI Agent and littlespidy.*

---

## Overview

**CSP Inspector** is a Burp Suite extension built on the modern Montoya API to audit, group, and analyze **Content Security Policy (CSP)** implementations across target web applications.

It empowers penetration testers and security researchers to rapidly identify:
- Endpoints completely **missing CSP** protection.
- High-risk source directives like `'unsafe-inline'` and `'unsafe-eval'`.
- Overly permissive **wildcards** (`*`, `https://*`, `http://*`, `data:`, `blob:`).
- Clickjacking vulnerability surfaces (missing or weak `frame-ancestors`).
- Legacy/test configurations via `Content-Security-Policy-Report-Only`.

---

## Key Features

1. **On-Demand Proxy History Ingestion & Automatic Deduplication**:
   - Ingests HTTP responses on demand via **"Load Proxy History"** using a background `SwingWorker` (zero UI freezing).
   - Automatically deduplicates targets by `HTTP Method + URL`, collapsing duplicate hits into clean, unique records.
   - Dynamic **In-Scope Only** filtering during or after import.

2. **Multi-Mode Directive Breakdown**:
   - **Full Policy View**: Groups endpoints by identical full CSP policy strings.
   - **Directive Views**: Analyze specific directives (`script-src`, `default-src`, `frame-ancestors`, `object-src`, `base-uri`, `form-action`, `style-src`, `connect-src`, `img-src`, `font-src`, `report-uri`).
   - **All Sources / Tokens View**: Deconstructs every individual source expression across all directives.
   - **CSP-Report-Only View**: Inspects report-only headers.

3. **Multi-Faceted Triage Filtering**:
   - **Status Code**: Exact codes, comma-separated lists (`200, 302, 404`), or status wildcards (`2xx`, `3xx`, `4xx`, `5xx`).
   - **Content-Type**: Substring matching (`html`, `json`, `text`, `javascript`) to isolate web pages from API endpoints.
   - **Keyword Filter**: Free-form text matching across policy strings and directive values.
   - **Quick Presets**: One-click chips for `'unsafe-inline'`, `'unsafe-eval'`, `data:`, `*`, `(missing CSP)`, `CSP-Report-Only`, `frame-ancestors 'none'`, and `object-src 'none'`.
   - **Reset Filters**: Instant one-click restoration of unconstrained views.

4. **Security Assessment & Visual Badging**:
   - The summary table automatically classifies findings with severity highlights:
     - `CRITICAL`: Missing CSP protection entirely.
     - `HIGH`: Directives permitting `'unsafe-inline'` script execution.
     - `MEDIUM`: Directives permitting `'unsafe-eval'`, wildcards (`*`), or `data:` / `blob:` schemes.
     - `GOOD`: Directives enforcing strict clickjacking defense (`frame-ancestors 'none'` / `'self'`) and restricted plugins (`object-src 'none'`).

5. **Integrated Master-Detail Viewer**:
   - Select any URL row to view the full, raw HTTP request and response in Burp's native Pretty/Raw/Hex editors without leaving the tab.

6. **Export Capabilities**:
   - `Ctrl+C` / `Cmd+C` on any table to copy selected rows as tab-separated values (TSV) to the clipboard.
   - One-click `Export TSV` button to export all currently displayed URL records to clipboard.

---

## Building the Extension

To compile the standalone JAR:

```bash
cd /home/littlespidy/myextra/burpsuite/CSPInspector_littlespidy
./gradlew clean build
```

The output JAR will be generated at:
```
build/libs/csp-inspector-littlespidy-1.0.0.jar
```

---

## Installation in Burp Suite

1. Open **Burp Suite**.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. Set **Extension Type** to `Java`.
5. Select the compiled JAR file (`build/libs/csp-inspector-littlespidy-1.0.0.jar`).
6. Click **Next** -> the **CSP Inspector** tab will appear in Burp's top navigation bar.
7. Click **Load Proxy History** to import and audit your captured targets!
