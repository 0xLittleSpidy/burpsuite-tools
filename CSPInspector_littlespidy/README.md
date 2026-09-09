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
   - **Method / Status / Content-Type Multi-Select**: MultiSelectFilterButton popups for rapid scoping.
   - **Keyword Filter**: Free-form text matching across policy strings and directive values.
   - **Reset Filters**: Instant one-click restoration of unconstrained views.

4. **Security Assessment & Visual Badging (Summary Table)**:
   - The summary table displays:
     - **Value**: The actual raw CSP header or directive value.
     - **Domains**: Comma-separated distinct hostnames with hover tooltip showing all domains.
     - **Count**: Number of endpoints enforcing this policy.
     - **Assessment**: Severity highlights (`CRITICAL`, `HIGH`, `MEDIUM`, `GOOD`, `STANDARD`).

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
