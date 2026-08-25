# Cache Header Inspector (Burp Suite Extension)

**Author**: littlespidy  
*Created with the help of an AI Agent and littlespidy.*

---

## Overview

**Cache Header Inspector** is a Burp Suite extension (built on the modern Montoya API) designed to give security testers a real-time, interactive overview of HTTP caching behavior across target applications.

It allows you to aggregate, search, and filter unique cache directive values (e.g. `Cache-Control`, `Pragma`, `Expires`, `Age`, `ETag`, `Vary`, `X-Cache`, `CF-Cache-Status`) and immediately retrieve all associated URLs.

---

## Key Features

1. **On-Demand Proxy History Ingestion & Automatic Deduplication**:
   - Ingests requests and responses directly from Burp Proxy history on demand via the **"Load Proxy History"** button.
   - Automatically deduplicates entries by HTTP method + URL, collapsing repeat visits into unique endpoint records.
   - Optional **In-Scope Only** filtering during or after import.

2. **12 Indexed Caching & CDN Headers**:
   - Tracks: `Cache-Control`, `Pragma`, `Expires`, `Age`, `ETag`, `Last-Modified`, `Vary`, `X-Cache`, `X-Cache-Hits`, `CDN-Cache-Control`, `Surrogate-Control`, and `CF-Cache-Status`.

3. **Directive Aggregation & URL Grouping**:
   - Groups responses by unique directive values with live URL counts (e.g. `max-age=0`, `no-store`, `public`, `private`, `(not set)`).
   - **Clicking any row** in the summary table instantly filters and displays all associated URLs.

4. **Multi-Faceted Triage Filtering**:
   - **Status Code**: Filter by exact code or comma-separated lists (`200, 302, 404`) and status wildcards (`2xx`, `3xx`, `4xx`, `5xx`).
   - **Content-Type**: Substring matching (`json`, `html`, `text`, `image`) to isolate APIs or static assets.
   - **Directive Value**: Free-form text and preset chips (`no-store`, `no-cache`, `public`, `private`, `max-age=0`, `must-revalidate`, `stale-while-revalidate`, `HIT`, `MISS`, `(not set)`).
   - **Scope**: Toggle in-scope targets dynamically.

5. **Built-in Master-Detail Viewer**:
   - Select any URL row to view the full, raw HTTP request and response in Burp's native Pretty/Raw/Hex editors without leaving the tab.

6. **Export Capabilities**:
   - Copy selected rows as TSV using `Ctrl+C` / `Cmd+C`.
   - One-click `Export TSV` button to export all filtered URLs to system clipboard.

---

## Building the Extension

To compile the standalone JAR file:

```bash
cd /home/littlespidy/myextra/burpsuite/CacheHeaderInspector_littlespidy
./gradlew jar
```

The output JAR will be generated at:
```
build/libs/cache-header-inspector-littlespidy-1.0.0.jar
```

---

## Installation in Burp Suite

1. Open **Burp Suite**.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. Set **Extension Type** to `Java`.
5. Select the compiled JAR file (`build/libs/cache-header-inspector-littlespidy-1.0.0.jar`).
6. Click **Next** -> the **Cache Inspector** tab will appear in Burp's top navigation bar.
