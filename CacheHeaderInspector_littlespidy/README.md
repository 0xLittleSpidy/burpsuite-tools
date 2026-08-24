# Cache Header Inspector (Burp Suite Extension)

**Author**: littlespidy  
*Created with the help of an AI Agent and littlespidy.*

---

## Overview

**Cache Header Inspector** is a Burp Suite extension (built on the modern Montoya API) designed to give security testers a real-time, interactive overview of HTTP caching behavior across target applications.

It allows you to aggregate, search, and filter unique cache directive values (e.g. `Cache-Control`, `Pragma`, `Expires`, `Age`, `ETag`, `Vary`, `X-Cache`, `CF-Cache-Status`) and immediately retrieve all associated URLs.

---

## Key Features

1. **Passive Real-Time Inspection**:
   - Intercepts and indexes response headers across all Burp tools (Proxy, Repeater, Scanner).
   - Tracks 12 essential caching headers:
     - `Cache-Control`
     - `Pragma`
     - `Expires`
     - `Age`
     - `ETag`
     - `Last-Modified`
     - `Vary`
     - `X-Cache`
     - `X-Cache-Hits`
     - `CDN-Cache-Control`
     - `Surrogate-Control`
     - `CF-Cache-Status`

2. **Directive Aggregation & URL Filtering**:
   - Groups responses by unique directive values with live URL counts (e.g. `max-age=0`, `no-store`, `public`, `private`, `(not set)`).
   - **Clicking any row** in the summary table instantly filters and displays all associated URLs.

3. **Built-in Master-Detail Viewer**:
   - Select any URL row to view the full, raw HTTP request and response in Burp's native Pretty/Raw/Hex editors.

4. **One-Click Proxy History Ingestion**:
   - `Load Proxy History` imports past traffic with optional **In-Scope Only** filtering.

5. **Quick Filter Chips & Search**:
   - Quick preset buttons for `no-store`, `no-cache`, `public`, `private`, `max-age=0`, `must-revalidate`, `stale-while-revalidate`, `HIT`, `MISS`, `(not set)`.
   - Free-form text search across header values.

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
