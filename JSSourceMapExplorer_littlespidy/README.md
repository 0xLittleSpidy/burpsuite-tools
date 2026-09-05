# JS SourceMap Explorer (Burp Suite Extension)

**Author**: littlespidy  
*Created with the help of an AI Agent and littlespidy.*

---

## Overview

**JS SourceMap Explorer** is a Burp Suite extension built on the modern Montoya API to help security testers and bug bounty hunters analyze client-side JavaScript assets, automatically deduplicate scripts, classify 1st-party vs 3rd-party origins, detect exposed `.map` files (source maps) through passive inspection and on-demand active probing, inspect both JS and `.map` HTTP requests/responses, unpack original source trees, and automatically mine for hidden API endpoints and sensitive credentials across both raw JS and unpacked source maps.

---

## Key Features

1. **Automatic URL Deduplication**:
   - Duplicate JavaScript URLs and requests are automatically deduplicated by default so each script is tracked and analyzed once.

2. **1st Party (App) vs 3rd Party (CDN/Trackers) Classification**:
   - Automatically separates your target application's proprietary JavaScript from external libraries, CDNs, and trackers (e.g. Google Analytics, Stripe, Sentry, Cloudflare, Recaptcha, Datadog).
   - Quick one-click radio filters: `All`, `1st Party (App)`, `3rd Party (CDN/Trackers)`, and `Exposed .map Only`.

3. **Separate Passive & On-Demand Active Probe Columns**:
   - **`Passive .map`**: Displays passive indicators:
     - `Found (Comment)`: `//# sourceMappingURL=...` or `/*# ... */` detected in the JS body.
     - `Found (Header)`: `SourceMap` or `X-SourceMap` HTTP response header found.
     - `Found (Inline Base64)`: Embedded inline Base64 data URI map found.
     - `Not Found`: No passive map indicators detected.
   - **`On-Demand Probe`**: Displays on-demand active probing results:
     - `-`: Not run yet.
     - `Pass (200 OK)`: Active `.map` probe succeeded (200 OK + valid SourceMap JSON).
     - `Fail (404/Error)`: Active probe returned 404 Not Found or error.

4. **Dedicated Recon Columns (JS vs SourceMap)**:
   - **`JS Recon (Paths / Keys)`**: Shows endpoints and secrets automatically discovered in the raw JavaScript file itself (e.g. `12 eps | 2 keys`).
   - **`Map Recon (Paths / Keys)`**: Shows endpoints and secrets discovered across all unpacked Source Map original files (e.g. `84 eps | 5 keys`).

5. **4-Way Raw HTTP Message Inspection**:
   - Select any script to view:
     - **`JS Request`** & **`JS Response`** in Burp's native Pretty/Raw/Hex editors.
     - **`SourceMap Request`** & **`SourceMap Response`** when a source map is found, probed, or unpacked.

6. **Dedicated Top-Level "Recon & Secret Mining" Suite Tab**:
   - Sequential request-first master-detail layout:
     - **Master Table (Top)**: Lists requests sequentially with method, URL, status, origin, and counts of discovered paths, secrets, cloud URLs, and dependencies.
     - **Bottom Detail Split**: Selecting any request updates native Montoya HTTP Request and Response editors on the left, paired with dedicated **Paths**, **Secrets**, **Cloud URLs**, and **Dependencies** tabs on the right.
   - **Multi-Select Technique & Category Filtering**:
     - **Paths Tab**: Features `Method ▾` (GET, POST, etc.) and `Technique ▾` (Regex/Pattern, LinkFinder, etc.) multi-select buttons alongside search and TSV export.
     - **Secrets Tab**: Features `Category ▾` (JWT, Google API Key, AWS Keys, Slack, etc.) and `Confidence ▾` multi-select buttons.
     - **Cloud URLs Tab**: Features `Provider ▾` multi-select (AWS S3, Google Cloud Storage, Azure Blob, Firebase, etc.).
     - **Dependencies Tab**: Features `Status ▾` multi-select (Internal/Private, Unregistered/Hijackable, Safe/Registered, Unchecked) with in-Burp NPM registry verification.
   - Top-level toolbar with Source Type (`All Sources`, `JS Files Only`, `SourceMap Files Only`), HTTP Status filter, and full-text search.

7. **Download JavaScript File(s)**:
   - Save individual JavaScript files or batch-download hundreds of selected files to a target directory.
   - Automatic unique naming (`<cleanHost>_<id>_<filename>.js`) prevents overwriting scripts with identical names across different endpoints.
   - Available via the workspace toolbar, right-click context menu on `Discovered JavaScript Scripts`, and right-click context menu in the `Recon & Secret Mining` requests table.

8. **AI Security Analyst (Local LLM & Antigravity CLI)**:
   - Dedicated **AI Security Analyst** tab with dual backend architecture:
     - **Local LLM (OpenAI-compatible REST API)**: Direct, zero-dependency integration with **Ollama** (`http://127.0.0.1:11434`), **LM Studio** (`http://127.0.0.1:1234`), or custom endpoints. Configurable model selection (`qwen2.5-coder`, `deepseek-coder`, `llama3.3`, etc.).
     - **Google Antigravity CLI (`agy`)**: Automated subprocess invocation of the `agy` CLI agent with local workspace directory context and real-time streaming output.
   - **Audit Presets**: Comprehensive Audit, DOM XSS & Client Injection, API & Auth Flaws, Hardcoded Secrets & Leakage, or Custom Prompts.
   - **One-Click Triggers**:
     - `🤖 Analyze with AI...` in workspace toolbar and table context menu.
     - `🤖 Analyze with AI...` in Recon Mining requests table context menu.
     - `🤖 AI Review` button in Source Tree code viewer.
   - Markdown report export (`.md`) and clipboard copying.

9. **Hover Cloud Tooltips**:
   - Hovering over any truncated table cell (long URL, file path, secret token, or endpoint route) displays a formatted HTML cloud popup box showing the complete, untruncated value.

10. **Right-Click Context Menu & Fast Copying**:
    - Right-click any row or cell across all tables to immediately access:
      - **`Copy Cell Value`**: Copies the exact string under the cursor.
      - **`Copy Full JS URL`** / **`Copy SourceMap URL`** / **`Copy Route`** / **`Copy Secret`**.
      - **`Copy Selected Row(s) as TSV`**.
      - Quick shortcuts to trigger on-demand `.map` probing, unpacking, JS download, or AI analysis.

11. **In-Burp Source Tree Reconstructor & Code Viewer**:
    - Parses SourceMap v3 JSON.
    - Reconstructs the full original folder hierarchy (supporting Webpack, Vite, Turbopack, Rollup, etc.) inside an interactive `JTree`.
    - Monospace code editor with line numbers, code copy, and individual file save tools.

12. **Offline Export for VS Code**:
    - **`Export Project Tree to Disk...`** writes the entire reconstructed source code directory structure to a folder on your local machine so you can open and analyze it in VS Code, WebStorm, or command-line grep tools.

---

## Building the Extension

To compile the standalone JAR file:

```bash
cd /home/littlespidy/myextra/burpsuite/JSSourceMapExplorer_littlespidy
./gradlew jar
```

The output JAR will be generated at:
```
build/libs/js-sourcemap-explorer-littlespidy-1.0.0.jar
```

---

## Installation in Burp Suite

1. Open **Burp Suite**.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. Set **Extension Type** to `Java`.
5. Select the compiled JAR:
   ```
   /home/littlespidy/myextra/burpsuite/JSSourceMapExplorer_littlespidy/build/libs/js-sourcemap-explorer-littlespidy-1.0.0.jar
   ```
6. Click **Next** -> the **JS Explorer** tab will appear in Burp's top navigation bar.
