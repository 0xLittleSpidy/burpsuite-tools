# JS SourceMap Explorer (Burp Suite Extension)

**Author**: littlespidy  
*Created with the help of an AI Agent and littlespidy.*

---

## Overview

**JS SourceMap Explorer** is a Burp Suite extension built on the modern Montoya API to help security testers and bug bounty hunters analyze client-side JavaScript assets, automatically deduplicate scripts, classify 1st-party vs 3rd-party origins, detect exposed `.map` files (source maps) through passive inspection and on-demand active probing, inspect both JS and `.map` HTTP requests/responses, unpack original source trees, and automatically mine for hidden API endpoints and sensitive credentials across both raw JS and unpacked source maps.

---

### Key Features

1. **High-Performance Two-Stage Ingestion Pipeline & Live Status Strip**:
   - **Zero-Freeze Architecture**: Solves performance slowness and out-of-memory crashes when loading massive Burp Proxy histories (10,000+ entries).
   - **Stage 1 (Instant Ingestion)**: Rapidly filters and deduplicates scripts via `isKnownUrl(url)`, applies a 5MB response size ceiling to prevent heap exhaustion, performs instant framework detection and source map indicator extraction, and adds items directly to the UI without blocking.
   - **Stage 2 (Bounded Deep Mining)**: Bounded worker pool (`Math.max(2, Math.min(8, CPUs))`) mines regexes, endpoints, and secrets asynchronously in the background.
   - **Live Progress Bar Status Strip**: Real-time status strip at the top of the workspace shows live scan states (`● Idle`, `● Processing: ...`, `Deep scanning: X/Y (Z%)`) with a determinate 220x16 progress bar that auto-hides when tasks complete.

2. **Ghost-Js Secret Mining & Shannon Entropy Suppression**:
   - **40+ Curated Secret Signatures**: High-fidelity detection across Cloud (AWS, GCP, Azure, DigitalOcean, Cloudflare, Heroku), Payment (Stripe, PayPal, Square), CI/CD & DevOps (GitHub, GitLab, Bitbucket, Vercel, Netlify, npm), SaaS (Slack, Discord, SendGrid, Twilio, Mailgun, OpenAI), and Auth (JWTs, private keys).
   - **Confidence Tracking & Entropy Scoring**: Numeric confidence scores (70–98%) with Shannon entropy bit-per-character calculation (`shannon` / `calculate`) to eliminate low-entropy false positives.
   - **Interactive Signatures & Pattern Catalog (`📋 Signatures Catalog`)**: In-GUI dialog displaying all 48 supported signatures with their exact regular expressions, categories, confidence, and entropy requirements.
   - **Intelligent FP Suppression**: Suppresses documented tutorial sample credentials (`AKIAIOSFODNN7EXAMPLE`, `EXAMPLEKEY`), public-by-design keys (`pk_live_`, `pk_test_`, reCAPTCHA tokens), placeholder templates (`YOUR_API_KEY_HERE`, `change_me`), 32-hex hash collisions (with exemptions for legitimate 32-hex formats), repetitive character junk, and natural-language UI text.
   - **Exact Character Offsets**: Tracks `startOffset` and `endOffset` for every discovered secret and endpoint to enable instantaneous editor deep-linking.

3. **js-recon Advanced Techniques Integration**:
   - **Webpack Chunk Extractor**: Automatically parses Webpack runtime chunk-loading patterns (numeric object-maps, if-chains, and string-keyed hash maps) to statically discover and reconstruct hidden, lazy-loaded chunk bundle URLs.
   - **Framework Fingerprinting**: Detects Next.js, Nuxt.js, React, Vue.js, Svelte/SvelteKit, Angular, Vite HMR, and development servers from both URL patterns and script bodies. Displayed in a dedicated **`Framework`** column (column 2) in the main table.
   - **Inline Base64 Data URI Decoding**: Decodes embedded `data:application/json;base64,...` source maps in-memory without initiating external HTTP requests.
   - **Directory Traversal Protection**: Defensively sanitizes source map relative paths to prevent directory traversal exploits (`../../`) when reconstructing or exporting source trees.

4. **4-Pillar Deep-Linking Quad in Montoya Editors**:
   - Double-clicking or selecting any finding across **Paths**, **Secrets**, **Cloud URLs**, or **Dependencies** triggers the 4-pillar deep-linking quad:
     1. **Range Highlighting**: Attaches native Montoya markers (`Marker.marker(Range.range(start, end))`) to highlight the exact matched token.
     2. **Search Expression**: Syncs Burp's native editor search bar (`setSearchExpression(token)`) for quick navigation.
     3. **Caret Auto-Scroll**: Recursively traverses Swing editor components (`scrollTextComponent`) to bring the matched line into view.
     4. **Tab Focus**: Automatically switches focus to the matching `Request` or `Response` editor tab.

5. **Multi-Interval Selection & Burp Suite Native Tool Dispatch**:
   - Multi-interval row selection support across tables.
   - Native dispatch actions in context menus:
     - **`Send to Repeater`**
     - **`Send to Intruder`**
     - **`Send to Organizer`**
   - Available on the main JS scripts table, requests table, and detail viewers.

5. **Multi-Interval Selection & Burp Suite Native Tool Dispatch**:
   - Multi-interval row selection support across tables.
   - Native dispatch actions in context menus:
     - **`Send to Repeater`**
     - **`Send to Intruder`**
     - **`Send to Organizer`**
   - Available on the main JS scripts table, requests table, and detail viewers.

6. **Default-Enabled In-Scope Ingestion & Multi-Select Domain Filter (`In-Scope Only` & `Domains ▾`)**:
   - **Strict In-Scope Ingestion**: The **`In-Scope Only`** checkbox is **enabled by default** across both the Workspace tab and Recon & Secret Mining tab. Gated by both `item.request().isInScope()` and `api.scope().isInScope(url)`, preventing out-of-scope assets from flooding memory and the UI.
   - **Granular Multi-Select Domain Filter (`Domains ▾`)**: Sits directly adjacent to the `In-Scope Only` checkbox on the top toolbar in both the Workspace tab and Recon & Secret Mining tab.
     - **All Domains Selected by Default**: Automatically discovers and lists all target application hosts as traffic is ingested.
     - **Flexible Selection**: Users can select 1 or more specific target domains (or click "Select All" / "Clear") to instantly isolate specific subdomains and endpoints without modifying Burp Suite's global project scope.
     - **Subdomain-Aware**: Accurately matches both exact hostnames and subdomains (`api.target.com` matches `target.com`).

7. **Visual Tab Navigation**:
   - Clear emoji symbol prefixes across all suite tabs and sub-tabs:
     - `📖 Welcome & Guide`
     - `🗺️ JS & SourceMap Workspace`
     - `🔍 Recon & Secret Mining`
     - `✨ AI Security Analyst`
     - `🌲 Reconstructed Source Tree`
     - `📤 Request` / `📥 Response`
     - `🛣️ Paths`, `🔑 Secrets`, `💬 Comments`, `🛡️ Security Bypasses`, `☁️ Cloud URLs`, `📦 Dependencies`

8. **Automatic URL Deduplication**:
   - Duplicate JavaScript URLs and requests are automatically deduplicated by default so each script is tracked and analyzed once.

9. **Dedicated Exposed .map Filter**:
   - Dedicated **`[ ] Exposed .map Only`** standalone toggle checkbox in the filter toolbar to immediately filter for scripts with confirmed passive or active `.map` exposures.
   - Cleanly replaces former 1st-party / 3rd-party CDN radio boxes with the more precise `Domains ▾` filter.

10. **Separate Passive & On-Demand Active Probe Columns**:
    - **`Passive .map`**: Displays passive indicators:
      - `Found (Comment)`: `//# sourceMappingURL=...` or `/*# ... */` detected in the JS body.
      - `Found (Header)`: `SourceMap` or `X-SourceMap` HTTP response header found.
      - `Found (Inline Base64)`: Embedded inline Base64 data URI map found.
      - `Not Found`: No passive map indicators detected.
    - **`On-Demand Probe`**: Displays on-demand active probing results:
      - `-`: Not run yet.
      - `Pass (200 OK)`: Active `.map` probe succeeded (200 OK + valid SourceMap JSON).
      - `Fail (404/Error)`: Active probe returned 404 Not Found or error.

11. **Streamlined Workspace Views**:
    - **JS Workspace Tab**: Streamlined view showing `#`, `Framework`, `Status`, `Host`, `JS Path`, `Passive .map`, `On-Demand Probe`, `SourceMap Location`, `Unpacked Files`, and `Size`.
    - **Recon Tab Ingestion**: Includes the dedicated `Load Proxy History` button right next to `In-Scope Only` and `Domains ▾` multi-select filter.

12. **4-Way Raw HTTP Message Inspection**:
    - Select any script to view:
      - **`JS Request`** & **`JS Response`** in Burp's native Pretty/Raw/Hex editors.
      - **`SourceMap Request`** & **`SourceMap Response`** when a source map is found, probed, or unpacked.

13. **Dedicated Top-Level "Recon & Secret Mining" Suite Tab**:
    - Sequential request-first master-detail layout:
      - **Master Table (Top)**: Lists requests sequentially with method, URL, status, and counts of discovered paths, secrets, comments, security bypasses, cloud URLs, and dependencies.
      - **Bottom Detail Split**: Selecting any request updates native Montoya HTTP Request and Response editors on the left, paired with dedicated **Paths**, **Secrets**, **💬 Comments**, **🛡️ Security Bypasses**, **Cloud URLs**, and **Dependencies** tabs on the right.
    - **Multi-Select Technique, Category, and Header Filtering**:
      - **Top Filter Toolbar**: Includes `In-Scope Only` (enabled by default), `Domains ▾` multi-select button, `Method ▾`, `Status ▾` multi-select filter buttons, `Source Type` selector, and real-time search with 300ms debounce.
      - **Paths Tab**: Features `Method ▾` (GET, POST, etc.) and `Technique ▾` (Regex/Pattern, LinkFinder, etc.) multi-select buttons alongside search and TSV export.
      - **Secrets Tab**: Features `Category ▾`, `Signature ▾`, `Confidence ▾` multi-select buttons, search, and the `📋 Signatures Catalog` modal viewer.
      - **💬 Comments Tab**: Extracts all developer comments (single-line `//`, multi-line `/* */`, HTML `<!-- -->`) with line numbers, code offsets for Burp editor deep-linking, and category tags (`TODO/FIXME`, `Credentials/Auth`, `Debug/Config`, `General`), plus `Type ▾` and `Category ▾` multi-select filters.
      - **🛡️ Security Bypasses Tab (DOM XSS & Sanitizer Bypasses)**:
        - **Framework Detection**: Detects sanitization bypasses and dangerous sinks across **Angular** (`bypassSecurityTrustHtml`, `bypassSecurityTrustScript`, `bypassSecurityTrustStyle`, `bypassSecurityTrustUrl`, `bypassSecurityTrustResourceUrl`, `ɵɵtrustConstantHtml`, `$sce.trustAs*`), **React** (`dangerouslySetInnerHTML`), **Vue.js** (`v-html`, `domProps.innerHTML`, `{{{ }}}`), **Svelte** (`{@html ...}`), **Sanitizers & Policies** (`DOMPurify.sanitize` loose configs, `trustedTypes.createPolicy` passthrough), and **Vanilla DOM Sinks** (`innerHTML` / `outerHTML` assignments, `document.write`, `insertAdjacentHTML`, `eval()`, `new Function()`, `$.html()`).
        - **Intelligent FP Suppression**: Suppresses harmless empty innerHTML cleanups (`""`, `''`, `null`, `undefined`).
        - **Multi-Select Filtering**: `Framework ▾` and `Risk ▾` (Critical, High, Medium) multi-select buttons, full-text search, TSV export, and 4-pillar deep-linking quad into Burp editors.
      - **Cloud URLs Tab**: Features `Provider ▾` multi-select (AWS S3, Google Cloud Storage, Azure Blob, Firebase, etc.).
      - **Dependencies Tab**: Features `Status ▾` multi-select (Internal/Private, Unregistered/Hijackable, Safe/Registered, Unchecked) with in-Burp NPM registry verification.

14. **Download JavaScript File(s)**:
    - Save individual JavaScript files or batch-download hundreds of selected files to a target directory.
    - Automatic unique naming (`<cleanHost>_<id>_<filename>.js`) prevents overwriting scripts with identical names across different endpoints.

15. **AI Security Analyst (Local LLM & Antigravity CLI)**:
    - Dedicated **AI Security Analyst** tab with dual backend architecture:
      - **Local LLM (OpenAI-compatible REST API)**: Direct, zero-dependency integration with **Ollama** (`http://127.0.0.1:11434`), **LM Studio** (`http://127.0.0.1:1234`), or custom endpoints. Configurable model selection (`qwen2.5-coder`, `deepseek-coder`, `llama3.3`, etc.).
      - **Google Antigravity CLI (`agy`)**: Automated subprocess invocation of the `agy` CLI agent with local workspace directory context and real-time streaming output.
    - **Audit Presets**: Comprehensive Audit, DOM XSS & Client Injection, API & Auth Flaws, Hardcoded Secrets & Leakage, or Custom Prompts.

16. **Hover Cloud Tooltips & Right-Click Fast Actions**:
    - Complete untruncated values on cell hover.
    - Right-click actions for copying cell values, TSV rows, full URLs, and opening findings.

17. **In-Burp Source Tree Reconstructor & Offline VS Code Export**:
    - Full folder hierarchy reconstruction in an interactive `JTree`.
    - **`Export Project Tree to Disk...`** exports the entire unpacked frontend codebase to local disk for VS Code or terminal analysis.

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
