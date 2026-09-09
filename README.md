# burpsuite-tools

A curated collection of Burp Suite extensions, Bambdas, and custom scan checks (BChecks) designed for modern web application security testing and bug bounty hunting.

---

## 📦 Downloads (Pre-built JARs)

Pre-compiled extension JARs are available for download from the [Latest Release (v1.0.0)](https://github.com/0xLittleSpidy/burpsuite-tools/releases/tag/v1.0.0):

| Extension | Direct JAR Download | Description |
| :--- | :--- | :--- |
| **JS SourceMap Explorer** | [📥 `js-sourcemap-explorer-littlespidy-1.0.0.jar`](https://github.com/0xLittleSpidy/burpsuite-tools/releases/download/v1.0.0/js-sourcemap-explorer-littlespidy-1.0.0.jar) | SourceMap reconstructor, hidden route miner, VS Code export |
| **Cache Header Inspector** | [📥 `cache-header-inspector-littlespidy-1.0.0.jar`](https://github.com/0xLittleSpidy/burpsuite-tools/releases/download/v1.0.0/cache-header-inspector-littlespidy-1.0.0.jar) | Passive CDN & cache header indexing and directive analysis |
| **Convert POST to GET** | [📥 `convert-post-to-get-littlespidy-1.0.0.jar`](https://github.com/0xLittleSpidy/burpsuite-tools/releases/download/v1.0.0/convert-post-to-get-littlespidy-1.0.0.jar) | Request body to GET query converter for auth bypass testing |
| **Input Validation Fuzzer** | [📥 `input-validation-fuzzer-littlespidy-1.0.0.jar`](https://github.com/0xLittleSpidy/burpsuite-tools/releases/download/v1.0.0/input-validation-fuzzer-littlespidy-1.0.0.jar) | Multi-point input validation and boundary fuzzer |
| **Response Inspector** | [📥 `response-inspector-littlespidy-1.0.0.jar`](file:///home/littlespidy/myextra/burpsuite/ResponseInspector_littlespidy/build/libs/response-inspector-littlespidy-1.0.0.jar) | Response analyzer for passwords, strict SSNs, internal IPs, OS server paths, errors, and secrets |
| **JWT Comparator** | [📥 `jwt-comparator-littlespidy-1.0.0.jar`](file:///home/littlespidy/myextra/burpsuite/JWTComparator_littlespidy/build/libs/jwt-comparator-littlespidy-1.0.0.jar) | Dynamic N-token JWT side-by-side comparator, claim diff matrix, timestamp translator |
| **CSP Inspector** | [📥 `csp-inspector-littlespidy-1.0.0.jar`](file:///home/littlespidy/myextra/burpsuite/CSPInspector_littlespidy/build/libs/csp-inspector-littlespidy-1.0.0.jar) | Content Security Policy auditor, raw value and affected domain indexer |
| **HSTS Inspector** | [📥 `hsts-inspector-littlespidy-1.0.0.jar`](file:///home/littlespidy/myextra/burpsuite/HSTSInspector_littlespidy/build/libs/hsts-inspector-littlespidy-1.0.0.jar) | HTTP Strict Transport Security auditor, raw value and affected domain indexer |

---

## 🛠️ Included Extensions

### 1. [JS SourceMap Explorer](file:///home/littlespidy/myextra/burpsuite/JSSourceMapExplorer_littlespidy)
- **High-Performance Two-Stage Ingestion Pipeline**: Eliminates proxy history loading freezes via instantaneous Stage 1 deduplication/ingestion and bounded multi-threaded Stage 2 deep mining with a live progress bar.
- **Ghost-Js Secret Mining & Shannon Entropy Suppression**: 40+ curated secret patterns with Severity & Confidence tracking, Shannon entropy heuristic, exact character offsets, and false-positive suppression of sample keys, public tokens, and hashes.
- **js-recon Advanced Techniques**: Webpack chunk extractor (object maps, if-chains, string-keyed maps), framework fingerprinting (Next.js, Nuxt.js, React, Vue, Svelte, Angular, Vite), inline Base64 data URI decoding, and directory traversal protection.
- **4-Pillar Deep-Linking Quad**: Double-clicking any secret, endpoint, cloud URL, or dependency automatically marks range offsets in native Montoya editors, syncs search, scrolls caret to view, and activates the request/response tab.
- **Tool Dispatch & Row Pinning**: Multi-interval row selection with `Send to Repeater`, `Send to Intruder`, and `Send to Organizer`, plus row pinning (`📌 Pin Selected`) with amber highlighting.
- **1st Party vs 3rd Party Classification**: Automatically distinguishes target app scripts from external CDNs, analytics, and trackers.
- **Passive & Active .map Detection**: Detects `//# sourceMappingURL=...` trailing comments, response headers, inline Base64 data URIs, and supports on-demand batch `.map` active probing.
- **In-Burp Unpacker & Source Tree Reconstructor**: Parses SourceMap v3 JSON, reconstructs original repository directory hierarchies (`webpack:///`, `vite://`, etc.), and provides a built-in monospace source code editor with offline VS Code export.

### 2. [Cache Header Inspector](file:///home/littlespidy/myextra/burpsuite/CacheHeaderInspector_littlespidy)
- **Passive Cache Header Monitoring**: Passively intercepts responses and indexes 12 key caching & CDN response headers (`Cache-Control`, `Pragma`, `Expires`, `Age`, `ETag`, `Last-Modified`, `Vary`, `X-Cache`, `CF-Cache-Status`, etc.).
- **Directive Aggregation & URL Filtering**: Groups responses by unique directive values (e.g. `max-age=0`, `no-store`, `public`, `private`) and shows all associated URLs on click.
- **Master-Detail Request/Response Viewer**: Embedded Montoya Pretty/Raw/Hex editors for selected URLs.
- **Proxy History Ingestion & TSV Export**: Background loading and clipboard export.

### 3. [Convert POST to GET](file:///home/littlespidy/myextra/burpsuite/ConvertPostToGet_littlespidy)
- Converts POST request bodies (Form-URL-Encoded, JSON top-level keys, Multipart, Query) into GET requests for testing HTTP method overrides, CSRF bypasses, and AuthZ flaws.
- **Core Four Triage Filters**: `MultiSelectFilterButton`s for Status Code, Content-Type, and Parameter Location, non-destructive live `In-Scope Only` gating, and sanitized domain matching.
- **Burp-Style Search & Presets**: Regex, case sensitivity, and negative/inversion matching across endpoints; quick preset chips (`[JSON Payloads]`, `[Form Encoded]`, `[Has Auth / Token]`).
- **Collapsible Smart Filter Sidebar (500px)**: Hashed signature suppression (`status:length:contentType`) to auto-hide repetitive generic responses and highlight 403 $\rightarrow$ 200 bypasses.
- **4-Pillar Deep-Linking Quad**: Auto-switches between Request/Response tabs, renders native Montoya yellow/orange highlight markers on migrated parameters, syncs search, and scrolls the viewport directly to findings.
- **Burp Interoperability & Row Pinning**: Right-click `Send to Repeater` (`METHOD host/path`), `Send to Intruder`, and `Send to Organizer`, with row pinning (`Pin Selected`) and ambient status completion glyphs (`⚠️` / `✔`).

### 4. [Input Validation Fuzzer](file:///home/littlespidy/myextra/burpsuite/InputValidationFuzzer_littlespidy)
- Multi-parameter input validation testing across URL query, body, and header insertion points.

### 5. [Response Inspector](file:///home/littlespidy/myextra/burpsuite/ResponseInspector_littlespidy)
- **5 Dedicated Tabs**: Welcome & Guide, Passwords, PII & Server Paths & Internal IPs, Errors & Exceptions, and Secrets & Tokens.
- **Multi-Threaded Ingestion Pool**: High-speed parallel proxy history scanning via bounded thread pools (`ExecutorService`) with atomic progress tracking and non-blocking batch UI updates.
- **Two-Stage Refiner Regex Engine**: Ported from `sensitive-discoverer` to eliminate regex backtracking: matches fast anchor suffixes and scans look-back windows to extract complete S3 buckets, Azure Blobs, Firebase DBs, Google OAuth IDs, and Teams webhooks.
- **MIME Blacklisting & Size Guard**: Bypasses images, audio, video, flash, and fonts plus responses > 10MB to achieve ~80% scan speedup and zero binary false positives.
- **Multi-Section Scanning & TSV Export**: Analyzes both `Response Headers` and `Response Body`; includes dedicated **`Export TSV`** toolbar button and clipboard TSV export (`Ctrl+C`).
- **Granular In-Scope Domain Selection**: Multi-checkbox search dialog allowing users to pick specific in-scope target subdomains/hosts instead of an all-or-nothing scope gate.
- **Target Password Prompting & Config**: Prominent `Configure Passwords...` modal dialog with text pasting, import from wordlists, and case sensitivity controls.
- **Strict SSN & OS Server Path Extraction**: Validates US SSN area/group/serial formats and extracts real OS server filesystem paths (`/etc/`, `/var/log/`, `C:\inetpub\...`, UNC shares) while discarding normal web routes.
- **Comprehensive Error & Token Signatures**: Database leaks, stack traces, cloud tokens (AWS, GCP, GitHub, Slack, Stripe, OpenAI, Square, Mailgun, NuGet, JWTs, .env) with 4-pillar deep-linking.

### 6. [JWT Comparator](file:///home/littlespidy/myextra/burpsuite/JWTComparator_littlespidy)
- **Dynamic $N$-Token Comparison Matrix**: Compare 2, 3, 4, or more JWT tokens simultaneously across different domains or user roles with color-coded diff statuses (Amber: value mismatch, Soft Red: partially missing, Neutral: identical).
- **On-Demand Context Menu Extraction**: Right-click any HTTP request or response in Burp (Proxy, Repeater, Logger) to instantly send tokens to specific slots or new slots, with auto-detection from `Authorization: Bearer`, cookies, request/response bodies, or text selections.
- **Differences Only Focused Triage**: Toggle between `All Claims` and `Differences Only` to immediately eliminate noise and isolate divergence in roles, scopes, permissions, tenants, or algorithms.
- **Epoch Timestamp & Expiration Inspector**: Translates Unix epoch timestamps (`exp`, `iat`, `nbf`, `auth_time`) into human-readable UTC/Local dates with active/expired relative status.
- **Detailed Claim Inspector & Decoded Viewers**: Deep-inspect complex nested JSON claims in dedicated per-token tabs and view pretty-printed JSON.
- **One-Click TSV Export**: Export the entire comparison matrix to clipboard as TSV for bug bounty and audit reports.
- **Welcome & Guide Dashboard**: Integrated onboarding tab with tutorial cards and workflow recommendations.

### 7. [CSP Inspector](file:///home/littlespidy/myextra/burpsuite/CSPInspector_littlespidy)
- **Raw Policy & Affected Domain Summary**: Grouping table showing the actual raw CSP header, comma-separated distinct affected hostnames, URL counts, and security posture assessment.
- **Directive & Source Breakdown**: Inspect individual directive tokens (`script-src`, `frame-ancestors`, `object-src`, etc.) across all responses.
- **Multi-Select Triage Toolbar**: Dynamic multi-select popup buttons for Method, Status Code, and Content-Type filtering.

### 8. [HSTS Inspector](file:///home/littlespidy/myextra/burpsuite/HSTSInspector_littlespidy)
- **Raw HSTS Header & Affected Domain Overview**: Aggregates endpoints by raw Strict-Transport-Security header value, listing distinct affected hostnames, occurrence counts, and color-coded security assessments.
- **Inspection Modes**: Filter by full header, max-age thresholds, `includeSubDomains`, `preload` readiness, or completely missing HSTS.
- **Master-Detail Request/Response Viewer**: Embedded native Montoya editors for selected endpoints.

---

## 🧩 Bambdas & BChecks

- **[`bambdas/`](file:///home/littlespidy/myextra/burpsuite/bambdas)**: Custom actions, scan checks, filter scripts, and match-and-replace rules.
- **[`BChecks/`](file:///home/littlespidy/myextra/burpsuite/BChecks)**: Custom passive and active Burp Scanner checks.
- **[`ExtensionTemplateProject/`](file:///home/littlespidy/myextra/burpsuite/ExtensionTemplateProject)**: Starter template for modern Java Montoya API extensions.

---

## 🧠 Custom Agent Skills

- **[`burp-suite-creator`](file:///home/littlespidy/myextra/burpsuite/.agents/skills/burp-suite-creator/SKILL.md)**: Generates Burp Suite tools, Montoya API extensions, Bambdas, and BChecks based on security testing scenarios.
- **[`sensitive-pattern-extractor`](file:///home/littlespidy/myextra/burpsuite/.agents/skills/sensitive-pattern-extractor/SKILL.md)**: Catalog and refiners for sensitive tokens, cloud storage URLs, credentials, and keywords stored in **[`patterns.md`](file:///home/littlespidy/myextra/burpsuite/.agents/skills/sensitive-pattern-extractor/patterns.md)**.

---

## ⚙️ Building

Each extension is Gradle-based (Java 17/21). To build any extension JAR:

```bash
cd <ExtensionDirectory>
./gradlew jar
```

Compiled JARs are output to `build/libs/<name>-1.0.0.jar`.
