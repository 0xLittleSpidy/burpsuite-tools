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

---

## 🛠️ Included Extensions

### 1. [JS SourceMap Explorer](file:///home/littlespidy/myextra/burpsuite/JSSourceMapExplorer_littlespidy)
- **1st Party vs 3rd Party Classification**: Automatically distinguishes target app scripts from external CDNs, analytics, and trackers.
- **Passive & Active .map Detection**: Detects `//# sourceMappingURL=...` trailing comments, response headers, inline Base64 data URIs, and supports on-demand batch `.map` active probing.
- **In-Burp Unpacker & Source Tree Reconstructor**: Parses SourceMap v3 JSON, reconstructs original repository directory hierarchies (`webpack:///`, `vite://`, etc.), and provides a built-in monospace source code editor.
- **Offline VS Code Export**: One-click export of the entire reconstructed frontend source tree to disk.
- **Dedicated Recon & Secret Mining**: Automated regex extraction of hidden `/api/...` routes, GraphQL queries, JWTs, API keys, AWS tokens, and developer notes with TSV clipboard export.
- **Hover Cloud Tooltips & Right-Click Copying**: Fast copying of cells, full URLs, and context snippets.

### 2. [Cache Header Inspector](file:///home/littlespidy/myextra/burpsuite/CacheHeaderInspector_littlespidy)
- **Passive Cache Header Monitoring**: Passively intercepts responses and indexes 12 key caching & CDN response headers (`Cache-Control`, `Pragma`, `Expires`, `Age`, `ETag`, `Last-Modified`, `Vary`, `X-Cache`, `CF-Cache-Status`, etc.).
- **Directive Aggregation & URL Filtering**: Groups responses by unique directive values (e.g. `max-age=0`, `no-store`, `public`, `private`) and shows all associated URLs on click.
- **Master-Detail Request/Response Viewer**: Embedded Montoya Pretty/Raw/Hex editors for selected URLs.
- **Proxy History Ingestion & TSV Export**: Background loading and clipboard export.

### 3. [Convert POST to GET](file:///home/littlespidy/myextra/burpsuite/ConvertPostToGet_littlespidy)
- Converts POST request bodies (JSON, Form-URL-Encoded, Multipart, Query) into GET requests for testing HTTP method overrides and AuthZ bypasses.

### 4. [Input Validation Fuzzer](file:///home/littlespidy/myextra/burpsuite/InputValidationFuzzer_littlespidy)
- Multi-parameter input validation testing across URL query, body, and header insertion points.

---

## 🧩 Bambdas & BChecks

- **[`bambdas/`](file:///home/littlespidy/myextra/burpsuite/bambdas)**: Custom actions, scan checks, filter scripts, and match-and-replace rules.
- **[`BChecks/`](file:///home/littlespidy/myextra/burpsuite/BChecks)**: Custom passive and active Burp Scanner checks.
- **[`ExtensionTemplateProject/`](file:///home/littlespidy/myextra/burpsuite/ExtensionTemplateProject)**: Starter template for modern Java Montoya API extensions.

---

## ⚙️ Building

Each extension is Gradle-based (Java 17/21). To build any extension JAR:

```bash
cd <ExtensionDirectory>
./gradlew jar
```

Compiled JARs are output to `build/libs/<name>-1.0.0.jar`.
