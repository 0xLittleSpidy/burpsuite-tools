# Header Inspector (Montoya Edition)

> **Created with the help of an AI Agent and littlespidy.**

A consolidated, high-performance Burp Suite extension (Montoya API) unifying HTTP header collection, method auditing, status code intelligence, caching behavior analysis, Content Security Policy (CSP) auditing, and HTTP Strict Transport Security (HSTS) validation into a single suite interface with synchronized on-demand Proxy history ingestion.

---

## 🌟 Key Features

### 1. 📋 Header Collector
* **Dual-Direction Header Indexing**: Passively parses and aggregates both HTTP Request and Response headers.
* **Granular Grouping**: Groups all unique header values under their respective header names (e.g. `Server`, `Authorization`, `Cache-Control`, `Set-Cookie`).
* **Domain Association**: Identifies and links every unique header name-value pair with all associated target hostnames and domains.
* **Master-Detail Layout**: Top master table displays headers and summary counts; selecting a header displays all distinct values, associated domains, and endpoint frequencies.
* **4-Pillar Deep-Linking**: Selecting any unique header value automatically switches to the Request or Response editor, paints native yellow/orange highlight markers over the header line, populates the search bar, and highlights the finding.
* **Offline http.dev Header Knowledge Base**: Embedded offline reference with 307 HTTP headers, directives, syntax, and RFC specifications.
* **Interoperability & Export**: Right-click `Send to Repeater`, `Send to Intruder`, and `Send to Organizer`, plus one-click TSV export to clipboard (`Ctrl+C` or toolbar button).

### 2. ⚡ Method Collector (NEW)
* **HTTP Verb Aggregation**: Automatically aggregates and inventories all HTTP request methods (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`, `HEAD`, `TRACE`, `CONNECT`, `QUERY`, `PRI`, and custom/WebDAV verbs).
* **RFC Semantics & Properties**: Immediately classifies methods with RFC 9110 **Safe** (Yes/No), **Idempotent** (Yes/No), and **Cacheable** (Yes/No/Conditional) properties.
* **Endpoint & Domain Correlation**: For each method, lists all endpoints called, target hostnames, request counts, and associated response status codes.
* **Master-Detail Deep-Linking**: Selecting an endpoint immediately loads the request/response pair into Montoya editors with yellow highlight markers directly on the request verb.
* **Offline http.dev Method Knowledge Base**: Includes a dedicated `📖 Method Explained (http.dev)` panel embedding official explanations, request body rules, idempotency considerations, and RFC specifications.

### 3. 🔢 Status Collector (NEW)
* **Response Status Intelligence**: Aggregates all HTTP response status codes observed in traffic across all domains and endpoints.
* **Class & Vendor Classification**: Groups status codes by class (`1xx Informational`, `2xx Success`, `3xx Redirection`, `4xx Client Error`, `5xx Server Error`) and detects vendor-specific codes (Cloudflare `520`-`530`, Nginx `444`/`494`-`499`, Microsoft `440`/`449`, Akamai, Edgio, LinkedIn `999`).
* **Actionable Meanings & Client Actions**: Surfaces immediate recommended client actions (e.g. retry strategies, backoff rules, redirect handling).
* **Master-Detail Deep-Linking**: Selecting an endpoint immediately loads the request/response pair with yellow highlight markers on the HTTP status line.
* **Offline http.dev Status Knowledge Base**: Embedded offline reference covering 136 HTTP status codes with in-depth SEO/indexing impact, caching rules, and RFC specifications in the `📖 Status Explained (http.dev)` panel.

### 4. 🗄️ Cache Inspector
* **Passive Cache & CDN Header Monitoring**: Indexes 12 key caching headers (`Cache-Control`, `Pragma`, `Expires`, `Age`, `ETag`, `Last-Modified`, `Vary`, `X-Cache`, `CF-Cache-Status`, etc.).
* **Directive Aggregation**: Groups unique endpoints by directive values (e.g. `no-store`, `max-age=0`, `public`, `private`).
* **Multi-Select Filtering**: Filter simultaneously by HTTP Method, Status Code, and Content-Type.

### 5. 🛡️ CSP Inspector (Inbuilt Google CSP Evaluator Engine)
* **100% Offline Port of Google CSP Evaluator**: Evaluates policies directly inside Burp Suite using Google's official rule engine and datasets without external network requests or browser dependency.
* **Allowlist Bypass Detection**: Flags known JSONP and Angular library bypass endpoints on allowlisted origins (e.g. `cdnjs.cloudflare.com`, `googleapis.com`, `google-analytics.com`, `yandex.st`).
* **Security & Strict CSP Audits**: Evaluates `'unsafe-inline'`, `'unsafe-eval'`, wildcards, missing `object-src`/`base-uri`, nonce lengths, and strict-dynamic backwards compatibility.
* **Interactive Google CSP Scratchpad**: Toolbar button `🧪 Google CSP Scratchpad` allows testers to paste, edit, and audit arbitrary CSP strings on the fly with preloaded templates.
* **Master-Detail Evaluator Tab**: Added alongside Request & Response editors (`🔍 Google CSP Evaluator`), displaying detailed findings, severity badges, and Google remediation guidance.
* **GitHub Release & Engine Update Checker**: Built-in update checker queries `https://api.github.com/repos/google/csp-evaluator/releases/latest` so testers can verify whether their embedded engine (`v1.1.8`) is current, view release notes, and copy an update notice for the developer with one click.

### 6. 🔒 HSTS Inspector
* **Strict-Transport-Security Auditor**: Evaluates `max-age` durations, `includeSubDomains`, and `preload` readiness.
* **Assessment Engine**: Identifies missing headers, opt-outs (`max-age=0`), and dangerously short durations (< 30 days).

---

## 🏛️ Tab Structure (Single Unified Welcome & Guide)
* **`📖 Welcome & Guide`**: Single, centralized onboarding dashboard, module overview, and quick-start instructions at the root extension level.
* **`📋 Header Collector`**: Direct, distraction-free Request & Response header aggregation workspace.
* **`⚡ Method Collector`**: Direct HTTP method inventory, RFC properties, endpoint correlation, and http.dev method reference.
* **`🔢 Status Collector`**: Direct HTTP status code auditing, class/vendor classification, SEO impact, and http.dev status reference.
* **`🗄️ Cache Inspector`**: Direct cache directive and CDN header auditing workspace.
* **`🛡️ CSP Inspector`**: Direct CSP analysis workspace with integrated Google CSP Evaluator.
* **`🔒 HSTS Inspector`**: Direct HSTS auditing and preload readiness workspace.

---

## ⚡ Synchronized On-Demand Ingestion (Freeze Prevention)

* **Single-Click Ingestion Across All Tabs**: When a user clicks **Load Proxy History** in ANY tab (Header Collector, Method Collector, Status Collector, Cache, CSP, or HSTS), traffic is parsed once in a non-blocking background `SwingWorker` and distributed across all 6 inspectors simultaneously.
* **Zero Passive CPU Overhead**: Purely on-demand operation with no passive background listeners running during normal proxy usage.
* **In-Scope Gating**: Default-checked `[x] In-Scope Only` pre-filters out third-party trackers, CDNs, and telemetry *before* object allocation, preventing UI hangs or JVM GC spikes on large proxy histories.

---

## 🛠️ Building & Installation

### Requirements
* Java 17 or higher
* Gradle 8+ (or use the included `./gradlew` wrapper)

### Build
Run from the extension directory:
```bash
./gradlew jar
```

The output JAR will be created at:
```
build/libs/header-inspector-littlespidy-1.0.0.jar
```

### Installation in Burp Suite
1. Open Burp Suite.
2. Go to **Extensions** $\rightarrow$ **Installed** $\rightarrow$ **Add**.
3. Set **Extension type** to **Java**.
4. Select `header-inspector-littlespidy-1.0.0.jar`.
5. The **📋 Header Inspector** tab will appear in the top suite navigation bar.
