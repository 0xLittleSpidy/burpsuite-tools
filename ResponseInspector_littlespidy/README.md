# Response Inspector (Burp Suite Extension)

<!-- Created with the help of an AI Agent and littlespidy. -->

A high-performance Burp Suite extension built on the modern **Montoya API** to passively analyze and triage sensitive data exposures in HTTP responses across five tabs:

1. **📖 Welcome & Guide**: Static onboarding dashboard with modular tutorial cards explaining the audit methodology, zero-overhead philosophy, and triage tools.
2. **🔑 Passwords**: Targeted scanning for user-configured passwords leaked in response bodies, headers, and cookies.
3. **🛡️ PII, Network & Server Paths**: Strict Social Security Numbers (SSNs), RFC 1918 / loopback internal IP addresses, and real OS filesystem paths (Linux & Windows).
4. **⚠️ Errors & Exceptions**: Comprehensive database leaks, stack traces, and verbose server error disclosures ported from `DetectHTTPResponseErrors_littlespidy.bambda`.
5. **🔐 Secrets & Tokens**: Cloud API keys, auth tokens, private keys, JWTs, and environment configurations ported from `sensitive-discoverer`.

---

## 🚀 Key Features

- **Multi-Threaded Ingestion Pool**: Rapid parallel scanning of Proxy HTTP history powered by a bounded `ExecutorService` (`Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()))`) with atomic progress counters and non-blocking batch UI updates.
- **Two-Stage Refiner Regex Engine**: Ported from `sensitive-discoverer` to eliminate regex backtracking: matches fast anchor suffixes (e.g. `s3.amazonaws.com`, `blob.core.windows.net`, `firebaseio.com`, `apps.googleusercontent.com`, `webhook.office.com`) and then applies a backward look-back window refiner regex to capture complete bucket, storage, and client prefixes without false positives.
- **MIME-Type Blacklisting & Max Size Guard**: Automatically bypasses non-textual binary assets (`IMAGE_*`, `VIDEO`, `SOUND`, `FONT_*`, `APPLICATION_FLASH`) and oversized bodies (>10MB), accelerating history scans by ~80% and preventing memory bloat.
- **Multi-Section Scanning (Headers + Body)**: Scans both `Response Headers` (detecting leaked tokens in `Set-Cookie`, redirects in `Location`, internal IPs in `X-Forwarded-For` / `X-Backend-Server`) and `Response Body` with accurate byte alignment.
- **TSV Findings Export**: Dedicated **`Export TSV`** toolbar button and right-click context menu item to save currently displayed or filtered findings to a clean Tab-Separated Values (`.tsv`) file for rapid spreadsheets or reporting.
- **Welcome & Onboarding Dashboard**: A dedicated first tab featuring structured playbook cards outlining discovery rules, threading design, and workflow integrations.
- **Granular In-Scope Domain Selection**: Rather than forcing a coarse all-or-nothing scope filter, the **`In-Scope Domains... (N/M)`** button opens a multi-checkbox search modal to select or deselect specific target subdomains/hosts.
- **On-Demand Processing (Zero Overhead)**: Analyzes captured responses via a dedicated **Load Proxy History** button backed by asynchronous `SwingWorker` threads. Does not add continuous background overhead to Proxy/Repeater operations.
- **Dedicated Target Password Management**: Prominent **`Configure Passwords... (N active)`** toolbar action opens a modal editor allowing testers to enter, paste, or import wordlists from disk, with optional case-sensitivity toggles.
- **Strict SSN & False-Positive Suppression**: Enforces standard US SSN format (`\b\d{3}-\d{2}-\d{4}\b`) and verifies area, group, and serial number validity (excluding `000-`, `666-`, `900-999-`, `00`, `0000`, and sequential dummy sequences like `111-11-1111`).
- **OS Filesystem Paths vs Web Routes**: Specifically isolates real server filesystem paths (e.g. `/etc/passwd`, `/var/log/...`, `/home/...`, `C:\inetpub\...`, `\\server\share\...`) rather than standard client-side URLs or web routes.
- **Master-Detail Layout**: Top sortable table with status-code color-coding; bottom native Montoya `HttpRequestEditor` and `HttpResponseEditor` (Pretty / Raw / Hex) with zero UI lag.
- **Multi-Select Filter Buttons (`MultiSelectFilterButton`)**: Popover checkbox controls allowing multi-value filtering across HTTP Methods (`GET`, `POST`, etc.), Status Codes (`2xx`, `3xx`, `4xx`, `5xx`, `200`, `302`, `401`, `403`, `404`, `500`), and Content-Types (`JSON`, `HTML`, `JavaScript`, `XML`, `Plain`).
- **Secret Type Multi-Select Filter**: The Secrets & Tokens tab features a dedicated **`Secret Type ▾`** filter button allowing testers to isolate specific secret patterns (e.g. `AWS S3 Bucket`, `OpenAI API Key`, `JSON Web Token (JWT)`, `Google API Key`, `Stripe Webhook Secret`) or view all by default (`All Secret Types`).
- **Live Ingestion Progress Bar**: Dedicated status strip below the toolbar displays real-time item and finding counts (`Scanning Proxy history: 450 / 2100 items...`) alongside an auto-hiding determinate `JProgressBar` with guaranteed `try-finally` fail-safe recovery.
- **Auto-Navigation & Deep-Linking Quad**: Selecting any finding row immediately:
  1. *Tab Auto-Switching*: Flips the editor to the **Response** (or Request) sub-tab automatically.
  2. *Native Marker Highlighting*: Paints native Burp yellow/orange markers over the match range across Pretty, Raw, and Hex editors.
  3. *Search Expression Populating*: Populates Burp's search bar with the finding value to enable immediate `Enter` / `Shift+Enter` keyboard jumping.
  4. *Viewport Auto-Scroll*: Automatically scrolls the text component vertically and horizontally to center the finding on-screen (handling header offsets vs body offsets accurately).
- **Row Pinning**: Isolate high-value findings using **Pin Selected** and **Clear Pins** to bypass general filters during deep analysis.
- **Inter-Tool Integration**: Right-click context menu on all tables to **Send to Repeater** (with clean `METHOD host/path` tab naming), **Send to Intruder**, **Send to Organizer**, and **Copy Match Excerpt**.
- **Clipboard TSV Export**: Standard `Ctrl+C` / `Cmd+C` hotkey exports selected rows directly to clipboard in tab-separated format for reporting.

---

## 🛠️ Tabs & Coverage

### 0. 📖 Welcome & Guide Tab
- Overview of architecture, zero-EDT-freeze guidelines, domain selection walkthrough, and triage shortcuts.

### 1. 🔑 Passwords Tab
- Prompts or opens via **`Configure Passwords... (N active)`**.
- Scans response bodies and all response headers (`Set-Cookie`, custom authentication headers).
- Highlights context snippets surrounding leaked credentials.

### 2. 🛡️ PII, Network & Server Paths Tab
- **Strict SSN**: Validates valid area, group, and serial numbers. Masks output (`***-**-1234`) for safe viewing.
- **Internal IPs**: Matches RFC 1918 Class A (`10.0.0.0/8`), Class B (`172.16.0.0/12`), Class C (`192.168.0.0/16`), Loopback (`127.0.0.0/8`), and Link-Local (`169.254.0.0/16`) across both Response Headers (`X-Forwarded-For`, `X-Backend-Server`, `Via`) and Response Bodies.
- **OS Server Paths**: Detects Linux root and service directories (`/etc/`, `/var/log/`, `/var/www/`, `/opt/`, `/root/`, `/home/<user>/`, `/proc/`, `/sys/`) and Windows filesystem paths (`C:\inetpub\...`, `C:\Windows\...`, `C:\Users\...`, drive letters, and UNC network shares).

### 3. ⚠️ Errors & Exceptions Tab
Ported from `DetectHTTPResponseErrors_littlespidy.bambda`:
- **Web Servers**: Apache (`AH\d{5}:`, `mod_\w+:`), NGINX, JBoss/WildFly (`JBWEB\d{6}:`, `WFLY\w+:`), Waitress, WebSEAL.
- **ASP.NET & IIS**: .NET exceptions, OLE DB providers, `System.*Exception`, C# source line references.
- **Databases**: MySQL/MariaDB, PostgreSQL, Oracle DB (`ORA-\d{5}`), Microsoft SQL Server, SQLite, IBM DB2, MongoDB, LDAP directory leakage.
- **Languages & Runtimes**: PHP fatal/warning traces, Java stack traces (`java.lang.*Exception`, `.java:\d+`), Python tracebacks, Ruby/ActiveRecord errors, Go panics, Node.js/JavaScript errors.
- **Frameworks**: Django ORM, Hibernate / JPA.

### 4. 🔐 Secrets & Tokens Tab
Comprehensive patterns ported from `sensitive-discoverer` using the Two-Stage Refiner Engine:
- **Cloud Storage & Infrastructure**:
  - AWS S3 Buckets (`*.s3.amazonaws.com`, `.s3.dualstack...`)
  - Azure Blob Storage (`*.blob.core.windows.net`)
  - Firebase Realtime Database (`*.firebaseio.com`, `*.firebasedatabase.app`)
  - Google Cloud Storage (`gs://...`)
  - Amazon ARN (`arn:aws:...`)
  - Microsoft Teams / Office 365 Incoming Webhooks (`outlook.office.com/webhook/...`, `*.webhook.office.com`)
- **API Keys & Credentials**:
  - OpenAI API Keys (`sk-...`)
  - AWS Access Key ID (`AKIA...`, `ASIA...`, `ABIA...`, `AROA...`)
  - AWS Secret Access Key
  - Amazon MWS Auth Tokens
  - Google API Keys (`AIza...`)
  - Google OAuth Access Tokens (`ya29...`)
  - Google OAuth Client ID (`*.apps.googleusercontent.com`) & Client Secret (`GOCSPX-...`)
  - GitHub Personal Access Tokens (`ghp_...`, `gho_...`, `ghu_...`, `ghs_...`) & Fine-Grained PATs (`github_pat_...`)
  - Slack Incoming Webhooks & Bot/User Tokens (`xoxb-...`, `xoxp-...`, `xoxa-...`, `xoxe-...`)
  - Square Tokens (`sq0atp-...`, `sq0csp-...`, `sq0idp-...`)
  - MailGun API Keys (`key-...`)
  - NuGet API Keys (`oy2...`)
  - Stripe API Secret Keys (`sk_live_...`, `rk_live_...`) & Webhook Signing Secrets (`whsec_...`)
  - Twilio API Key / SID (`SK...`)
  - SendGrid API Keys (`SG....`)
  - Generic API Key & Secret assignments (`api_key: '...'`, `secret: '...'`)

---

## 📚 Pattern Reference & Skill

For the concise catalog of all regex patterns, two-stage refiners, and extraction rules, see:
- [Pattern Reference (`patterns.md`)](file:///home/littlespidy/myextra/burpsuite/ResponseInspector_littlespidy/patterns.md)
- Custom Skill: `sensitive-pattern-extractor` at [`.agents/skills/sensitive-pattern-extractor/SKILL.md`](file:///home/littlespidy/myextra/burpsuite/.agents/skills/sensitive-pattern-extractor/SKILL.md)

---

## 📦 Building and Installing

### Build with Gradle

Ensure Java 17+ is installed. Run:

```bash
cd /home/littlespidy/myextra/burpsuite/ResponseInspector_littlespidy
./gradlew jar
```

The compiled standalone JAR will be placed at:
```
build/libs/response-inspector-littlespidy-1.0.0.jar
```

### Load in Burp Suite

1. Open Burp Suite.
2. Navigate to **Extensions** → **Installed**.
3. Click **Add**.
4. Select **Extension type: Java**.
5. Click **Select file...** and choose `ResponseInspector_littlespidy/build/libs/response-inspector-littlespidy-1.0.0.jar`.
6. Click **Next**. The extension will load and register the **Response Inspector** top-level Suite tab.
