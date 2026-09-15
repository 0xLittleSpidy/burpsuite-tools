# Response Inspector (Burp Suite Extension)

<!-- Created with the help of an AI Agent and littlespidy. -->

A high-performance Burp Suite extension built on the modern **Montoya API** to passively analyze and triage sensitive data exposures in HTTP responses across six functional tabs:

1. **📖 Welcome & Guide**: Onboarding dashboard with modular tutorial cards explaining the audit methodology, zero-overhead philosophy, JS exclusion policy, and triage shortcuts.
2. **🔑 Passwords**: Targeted scanning for user-configured passwords leaked in response bodies, headers, and cookies.
3. **🛡️ PII, Network & Server Paths**: Strict Social Security Numbers (SSNs), RFC 1918 / loopback internal IP addresses, and real OS filesystem paths (Linux & Windows).
4. **⚠️ Errors & Exceptions**: Comprehensive database leaks, stack traces, and verbose server error disclosures ported from `DetectHTTPResponseErrors_littlespidy.bambda`.
5. **🔐 Secrets**: Cloud API keys, auth tokens, private keys, JWTs, and cloud storage buckets upgraded with 40+ curated patterns, Shannon entropy scoring, Signatures Catalog dialog, and one-click KeyHacks credential verification in Burp Repeater.
6. **💬 Comments**: Developer comments extracted from HTTP responses (single-line `//`, multi-line `/* */`, and HTML `<!-- -->`), categorized into `TODO / FIXME`, `Credentials / Auth`, `Debug / Config`, and `General`.

---

## 🚀 Key Features & Architectural Upgrades

- **💬 Dedicated Developer Comments Tab**: Extracts inline, block, and HTML comments from response bodies, filtering by comment syntax and semantic category with zero EDT lag and automatic 500-item safeguard against response flooding.
- **🔐 Upgraded Secrets Tab with KeyHacks Verification**:
  - **40+ Curated Signatures**: Patterns covering Cloud (AWS, GCP, Azure, Firebase, DigitalOcean, Cloudflare), Payments (Stripe, PayPal, Square), Source Control & CI/CD (GitHub, GitLab, Bitbucket, Vercel, Netlify, npm), AI/ML (OpenAI, Anthropic, HuggingFace, Cohere), and SaaS (Slack, Discord, Algolia, SendGrid, Twilio).
  - **Shannon Entropy Guard & False-Positive Suppression**: Automatically suppresses dummy tutorial keys, template variables (`${...}`), and repetitive low-entropy sequences.
  - **Signatures Catalog Dialog**: Click **`📋 Signatures Catalog (N)`** to review active detection regexes, confidence levels, and entropy guards in a filterable modal dialog.
  - **KeyHacks Credential Verification**: Click **`🧪 Verify Secret (Repeater)`** or right-click any secret row to construct an authentic, non-destructive identity query request and dispatch it directly to Burp Repeater.
- **🔎 Universal "Finding Type" Filter**: Every tab features a dedicated **`Finding Type ▾`** `MultiSelectFilterButton` popup tailored to that tab (e.g. SSN / Internal IP / OS Path on PII tab; DB & runtime exception names on Errors tab; Secret Signatures on Secrets tab; Comment Types on Comments tab).
- **🚫 Strict JavaScript File Exclusion**: JavaScript files (`.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.map`) and script MIME responses are intentionally excluded from loading and scanning in Response Inspector to eliminate tool overlap, as full JavaScript intelligence and Source Map extraction are provided by the companion [JS SourceMap Explorer](file:///home/littlespidy/myextra/burpsuite/JSSourceMapExplorer_littlespidy).
- **📌 Clean Non-Destructive Triage (Pinning Removed)**: Row pinning has been completely removed in favor of clean live non-destructive view filtering, ensuring dataset integrity and immediate filter resetting.
- **🌐 In-Scope Dual-Stage Strategy (`extension_architecture.md`)**: Live target scope evaluation (`api.scope().isInScope(url)`) combined with an optional ingestion pre-filter and a granular **`In-Scope Domains...`** dialog to isolate specific target subdomains without re-importing history.
- **⚡ Multi-Threaded Ingestion Pool**: Rapid parallel scanning of Proxy HTTP history powered by a bounded `ExecutorService` (`Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()))`) with atomic progress counters and non-blocking batch UI updates.
- **📊 TSV Findings Export**: Dedicated **`Export TSV`** toolbar button and right-click context menu item to save currently displayed or filtered findings to a clean Tab-Separated Values (`.tsv`) file for reporting.
- **🎯 Auto-Navigation & Deep-Linking Quad**: Selecting any finding row immediately:
  1. *Tab Auto-Switching*: Flips the editor to the **Response** (or Request) sub-tab automatically.
  2. *Native Marker Highlighting*: Paints native Burp yellow/orange markers over the match range across Pretty, Raw, and Hex editors.
  3. *Search Expression Populating*: Populates Burp's search bar with the finding value to enable immediate `Enter` / `Shift+Enter` keyboard jumping.
  4. *Viewport Auto-Scroll*: Automatically scrolls the text component vertically and horizontally to center the finding on-screen.
- **🔄 Inter-Tool Integration**: Right-click context menu on all tables to **Send to Repeater** (with clean `METHOD host/path` tab naming), **Send to Intruder**, **Send to Organizer**, and **Copy Match Excerpt**.

---

## 🛠️ Tabs & Coverage

### 0. 📖 Welcome & Guide Tab
- Overview of architecture, zero-EDT-freeze guidelines, domain selection walkthrough, JS exclusion notice, and triage shortcuts.

### 1. 🔑 Passwords Tab
- Prompts or opens via **`Configure Passwords... (N active)`**.
- Scans response bodies and all response headers (`Set-Cookie`, custom authentication headers).
- Highlights context snippets surrounding leaked credentials.

### 2. 🛡️ PII, Network & Server Paths Tab
- **Strict SSN**: Validates valid area, group, and serial numbers. Masks output (`***-**-1234`) for safe viewing.
- **Internal IPs**: Matches RFC 1918 Class A (`10.0.0.0/8`), Class B (`172.16.0.0/12`), Class C (`192.168.0.0/16`), Loopback (`127.0.0.0/8`), and Link-Local (`169.254.0.0/16`).
- **OS Server Paths**: Detects Linux root and service directories (`/etc/`, `/var/log/`, `/var/www/`, `/opt/`, `/root/`, `/home/<user>/`, `/proc/`, `/sys/`) and Windows filesystem paths (`C:\inetpub\...`, `C:\Windows\...`, `C:\Users\...`, drive letters, and UNC network shares).
- **Finding Type Filter**: Multi-select between SSN, Internal IP, and Server File Path.

### 3. ⚠️ Errors & Exceptions Tab
Ported from `DetectHTTPResponseErrors_littlespidy.bambda`:
- **Web Servers**: Apache, NGINX, JBoss/WildFly, Waitress, WebSEAL.
- **ASP.NET & IIS**: .NET exceptions, OLE DB providers, `System.*Exception`, C# source line references.
- **Databases**: MySQL/MariaDB, PostgreSQL, Oracle DB, Microsoft SQL Server, SQLite, IBM DB2, MongoDB, LDAP directory leakage.
- **Languages & Runtimes**: PHP fatal/warning traces, Java stack traces, Python tracebacks, Ruby/ActiveRecord errors, Go panics, Node.js/JavaScript errors.
- **Frameworks**: Django ORM, Hibernate / JPA.
- **Finding Type Filter**: Multi-select filter across all 22 supported error signatures.

### 4. 🔐 Secrets Tab
Curated pattern mining engine with Shannon entropy scoring and KeyHacks verification:
- **Cloud Infrastructure**: AWS S3 Buckets, Azure Blob Storage, Firebase Realtime Database, Google Cloud Storage, Amazon ARN.
- **Cloud Credentials**: AWS Access Key (`AKIA...`), AWS Secret Key, AWS Session Token (`ASIA...`), Google API Key, Google OAuth Client Secret, Azure Storage Connection String, Azure SharedAccessKey, DigitalOcean Token, Cloudflare Token, Heroku API Key.
- **Financial & Payment**: Stripe Live/Restricted Keys, PayPal Secret, Square Access/OAuth Tokens.
- **Source Control & CI/CD**: GitHub PAT & Fine-Grained Tokens, GitLab PAT, Bitbucket Token, Vercel, Netlify, npm Access Tokens.
- **AI & ML**: OpenAI Project & Classic Keys, Anthropic API Keys, HuggingFace Tokens, Cohere API Keys.
- **Messaging & SaaS**: Slack Tokens, Discord Bot Tokens, Algolia Admin Keys, SendGrid, Mailgun, Twilio Auth Tokens.
- **API & Auth**: JSON Web Tokens (JWT), Hardcoded Bearer Tokens, Authorization Headers, OAuth Refresh Tokens, Generic API Secrets.
- **Cryptographic Keys**: PEM Private Keys (`-----BEGIN RSA/EC PRIVATE KEY-----`), Encrypted Private Keys.
- **KeyHacks Repeater Verification**: Dispatch non-destructive identity checks to Burp Repeater.
- **Finding Type Filter**: Multi-select filter across all secret signature rules.

### 5. 💬 Comments Tab
- **Syntax Types**: Single-line (`//`), multi-line (`/* */`), and HTML (`<!-- -->`).
- **Semantic Categories**:
  - `TODO / FIXME`: Technical debt, temporary code, bug tags (`TODO`, `FIXME`, `HACK`, `BUG`, `WORKAROUND`).
  - `Credentials / Auth`: Passwords, auth keys, tokens, admin notes (`password`, `secret`, `token`, `apikey`, `admin`, `root`).
  - `Debug / Config`: Development endpoints, testing flags, localhost configurations (`debug`, `test`, `dev`, `staging`, `internal`).
  - `General`: Informational and developer documentation comments.
- **Toolbar Controls**: Independent multi-select filters for **Comment Type** and **Category**, combined with text search and TSV export.

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
