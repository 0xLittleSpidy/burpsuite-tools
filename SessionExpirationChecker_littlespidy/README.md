# ⏱️ Session Expiration Checker (littlespidy)

> **Created with the help of an AI Agent and littlespidy.**

A modern Burp Suite extension built on the **Montoya API** designed to automate session timeout, token expiration, session token discovery, and cookie inventory auditing. Security testers can send authenticated requests to schedule multiple custom milestone probes (e.g., **30 min**, **1 hr**, **3 hr**, **8 hr**, or arbitrary intervals), systematically identify which specific cookies or authorization headers maintain the session, inspect all observed cookies and track exact value repetition counts across HTTP traffic, and verify behavior against baseline responses.

---

## 🎯 Key Features

### 1. 🍪 Systematic Session Cookie & Auth Header Finder (Tab #2)
- **Target Ingestion**:
  - Right-click any HTTP request in **Proxy History**, **Repeater**, **Logger**, or the **HTTP Message Editor** and choose **`🍪 Send to Session Cookie Finder`** (or paste raw requests directly from the clipboard).
- **Automated Credential Discovery**:
  - Automatically parses individual cookies from the `Cookie` header (`JSESSIONID`, `PHPSESSID`, `token`, `remember_me`, `_ga`, etc.).
  - Automatically recognizes standard and common authorization headers (`Authorization`, `Proxy-Authorization`, `X-Access-Token`, `X-Auth-Token`, `Bearer`, `Token`, `X-Session-ID`, etc.).
- **Suspect Custom Header Configuration**:
  - Allows testers to specify arbitrary custom headers suspect for authentication (e.g., `X-Custom-Auth, X-Session-Token, X-User-Token, X-API-Key, ApiKey`).
- **Systematic Isolation & Fuzzing Pipeline**:
  - **Authenticated Baseline**: Captures initial active response ($200\text{ OK}$, body length, keywords).
  - **Anonymous Control Benchmark**: Strips all cookies, standard auth headers, and custom headers to benchmark unauthenticated response behavior.
  - **Cookie-by-Cookie Removal**: Systematically removes *only* cookie $C_i$ while preserving all other cookies and headers, pinpointing which specific cookie maintains the session.
  - **Header-by-Header Removal**: Systematically removes *only* authorization header $H_j$ while preserving cookies.
  - **Group Tests**: Runs group isolation tests (all cookies removed vs all headers removed) to identify if the application accepts tokens via header alone, cookies alone, or both.
- **Actionable Verdicts & Signal Analysis**:
  - Color-coded results table:
    - **`🚨 Session Token (Required)`**: Removing this credential broken session (status shift to 401/403, redirect to `/login`, expiry keywords, or body drop matching anonymous control).
    - **`⚠️ Suspicious / Changed`**: Significant content delta or unexpected status code change.
    - **`ℹ️ Optional (Non-Session)`**: Session remained fully active; cookie or header is not required for authentication (e.g., analytics, UI preferences).
- **Direct Workflow Handoff**:
  - Right-click any finding to send to **Repeater**, **Intruder**, **Organizer**, or click **`⏱️ Track Expiration in Session Monitor`** to immediately schedule milestone timers on the target.

### 2. 📦 Comprehensive Cookie Store Tab (Tab #4)
- **Modeled after Header Collector**:
  - Features an intuitive **Master-Detail** split pane interface inspired by `HeaderInspector_littlespidy`.
  - Ingests cookies from both request `Cookie:` headers and response `Set-Cookie:` headers.
- **Master Cookie Grouping**:
  - Master table displays unique **Cookie Names**, **Distinct Values Count**, **Total Occurrences**, **Observed Domains**, and **Source** (`REQUEST`, `RESPONSE`, or `BOTH`).
- **Exact Value Repetition Tracking**:
  - The detail table lists each unique cookie value associated with the selected cookie name.
  - Displays a dedicated **`Repeated (Count)`** column tracking exactly how many times that specific cookie value was observed across all captured traffic.
  - Captures `Value Length`, `Observed Domains`, `First Seen`, `Last Seen`, and sample request/response metadata (`Method`, `URL`, `Status`).
- **Detailed Set-Cookie Attributes**:
  - Surfaces security flags and parameters: `HttpOnly`, `Secure`, `SameSite` (`Strict`/`Lax`/`None`), `Path`, `Domain`, and `Expires / Max-Age`.
- **Synchronized Proxy History Ingestion**:
  - One-click **`📥 Load Proxy History`** button runs a background worker with optional **`[x] In-Scope Only`** filter gating to parse thousands of items without freezing the UI.
- **Search & Domain Filtering**:
  - Live search filters both cookie names and values with regex and case-insensitivity support.
  - Dynamic domain combo box filters cookies down to specific hosts.
- **4-Pillar Deep-Linking with Native Montoya Editors**:
  - Selecting any cookie value displays the sample HTTP Request & Response in native Montoya Pretty/Raw/Hex editors.
  - Applies vibrant yellow/orange highlight markers over the selected cookie name and value directly in the request and response viewers.
- **Burp Interoperability & Export**:
  - Right-click any request in Burp Suite to choose **`📦 Send to Cookie Store`** or **`📦 Open Cookie Store`**.
  - One-click **`📋 Export TSV`** button for bug bounty reports, session audits, and spreadsheet triage.

### 3. ⏱️ Automated Baseline & 6-Editor Inspector
- **Automatic Live Baseline Probe**:
  - Whenever a session is scheduled or sent to the extension, the baseline probe is **automatically dispatched at $T_0$** by default without requiring user prompt.
- **Preserved Original vs. Baseline Messages**:
  - Stores both the untouched **Original Request & Response** (captured when sent from Burp) and the fresh **Baseline Request & Response** (executed at $T_0$).
- **6 Dedicated Montoya Editors**:
  - Side-by-side tabs in the inspector:
    - **`📤 Probe Request`**
    - **`📥 Probe Response`**
    - **`🎯 Baseline Request`**
    - **`🎯 Baseline Response`**
    - **`📄 Original Request`**
    - **`📄 Original Response`**

### 4. ⏱️ Custom Milestone Timers (Milestone-based from $T_0$)
- Configures **16 milestones by default** every 30 minutes from **30m up to 8 hours** (`30m`, `1h`, `1h 30m`, `2h`, `2h 30m`, `3h`, `3h 30m`, `4h`, `4h 30m`, `5h`, `5h 30m`, `6h`, `6h 30m`, `7h`, `7h 30m`, `8h`).
- Timers count down concurrently from baseline start time ($T_0$).
- Fast preset buttons to reload all 16 defaults or custom intervals.

### 5. HTTP Response Date & Time Highlighting
- Automatically inspects the standard HTTP `Date:` response header (as well as `Expires` and `Last-Modified`).
- Applies native Montoya `Marker` highlighting to paint vibrant yellow/orange highlight boxes over server date/time stamps across Pretty, Raw, and Hex editors.
- Displays the server's `Date:` header in the **Milestones & History** table to correlate server clock time against local milestone schedules.

### 6. Multi-Factor Verification Engine & Auto-Cancellation
- Compares probe responses against baseline behavior:
  - **Status Code Shifts**: Identifies `200 -> 401 Unauthorized`, `200 -> 403 Forbidden`, or redirect codes (`302/301/307`).
  - **Auth Redirects**: Detects redirects to login endpoints (`/login`, `/signin`, `auth`, `sso`, etc.).
  - **Header Invalidation**: Detects `Set-Cookie` headers clearing sessions (`Max-Age=0`, `expires=1970`).
  - **Body Signature Inspection**: Flags keywords indicating session termination (`"session expired"`, `"token expired"`, `"please log in"`, etc.) absent in the baseline.
- **Auto-Cancellation on Expiry**: Automatically cancels all remaining scheduled milestone timers for a task once session expiration is detected.

### 7. Master-Detail Workspace & Triage Filters
- **Live Dynamic Countdown**: Master table shows real-time countdowns (`29m 14s`) ticking down to the next scheduled check.
- **Core Triage Filters**: Rapid filtering by Host/Domain, Method (`MultiSelectFilterButton`), Status Code, and State (`ACTIVE`, `EXPIRED`, `PENDING`, `RUNNING`, `CANCELLED`).
- **Burp Suite Interoperability**: Right-click any session or probe to send to **Repeater**, **Intruder**, or **Organizer**.

---

## 🏗️ Architecture & Technical Specs

- **Montoya API**: Built using `net.portswigger.burp.extensions:montoya-api:2023.12.1`.
- **Concurrency & Zero-Freeze UI**:
  - Milestone scheduling handled by a daemon `ScheduledExecutorService`.
  - HTTP requests executed asynchronously in worker thread pools.
  - All UI state changes dispatched cleanly to the Swing Event Dispatch Thread (EDT).
  - Unload hook (`registerUnloadingHandler`) cleanly terminates all background threads and executors.
- **Target Java Version**: Java 17+ bytecode compatibility.

---

## 🚀 Building the Extension

Ensure you have Java 17 or higher installed:

```bash
cd /home/littlespidy/myextra/burpsuite/SessionExpirationChecker_littlespidy
./gradlew jar
```

The compiled fat JAR will be generated at:
```
build/libs/session-expiration-checker-littlespidy-1.0.0.jar
```

---

## 🔌 Installing into Burp Suite

1. Open **Burp Suite**.
2. Navigate to **Extensions** → **Installed**.
3. Click **Add**.
4. In the dialog:
   - **Extension type**: `Java`
   - **Extension file (.jar)**: Browse and select `SessionExpirationChecker_littlespidy/build/libs/session-expiration-checker-littlespidy-1.0.0.jar`.
5. Click **Next**. The extension tab **`⏱️ Session Expiration Checker`** will appear in the top suite bar.

---

## 📖 Testing Workflow Guide

### Workflow A: Identify Session Cookies & Auth Headers
1. Right-click any authenticated request in Proxy or Repeater and select **`🍪 Send to Session Cookie Finder`**.
2. If your target uses non-standard authentication headers, specify them in **Suspect Custom Headers** (e.g., `X-Custom-Auth, X-Session-Id, Api-Key`).
3. Click **`▶️ Run Cookie & Auth Finder`**.
4. Inspect the results table:
   - Rows marked **`🚨 Session Token (Required)`** identify the exact cookie(s) or header(s) maintaining the session.
   - Rows marked **`ℹ️ Optional (Non-Session)`** show non-critical tracking/analytics cookies.
5. Click **`⏱️ Track Expiration in Session Monitor`** to seamlessly schedule expiration checks on the validated target!

### Workflow B: Schedule Milestone Expiration Tracking
1. Right-click any authenticated request and select **`⏱️ Send to Session Expiration Checker`**.
2. Choose milestone presets (e.g. `+30m`, `+1h`, `+3h`, `+8h`) or add custom intervals.
3. Click **`▶️ Start Tracking`** (the baseline probe is automatically dispatched at $T_0$ immediately).
4. Monitor the countdown in the master table; when expired, remaining timers auto-cancel and the exact expiration time is highlighted.

### Workflow C: Inspect and Audit Cookies in Cookie Store
1. Open the **`📦 Cookie Store`** tab in the extension.
2. Click **`📥 Load Proxy History`** (toggle **`In-Scope Only`** if desired) to ingest all cookies from Proxy traffic. Alternatively, right-click any request in Burp and choose **`📦 Send to Cookie Store`**.
3. Select any cookie name in the left **Cookie Names** table (e.g., `JSESSIONID`, `PHPSESSID`, `session_token`).
4. In the right **Cookie Values** table, check the **`Repeated (Count)`** column to see how many times each specific cookie value appeared.
5. Review security attributes (`HttpOnly`, `Secure`, `SameSite`) to identify misconfigured cookies.
6. Click any value to view the highlighted sample request and response in the embedded Montoya viewer.
7. Click **`📋 Export TSV`** to copy the cookie inventory directly to your clipboard.
