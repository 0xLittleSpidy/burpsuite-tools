# 🍪 Active Scan Session Keeper (littlespidy)

> **Created with the help of an AI Agent and littlespidy.**

A powerful Burp Suite extension built on the **Montoya API** designed to prevent Burp's Active Scanner from failing when target application session cookies expire during long-running security audits.

When scanning authenticated web applications, sessions often expire due to idle or absolute timeouts (e.g. 15–30 minutes). When this happens, Burp Scanner unknowingly continues sending hundreds or thousands of attack payloads against an unauthenticated session, leading to missed vulnerabilities and wasted scan time.

**Active Scan Session Keeper** continuously monitors active scanner traffic. When session expiration is detected across customizable multi-factor criteria, it **immediately pauses all active scan threads**, sounds an alert, and prompts the tester with an interactive modal dialog to supply fresh cookies. Once updated, it automatically retries the failed request with the fresh credentials and seamlessly resumes the scan without losing a single payload check.

---

## 🎯 Key Features

### 1. 🚦 Automated Active Scan Interception
- **Zero Configuration Necessary**: Registers natively as a Montoya `HttpHandler` that monitors traffic from Burp's Active Scanner.
- **Selective Tool Monitoring**: Easily toggle monitoring for **Scanner** (default), **Repeater**, **Intruder**, and other **Extensions**.
- **Scope & Host Gating**:
  - `Burp In-Scope Only`: Confines session monitoring strictly to in-scope targets.
  - `Target Host Filter`: Supports wildcard domain matching (e.g. `*.target.com` or `target.com`).

### 2. 🔍 Multi-Factor Expiration Detection Engine
Includes a comprehensive suite of expiration checks that can be toggled and configured individually:
- **HTTP Status Codes**:
  - Detects `401 Unauthorized`, `403 Forbidden`, `419 Page Expired` (Laravel), `440 Login Timeout` (IIS), `498 Invalid Token`, and arbitrary custom codes.
- **Login / Authentication Redirects (3xx)**:
  - Detects redirects where the `Location:` header matches authentication paths (`.*(login|signin|sign-in|log-in|auth|authenticate|sso|oauth|cas).*`).
- **Response Body Signatures & Keywords**:
  - Detects customizable case-insensitive regex patterns and keywords, such as:
    - `"session expired"`, `"session timeout"`, `"your session has ended"`
    - `"please log in"`, `"please sign in"`, `"log in again"`
    - `"invalid token"`, `"token expired"`, `"invalid session"`
    - `"you have been logged out"`, `"unauthorized access"`, `"access denied"`
    - JSON error objects: `{"error": "invalid_token"}`
- **Set-Cookie Invalidation Headers**:
  - Flags responses where the server attempts to delete or expire session cookies (`Max-Age=0`, `expires=Thu, 01 Jan 1970`, or `=deleted`).
- **Sudden Body Length Drop**:
  - Flags responses where the body length drops below a configurable threshold (e.g. $\le 150$ bytes).
- **Custom Regex**:
  - Allows testers to define arbitrary regex patterns evaluated against the full HTTP response.

### 3. 🛑 Thread-Safe Scanner Pausing & Prompting
- **Single-Prompt Coordination**: Active scans often run with 10–20 concurrent threads. When session expiration occurs, an atomic lock ensures **only one prompt dialog opens**; all other threads gracefully wait on a condition variable without deadlocks or UI freezes.
- **Audio / System Beep Alert**: Emits an audible chime via `Toolkit.beep()` to alert the tester immediately when the scan pauses.
- **Interactive Swing Prompt**:
  - Displays the exact trigger reason and the target URL that failed.
  - Pre-populates existing cookies for fast editing.
  - Supports pasting full `Cookie:` headers, specific named cookies (e.g. `JSESSIONID`), or `Authorization: Bearer` tokens.
  - Provides quick action buttons:
    - **`✅ Update Cookie & Resume Scan`**: Injects new credentials, unblocks all threads, and retries the failed request.
    - **`⏭ Ignore Once & Resume`**: Bypasses the pause and lets threads continue.
    - **`❌ Disable Keeper for this Scan`**: Disables interception so the scanner runs unhindered.

### 4. 🔄 Automated Request Retries
- When enabled, the request that triggered the session expiration is automatically re-sent with the newly supplied session cookie.
- The fresh, successful response is returned directly to the Burp Scanner engine via `ResponseReceivedAction.continueWith(retryResponse)`. Burp Scanner never sees the 401/302, ensuring zero false negatives and preserving scan accuracy.

### 5. 📊 Live Activity Log & Native Montoya HTTP Inspectors
- **Live Activity Log**: Displays timestamped events (`SESSION_EXPIRED`, `SCAN_PAUSED`, `COOKIE_UPDATED`, `REQUEST_RETRIED`, `COOKIE_INJECTED`, `TEST_PROBE`).
- **Triage Filtering Toolbar**:
  - `MultiSelectFilterButton` for **Tool** (`All`, `Scanner`, `Repeater`, `Intruder`, `Manual`, `User`).
  - `MultiSelectFilterButton` for **Status** (`All`, `2xx`, `3xx`, `4xx`, `5xx`).
  - `MultiSelectFilterButton` for **Event** (`All`, `SESSION_EXPIRED`, `REQUEST_RETRIED`, `SCAN_PAUSED`, `SCAN_RESUMED`, `COOKIE_UPDATED`).
  - Live search across URL, Host, and details.
  - **Export TSV**: Copies activity history to system clipboard for reporting.
- **Montoya Message Editors**: Master-detail view with embedded native **Request** and **Response** message viewers for inspecting any logged event.

### 6. 🖱️ Context Menu Integration
Right-click any request in Burp (**Proxy History**, **Repeater**, **Logger**, **Scanner**):
- **`🍪 Set as Active Scan Session Cookie`**: Instantly captures the `Cookie:` header and host from the selected request and populates the Session Keeper.
- **`🎯 Set Target Host Scope`**: Configures the host filter to match the selected target.
- **`⏸ Pause / ▶ Resume Active Scanner`**: Manually pause or resume active scanner threads on-demand.

---

## 🏗️ Architecture & Technical Specs

- **Montoya API**: Built using `net.portswigger.burp.extensions:montoya-api:2023.12.1`.
- **Concurrency & Zero-Freeze UI**:
  - Uses `ReentrantLock` and `Condition` for thread synchronization.
  - UI modal dialogs safely dispatched to the Swing Event Dispatch Thread (EDT).
  - Unload hook (`registerUnloadingHandler`) unpauses any waiting threads to prevent scanner lockups when updating or unloading the extension.
- **Target Java Version**: Java 17+ bytecode compatibility.

---

## 🚀 Building the Extension

### Using Gradle (Recommended):
```bash
cd /home/littlespidy/myextra/burpsuite/ActiveScanSessionKeeper_littlespidy
./gradlew jar
```
The compiled JAR will be located at:
```
build/libs/activescan-session-keeper-littlespidy-1.0.0.jar
```

### Using Maven:
```bash
cd /home/littlespidy/myextra/burpsuite/ActiveScanSessionKeeper_littlespidy
mvn clean package
```
The compiled JAR will be located at:
```
target/activescan-session-keeper-littlespidy-1.0.0.jar
```

---

## 🔌 Installing into Burp Suite

1. Open **Burp Suite**.
2. Navigate to **Extensions** → **Installed**.
3. Click **Add**.
4. Configure the installer dialog:
   - **Extension type**: `Java`
   - **Extension file (.jar)**: Browse and select `ActiveScanSessionKeeper_littlespidy/build/libs/activescan-session-keeper-littlespidy-1.0.0.jar`.
5. Click **Next**.
6. The **`Session Keeper`** tab will appear in Burp Suite's top tab bar!

---

## 📖 Recommended Workflow

1. **Ingest Initial Session**:
   - Perform an authenticated request in your browser through Burp Proxy.
   - Right-click the authenticated request in **Proxy HTTP history** and select **`🍪 Set as Active Scan Session Cookie`**.
2. **Start Active Scan**:
   - Right-click any authenticated target URL or endpoint and choose **`Scan`** (Active Scan / Audit).
3. **Wait for Timeout**:
   - Continue testing while Burp active scanner executes.
   - When the session expires, the extension alerts you with a chime and pops up the modal prompt dialog.
4. **Supply Fresh Cookie**:
   - Refresh your authenticated session in the browser, copy the new cookie, and paste it into the prompt.
   - Click **`✅ Update Cookie & Resume Scan`**.
5. **Seamless Continuation**:
   - The extension retries the expired check and automatically updates all subsequent scanner payloads with the fresh cookie!
