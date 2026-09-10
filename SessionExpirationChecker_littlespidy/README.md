# ⏱️ Session Expiration Checker (littlespidy)

> **Created with the help of an AI Agent and littlespidy.**

A modern Burp Suite extension built on the **Montoya API** designed to automate session timeout and token expiration testing. Security testers can send authenticated requests and schedule multiple custom milestone probes (e.g., **30 min**, **1 hr**, **3 hr**, **8 hr**, or arbitrary intervals) to systematically determine when a session or token becomes invalid.

---

## 🎯 Key Features

- **One-Click Target Ingestion**:
  - Right-click any HTTP request in **Proxy History**, **Repeater**, **Logger**, or the **HTTP Message Editor** and choose **`⏱️ Send to Session Expiration Checker`**.
  - Supports both single and multi-request selection.
- **Custom Milestone Timers (Milestone-based from $T_0$)**:
  - Configures **16 milestones by default** every 30 minutes from **30m up to 8 hours** (`30m`, `1h`, `1h 30m`, `2h`, `2h 30m`, `3h`, `3h 30m`, `4h`, `4h 30m`, `5h`, `5h 30m`, `6h`, `6h 30m`, `7h`, `7h 30m`, `8h`).
  - Timers count down concurrently from baseline start time ($T_0$).
  - Fast preset buttons to reload all 16 defaults or custom intervals.
- **HTTP Response Date & Time Highlighting**:
  - Automatically inspects the standard HTTP `Date:` response header (as well as `Expires` and `Last-Modified`).
  - Applies native Montoya `Marker` highlighting to paint vibrant yellow/orange highlight boxes over server date/time stamps across Pretty, Raw, and Hex editors.
  - Displays the server's `Date:` header in the **Milestones & History** table to correlate server clock time against local milestone schedules.
- **Baseline Comparison & Verification Engine**:
  - Captures an authenticated baseline response with session cookies and authentication headers.
  - Compares probe responses against baseline behavior:
    - **Status Code Shifts**: Identifies `200 -> 401 Unauthorized`, `200 -> 403 Forbidden`, or redirect codes (`302/301/307`).
    - **Auth Redirects**: Detects redirects to login endpoints (`/login`, `/signin`, `auth`, `sso`, etc.).
    - **Header Invalidation**: Detects `Set-Cookie` headers clearing sessions (`Max-Age=0`, `expires=1970`).
    - **Body Signature Inspection**: Flags keywords indicating session termination (`"session expired"`, `"token expired"`, `"please log in"`, etc.) absent in the baseline.
- **Auto-Cancellation on Expiry**:
  - Automatically cancels all remaining scheduled milestone timers for a task once session expiration is detected, saving traffic volume and server load.
- **Master-Detail Workspace**:
  - **Live Dynamic Countdown**: Master table shows real-time countdowns (`29m 14s`) ticking down to the next scheduled check.
  - **Milestones & History Table**: Inspect each milestone probe's target time, execution time, server date header, HTTP status, body length delta, and verdict signal.
  - **Native Montoya Message Editors**: Side-by-side dedicated editors for **`📤 Probe Request`**, **`📥 Probe Response`**, **`🎯 Baseline Request`**, and **`🎯 Baseline Response`**.
  - **Core Triage Filters**: Rapid filtering by Host/Domain, Method (`MultiSelectFilterButton`), Status Code, and State (`ACTIVE`, `EXPIRED`, `PENDING`, `RUNNING`, `CANCELLED`).
  - **Burp Suite Interoperability**: Right-click any session or probe to send to **Repeater**, **Intruder**, or **Organizer**.
- **📖 Welcome & Onboarding Dashboard**:
  - Integrated first tab displaying tutorial cards covering testing methodology (Idle vs Absolute timeout), baseline matching rules, milestone calculation ($T_0 + \Delta$), detection heuristics, and on-demand controls with a 1-click **`⏱️ Open Session Monitor`** button.

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

1. **Capture Authenticated Request**:
   - Log into your target application and identify a state-dependent endpoint (e.g. `/api/v1/user/profile` or `/dashboard`).
2. **Send to Checker**:
   - Right-click the request in Proxy or Repeater and select **`⏱️ Send to Session Expiration Checker`**.
3. **Configure Milestones**:
   - In the configuration dialog, choose quick-add presets (e.g. `+30m`, `+1h`, `+3h`, `+8h`) or input custom intervals.
   - Leave `Cancel remaining scheduled timers if session expires` checked.
   - Click **▶️ Start Tracking**.
4. **Monitor & Triage**:
   - Monitor the countdown and status in the master table.
   - When a milestone triggers, the extension re-probes the endpoint and compares against baseline.
   - If active, status stays `ACTIVE`.
   - When the session expires, the status flips to `EXPIRED`, signals the reason (e.g. `Expired (401 Unauthorized)`), and halts remaining timers.
