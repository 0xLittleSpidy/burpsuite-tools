# Convert POST to GET (Burp Suite Extension)

*Created with the help of an AI Agent and littlespidy.*

A modern Montoya API Burp Suite extension that converts state-changing, access-controlled, or WAF-protected `POST` requests into `GET` requests by migrating body parameters (form-urlencoded, JSON top-level keys, multipart) into URL query parameters. It tests whether backend servers silently accept GET requests, exposing CSRF bypasses, WAF evasion, authorization flaws, and HTTP method confusion.

Follows the architectural specifications and UI/filtering standards defined in `extension_architecture.md`.

---

## Key Features & Architecture

### 1. Interactive POST Traffic Discovery Tab
- **4 Clean Intake Modes**: All in-scope POST, Authenticated POST, Unauthenticated POST, and All POST traffic.
- **Automatic Deduplication**: Normalizes path structures (`/users/123` $\rightarrow$ `/users/{id}`) and collapses duplicate endpoint shapes.
- **Core Four Triage Filters**:
  - **Domain / Host Filter**: Dedicated text input with automatic URL/port/wildcard sanitization (`api.target.com`, `*.target.com`) and 300ms debounce.
  - **Multi-Select Status Code Filter (`MultiSelectFilterButton`)**: Independent selection of `2xx Success`, `200 OK`, `201 Created`, `3xx Redirect`, `4xx Client Error`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `5xx Server Error`, etc.
  - **Multi-Select Content-Type Filter**: Filter instantly by `Form URL-Encoded`, `JSON`, `Multipart Form-Data`, `XML`, `Plain Text`, or `Other`.
  - **Multi-Select Parameter Type Filter**: Filter candidates by parameter location (`Body Parameters`, `JSON Top-Level Keys`, `Multipart Parameters`, `URL Query Parameters`, `XML Elements`).
  - **In-Scope Only View Filter**: Live, non-destructive filter using `api.scope().isInScope(url)` to instantly hide out-of-scope third-party traffic without re-importing.
- **Burp-Style Search Engine**:
  - Search across URL or Path with **Regex**, **Match Case**, and **Invert (Negative)** search options.
  - Parameter name filtering (e.g. `action, csrf, token, id, user`).
- **Quick Preset Chips**:
  - `[All Candidates]`, `[JSON Payloads]`, `[Form Encoded]`, `[Has Auth / Token]`.
- **Manual Item Selection (Row Pinning)**:
  - `Pin Selected` and `Clear Pins` toolbar buttons and right-click actions. Pinning takes precedence over all active filters to isolate specific endpoints.
- **Burp Suite Interoperability**:
  - Right-click context menu integration for:
    - **Send to Repeater** (`METHOD host/path`)
    - **Send to Intruder**
    - **Send to Organizer**
    - **Export Selected / All Visible to TSV**
    - **Copy Selected as TSV** (`Ctrl+C` / `Cmd+C`)
- **Direct Candidate Inspection**: Bottom Montoya Pretty/Raw/Hex editors display the selected candidate's original POST request and response.

---

### 2. Dedicated Multi-Target Attack Session Workspace
- **Checkbox-Driven `⚡ Attack` Launcher**: Launches isolated session tabs for checked candidates (`Attack (3 targets) ×` or `POST /profile ×`).
- **Collapsible Filter Sidebar (380px/500px)**:
  - **Smart Pattern Suppression**: Automatically hashes and suppresses repetitive response signatures (`status:length:contentType`) to highlight unique behaviors.
  - **Multi-Select Outcome / Signal Filter**: Isolate `Bypass Detected (403/401 -> 200)`, `Method Permitted / CSRF Potential`, `5xx Server Error`, `Redirect Maintained`, or `405 Method Not Allowed`.
  - **Multi-Select Severity Filter**: `High`, `Medium`, `Low`, `Info`.
  - **Multi-Select GET Status Code Filter**: Granular status code filtering for converted responses.
  - **Quick Presets**: `[Bypasses (403->200)]`, `[CSRF Candidates]`, `[5xx Errors]`, `[All Anomalies]`.
  - **Content Bounds**: Filter by response min/max byte length and search within Signal / Evidence text.
- **Deep-Linking Quad in Montoya HTTP Editors**:
  1. **Active Tab Auto-Switching**: Automatically switches to Converted GET Response or Request depending on finding severity.
  2. **Native Marker Highlighting**: Renders native yellow/orange Burp highlight markers on converted query parameters in the request editor.
  3. **Search Bar Expression Populating**: Automatically populates the native Montoya bottom search bar with migrated parameter names.
  4. **Caret Positioning & Viewport Auto-Scroll**: Centers the editor viewport directly on findings.
- **Row Pinning in Results**: Pin specific interesting conversion results to review them in isolation.
- **Burp Tool Integration**:
  - `Send Converted GET to Repeater`
  - `Send Original POST to Repeater`
  - `Send Converted GET to Intruder`
  - `Send Converted Result to Organizer`
- **Live Ambient Status Glyphs**:
  - Session tab header automatically updates on completion with ambient status symbols: `⚠️` if High/Medium bypasses or CSRF vectors were found, or `✔` if all conversions were cleanly blocked.
- **Custom Headers & Auth Token Injection**:
  - Click `Custom Headers & Auth... (N)` to inject fresh session cookies, Bearer tokens, or API keys when auditing expired sessions.

---

### 3. Burp Active Scanner Integration
- Automatically registers an active `ScanCheck` (`activeAudit()`) to test POST $\rightarrow$ GET conversions during Burp Suite active scans.

---

## Building the Extension

```bash
cd /home/littlespidy/myextra/burpsuite/ConvertPostToGet_littlespidy
./gradlew clean jar
```

The compiled JAR file is located at:
`build/libs/convert-post-to-get-littlespidy-1.0.0.jar`

---

## Installation in Burp Suite

1. Open **Burp Suite**.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. Set **Extension type** to `Java`.
5. Select the JAR:
   `/home/littlespidy/myextra/burpsuite/ConvertPostToGet_littlespidy/build/libs/convert-post-to-get-littlespidy-1.0.0.jar`
6. Click **Next**. The **"Convert POST to GET"** tab will appear in the main suite bar.

---

## Usage Workflow

1. Go to **POST Traffic Discovery** and click **Load from Proxy History**.
2. Use the **Core Four Triage Filters** (Domain, Status, Content-Type, Param Types, In-Scope, and Regex Search) or **Preset Chips** to isolate target endpoints.
3. Check target candidates `[x]` (or click `Pin Selected`) and click **⚡ Attack**.
4. In the session tab:
   - Optionally inject updated authentication via **Custom Headers & Auth...**.
   - Click **Start Conversion Test**.
   - Use the **Collapsible Smart Filter Sidebar** to filter out repetitive responses and focus on `403 -> 200` bypasses or `200 -> 200` CSRF potentials.
   - Click any result row to view deep-linked parameters and comparative exchanges in the Montoya editors.
   - Right-click to send interesting requests to **Repeater**, **Intruder**, or **Organizer**.
