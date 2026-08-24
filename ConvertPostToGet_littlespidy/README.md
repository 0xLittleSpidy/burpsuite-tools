# Convert POST to GET (Burp Suite Extension)

*Created with the help of an AI Agent and littlespidy.*

A Montoya API Burp Suite extension that converts state-changing, access-controlled, or WAF-protected `POST` requests into `GET` requests by migrating body parameters (form-urlencoded, JSON top-level keys, multipart) into URL query parameters. It tests whether the backend server silently accepts GET requests, exposing CSRF bypasses, WAF evasion, or authorization flaws.

---

## Key Features

- **Interactive POST Traffic Discovery Tab**:
  - **4 Clean Intake Modes**: All in-scope POST, Authenticated POST, Unauthenticated POST, and All POST traffic.
  - **Automatic Deduplication**: Normalizes path structures (`/users/123` $\rightarrow$ `/users/{id}`) and collapses duplicate endpoint shapes.
  - **Comma-Separated Parameter Filtering**: Instantly search by parameter names (e.g. `action, csrf, id, token`).
  - **Direct Candidate Inspection**: Bottom Montoya Pretty/Raw/Hex editors show the selected candidate's original POST request and response.
  - **Checkbox Selection Controls**: `Select All` and `Deselect All` buttons.
- **Dedicated Multi-Target Attack Session Tabs**:
  - **Checkbox-Driven `Attack` Launcher**: Launches dedicated session tabs for checked candidates (`Attack (3 targets) ×` or `POST /profile ×`).
  - **Custom Headers & Auth Token Injection**: Click `Custom Headers & Auth...` in the session tab to inject fresh session cookies, Bearer tokens, or API keys when testing captured traffic at the end of an assessment.
  - **Live Results Workspace**: Streaming results table with high-contrast color badging (`403 -> 200 Bypass Detected`, `200 -> 200 Method Permitted / CSRF`, `405 Method Not Allowed`).
  - **Side-by-Side Montoya Editors**: Converted GET Request & Response vs Original POST Request & Response.
  - **Collapsible Filter Sidebar**: Smart signature suppression + manual filter controls.
- **Burp Active Scanner Integration**:
  - Implements `ScanCheck` (`activeAudit()`) to automatically test POST $\rightarrow$ GET conversions during active scans.

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

## Usage

1. Go to the **POST Traffic Discovery** tab and click **Load from Proxy History**.
2. Filter candidates by parameter name (e.g. `action, token, id`) or status codes.
3. Check the desired endpoints `[x]` (or click `Select All`) and click **Attack**.
4. In the session tab:
   - Optionally inject fresh session cookies or auth tokens via **Custom Headers & Auth...**.
   - Click **Start Conversion Test**.
   - Review findings in the results table and inspect the fuzzed vs original exchanges in the editors.
