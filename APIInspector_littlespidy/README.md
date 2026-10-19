# API Inspector (littlespidy)

Burp Suite extension developed with the modern Montoya API for automated REST API version discovery, representation probing, and endpoint auditing.

## Overview

Modern web applications and APIs frequently maintain legacy, unreleased, deprecated, or undocumented API versions. These older or alternative representations can expose outdated business logic, missing authentication/authorization checks (BOLA/IDOR), or sensitive debug endpoints.

**API Inspector** introduces the **ResAPI Version Finder**, an automated assessment environment inside Burp Suite that probes target API endpoints across multiple versioning strategies and displays results in dedicated, interactive per-request workspaces.

---

## Features

### Feature 1: ResAPI Version Finder Tab
- Main workspace tab integrated directly into Burp Suite's top tab bar.
- Rapid launcher bar to manually submit full API URLs with configurable HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, etc.).
- Right-click context menu integration: Right-click any HTTP request in Proxy History, Repeater, Target site map, or Logger and select **Send to API Inspector (ResAPI Version Finder)**.

### Feature 2: Dedicated Sub-Tabs Per Request
- Each analyzed endpoint spawns its own isolated session sub-tab.
- Automatic naming convention: `"#<ID> <METHOD> <truncated_path>"` (e.g. `"#1 GET /api/v1/users"`).
- Double-click inline renaming on tab headers with zero modal popups:
  - Double-click to edit directly inside the tab header.
  - Press `Enter` to commit changes.
  - Press `Escape` to cancel.
  - Automatic commit on focus loss.
- Plain ASCII close button (`x`) for individual tabs, plus a "Close All Tabs" action.

### Feature 3: Persistent Session Storage & State Recovery (Across Restarts)
- **Automatic Directory Prompt on Load**: Prompts the user to select or confirm the session storage directory when the extension is added, or automatically detects open `.burp` project directories.
- **Preference Memory**: Remembers configured directory in Burp Suite's persistent preferences across sessions.
- **Toolbar Indicator & Switcher**: Live `Storage: [folder] [Change Folder]` controls in the header allow inspecting the active storage directory and switching locations dynamically.
- **Full State Reconstitution**: Restores all sub-tabs, custom renamed titles, baseline requests/responses, strategy options, version candidate lists, thread concurrency settings, delay intervals, probe results tables, and both Intruder strategy tracking views.
- **Atomic Debounced Saving**: Asynchronous saving debounced by 1500ms using atomic temporary file moves (`api_inspector_session.json.tmp` -> `api_inspector_session.json`) ensures zero data corruption.
- **Clean Shutdown Hook**: Registers an `ExtensionUnloadingHandler` ensuring all session data is flushed to disk before the extension or Burp is closed.

### Feature 4: API Documentation Intruder Strategy
- **Progressive Right-to-Left Path Trimming**: Generates requests by progressively removing path segments starting from the last segment until the root path is reached.
  - Example: For `/api/v1/admin`, generates `/api/v1/`, `/api/`, and `/`.
  - Preserves query parameters and handles root paths, trailing slashes, and variable path depths.
- **Automated Unauthenticated Copy Generation**:
  - Strips authentication headers (`Authorization`, `X-Api-Key`, `Token`, `Bearer`, etc.).
  - Strips session/auth cookies (`sessionid`, `jwt`, `token`, `connect.sid`, `phpsessid`, etc.) while strictly preserving non-authentication cookies (`theme`, `tracking_id`).
  - Leaves the original request completely untouched.
- **Automated Intruder Dispatch**: Automatically sends every generated path variation (both authenticated and unauthenticated) to Burp Intruder.
- **Dedicated Tracking Tab**: Logs reference endpoints, generated variations, authentication status, and dispatch status with embedded Montoya request viewer, CSV export, and resend controls.

### Feature 5: API Endpoint Discovery Intruder Strategy
- **Progressive Prefix & Segment Trimming**: Removes path prefixes and segments to discover unmapped or alternative endpoints.
  - Example: For `/api/v1/admin`, generates `/v1/admin`, `/admin`, `/api/v1/`, `/api/`, `/`.
- **Authenticated & Unauthenticated Variants**: Dispatches both authenticated requests and cleanly stripped unauthenticated requests directly to Burp Intruder.
- **Dedicated Tracking Tab**: Master-detail tracking view recording reference endpoints, generated variations, and dispatch outcomes.

### Feature 6: Hierarchical Context Menu Integration
- Right-click any HTTP request in Burp Suite (Proxy HTTP history, Repeater, Target site map, Logger, etc.) and access the **API Inspector (littlespidy)** sub-menu:
  - **Send to ResAPI Version Finder**: Spawns a dedicated Version Finder sub-tab.
  - **API Documentation Intruder Strategy**: Progressively removes trailing path segments, generates unauthenticated pairs, and sends all to Intruder.
  - **API Endpoint Discovery Strategy**: Progressively removes prefix and path segments, generates unauthenticated pairs, and sends all to Intruder.

### Feature 7: API Import Tab
- Import API definitions and collections into Burp Suite from local files or remote URLs.
- Supported specifications:
  - OpenAPI 3.0.x and 3.1.x (JSON and YAML).
  - Swagger 2.0 (JSON and YAML).
  - Postman Collections (v2.0 and v2.1 JSON).
- File import with multi-file batch selection and format validation.
- URL import with multi-URL ingestion, HTTP fetching via Montoya/Burp network settings, and error reporting.
- Collections management table displaying collection name, format, source path/URL, target base URL override, discovered endpoint count, status, and assigned authentication profile.
- Endpoint inspection sub-table with search filtering and detailed parameter/body viewer.
- Full session persistence for imported collections and discovered endpoints.

### Feature 8: Authentication Testing Tab
- Dedicated workspace to configure authentication profiles and execute automated test suites against imported collections.
- Modular authentication mechanisms supported:
  - Bearer Token authentication (`Authorization: Bearer <token>`).
  - API Key authentication (Header or Query Parameter).
  - HTTP Basic authentication (`Authorization: Basic <base64>`).
  - Cookie authentication (`Cookie: <name>=<value>`).
  - Custom Authentication Headers (`<Header-Name>: <value>`).
- Masked secret credentials in UI with Show/Hide toggle.
- Comparative unauthenticated testing: automatically sends unauthenticated request pairs to detect endpoints accessible without required authentication (`UNAUTHENTICATED_ACCESSIBLE`).
- Non-blocking multi-threaded test execution engine with configurable thread concurrency (1-20), delay intervals, and cancellation controls.
- Comprehensive results table with outcome categorization (`AUTHENTICATED_ONLY`, `UNAUTHENTICATED_ACCESSIBLE`, `AUTH_REJECTED`, `SUCCESS`, `CLIENT_ERROR`, `SERVER_ERROR`, `NETWORK_ERROR`).
- Embedded Montoya HTTP message viewers for inspecting authenticated and unauthenticated request/response pairs.
- Export results to CSV and JSON.

---

## Discovery Strategies Supported

1. **URI Path Versioning (Most Common)**
   - Automatically detects and replaces existing version segments: `/v1/`, `/v2/`, `/v1.0/`, `/v0/`, `/version/1/`.
   - Injects versions into clean paths: `/api/users` -> `/api/v1/users`, `/api/v2/users`.
   - Suffix versioning support: `/users_v1` -> `/users_v2`.
   - Comprehensive candidate range: `0`, `1`, `2`, `3`, `4`, `5`, `0.1`, `1.0`, `2.0`, `beta`, `alpha`, `latest`, `legacy`, `deprecated`, `internal`, `test`.

2. **Request Header Versioning**
   - Probes dedicated version headers:
     - `X-API-Version`
     - `API-Version`
     - `X-Version`
     - `Version`
     - `Accept-Version`
     - `X-Accept-Version`
     - `App-Version`
     - `Client-Version`
   - Injects both integer values (`1`, `2`) and prefixed values (`v1`, `v2`).

3. **Query Parameter Versioning**
   - Discovers version parameters: `version`, `v`, `api_version`, `api-version`, `apiVersion`, `ver`, `v_num`.
   - Updates existing query parameters or dynamically appends new query parameters.

4. **Content Negotiation / Media Type Versioning (Accept Header)**
   - Media type version parameters: `Accept: application/json; version=2`, `Accept: application/json; v=2`.
   - Vendor MIME type detection and substitution: `Accept: application/vnd.<vendor>.v{version}+json`.
   - Generic vendor probing: `Accept: application/vnd.api.v{version}+json`.

5. **Content-Type Body Versioning**
   - For state-modifying requests (`POST`, `PUT`, `PATCH`), mutates `Content-Type: application/json; version={version}`.

6. **Subdomain / Host Versioning**
   - Probes versioned hosts: `v1.api.example.com` -> `v2.api.example.com`, `api-v1.example.com` -> `api-v2.example.com`.

7. **Cookie Versioning**
   - Probes version cookies: `Cookie: api_version={version}; version={version}`.

---

## Intelligent Diff & Representation Analysis

Every probed response is compared against the baseline endpoint response:
- `ACTIVE ALTERNATIVE`: High-value finding where the alternative version returned `200 OK` with a different response payload or length delta.
- `STATUS SHIFT: 404 -> 200`: Discovery of an active API version where the baseline returned Not Found.
- `AUTH BYPASS SHIFT: 401/403 -> 200`: Alert for potential authorization bypass on legacy or alternative API endpoints.
- `VERSION ERROR / DEPRECATED`: Identifies deprecation banners or explicit error messages from API gateways.
- `SAME AS BASELINE`: Identical response structure indicating fallback behavior.

---

## Interactive Workspace Controls

- **Sortable Results Table**: Sort by ID, Strategy, Variation, Status code, Response length, or Latency (numeric sorting enabled).
- **Embedded Burp Editors**: Native Montoya `HttpRequestEditor` and `HttpResponseEditor` for full syntax highlighting and inspection.
- **Diff Comparison View**: Direct inspection of status and byte differences.
- **Context Actions**: Right-click any row to "Send to Repeater", "Send to Intruder", "Copy URL", or "Copy Request".
- **Export**: Export probe results to CSV for external reporting.

---

## Building and Installation

### Requirements
- JDK 17 or higher (tested with JDK 21 / 26)
- Gradle (wrapper included)

### Build the JAR
```bash
cd APIInspector_littlespidy
./gradlew clean test build
```

The compiled fat-JAR will be generated at:
```
build/libs/api-inspector-littlespidy-1.0.0.jar
```

### Install in Burp Suite
1. In Burp Suite, navigate to **Extensions** -> **Installed**.
2. Click **Add**.
3. Select **Extension type**: `Java`.
4. Choose the generated JAR file: `APIInspector_littlespidy/build/libs/api-inspector-littlespidy-1.0.0.jar`.
5. Click **Next**. The extension will load and register the **API Inspector** tab.
