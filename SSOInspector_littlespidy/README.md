# SSO Inspector (littlespidy)

SSO Inspector is an advanced Burp Suite extension written in Java utilizing the modern Montoya API (`net.portswigger.burp.extensions:montoya-api`). It is engineered to inspect, audit, and actively test Single Sign-On (SSO), OAuth 2.0, and OpenID Connect (OIDC) authentication flows during penetration testing and security assessments.

The extension integrates, updates, and modernizes all detection mechanisms and vulnerability checks from the legacy `oauth-scan` extension, delivering an interactive UI workspace alongside native Burp Scanner integration.

---

## Features

### 1. Dedicated Suite Tab: SSO Inspector -> OAuth
- **Interactive OAuth Request Workbench**: Penetration testers can right-click any HTTP request in Burp Suite (Proxy HTTP history, Repeater, Target, Logger) and select `Send to SSO Inspector -> OAuth`.
- **Row-per-Request Table with Explicit Issue Tracking**:
  - `#`: Monotonic request sequence ID.
  - `Time`: Local timestamp.
  - `Method`: HTTP verb (GET, POST).
  - `Host`: Target authorization server or application domain.
  - `Path`: Request endpoint path.
  - `Flow Type`: Automatically classified OAuth/OIDC flow name.
  - `Severity`: Highest detected vulnerability severity badge (`HIGH`, `MEDIUM`, `LOW`, `INFO`, `CLEAN`).
  - `Issues`: Count of detected issues for the row.
  - `Issue Summary`: Semicolon-delimited list of vulnerabilities directly in the row (e.g. `Missing State; PKCE Plaintext; Open Redirect`).
- **Interactive Filter Controls**:
  - Live full-text search across Host, URL, Parameters, and Issues.
  - Multi-select popup filter buttons for `Flow Type` and `Severity`.
- **Deep Inspection Sub-Tabs**:
  - **Request & Response Viewers**: Native Montoya syntax-highlighted HTTP message editors.
  - **OAuth Parameters Inspector**: Detailed breakdown of extracted parameters from URL Query, Request Body (URL-encoded & JSON), Authorization headers, and Cookies. Identifies standard IANA parameters versus vendor extensions, and automatically decodes URL encoding and JWT structures (Header + Payload claims).
  - **Security Audit Panel**: Comprehensive finding reports detailing issue descriptions, impact, remediation recommendations, and RFC references.
  - **Active Scanner Workbench**: Modular attack execution console with individual attack checklists, one-click "Run All" capability, Collaborator configuration, progress indicators, and live event logs.

### 2. Supported OAuth / OIDC Flow Classifications
- **Authorization Code Flow with PKCE** (RFC 7636)
- **Standard Authorization Code Flow** (RFC 6749 Section 4.1)
- **Implicit Flow** (RFC 6749 Section 4.2 - Deprecated)
- **Hybrid Flow** (OpenID Connect Core 1.0)
- **Client Credentials Flow** (RFC 6749 Section 4.4)
- **Resource Owner Password Credentials Flow** (RFC 6749 Section 4.3 - Deprecated)
- **Token Exchange Flow** (RFC 8693)
- **JWT Bearer Token Profile** (RFC 7523)
- **Device Authorization Grant** (RFC 8628)
- **Discovery / Well-Known Endpoints** (RFC 8414)

### 3. Integrated Security Checks (from oauth-scan)

#### Passive Audit Checks
- **Client Secret Leakage**: Exposure of `client_secret` in URL query parameters or HTTP GET requests.
- **State Parameter Validation**: Detection of missing `state` parameter (CSRF risk) or weak entropy/predictable state values.
- **Nonce Parameter Validation**: Missing or predictable `nonce` parameter in OpenID Connect flows.
- **PKCE Misconfigurations**: Authorization code flows lacking PKCE or configured with `code_challenge_method=plain`.
- **Insecure / Deprecated Flows**: Automatic flagging of deprecated Implicit and Resource Owner Password Credentials flows.
- **Referer Leakage**: Exposure of authorization codes, access tokens, or ID tokens in HTTP `Referer` headers.
- **Token Lifetime Analysis**: Detection of excessive token validity periods (> 24 hours) or missing expiration parameters.
- **Improper Refresh Token Issuance**: Detection of refresh tokens released in response to Client Credentials grants.
- **Metadata Exposure**: Detection of `.well-known/openid-configuration` and `.well-known/oauth-authorization-server` endpoints.

#### Active Probing Attacks (Interactive & Burp Scanner)
- **Redirect URI Fuzzing / Open Redirect**:
  - Path traversal vectors (`/../../../../../notexist`, `%2f%2e%2e%2f...`, `/..;/..;/..;/../testOauth`)
  - External domain destinations (`https://burpcollaborator.net/`, `@burpcollaborator.net/`, `.burpcollaborator.net/`)
  - Fragment anchor bypass (`https://burpcollaborator.net#`)
  - Userinfo credential injection (`:password@burpcollaborator.net`)
  - Parameter pollution (`&redirect_uri=...`)
  - Localhost and loopback address bypasses (`127.0.0.1`, `http://localhost/`, `http://2130706433`)
  - Host header poisoning (`Host: collaborator/target`)
  - OpenID fragment response mode injection (`&response_mode=fragment`)
- **Scope Escalation & Fuzzing**: Injects high-privilege scopes (`admin`, `premium`, `sudo`, `full`, `offline_access`, Okta cloud scopes) to identify unauthorized privilege elevation.
- **Authorization Code Replay Attack**: Replays used authorization codes against token endpoints to verify that the authorization server strictly enforces single-use code invalidation.
- **Nonce Reuse & Stripping**:
  - Replays authorization requests with identical nonces to test anti-replay enforcement.
  - Strips the nonce completely to verify if the server mandates nonce validation.
- **Response Type Coercion**:
  - Injects `response_type=none` to test for unsigned token bypasses.
  - Injects `response_type=token` to coerce secure Authorization Code flows into the insecure Implicit Flow.
- **PKCE Downgrade & Bypass**:
  - Strips `code_challenge` and `code_challenge_method` to test if the authorization server allows PKCE bypass.
  - Changes `code_challenge_method` from `S256` to `plain` to test for plaintext downgrade.
- **Well-Known & WebFinger Discovery**: Probes target host for active OIDC discovery metadata, authorization server metadata, and WebFinger resources.
- **Request URI SSRF Probing**: Dispatches out-of-band SSRF probes via `request_uri` targeting Burp Collaborator.
- **ACR Value Confusion / MFA Bypass**: Fuzzes `acr_values` to identify conditions where multi-factor authentication requirements can be bypassed.

### 4. Burp Scanner Integration
- Implements Montoya `ScanCheck` (`SSOScanCheck`).
- Passive checks run automatically on all in-scope traffic during automated scans.
- Active checks run during automated Burp active scans against relevant insertion points (`redirect_uri`, `response_type`, `code`, `state`).

---

## Build Instructions

### Requirements
- Java Development Kit (JDK) 17 or later
- Gradle (Gradle wrapper included)

### Building the Fat JAR
From the project root:
```bash
./gradlew test jar
```

The resulting standalone JAR file will be generated at:
```
build/libs/sso-inspector-littlespidy-1.0.0.jar
```

---

## Installation in Burp Suite

1. Open Burp Suite.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. Set **Extension type** to **Java**.
5. Click **Select file...** and choose `build/libs/sso-inspector-littlespidy-1.0.0.jar`.
6. Confirm that **SSO Inspector (littlespidy)** loads cleanly without errors in the Output tab.

---

## Usage Guide

1. **Sending Requests to the Extension**:
   - In **Proxy HTTP history**, **Repeater**, **Target**, or **Logger**, locate an OAuth authorization or token request.
   - Right-click the request and select **Send to SSO Inspector** -> **OAuth**.
2. **Reviewing Captured Requests**:
   - Navigate to the **SSO Inspector** top-level suite tab and open the **OAuth** tab.
   - Select the request row in the top table.
   - Review detected issues in the `Severity`, `Issues`, and `Issue Summary` columns.
3. **Inspecting Parameters & JWTs**:
   - Open the **OAuth Parameters** sub-tab to view parsed parameters, locations, and decoded JWT contents.
4. **Reviewing Security Findings**:
   - Open the **Security Audit** sub-tab to inspect detailed technical explanations, impact descriptions, remediation guidelines, and RFC references.
5. **Running Active Probes**:
   - Open the **Active Scanner** sub-tab.
   - Configure a callback domain (defaults to `burpcollaborator.net` or automatically uses Burp Collaborator if available).
   - Select specific attack checkboxes or click **Run All Active Checks**.
   - Monitor live progress in the execution log console.
6. **Exporting Reports**:
   - Click the **Export Report** button in the top toolbar to generate a Markdown or JSON summary of all captured requests and findings.

---

## Author & Attribution
- Author: littlespidy
- Core audit algorithms and detection patterns ported and modernized from OAUTHScan by Maurizio Siddu.
