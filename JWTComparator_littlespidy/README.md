# JWT Comparator (Burp Suite Extension)

**Author**: littlespidy  
*Created with the help of an AI Agent and littlespidy.*

---

## Overview

**JWT Comparator** is an interactive multi-token comparison and diffing extension for Burp Suite built on the modern **Montoya API**.

In modern web applications, microservice architectures, and multi-tenant platforms, different domains, subdomains, and API gateways frequently require distinct JSON Web Tokens (JWTs). Testers must inspect and compare these tokens side-by-side to understand authorization scope variances, issuer/audience configurations, permission divergences, and lifecycle differences.

JWT Comparator solves this by providing dynamic $N$-token side-by-side comparison, intelligent on-demand context menu extraction, and color-coded claim diffing.

---

## Key Features

1. **Welcome & Guide Dashboard (Initial View)**:
   - Onboarding tab loaded first upon opening Burp Suite, offering interactive workflow guides and a 1-click launcher to switch directly to the comparator tab.

2. **Side-by-Side Vertical Columns (Left to Right)**:
   - Compare 2, 3, 4, or dynamic $N$ tokens side-by-side in vertical column cards arranged horizontally from left to right.
   - Smooth horizontal scrolling for unlimited simultaneous token comparisons.
   - Click `➕ Add Another Token Slot` to append new comparison columns.

3. **Custom Token Naming**:
   - Explicit `Name:` input field on every column card (e.g., `Admin Prod`, `Staging User`, `Microservice Gateway`).
   - Editing names live-syncs immediately across matrix table column headers, detail inspector tabs, and TSV exports.

4. **Session JSON Save & Import**:
   - Save your entire working token set, custom labels, and slot configurations to a JSON file via `💾 Export JSON`.
   - Restore saved sessions anytime via `📂 Import JSON` to resume multi-environment security audits without re-pasting tokens.
   - Flexible parser supporting standard exports, object arrays, key-value maps, and raw token lists.

5. **TSV File Download & Clipboard Export**:
   - Download the full claims comparison matrix directly to disk as a `.tsv` file (`💾 Download TSV`).
   - One-click copy to clipboard (`📋 Copy TSV`) for rapid reporting, spreadsheet analysis, and bug bounty proof-of-concept sharing.

6. **On-Demand Context Menu Extraction (`Send to JWT Comparator`)**:
   - Right-click any HTTP request or response in Burp (**Proxy**, **Repeater**, **Logger**, or **Scanner**).
   - Automatically detects and extracts JWTs from:
     - `Authorization: Bearer <JWT>` headers
     - Session and Auth `Cookie` headers
     - Custom auth headers (`X-Access-Token`, `Token`, `JWT`)
     - JSON request / response bodies
     - User-selected text highlighted in the message editor
   - Direct the token into a specific existing slot or append as a new slot. Automatically switches to the comparator tab.

7. **Color-Coded Claims Diffing & Status Tracking**:
   - Compares all Header parameters and Payload claims in a unified matrix:
     - **Amber / Orange**: Value Mismatch (claim present in tokens but with different values).
     - **Soft Red / Italics**: Partially Missing (claim present in some tokens but absent in others).
     - **Neutral**: Identical (same claim and value across all tokens).

8. **"Differences Only" Focused Triage**:
   - Toggle the View filter between `All Claims`, `Differences Only` (hides identical claims to immediately focus on divergences), `Missing Only`, and `Matches Only`.
   - Filter by section (`All`, `Header`, `Payload`) and instant text search across keys and values.

9. **Ignored Claims in Differences View**:
   - Eliminate expected drift and noise (e.g., `exp`, `iat`, `nbf`, `jti`, `auth_time`) from the `Differences Only` view.
   - Configure via the `Ignore:` toolbar field, click `⚙️` to access presets (Timestamps, Nonces), or right-click any row directly in the Claims Comparison Matrix to ignore or unignore that claim on demand.
   - Summary label automatically reports how many differences are currently hidden by the ignore filter.
   - Ignored claims preferences are saved and restored with `💾 Export JSON` / `📂 Import JSON` sessions.

10. **Epoch Timestamp & Validity Translation**:
    - Automatically translates Unix epoch timestamps (`exp`, `iat`, `nbf`, `auth_time`, `updated_at`) into human-readable UTC and Local dates with relative duration (e.g. `Active (expires in 1h 45m)` or `Expired 3d ago`).

11. **Selected Claim Inspector & Decoded Viewers**:
    - Select any claim in the matrix to inspect raw and formatted JSON representations in per-token tabs.
    - Click `🔍 View Decoded` on any token card for complete pretty-printed Header and Payload JSON.

12. **Token Attacker & Access Matrix (Active BOLA / IDOR Verification)**:
    - Dedicated **Token Attacker** tab (Tab 2) designed to test authorization boundaries across multiple requests and tokens.
    - Right-click any request or multiple selected requests in Burp (**Proxy**, **Repeater**, **Logger**) ➔ `⚔️ Send Request(s) to Token Attacker`.
    - Click `🚀 Start Attack` to replay all queued requests substituting **all loaded JWT tokens** from Tab 1 (`Token 1..N`), plus an optional unauthenticated baseline probe.
    - Automated detection & flagging:
      - `🚨 BOLA / Access Bypass`: Highlighted in bright red when multiple tokens (e.g., lower-privileged user tokens) receive `200 OK` on privileged endpoints.
      - `⚠️ Unauthenticated Access`: Flagged when endpoints allow unauthorized access without tokens.
      - `✔ Access Enforced`: Properly segregated endpoints where primary tokens succeed and secondary tokens receive `401` / `403`.
    - Real-time execution controls: Configurable worker threads (1–32), per-request throttle delay (0–5000 ms), pause/resume, and stop buttons.
    - Side-by-side Montoya `HttpRequestEditor` and `HttpResponseEditor` inspection per token (`Baseline`, `Token 1`, `Token 2`, ..., `Unauthenticated`).
    - Download or copy the entire Access Matrix as TSV (`💾 Download TSV` / `📋 Copy TSV`).

---

## Building the Extension

Ensure Java 17 or higher is installed:

```bash
cd /home/littlespidy/myextra/burpsuite/JWTComparator_littlespidy
./gradlew clean jar
```

The compiled standalone fat JAR will be located at:
```
build/libs/jwt-comparator-littlespidy-1.0.0.jar
```

---

## Loading into Burp Suite

1. Open Burp Suite.
2. Navigate to **Extensions** ➔ **Installed**.
3. Click **Add**.
4. Choose **Java** as the Extension Type.
5. Select `build/libs/jwt-comparator-littlespidy-1.0.0.jar`.
6. Click **Next** — the extension will load and add the **JWT Comparator** top-level Suite tab.
