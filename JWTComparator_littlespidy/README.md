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

1. **Dynamic $N$-Token Comparison Matrix**:
   - Compare 2, 3, 4, or more JWT tokens simultaneously across different domains or user roles.
   - Click `➕ Add Another Token Slot` to dynamically add more comparison columns.
   - Customizable domain labels on each card (e.g., `api.domain-a.com (Admin)`, `auth.domain-b.com (User)`).

2. **On-Demand Context Menu Extraction (`Send to JWT Comparator`)**:
   - Right-click any HTTP request or response in Burp (**Proxy**, **Repeater**, **Logger**, or **Scanner**).
   - Automatically detects and extracts JWTs from:
     - `Authorization: Bearer <JWT>` headers
     - Session and Auth `Cookie` headers
     - Custom auth headers (`X-Access-Token`, `Token`, `JWT`)
     - JSON request / response bodies
     - User-selected text highlighted in the message editor
   - Direct the token into a specific existing slot (`Token 1`, `Token 2`, etc.) or append as a new slot.
   - Automatically pre-populates the host domain as the token's label.

3. **Color-Coded Claims Diffing & Status Tracking**:
   - Compares all Header parameters and Payload claims in a unified matrix:
     - **Amber / Orange**: Value Mismatch (claim present in tokens but with different values).
     - **Soft Red / Italics**: Partially Missing (claim present in some tokens but absent in others).
     - **Neutral**: Identical (same claim and value across all tokens).

4. **"Differences Only" Focused Triage**:
   - Toggle the View filter between:
     - `All Claims`
     - `Differences Only` (hides identical claims to immediately focus on divergences)
     - `Missing Only` (isolates claims that are absent in some tokens)
     - `Matches Only`
   - Filter by section (`All`, `Header`, `Payload`) and instant text search across keys and values.

5. **Epoch Timestamp & Validity Translation**:
   - Automatically translates Unix epoch timestamps (`exp`, `iat`, `nbf`, `auth_time`, `updated_at`) into human-readable UTC and Local dates.
   - Real-time relative duration calculation (e.g. `Active (expires in 1h 45m)` or `Expired 3d 2h ago`).

6. **Selected Claim Inspector & Decoded Viewers**:
   - Select any claim in the matrix to inspect raw and formatted JSON representations in per-token tabs.
   - Click `🔍 View Decoded` on any token card for complete pretty-printed Header and Payload JSON.

7. **One-Click TSV Export**:
   - Export the entire comparison matrix to your clipboard with `📋 Copy TSV Diff` for bug bounty writeups, compliance reports, and audit logs.

8. **Welcome & Guide Dashboard**:
   - Built-in onboarding tab with modular tutorial cards and workflow best practices.

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
