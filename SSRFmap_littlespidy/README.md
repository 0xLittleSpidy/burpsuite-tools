# SSRFmap Burp Suite Extension [littlespidy]

// Created with the help of an AI Agent and littlespidy.

A high-performance, native Java Burp Suite extension converting the SSRFmap CLI into an interactive graphical testing and exploitation environment powered by the modern Montoya API.

---

## Key Features

1. **Context Menu Dispatch**:
   - Right-click any HTTP request in Burp Suite (Proxy History, Repeater, Target, or Logger).
   - Select **Send to SSRFmap** to open a new root request session tab.

2. **Root Multi-Session Tabs**:
   - Every sent request creates an isolated root tab (e.g., `1: POST /api/v1/import/url`, `2: GET /fetch_document`) with a close `[x]` button.

3. **Burp Intruder-Style Marker Editor**:
   - Highlight any candidate parameter value in the raw HTTP request editor.
   - Click **Add Section Marker (§)** to wrap the target value in `§...§`.
   - Click **Clear Markers (§)** to strip marker symbols while preserving original text.

4. **HTTP 400 Bad Request Fix & Normalization**:
   - Automatically normalizes all request line breaks to RFC-compliant `\r\n` (CRLF).
   - Automatically recalculates and updates the `Content-Length` header whenever payload substitution modifies the body byte size, preventing server-side body parsing and truncation errors.

5. **Button-Driven Test Execution**:
   - **Protocol Schemes**: Single **Run All Protocols** button testing `file://`, `dict://`, `sftp://`, `tftp://`, `ldap://`, `smtp://`, `gopher://`, `http://`, and `https://`.
   - **Cloud Metadata Attacks**: Individual buttons for **AWS**, **GCP**, **Azure**, **Alibaba**, **DigitalOcean**, plus **Run All Clouds**.
   - **SSRF Service Exploits**: Individual buttons for **Redis**, **Docker**, **FastCGI**, **ReadFiles**, **Memcached**, **PortScan**, plus **Run All Services**.
   - **Collaborator Dedicated Probe**: Generates a unique Burp Collaborator URL, injects it into the marked parameter, sends the request immediately, and polls for DNS, HTTP, and SMTP callbacks.
   - **View Payloads**: Displays a searchable, categorized library of all loaded payloads and raw JSON source.

6. **JSON-Based Payload Storage**:
   - All payload definitions are stored in `src/main/resources/payloads_littlespidy.json`.
   - Includes extensive cloud metadata endpoints for AWS (16 URLs including IAM, user-data, instance-identity), Google Cloud (6 URLs), and Azure (3 URLs).

7. **History Retention & Multi-Select Attack Filter**:
   - Log history is preserved across attack runs (results append continuously).
   - Multi-select dropdown in the results toolbar allows filtering visible log rows by attack types (`file`, `aws`, `redis`, `collaborator`, etc.).

---

## Building and Installation

### Prerequisites
- Java Development Kit (JDK) 17 or higher
- Burp Suite Professional or Community Edition (supporting Montoya API 2024+)

### Build Fat-JAR
Run the following command from the extension directory:
```bash
./gradlew clean test jar
```
The compiled fat-JAR will be generated at:
`build/libs/ssrfmap-littlespidy-1.0.0.jar`

### Install in Burp Suite
1. In Burp Suite, navigate to **Extensions** -> **Installed**.
2. Click **Add**.
3. Under **Extension Details**:
   - Extension type: **Java**
   - Extension file: Select `build/libs/ssrfmap-littlespidy-1.0.0.jar`
4. Click **Next** and verify the extension tab **SSRFmap** appears in the top menu bar.
