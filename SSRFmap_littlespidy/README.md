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
   - Click **Auto-Detect Marker** to automatically identify potential SSRF parameters (e.g. `url=`, `redirect=`, `path=`, `dest=`, `webhook=`).

4. **Comprehensive Test Modules**:
   - **7 Core Protocol Schemes**:
     - `file://`: Local file disclosure (`/etc/passwd`, `/etc/hosts`, `/proc/self/environ`, `c:/windows/win.ini`).
     - `dict://`: In-memory service probing (Memcached `stat`, Redis `info`, FTP `quit`).
     - `sftp://`: Out-of-band SSH/SFTP callbacks and internal port probes.
     - `tftp://`: UDP TFTP interactions and file extraction probes.
     - `ldap://`: Out-of-band directory queries and internal root DSE queries.
     - `smtp://`: Mail injection and local MTA probes.
     - `gopher://`: Raw TCP protocol tunneling for Redis commands, FastCGI PHP-FPM, and Memcached.
   - **Cloud Metadata Services**:
     - AWS EC2 IMDSv1 and IAM security credentials.
     - Google Cloud Compute Metadata (`computeMetadata/v1`).
     - Alibaba Cloud ECS Metadata (`100.100.100.200`).
     - DigitalOcean Droplet Metadata JSON.
     - Azure Instance Metadata Service.
   - **Service Exploits & Scanning**:
     - Redis INFO and command execution.
     - Docker Remote API container inspection.
     - FastCGI PHP-FPM handshake tunnel.
     - ReadFiles Linux/Windows file diffing.
     - Port Scanner for common internal TCP ports.

5. **Hybrid Verification & Traffic Inspector**:
   - **Automated Baseline**: Sends an initial request with the original marked value to capture baseline response size, status code, and content.
   - **Diff Analyzer**: Real-time line-by-line diffing and regex indicator detection (`root:x:0:0:`, `redis_version:`, `ami-id`, etc.).
   - **Burp Collaborator Integration**: Generates unique subdomains and automatically polls for out-of-band DNS, HTTP, and SMTP callbacks.
   - **Split Traffic Viewer**: Interactive table paired with synchronized Burp Montoya Request/Response editors, Response Diff analysis tab, and Collaborator detail logs.

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

---

## Interactive HTML Mockup Preview
A standalone HTML5 UI preview is available at:
`ssrfmap_ui_preview_littlespidy.html`

To launch:
```bash
xdg-open ssrfmap_ui_preview_littlespidy.html
```
