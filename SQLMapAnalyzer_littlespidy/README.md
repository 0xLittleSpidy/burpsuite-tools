# SQLMap Output Analyzer and Scanner Burp Suite Extension (_littlespidy)

// Created with the help of an AI Agent and littlespidy.

## Overview

The **SQLMap Output Analyzer and Scanner** is a complete, modern Burp Suite extension built with the Montoya API (`net.portswigger.burp.extensions:montoya-api:2026.4`). It converts and integrates the functionality of **SQLiPy** into a clean, multi-threaded Java architecture, while providing offline database browsing, structural analysis, and persistent session management.

Penetration testers can launch, configure, monitor in real time, and cancel SQLMap scans directly from Burp Suite requests, and then browse and analyze the extracted database tables and sensitive columns without manual CSV inspection.

---

## Features

### 1. Tab 1: SQLMap Scanner (Java Conversion of SQLiPy)
- **Montoya Context Menu Integration**:
  - Right-click any HTTP request in **Proxy History**, **Repeater**, **Logger**, or **Target SiteMap** and select **"Send to SQLMap Scanner"**.
  - Automatically parses target URL, HTTP method, headers, cookies, POST body, and injection parameters.
- **Request-Based Child Sub-Tabs**:
  - Spawns an isolated, closeable child tab for each request (`#1 POST /api/login [x]`).
  - No single-window overwrites; manage multiple target requests concurrently.
- **Dual-Pane Interface**:
  - **Left Pane (Configuration)**:
    - Quick presets: `Fast Detection`, `Standard Audit`, `Thorough`, and `WAF Bypass`.
    - Injection parameter selection (`-p`), Level (1-5), Risk (1-3), Techniques (`BEUSTQ`), DBMS, Tamper scripts.
    - Timing & Network: Threads (1-10), Delay, Timeout, Retries, Tor Socks5, HPP.
    - Enumeration: Banner (`-b`), Current DB, Current User, Is DBA, Hostname, Users, Passwords, Tables, Columns, Dump.
    - Action controls: `[Start Scan]`, `[Stop / Cancel Scan]`, and `[Copy CLI Command]`.
  - **Right Pane (Native Request View)**:
    - Embedded native Montoya `HttpRequestEditor` with syntax highlighting and raw/headers/params views.
- **Real-Time Streaming Log Console**:
  - Positioned at the bottom with automatic background log polling every 1000ms.
  - Live status badge: `IDLE`, `RUNNING`, `VULNERABLE`, `COMPLETED`, `CANCELLED`, `ERROR`.
  - Log level filtering (`ALL`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`), auto-scroll toggle, clear logs, and copy to clipboard.
  - **Vulnerability Findings Tab**: Structured table showing confirmed vulnerable parameters, detected DBMS, injection types, and proof-of-concept payloads.
- **Repeated Request Management (Execution Runs)**:
  - If the same endpoint is submitted multiple times, the existing tab is focused and a new execution run (`Run #2`) is created.
  - Execution history dropdown allows instant switching between past runs to compare configurations, logs, and findings without cluttering duplicate tabs.
- **Immediate Scan Cancellation**:
  - `[Stop / Cancel Scan]` calls `/scan/<taskid>/kill` on the SQLMap REST API, halts background polling, updates the status to `CANCELLED`, and logs the termination notice safely.
- **API Server Control Bar**:
  - Configure Host and Port (default: `127.0.0.1:8775`).
  - `[Test Connection]` checks server reachability.
  - `[Start Local API]` and `[Stop Local API]` can spawn and manage a local `sqlmapapi.py` subprocess directly.

### 2. Tab 2: Database and Table Viewer
- **Smart Directory Scanning**:
  - Auto-detects OS default SQLMap output directories (`~/.local/share/sqlmap/output/` on Linux/macOS and `%LOCALAPPDATA%\sqlmap\output\` on Windows).
  - Handles direct `<db>/<table>.csv` or target dump structures (`<target>/dump/<db>/<table>.csv`).
- **Dynamic Dropdowns**: Populated with discovered databases and dynamically updating table lists.
- **Breadcrumb Statistics**: Displays active database, table, total rows, and visible/total column counts.
- **Column Visibility Manager**: Dedicated modal dialog allowing users to toggle visible columns on or off with Select All and Deselect All controls.
- **Real-Time Data Filtering**: High-speed row search supporting case-insensitive matching across table contents.
- **Data Viewer**: Multi-column scrollable table with horizontal and vertical scrollbars, handling empty cells, special characters, and multiline text.
- **CSV Export**: Export filtered or full table views to disk.

### 3. Tab 3: Analysis
- **Table Gathering**:
  - Global catalog of all discovered tables across all databases with column count, row count, file size, and target host.
  - Search filter for rapid table discovery.
  - Double-click navigation: Double-clicking any table row immediately switches to Tab 2 with that database and table loaded.
- **Column Gathering**:
  - Aggregates unique column names across all databases.
  - Grouped master-detail split layout:
    - Master list on the left displays unique column names and occurrence counts (e.g. `username (5 occurrences)`).
    - Detail table on the right displays every occurrence (database, table name, total rows, target host).
  - Double-click navigation: Double-clicking an occurrence immediately opens that table in Tab 2.
- **Column Keyword Search**:
  - Case-insensitive partial matching and regex support.
  - Quick audit presets: `pass`, `user`, `email`, `token`, `secret`, `number`, `admin`, `hash`.
  - Results table displaying column name, database, table, rows, and host.
  - Double-click navigation: Double-clicking any search result immediately opens that table in Tab 2.

### 4. Persistent Session Storage & State Recovery
- **No Auto-Load By Default**: Prompts the user on startup with three explicit choices:
  - **Open Existing Session**: Load a previously saved `.json` session file to restore parsed databases, tables, metadata, bookmarks, and notes.
  - **Create New Session**: Select a directory and specify a session filename to bind and auto-save state as testing progresses.
  - **Temporary / In-Memory Session**: Run in-memory without saving to disk (can be saved at any time).
- **Persistent Toolbar Controls**:
  - Arranged in standard Left-to-Right layout:
    - **Left Side (Action Buttons)**: `[New Session]`, `[Open Session]`, `[Save]`, `[Save As...]`, `[Offboard Session]`.
    - **Right Side (Session Status)**: `Session: <filename> (<folder>)` or `Session: [Temporary / In-Memory]`.
  - **Explicit Save Button**: The `[Save]` button allows testers to immediately flush active session data to disk synchronously.
- **Automated Session Synchronization**: Background daemon executor automatically syncs state changes to disk debounced by 1500ms whenever an active session file is bound.
- **Session Offboarding**: Clear active tables, databases, and metadata, unbind the session file, and restore a fresh workspace without restarting Burp.
- **Debounced Atomic Auto-Save Engine**: Background daemon executor writes to `.tmp` followed by atomic replacement to prevent file corruption.
- **Clean Shutdown Hook**: Registers an unloading handler via Montoya API to ensure safe state preservation on Burp exit or extension reload.

### 5. Sample SQLMap Output for Personal Analysis
The repository includes a ready-to-test SQLMap output directory under `SQLMapAnalyzer_littlespidy/sample_output/`:
- **Target Host**: `app.target.local`
- **Databases & Tables**:
  - `auth_db/`: `users.csv`, `password_resets.csv`, `api_tokens.csv`
  - `billing_db/`: `customers.csv`, `payment_cards.csv`, `invoices.csv`
  - `admin_db/`: `administrators.csv`, `system_config.csv`, `audit_logs.csv`

---

## Building and Installation

### Prerequisites
- Java Development Kit (JDK) 17 or higher
- Burp Suite Professional or Community Edition (supporting Montoya API 2026.4 or later)
- SQLMap with `sqlmapapi.py` (either running as REST server or installed on PATH)

### Build Instructions
Run the Gradle build command from within the project directory:

```bash
cd SQLMapAnalyzer_littlespidy
./gradlew clean test jar
```

The compiled release fat-JAR will be created at:
`SQLMapAnalyzer_littlespidy/build/libs/sqlmap-analyzer-littlespidy-1.0.0.jar`

### Loading into Burp Suite
1. Open Burp Suite.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. Set **Extension type** to **Java**.
5. Click **Select file...** and choose `SQLMapAnalyzer_littlespidy/build/libs/sqlmap-analyzer-littlespidy-1.0.0.jar`.
6. Click **Next**. The extension will load, display the session startup dialog, and add the **SQLMap Analyzer** top-level tab.

---

## Author
Created with the help of an AI Agent and littlespidy.
