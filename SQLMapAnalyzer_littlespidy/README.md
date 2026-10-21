# ng-sqlmap littlespidy - SQLMap Scanner & Output Analyzer

// Created with the help of an AI Agent and littlespidy.

## Overview

The **ng-sqlmap littlespidy** extension is a complete, modern Burp Suite extension built with the Montoya API (`net.portswigger.burp.extensions:montoya-api:2026.4`). It converts and integrates the functionality of **SQLiPy** into a clean, multi-threaded Java architecture, while providing offline database browsing, structural analysis, and persistent session management.

Penetration testers can launch, configure, monitor in real time, and cancel SQLMap scans directly from Burp Suite requests, and then browse and analyze the extracted database tables and sensitive columns without manual CSV inspection.

---

## Features

### 1. Tab 1: SQLMap Scanner (Java Conversion of SQLiPy)
- **Montoya Context Menu Integration**:
  - Right-click any HTTP request in **Proxy History**, **Repeater**, **Logger**, or **Target SiteMap** and select **"Send to SQLMap Scanner"**.
  - Automatically parses target URL, HTTP method, headers, cookies, POST body, and injection parameters.
- **Request-Based Child Sub-Tabs & Double-Click In-Place Renaming**:
  - Spawns an isolated, closeable child tab for each request (`#1 POST /api/login [x]`).
  - **Double-Click In-Place Renaming**: Double-clicking any request tab name swaps the label into an inline text field directly in the tab header to rename the tab with zero modal popups (`Enter` to commit, `Escape` to cancel).
  - Custom tab names are persisted across session saves and state restoration.
  - No single-window overwrites; manage multiple target requests concurrently.
- **Dual-Pane Interface**:
  - **Left Pane (Configuration)**:
    - Quick presets: `Fast Detection`, `Standard Audit`, `Thorough`, and `WAF Bypass`.
    - Injection parameter selection (`-p`), Level (1-5), Risk (1-3), Techniques (`BEUSTQ`), DBMS.
    - **Multi-Select Tamper Script Dropdown**: Live search filter, scrollable checklist of popular tamper scripts (`between`, `randomcase`, `space2comment`, etc.), "Select All" and "Clear" shortcuts, and manual text editing.
    - **Target Specific Resources (Optional)**: Specific target inputs for Database (`-D`), Table (`-T`), and Column (`-C`).
    - Timing & Network: Threads (1-10), Delay, Timeout, Retries, Tor Socks5, HPP.
    - Enumeration: Banner (`-b`), Current DB, Current User, Is DBA, Hostname, Users, Passwords, Tables, Columns, Dump.
    - Action controls: `[Start Scan]`, `[Stop / Cancel Scan]`, and `[Copy CLI Command]`.
    - **Compact Copy CLI Dialog**: Displays the generated command in a compact, code-formatted window with monospace syntax view, standard close (X) button, ESC shortcut, and "Copy Again" action.
  - **Right Pane (Native Request View)**:
    - Embedded native Montoya `HttpRequestEditor` with syntax highlighting and raw/headers/params views.
- **Real-Time Streaming Log Console**:
  - Positioned at the bottom with automatic background log polling every 1000ms.
  - Live status badge: `IDLE`, `RUNNING`, `VULNERABLE`, `COMPLETED`, `CANCELLED`, `ERROR`.
  - Log level filtering (`ALL`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`), auto-scroll toggle, clear logs, and copy to clipboard.
  - **Vulnerability Findings Tab**: Structured table showing confirmed vulnerable parameters, detected DBMS, injection types, and proof-of-concept payloads.
- **Repeated Request Management & Automated Execution Runs**:
  - When a completed scan (`COMPLETED`, `VULNERABLE`, `ERROR`) has **Start Scan** clicked again, the extension automatically spawns the next execution run (`Run #2`, `Run #3`, etc.).
  - When restarting a `CANCELLED` scan, the existing execution run is safely reused and restarted without creating unnecessary duplicate entries.
  - Execution history dropdown allows instant switching between past runs to compare configurations, logs, and findings.
- **Immediate Scan Cancellation & Accurate Status**:
  - `[Stop / Cancel Scan]` terminates the scan immediately on the SQLMap API, cancels background polling, sets the status permanently to `CANCELLED`, and prevents subsequent polling cycles from erroneously overwriting the status with `COMPLETED`.
- **API Server Control Bar**:
  - Configure Host and Port (default: `127.0.0.1:8775`).
  - `[Test Connection]` checks server reachability.
  - `[Start Local API]` and `[Stop Local API]` can spawn and manage a local `sqlmapapi.py` subprocess directly.

### 2. Tab 2: Database and Table Viewer
- **Smart Directory Scanning**:
  - Auto-detects OS default SQLMap output directories (`~/.local/share/sqlmap/output/` on Linux/macOS and `%LOCALAPPDATA%\sqlmap\output\` on Windows).
  - Handles direct `<db>/<table>.csv` or target dump structures (`<target>/dump/<db>/<table>.csv`).
- **Clean Database Dropdown**: Displays only the clean database name in the dropdown (removing path/host directory prefixes for optimal readability).
- **Dynamic Dropdowns**: Populated with discovered databases and dynamically updating table lists.
- **Dynamic Column Auto-Fit**: Table columns automatically calculate and fit their optimal width based on header text and sample cell contents with horizontal scrolling.
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
- **Column Gathering & Quick Presets**:
  - Aggregates unique column names across all databases.
  - **Quick Presets Toolbar**: One-click filter presets for high-value targets including `SSN`, `Account`, `Social`, `Security`, `number`, `pass`, `user`, `email`, `token`, and `secret`, plus `Clear`.
  - Grouped master-detail split layout:
    - Master list on the left displays unique column names and occurrence counts (e.g. `username (5 occurrences)`).
    - Detail table on the right displays every occurrence (database, table name, total rows, target host).
  - Double-click navigation: Double-clicking an occurrence immediately opens that table in Tab 2.

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

### 5. Compact Space-Optimized Navigation Layout
- **Single-Row Navigation Strip**:
  - Located directly below the session control toolbar.
  - **Far-Left Side**: Navigation toggle buttons (`[ SQLMap ]`, `[ Database and Table Viewer ]`, `[ Analysis ]`) switching active views smoothly via `CardLayout`.
  - **Far-Right Side**: SQLMap output directory controls (`Output Dir: [path] [Browse...] [Scan / Import] [Status]`).
  - Eliminates vertical screen space waste, maximizing visibility for scan options, request inspection, and data tables.

### 6. Sample SQLMap Output for Personal Analysis
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
`SQLMapAnalyzer_littlespidy/build/libs/ng-sqlmap-littlespidy-1.0.0.jar`

### Loading into Burp Suite
1. Open Burp Suite.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. Set **Extension type** to **Java**.
5. Click **Select file...** and choose `SQLMapAnalyzer_littlespidy/build/libs/ng-sqlmap-littlespidy-1.0.0.jar`.
6. Click **Next**. The extension will load, display the session startup dialog, and add the **ng-sqlmap littlespidy** top-level tab.

---

## Author
Created with the help of an AI Agent and littlespidy.
