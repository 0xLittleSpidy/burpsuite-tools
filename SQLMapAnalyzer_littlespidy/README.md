# SQLMap Output Analyzer Burp Suite Extension (_littlespidy)

// Created with the help of an AI Agent and littlespidy.

## Overview

The **SQLMap Output Analyzer** is a modern Burp Suite extension built with the Montoya API (`net.portswigger.burp.extensions:montoya-api:2026.4`). It allows penetration testers and security auditors to import, browse, search, and analyze SQLMap extraction outputs directly inside Burp Suite without leaving their workflow or manually opening individual CSV files.

---

## Features

### 1. Smart Directory Scanning
- Automatically detects and populates standard SQLMap output directories:
  - **Linux:** `~/.local/share/sqlmap/output/`
  - **Windows:** `%USERPROFILE%\AppData\Local\sqlmap\output\` or `%LOCALAPPDATA%\sqlmap\output\`
  - **macOS:** `~/.local/share/sqlmap/output/` or `~/Library/Application Support/sqlmap/output/`
- Supports flexible directory layouts:
  - Direct database structure: `<root>/<database>/<table>.csv`
  - Target host dump structure: `<root>/<target_host>/dump/<database>/<table>.csv`
- Non-blocking background scanning with real-time status and progress indicator.

### 2. Tab 1: Database and Table Viewer
- **Dynamic Selectors**:
  - Database dropdown populated with all discovered databases (with target host tags when applicable).
  - Table dropdown dynamically updating whenever the database selection changes.
- **Breadcrumb Summary**: Displays active database, table, total rows, and visible/total column counts.
- **Column Visibility Manager**: Dedicated modal dialog allowing users to toggle visible columns on or off with Select All and Deselect All controls.
- **Real-Time Data Filtering**: High-speed row search supporting case-insensitive matching across table contents.
- **Data Viewer**: Multi-column scrollable table with horizontal and vertical scrollbars, handling empty cells, special characters, and multiline text.
- **CSV Export**: Export filtered or full table views to disk.

### 3. Tab 2: Analysis
- **Table Gathering**:
  - Global catalog of all discovered tables across all databases.
  - Displays database name, table name, column count, row count, file size, and target host.
  - Search filter for rapid table discovery.
  - **Double-click navigation**: Double-clicking any table row immediately switches to Tab 1 with that database and table loaded.
- **Column Gathering**:
  - Aggregates unique column names across all databases.
  - Grouped master-detail split layout:
    - Master list on the left displays unique column names and occurrence counts (e.g. `username (5 occurrences)`).
    - Detail table on the right displays every occurrence (database, table name, total rows, target host).
  - **Double-click navigation**: Double-clicking an occurrence immediately opens that table in Tab 1.
- **Column Keyword Search**:
  - Case-insensitive partial matching and regex support.
  - One-click quick presets for security auditing:
    - `pass` (passwords, hashes, credentials)
    - `user` (usernames, user IDs, accounts)
    - `email` (email addresses)
    - `token` (tokens, API keys, session secrets)
    - `secret` (secrets, private keys)
    - `number` (account numbers, cards, SSNs, phone numbers)
    - `admin` (administrative roles, flags)
    - `hash` (cryptographic hashes)
  - Results table displaying column name, database, table, rows, and host.
  - **Double-click navigation**: Double-clicking any search result immediately opens that table in Tab 1.

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
- Demonstrates cross-database column gathering (`username`, `email`), sensitive keyword matching (`password_hash`, `api_token`, `card_number`, `is_admin`, `secret_key`), and RFC-4180 CSV parsing (quoted addresses, multiline notes, nulls).

---

## Building and Installation

### Prerequisites
- Java Development Kit (JDK) 17 or higher
- Burp Suite Professional or Community Edition (supporting Montoya API 2026.4 or later)

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
