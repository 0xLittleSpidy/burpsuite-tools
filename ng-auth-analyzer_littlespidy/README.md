# ng-auth-analyzer_littlespidy

Burp Suite Extension for automated authorization and access control testing, featuring persistent session management, XML data import, and synchronized multi-user inspection.

## Table of Contents
- [Overview](#overview)
- [Key Features and Improvements](#key-features-and-improvements)
- [Tab Architecture](#tab-architecture)
  * [1. Configuration Tab](#1-configuration-tab)
  * [2. History Tab](#2-history-tab)
  * [3. Import Tab](#3-import-tab)
- [Global Request/Response Switch](#global-requestresponse-switch)
- [Persistent Session Management](#persistent-session-management)
- [Parameter Extraction and Replacement](#parameter-extraction-and-replacement)
- [Building and Installation](#building-and-installation)
- [Author Marker](#author-marker)

---

## Overview
ng-auth-analyzer_littlespidy helps penetration testers and security auditors detect authorization vulnerabilities (such as IDOR, BAP, and privilege escalation). By navigating an application with a privileged account, the extension repeats each request using credentials, headers, or tokens defined for unprivileged or alternative user roles. Each repeated response is analyzed and evaluated for bypass conditions (SAME, SIMILAR, DIFFERENT, N/A).

---

## Key Features and Improvements
- Modern Tabbed Structure: Organized into three dedicated tabs: Configuration, History, and Import.
- Vertical Layout: Request history tables positioned at the top with request/response viewers positioned directly below.
- Multi-User Inspection: Distinct panels and tabs for each defined user (e.g., Original, User 1, User 2, User 3).
- Synchronized Request/Response Switch: Header toggle switch that instantly switches all user views between requests and responses.
- Independent XML Import: Dedicated Import tab allowing users to upload and analyze exported XML data without overwriting or interfering with live test history.
- Standardized Persistent Session Management: Interactive startup dialog, top toolbar controls (New, Open, Save, Save As, Offboard), atomic file writes, and debounced auto-saving.
- Strict Plain ASCII Standard: Professional UI and messaging without emojis or decorative unicode symbols.
- Dual API Support: Implements modern Montoya API (`burp.api.montoya.BurpExtension`) while preserving backward compatibility with legacy Extender callbacks.

---

## Tab Architecture

### 1. Configuration Tab
- Preserves all original settings, session setups, parameter replacements, header modifications, and request filters.
- Start/Stop and Pause controls with plain ASCII status indicators ([Running], [Stopped], [Paused]).
- Session definition manager supporting clone, rename, and delete actions.
- Parameter extraction rules: Auto Extract, From-To String, Static Value, and Prompt for Input.
- Comprehensive request filtering: In Scope, Only Proxy, Exclude Filetypes, Exclude Methods, Exclude Status Codes, Exclude Paths, and Exclude Queries.

### 2. History Tab
- Positioned in a top/bottom vertical split layout:
  - Top: Live request history table with filtering, regex/text search, status code, length difference, and bypass status columns.
  - Bottom: Request and Response viewer for inspecting Original traffic and repeated session responses side-by-side or individually.
- Compare View and Diff View with insertion/deletion calculations.
- Context menu options: Mark Row, Unmark Row, Repeat Request, Delete Row, and Add Comment.
- Actions: Clear Table and Export Table Data.

### 3. Import Tab
- Dedicated workspace for previously exported XML reports.
- Upload XML Data button to parse and load XML files.
- Reuses the identical table and viewer layout as the History tab.
- Completely isolated from live history data: importing XML never alters or overwrites active proxy history.
- Dynamic column and tab generation matching whatever user roles were present in the exported XML file.
- Full table filtering, search, and export capabilities.

---

## Global Request/Response Switch
The viewer header in both the History and Import tabs features a Request/Response toggle switch on the right side:
- Selecting Request updates all user panels to display their respective HTTP requests.
- Selecting Response updates all user panels to display their respective HTTP responses.
- When switching between user tabs, the active selection (Request or Response) remains persistent across all sessions.
- In Compare View, both panels adhere to the selected view mode, allowing straightforward request-to-request or response-to-response comparison and diffing.

---

## Persistent Session Management
ng-auth-analyzer_littlespidy conforms to the standardized persistent session storage architecture:
1. Startup Dialog: Prompts on initialization with three choices:
   - Open Existing Session: Select a `.json` file from disk to restore configuration, live history, and imported data.
   - Create New Session: Specify a target folder and filename to bind the workspace immediately to disk.
   - Temporary / In-Memory Session: Run without disk binding (can be saved manually at any time).
2. Persistent Top Toolbar:
   - Actions: `[New Session]`, `[Open Session]`, `[Save Session]`, `[Save As...]`, `[Offboard Session]`.
   - Live Status Indicator: Displays `Session: <filename> (<folder>)` or `Session: [Temporary / In-Memory]`.
3. Auto-Save Engine: Debounced asynchronous saves (1500ms delay) using a single-thread daemon executor whenever data changes.
4. Atomic File Moves: Writes to `.tmp` first and replaces atomically to prevent file corruption.
5. Offboard Session: Prompts to save any pending changes, unbinds the active file, and resets workspace tables to clean state.

---

## Building and Installation

### Prerequisites
- JDK 17 or higher
- Gradle (wrapper included)

### Build Release JAR
Run the following command from the `ng-auth-analyzer_littlespidy` directory:
```bash
./gradlew clean test jar
```

The compiled release fat-JAR will be located at:
```
build/libs/ng-auth-analyzer_littlespidy-1.1.14.jar
```

### Loading into Burp Suite
1. In Burp Suite, navigate to Extensions -> Installed.
2. Click Add.
3. Set Extension type to Java.
4. Select `ng-auth-analyzer_littlespidy/build/libs/ng-auth-analyzer_littlespidy-1.1.14.jar`.
5. Click Next. The extension will load and display the Session Startup dialog.

---

## Author Marker
Created with the help of an AI Agent and littlespidy.
