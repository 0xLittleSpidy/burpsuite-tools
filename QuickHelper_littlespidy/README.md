# Quick Helper (Burp Suite Extension)

Quick Helper is a high-performance Burp Suite extension written in Java using the modern Montoya API. It provides fast helper actions directly from Burp Suite's dedicated Suite Tab, top Menu Bar, and right-click Context Menus, designed to download all littlespidy security extensions in a single click and speed up reconnaissance and scope management during security assessments.

## Key Features

1. **Request Editor Tab ('Auth & Tokens')**:
   - Registers a dedicated Request Editor tab in Burp Suite's HTTP request viewer/editor across all Burp tools (Repeater, Proxy HTTP history, Logger, Target SiteMap).
   - Single-click quick copy buttons for:
     - **Copy Bearer Token**: Extracts the pure Bearer JWT / access token string stripped of scheme prefix.
     - **Copy Auth Header**: Copies the full `Authorization` header value.
     - **Copy Cookie Header**: Copies the complete raw `Cookie` header string.
     - **Copy All Cookies**: Copies all cookies formatted as key-value pairs.
   - Interactive table listing all parsed tokens, headers, and individual cookies with type badges, lengths, value previews, and instant copy actions.
   - In-tab dynamic status indicator confirming copy operations and character counts.
   - Detailed item inspector panel allowing full review of untruncated tokens.

2. **Single-Click Extension Downloader**:
   - Bundles a comprehensive catalog of all 21 official Burp Suite extensions published by littlespidy.
   - One-click action to download all extensions (`.jar` files) directly to a local directory (`~/Downloads/burpsuite-extensions/` or custom folder).
   - Real-time download progress tracking, speed calculation, status badges, and table filtering.
   - Background multi-threaded downloader with automatic HTTP redirect resolution.
   - Built-in directory browser and one-click "Open Download Folder" in system file manager.
   - Burp Suite step-by-step installation instructions integrated directly into the workspace.

2. **Copy All Domain Names**:
   - Queries the entire Target Site Map.
   - Extracts all unique hostnames/domain names.
   - Automatically deduplicates and sorts domains in natural alphabetical order.
   - Copies the result directly to the system clipboard (one domain per line).

3. **Copy All Domain Names with HTTP Schema**:
   - Extracts unique domain names alongside their HTTP protocol scheme (`https://` or `http://`).
   - Cleanly formats standard ports (e.g. `https://example.com`, `http://insecure.internal`).
   - Preserves non-standard ports where applicable (e.g. `https://internal.target:8443`, `http://dev.target:8080`).
   - Copies sorted unique URLs to the system clipboard.

4. **In-Scope Filtered Actions**:
   - **Copy In-Scope Domain Names**: Limits extraction strictly to targets currently configured within Burp Suite target scope.
   - **Copy In-Scope Domain Names with HTTP Schema**: In-scope domain extraction with protocol schemes.

5. **Non-Blocking Background Execution**:
   - Extension downloads and sitemap parsing run asynchronously on dedicated daemon worker threads.
   - Burp Suite's Swing Event Dispatch Thread (EDT) remains completely responsive.

6. **Non-Intrusive Notifications**:
   - Reports completion details and entry counts directly via `api.logging().raiseInfoEvent(...)` in Burp's Event Log and extension console output without blocking modal interruptions.

## UI and Navigation

The extension registers across four key locations in Burp Suite:

### 1. HTTP Request Editor Tab ("Auth & Tokens")
Appears directly in the request editor pane alongside Pretty, Raw, Hex, and Headers across Repeater, Proxy HTTP history, Logger, and Target Site Map. Tester can view detected auth tokens, bearer credentials, and parsed cookies, and copy them with a single click.

### 2. Dedicated Suite Tab ("Quick Helper")
A dedicated top-level tab in Burp Suite containing two sub-tabs:
- **Extensions Downloader**: Table of all 21 extensions with one-click "Download All Extensions (Single Click)", selective downloading, destination directory picker, progress bar, activity log console, and Burp installation instructions.
- **Domain Extractor**: Visual interface with checkboxes for HTTP schema and in-scope filtering, domain extraction, and formatted text output area.

### 3. Top Menu Bar
A dedicated **Quick Helper** menu appears on Burp Suite's top navigation bar:
- Quick Helper -> Download All Extensions (Single Click)
- Quick Helper -> Open Extension Downloader Tab
- (Separator)
- Quick Helper -> Copy All Domain Names
- Quick Helper -> Copy All Domain Names with HTTP Schema
- (Separator)
- Quick Helper -> Copy In-Scope Domain Names
- Quick Helper -> Copy In-Scope Domain Names with HTTP Schema

### 4. Context Menu (Right-Click)
Right-clicking anywhere across Burp Suite (Target Site Map tree/table, Proxy HTTP History, Repeater, Logger) displays the **Quick Helper** submenu with the same actions.

## Building and Packaging

The extension uses Gradle and requires Java 17+.

```bash
cd QuickHelper_littlespidy
./gradlew clean test build
```

The compiled release fat-JAR will be generated at:
```
QuickHelper_littlespidy/build/libs/quick-helper-littlespidy-1.0.0.jar
```

## Installation in Burp Suite

1. Open Burp Suite.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. Choose **Extension type: Java**.
5. Click **Select file...** and select `QuickHelper_littlespidy/build/libs/quick-helper-littlespidy-1.0.0.jar`.
6. Click **Next**. The extension will load and initialize.
7. Verify that the **Quick Helper** tab appears on the main Burp Suite tab bar, top menu bar, and in right-click context menus.

## Author Marker
Created with the help of an AI Agent and littlespidy.
