# Quick Helper (Burp Suite Extension)

Quick Helper is a high-performance Burp Suite extension written in Java using the modern Montoya API. It provides fast helper actions directly from Burp Suite's top Menu Bar and right-click Context Menus, designed to speed up reconnaissance and scope management during security assessments.

## Key Features

1. **Copy All Domain Names**:
   - Queries the entire Target Site Map.
   - Extracts all unique hostnames/domain names.
   - Automatically deduplicates and sorts domains in natural alphabetical order.
   - Copies the result directly to the system clipboard (one domain per line).

2. **Copy All Domain Names with HTTP Schema**:
   - Extracts unique domain names alongside their HTTP protocol scheme (`https://` or `http://`).
   - Cleanly formats standard ports (e.g. `https://example.com`, `http://insecure.internal`).
   - Preserves non-standard ports where applicable (e.g. `https://internal.target:8443`, `http://dev.target:8080`).
   - Copies sorted unique URLs to the system clipboard.

3. **In-Scope Filtered Actions**:
   - **Copy In-Scope Domain Names**: Limits extraction strictly to targets currently configured within Burp Suite target scope.
   - **Copy In-Scope Domain Names with HTTP Schema**: In-scope domain extraction with protocol schemes.

4. **Non-Blocking Background Execution**:
   - Sitemap parsing and processing run asynchronously on a dedicated daemon worker thread.
   - Even on very large assessments with tens of thousands of sitemap items, Burp Suite's Swing Event Dispatch Thread (EDT) remains responsive.

5. **Non-Intrusive Notifications**:
   - Reports completion details and entry count directly via `api.logging().raiseInfoEvent(...)` in Burp's Event Log and extension console output without annoying modal popup interruptions.

## Menu Locations

The extension registers in two convenient locations:

### 1. Top Menu Bar
A dedicated **Quick Helper** menu appears on Burp Suite's top navigation bar (alongside Burp, Project, Intruder, Repeater, Window, Help):
- Quick Helper -> Copy All Domain Names
- Quick Helper -> Copy All Domain Names with HTTP Schema
- (Separator)
- Quick Helper -> Copy In-Scope Domain Names
- Quick Helper -> Copy In-Scope Domain Names with HTTP Schema

### 2. Context Menu (Right-Click)
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
7. Verify that the **Quick Helper** menu item appears on Burp's top menu bar and in the right-click context menu.

## Author Marker
Created with the help of an AI Agent and littlespidy.
