---
name: burp-suite-creator
description: >
  Generates Burp Suite tools based on a user's security testing scenario. Use this skill whenever the user mentions "Burp Suite", "Bambda", "BChecks", "Burp extension", or the "Montoya API". It can create Montoya API extensions (Python/Java), Java Bambdas, and BChecks.
---
# Burp Suite Creator

This skill helps users create extensions, Bambdas, and custom scan checks (BChecks) for Burp Suite based on a described scenario.

## Core Directives

1. **Interactive Consultation**: Before generating any code or writing any files, you MUST prompt the user to discuss requirements. Propose a plan, confirm the optimal implementation strategy (Bambda vs Extension vs BCheck), and mention any local API references you plan to base the code on. Wait for the user's confirmation before proceeding.

2. **Analyze the Scenario**: Determine whether the user needs an **Extension** (Python or Java), a **Bambda** (Java), or a **BCheck**.
    - **BChecks**: Use for custom scan checks, matching simple request/response patterns or inserting payloads.
    - **Bambdas**: Use for quick, on-the-fly HTTP message filtering or basic modifications (e.g., in Proxy history or Logger).
    - **Extensions**: Use for complex logic, custom UI tabs, or session handling.

3. **Extensions (Montoya API ONLY)**:
    - ALWAYS use the modern **Montoya API** (`burp.api.montoya.*`), not the legacy Extender API.
    - **Python (Jython)**: Default to Python for extensions unless Java is explicitly requested. Output the `.py` script.
    - **Java**: If Java is requested, generate the `.java` source code along with a `pom.xml` configured to build a `.jar` with dependencies. Provide instructions to run `mvn package` to generate the jar file so the user can easily install it.

4. **Bambdas (Java)**:
    - Write a concise Java code snippet suitable for Burp's Bambda interface.
    - Bambdas typically have access to objects like `requestResponse`, `request`, `response`, and `utilities`. Write the logic directly as the Bambda body.

5. **BChecks**:
    - Write valid BCheck definition scripts. Include the required metadata (`name`, `description`, `author`) and the `given` / `then` blocks.

6. **External Tool Feature Integration**:
    - When asked to integrate, port, or extract features/methods from an external tool, repository, or script (e.g., LinkFinder, Arjun, Param Miner) into a Burp Suite extension:
        1. Thoroughly inspect and analyze the external tool's source code, algorithms, dependencies, and noise filters first.
        2. Consult `extension_architecture.md` (*Workflow Methodology → External Tool Feature Extraction & Integration*).
        3. Before generating code or writing files, **ask the user a structured series of targeted discovery questions** regarding:
            - **Scope & Methods**: Which specific routines, regexes, or algorithms to port.
            - **Data Pipeline & Provenance**: How findings should be stored, deduplicated, and tagged (e.g., `extractor` field / column).
            - **Trigger & Execution**: Passive listener vs on-demand button vs context menu action.
            - **Performance & Preprocessing**: Trade-offs for large/minified files to avoid freezing the EDT.
            - **UI & Filtering Controls**: Table columns, filter dropdowns, and search controls.
        4. Wait for the user's answers and approval before proceeding with implementation.

## Bambda Coding Standards

These rules apply to **every** Proxy Filter Bambda (`VIEW_FILTER`, `PROXY_HTTP_HISTORY`). Violating any of these is considered a bug.

### 1. Notes Must Always Append — Never Overwrite

When setting `requestResponse.annotations().setNotes(...)`, you MUST read the existing note first and **append** to it. Never blindly overwrite notes the user may have already written.

Use this exact safe-append pattern every time:

```java
String existingNote = requestResponse.annotations().notes();
String newNote      = "Your note here";
if (existingNote == null || existingNote.isEmpty()) {
    requestResponse.annotations().setNotes(newNote);
} else if (!existingNote.contains(newNote)) {
    requestResponse.annotations().setNotes(existingNote + " | " + newNote);
}
```

- The separator `" | "` keeps notes readable in the Proxy table.
- The `!existingNote.contains(newNote)` guard prevents duplicate appends on re-filter.
- **Never** call `setNotes(newNote)` directly without reading existing notes first.

### 2. User Configuration Block at the Top

Every Proxy Filter Bambda MUST declare all user-tunable variables at the very top of the source block, clearly separated with a comment banner. Example:

```java
// ─── USER CONFIGURATION ──────────────────────────────────────────
String  TARGET_HOST = "*";   // "*" = all hosts, or e.g. "example.com"
boolean ANNOTATE    = true;  // true = highlight + note on match
// ─────────────────────────────────────────────────────────────────
```

### 3. Always Guard Against Missing Response

Every Bambda that accesses `response()` MUST guard against a missing response first:

```java
if (!requestResponse.hasResponse()) {
    return false;
}
```

### 4. Host Filtering Pattern

When a `TARGET_HOST` config is present, use this exact pattern to support both exact matches and subdomains:

```java
if (!TARGET_HOST.equals("*")) {
    String host = requestResponse.request().httpService().host();
    if (!host.equalsIgnoreCase(TARGET_HOST) &&
        !host.toLowerCase().endsWith("." + TARGET_HOST.toLowerCase())) {
        return false;
    }
}
```

### 5. Highlight Colors

Use consistent `HighlightColor` values based on severity of the finding:
- `HighlightColor.RED`    → High severity (errors, stack traces, critical misconfigs)
- `HighlightColor.YELLOW` → Medium / informational (CORS headers, security header issues)
- `HighlightColor.CYAN`   → Neutral highlights (filtering aids, custom scopes)

## Extension UI Coding Standards

These rules apply to every Java extension that exposes a custom Swing UI tab.

### 6. Multi-Select Filter Buttons

When an extension toolbar exposes filter controls (e.g. Status Code, Content-Type, HTTP Method), **always use `MultiSelectFilterButton`** instead of a plain `JComboBox`. This component opens a popup checkbox list so the user can pick multiple values in a single interaction.

**File**: `com.littlespidy.cspinspector.ui.MultiSelectFilterButton` (reuse or copy from the CSP Inspector extension).

**Key API:**
```java
MultiSelectFilterButton btn = new MultiSelectFilterButton(
    "Method",                            // button label
    List.of("All Methods", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"),
    sel -> refreshView()                 // onChange callback
);
Set<String> selected = btn.getSelected(); // empty = "all"
btn.clearSelection();                     // reset to "all"
```

**Filter logic rules:**
- If `getSelected()` returns an empty `Set`, treat it as **"all pass"** — no filtering.
- For OR-matching multiple content-type selections, call the datastore filter once per selected value and merge results deduplicating by entry ID.
- Join multiple status code selections with `" / "` (e.g. `"200 / 302"`) so `matchesStatusCode()` can tokenise them.
- The first option in the list, if it starts with `"All"`, is treated as a **"Select All" toggle** that checks/unchecks all other items.

### 7. DataStore Filter Signatures (Method Filter)

Every `groupByMode()` and `getFilteredEntries()` signature in a DataStore class MUST include a `Set<String> methodFilter` parameter:

```java
public Map<String, List<Entry>> groupByMode(
    String mode, String valueFilter,
    String statusFilter, String contentTypeFilter,
    Set<String> methodFilter,            // ← NEW
    Predicate<String> inScopePredicate) { ... }
```

Use the static helper:
```java
public static boolean matchesMethod(String method, Set<String> selectedMethods) {
    if (selectedMethods == null || selectedMethods.isEmpty()) return true;
    if (method == null) return false;
    return selectedMethods.contains(method.toUpperCase());
}
```

### 8. Table Column Sorting (Proxy History & Intruder Behavior)

When an extension displays a results table (such as an activity log, scan findings, or HTTP traffic history), **always enable column sorting** so testers can sort and reverse-sort columns by clicking the column headers, mirroring the sorting behavior in Burp's Proxy History and Intruder tabs.

**Implementation**:
1. Configure `TableRowSorter` on the `JTable`:
```java
TableRowSorter<MyTableModel> sorter = new TableRowSorter<>(tableModel);
sorter.setSortsOnUpdates(true);
table.setRowSorter(sorter);
```
2. Ensure `getColumnClass(int columnIndex)` in the `TableModel` returns the exact class type (e.g. `Integer.class` for ID, Status, Length; `String.class` for Method, URL, Stage) so numbers sort numerically rather than lexicographically:
```java
@Override
public Class<?> getColumnClass(int columnIndex) {
    return COLUMN_CLASSES[columnIndex];
}
```
3. Always convert view row indices to model indices before retrieving data from the table model (`table.convertRowIndexToModel(selectedRow)`), ensuring row selection and context menus operate on the correct underlying item regardless of active sort.
4. Clicking a column header once sorts ascending; clicking a second time reverses the sort order (descending).
5. Explicitly register custom renderers for typed columns: When `getColumnClass` returns specific classes like `Integer.class`, Swing's default class renderers may override renderers registered only for `Object.class`. Explicitly register custom renderers for `Integer.class`, `String.class`, and other specific types to ensure consistent visual styling (e.g. status code badges) across sorted columns.

### 9. Dynamic Tab Naming Convention & Double-Click Inline Renaming (Zero Popups)

Whenever an extension spawns dynamic session tabs (e.g., when a user sends an HTTP request from context menus, Proxy history, Repeater, or scanner):

1. **Default Naming Convention**:
   - Always assign a structured, predictable default tab title: `"#<ID> <METHOD> <truncated_path>"` (e.g., `"#1 GET /api/v1/users"`, `"#2 POST /login"`).
   - Use an auto-incrementing atomic session counter (`AtomicInteger sessionCounter = new AtomicInteger(1)`) so concurrent tabs are clearly numbered and identifiable.
   - Truncate long URLs/paths cleanly to 20-25 characters with trailing `...` to keep the tab bar compact.
   - Set the full HTTP method, host, and path on the tab's tooltip via `tabbedPane.setToolTipTextAt(...)`.
   - Never use emojis in tab titles or status indicators; use plain ASCII text only (e.g., `[Running]`, `[Done]`, `[Alert]`).

2. **Double-Click In-Place Header Renaming (No Modal Popups)**:
   - When a user double-clicks the tab title in the tab bar header, allow them to edit the tab name **directly inline** inside the tab header.
   - **Strict Zero-Popup Rule**: Strictly avoid `JOptionPane.showInputDialog` or modal popup dialogs. Modal dialogs interrupt tester flow and require unnecessary mouse clicks.
   - Provide a custom tab component (`EditableTabHeader`) containing a `JLabel` (display mode), a `JTextField` (inline edit mode), and a close button (`JButton`).
   - Double-clicking the `JLabel` swaps it for the `JTextField`, populates it with the current title, requests focus (`requestFocusInWindow()`), and selects all text (`selectAll()`).
   - Pressing `Enter` commits the new title to both the label and `JTabbedPane.setTitleAt(...)`, then switches back to `JLabel`.
   - Pressing `Escape` cancels the edit without changing the title.
   - Focus loss (`focusLost`) automatically commits or cancels cleanly.


## Output and Saving

1. **Auto-Save Requirements**: By default, ALWAYS use your file-writing tools to save the generated code (extensions, Bambda scripts, BChecks, etc.) directly into the appropriate directory in the current workspace (e.g., save a Proxy Filter Bambda into `Filter/Proxy/HTTP/`).
2. **File Naming Marker**: The name of every generated file MUST include a distinct marker (e.g., `_littlespidy`) at the end of the filename so the user can easily distinguish between standard Burp-created files and files generated by this skill. DO NOT add "AI" as a prefix to the filename or internal names.
3. **Author Marker**: Every generated script or code file MUST include a comment at the top containing this exact phrase: `Created with the help of an AI Agent and littlespidy.`
4. **README Synchronization**: ALWAYS update the corresponding project's `README.md` (and workspace `README.md` if applicable) whenever creating, modifying, or refactoring a Burp extension, BCheck, Bambda, or feature. Document any new tabs, UI components, filters, CLI options, build instructions, or updated behavior so the documentation never falls out of sync with the implementation.
5. **Chat Response**: In your markdown response, include a brief explanation of the approach and the code block(s) for the required files (use appropriate language tags).
6. **Instructions**: Provide brief instructions on how to load or compile the tool in Burp Suite.

### Example: BCheck
**Scenario**: "Create a check for exposed .git directories."
**Output**:
```bcheck
metadata:
    language: v1-beta
    name: "Exposed .git directory"
    description: "Looks for a .git/config file"
    author: "Burp Creator"

given host then
    send request:
        method: "GET"
        path: "/.git/config"
    
    if "repositoryformatversion" in {latest.response.body} then
        report issue:
            severity: high
            confidence: certain
            detail: "The .git directory is accessible."
    end if
```

### Example: Java Extension
Provide `build.gradle.kts` (or `pom.xml`) with Montoya API dependency (`net.portswigger.burp.extensions:montoya-api`) and the main Java class implementing `BurpExtension`. Instruct the user to run `./gradlew build` (or `mvn clean package`) to get the JAR file, then load it in Burp via **Extender → Add → Java** and point to `build/libs/<name>.jar`.

## Reference Examples

Before generating code, ALWAYS refer to the existing examples in the current workspace directory (`/home/littlespidy/myextra/burpsuite`). This repository contains various tools that you should use to match best practices and current usage:
- **Bambdas**: Check the `/home/littlespidy/myextra/burpsuite/bambdas/` directory (e.g., `Filter/`, `CustomAction/`, `CustomScanChecks/`).
- **BChecks**: Check the `/home/littlespidy/myextra/burpsuite/BChecks/` directory for custom scan check definitions.
- **Upload Scanner** (`/home/littlespidy/myextra/burpsuite-extensions/UploadScanner_littlespidy/`): Reference for advanced file upload vulnerability scanning and probing with:
  - **Probe Extensions Scanner**: Probes upload endpoints using comprehensive lists of allowed/target extensions, including a consolidated dataset of 912 file extensions collected from Wikipedia (`https://en.wikipedia.org/wiki/Lists_of_filename_extensions` spanning alphanumeric subpages 0–9, A–E, F–L, M–R, S–Z). Used to discover accepted file types, map server-side whitelist/blacklist boundaries, and identify viable extension bypass vectors.
  - **ReDownloader Configuration**: Validates file persistence and execution via dynamic upload directory presets derived from baseline requests, with full enable/disable control to prevent unintended download requests.
  - **Compact Multi-Column Attack Types**: High-density grid categorization covering Server RCE, Image Libraries, XML/Documents, Client-Side/Polyglots, Archives/Quirks/DoS, Allowed Extensions, and Validation/EXIF Leakage.

Use the `list_dir`, `grep_search`, or `view_file` tools on these directories to find relevant examples based on what the user is asking for.