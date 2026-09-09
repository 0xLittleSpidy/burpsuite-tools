---
name: burp-extension-strategy
description: >
  Central methodology reference for Burp Suite security testing. This skill captures the
  testing philosophy, attack families, and proven bypass techniques derived from
  real-world Burp Suite extension development. All other skills (burp-suite-creator, etc.)
  should reference this skill when they need to understand *what* to test, *why* a
  technique works, and *how* to structure attack logic. Use this skill whenever the user
  mentions "methodology", "strategy", "testing approach", "bypass techniques", "attack
  playbooks", "security testing philosophy", or asks how to approach authorization bypass,
  IDOR, URL validation, or sweep coverage testing. Also consult this skill when creating
  extensions, Bambdas, or BChecks that need to incorporate real-world bypass logic.
---

# Security Testing Strategy & Methodology

This skill is the central methodology reference for Burp Suite extensions. It distills the reusable
**UI patterns**, **workflow features**, and **testing methodology**.

Other skills (like `burp-suite-creator`) should consult this document when they need to
understand which UI patterns, workflow features, and architectural decisions to incorporate
into any new Burp extension.

## Table of Contents

- [Design Philosophy](#design-philosophy)
- [Montoya API Integration Patterns](#montoya-api-integration-patterns)
- [UI Architecture Patterns](#ui-architecture-patterns)
  - [Core Toolbar Triage Filters (Status Code, Method, In-Scope, Domain)](#core-toolbar-triage-filters-status-code-method-in-scope-domain)
- [Workflow Methodology](#workflow-methodology)
  - [External Tool Feature Extraction & Integration](#3-external-tool-feature-extraction--integration-porting-methodology)
- [Results Presentation & Filtering](#results-presentation--filtering)
- [Threading & Performance](#threading--performance)
  - [Multi-Threaded Ingestion Pool](#multi-threaded-ingestion-pool--concurrent-history-analysis)
- [User Controls & Rate Limiting](#user-controls--rate-limiting)
- [Attack Family Quick Reference](#attack-family-quick-reference)

---

## Design Philosophy

Every new extension should consider adopting:

1. **One-click discovery** — The user should not have to manually collect targets. Pull them from Proxy history in a single click.
2. **Preview before execution** — Always let the tester see exactly what will be sent before any traffic leaves. No hidden request volume.
3. **Bounded, not brute-force** — Send enough probes to find real issues without becoming a noisy scanner.
4. **Adaptive, not manual** — Rate control should discover each host's ceiling automatically. No manual delay/RPS tuning.
5. **Signal over noise** — Show concrete changes like `403 -> 200` and suppress noisy `4xx -> 4xx` transitions. Smart + manual filtering in tandem.
6. **Named techniques** — Every technique has a stable ID, a rationale, and documentation of what broken server code it exposes. Not payload dumps.

---

## Montoya API Integration Patterns

### Context Menu Registration

```java
api.userInterface().registerContextMenuItemsProvider(
    new ContextMenuItemsProvider() {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            JMenuItem item = new JMenuItem("Send to Extension");
            item.addActionListener(e -> handleRequest(event));
            return List.of(item);
        }
    }
);
```

Registers in Proxy, Repeater, Sitemap, and Logger context menus.

### Built-in Request/Response Editors

```java
HttpRequestEditor reqEditor = api.userInterface().createHttpRequestEditor();
HttpResponseEditor respEditor = api.userInterface().createHttpResponseEditor();

// Update on table row selection:
reqEditor.setRequest(result.getRequest());
respEditor.setResponse(result.getResponse());
```

Gives you Pretty/Raw/Hex views for free. Never build your own request viewer.

### Proxy History Access

```java
List<ProxyHttpRequestResponse> history = api.proxy().history();
// Filter for in-scope items with specific status codes
```

### Collaborator Detection & Gating

```java
boolean available = CollaboratorSupport.isAvailable(api);
// If unavailable: disable checkbox, add i icon, prompt user to continue without OOB
```

### Suite Tab Registration

```java
api.userInterface().registerSuiteTab("Your Extension Name", mainPanel);
```

### Extension Lifecycle

```java
api.extension().registerUnloadingHandler(() -> {
    registry.cleanupAll();
    // Terminate all background threads, release resources
});
```

### HTTP/2 Support

```java
// Seamless support for both protocols
HttpMode.HTTP_1
HttpMode.HTTP_2
```


---

## UI Architecture Patterns

These patterns should be adopted when building any non-trivial Burp extension.

### Tab Hierarchy (Multi-Session Model)

```
Top-level Suite Tab
├── Welcome tab (static, onboarding/docs)
├── Sweep tab (persistent, broad coverage tool)
└── Per-request session tabs (dynamic, closeable)
    ├── Tool A sub-tab
    ├── Tool B sub-tab
    └── Tool C sub-tab
    |_ Etc
```

**How it works:**
- `ExtensionTab` extends `JPanel` with a root `JTabbedPane`.
- Each "Send to Extension" from the context menu spawns a new session tab with an `x`
  close button (borderless, non-focusable `JButton`).
- A `SessionRegistry` tracks all controllers so they can be cleaned up on extension unload.
- Tab title is truncated at 30 characters for readability (e.g., `POST /product/stock`).
- Close button prompts `JOptionPane.showConfirmDialog()` for user confirmation.

**Why this matters:** Most extensions create a single tab. Supporting multiple concurrent
sessions — each with its own request, results, and controls — gives the tester
dramatically better workflow. They can run tests on one endpoint while sweeping another.

### Tab Visual Styling & Symbol Prefixes (Icons & Emojis)

Burp Suite's top-level tab bar is naturally crowded with default core tools (`Dashboard`, `Target`, `Proxy`, `Intruder`, `Repeater`, `Collaborator`, `Sequencer`, `Decoder`, `Comparer`, `Logger`, `Extensions`) alongside any installed third-party BApps. Within an extension itself, root tabbed panes and master-detail viewers often present between 4 and 8 tabs.

Adding clean, contextual **symbol or emoji prefixes** before tab names significantly improves visual hierarchy, aesthetic polish, and rapid tool discoverability.

#### 1. Benefits & Workflow Value

- **Instant Suite Identity:** A distinct symbol (e.g., `🛡️ CSP Inspector`, `⚡ Input Validation Fuzzer`, `🔍 JS Explorer`) makes the extension immediately recognizable in Burp's suite tab bar without requiring the tester to read every text label.
- **Visual Categorization in Multi-Tab UIs:** Sub-tabs inside an extension (documentation, discovery sweeps, active session runners, findings, raw HTTP editors) are visually partitioned at a glance.
- **Ambient Status Signaling:** Dynamic session tabs can swap symbols to indicate background execution state in real time (e.g., `⏳ Running...` → `✔ Complete` or `⚠️ Findings`).

#### 2. Curated Symbol Catalog for Burp Extensions

Java Swing renders FlatLaf (Burp Suite's modern look-and-feel) across Linux, Windows, and macOS. Use standardized Unicode symbols or cross-platform emojis:

| Category | Recommended Symbol | Unicode Escape | Example Tab Title | Description / When to Use |
|---|---|---|---|---|
| **Security / Inspection** | `🛡️` or `🛡` | `\uD83D\uDEE1\uFE0F` / `\u26E8` | `🛡️ CSP Inspector` | Security policy auditing, HSTS, CORS, header checks |
| **Fuzzing / Attacks** | `⚡` | `\u26A1` | `⚡ Validation Fuzzer` | Active probing, fuzzer suites, mutation runners |
| **Recon / Sweeping** | `🎯` or `🌐` | `\uD83C\uDFAF` / `\uD83C\uDF10` | `🎯 Traffic Sweep` | Broad surface discovery, endpoint scrapers, crawler queues |
| **Search / Mining** | `🔍` or `🔎` | `\uD83D\uDD0D` / `\uD83D\uDD0E` | `🔍 Recon & Secrets` | Regex extractors, JS secret miners, endpoint finders |
| **Source / Tree** | `🌲` or `📁` | `\uD83C\uDF32` / `\uD83D\uDCC1` | `📁 Source Tree` | Reconstructed file trees, sitemap explorers, maps |
| **AI / Intelligence** | `✨` or `🤖` | `\u2728` / `\uD83E\uDD16` | `✨ AI Security Analyst` | LLM-assisted analysis, automated triaging |
| **Documentation / Guide** | `📖` or `ℹ️` | `\uD83D\uDCD6` / `\u2139\uFE0F` | `📖 Welcome & Guide` | Static onboarding tabs, workflow cheat sheets, cards |
| **Results / Data** | `📊` or `📋` | `\uD83D\uDCCA` / `\uD83D\uDCCB` | `📊 Findings & Evidence` | Findings tables, vulnerability summaries, audit logs |
| **HTTP Request** | `📤` or `→` | `\uD83D\uDCE4` / `\u2192` | `📤 Request` | Outgoing HTTP request editor tab |
| **HTTP Response** | `📥` or `←` | `\uD83D\uDCE5` / `\u2190` | `📥 Response` | Inbound HTTP response editor tab |
| **Configuration** | `⚙️` or `⚙` | `\u2699\uFE0F` / `\u2699` | `⚙️ Options & Scope` | Settings modals, rate limits, attack configurations |
| **Dynamic Running** | `⏳` or `🔄` | `\u23F3` / `\uD83D\uDD04` | `⏳ POST /api/v1 (Running)` | Session currently executing in background thread |
| **Dynamic Finished** | `✔` or `✅` | `\u2714` / `\u2705` | `✔ POST /api/v1 (Done)` | Session completed successfully |
| **Dynamic Alert** | `⚠️` or `🚨` | `\u26A0\uFE0F` / `\uD83D\uDEA8` | `⚠️ POST /api/v1 (3 Issues)` | Session completed with interesting security signals |

#### 3. Implementation Code Patterns

**Suite Tab Registration (Top-Level Burp Bar):**
```java
// Register with a distinct symbol prefix for instant visual identity
api.userInterface().registerSuiteTab("🛡️ CSP Inspector", mainPanel);
```

**Internal Root Tabbed Pane:**
```java
JTabbedPane rootTabbedPane = new JTabbedPane();

// Category-distinct tab labels:
rootTabbedPane.addTab("📖 Welcome & Guide", welcomePanel);
rootTabbedPane.addTab("🎯 Traffic Sweep", sweepPanel);
rootTabbedPane.addTab("🔍 Recon & Secrets", reconPanel);
rootTabbedPane.addTab("⚙️ Settings", settingsPanel);
```

**Request / Response Editor Sub-Tabs:**
```java
JTabbedPane editorTabs = new JTabbedPane();
editorTabs.addTab("📤 Request", requestEditor.uiComponent());
editorTabs.addTab("📥 Response", responseEditor.uiComponent());
editorTabs.addTab("📋 Evidence & Notes", new JScrollPane(evidenceTextArea));
```

**Dynamic Session Tabs with Close Button & Status Symbol:**
When launching dynamic session tabs (e.g. per-endpoint attack sessions), provide a custom tab component with an icon/symbol prefix, title truncation, and a close button:

```java
public void addSessionTab(String method, String path, JPanel sessionContent) {
    int index = rootTabbedPane.getTabCount();
    
    // Initial tab state with running symbol and safely truncated endpoint
    String truncatedPath = path.length() > 22 ? path.substring(0, 19) + "..." : path;
    String titleText = "⏳ " + method + " " + truncatedPath;
    
    rootTabbedPane.addTab(titleText, sessionContent);

    // Custom tab header component
    JPanel tabHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
    tabHeader.setOpaque(false);

    JLabel titleLabel = new JLabel(titleText);
    JButton closeBtn = new JButton("×");
    closeBtn.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4));
    closeBtn.setContentAreaFilled(false);
    closeBtn.setFocusable(false);
    closeBtn.setToolTipText("Close Session");
    closeBtn.addActionListener(e -> {
        int tabIdx = rootTabbedPane.indexOfComponent(sessionContent);
        if (tabIdx != -1) {
            rootTabbedPane.removeTabAt(tabIdx);
        }
    });

    tabHeader.add(titleLabel);
    tabHeader.add(closeBtn);
    rootTabbedPane.setTabComponentAt(index, tabHeader);
}
```

**Live Status Glyphs on Session Completion:**
When background execution finishes, update the tab's symbol prefix on the Swing EDT to give ambient feedback:

```java
// Inside worker completion callback (Swing EDT):
SwingUtilities.invokeLater(() -> {
    String statusSymbol = findingsCount > 0 ? "⚠️" : "✔";
    String updatedTitle = statusSymbol + " " + method + " " + truncatedPath;
    titleLabel.setText(updatedTitle);
});
```

#### 4. Formatting & Cross-Platform Best Practices

1. **Always Include a Trailing Space:** Always format as `"🛡️ CSP Inspector"` rather than `"🛡️CSP Inspector"`. Without a space, characters can visually collide or render clipped in certain Swing Look-and-Feels.
2. **Safe Unicode Characters for Linux Headless / Minimal Fonts:** While FlatLaf handles most emojis gracefully, older Linux distributions with minimal font packages may render high-surrogate color emojis as monochrome or boxes. If maximum universal compatibility is required across all host systems, prefer standard BMP Unicode symbols:
   - `⚡` (`\u26A1`), `✦` (`\u2726`), `★` (`\u2605`), `▶` (`\u25B6`), `●` (`\u25CF`), `✔` (`\u2714`), `✖` (`\u2716`), `ℹ` (`\u2139`), `⚙` (`\u2699`).
3. **Preserve Symbol During Truncation:** When truncating long URLs or paths for session tabs (e.g. 30 characters maximum), always truncate the *path string first* before prepending the symbol, ensuring the icon glyph is never sliced or corrupted.
4. **Consistency Across the Extension:** Keep symbol conventions consistent across the extension — if `📤 Request` and `📥 Response` are used in one panel, use the same symbols in all viewer panels.

### Collapsible Filter Sidebar

```
+------------------------------------------+
|  [Show/Hide Filters]  |  Results Table   |
|  +------------------+ |  +------------+  |
|  |  Smart Filter    | |  | Technique  |  |
|  |  Manual Filter   | |  | Payload    |  |
|  |  Status Code     | |  | Status     |  |
|  |  Content Length  | |  | Length     |  |
|  |  Content-Type    | |  | Signal     |  |
|  |  Payload         | |  |            |  |
|  |  Signal          | |  |            |  |
|  |  Highlight Color | |  |            |  |
|  +------------------+ |  +------------+  |
|       500px           |                  |
+------------------------------------------+
```

**How it works:**
- `ResultsWorkspace` uses a `JSplitPane(HORIZONTAL_SPLIT)`.
- Expanded sidebar: 500px wide. Collapsed: 58px with a vertical `"Show Filters"` button.
- This maximizes table real estate during analysis while keeping filters one click away.

**When to use:** Any extension that displays a results table with >50 rows should include
a collapsible filter sidebar. It is the difference between useful and overwhelming.

### Core Toolbar Triage Filters (Status Code, Method, In-Scope, Domain)

When an extension ingests Burp Proxy history or collects automated findings, real-world targets easily produce thousands of requests. Presenting these without rapid filtering creates overwhelming noise (third-party trackers, uninteresting status codes, irrelevant HTTP verbs, and out-of-scope analytics).

Every extension displaying captured HTTP messages, candidate endpoints, or attack results must incorporate the **Core Four Triage Filters** on its primary toolbar or filter panel:
1. **Status Code Filter**
2. **Method Filter**
3. **In-Scope Filter**
4. **Domain Filter**

```
+-------------------------------------------------------------------------------------------------------------------+
| [Load Proxy History] | Domain: [api.target.com        ] | Method: [All Methods v] | Status: [2xx, 3xx v]          |
| [x] In-Scope Only    | [Apply]  [Reset Filters]        | Total: 1,420 | Displayed: 86                              |
+-------------------------------------------------------------------------------------------------------------------+
```

#### 1. Filter Specifications & UI Components

| Filter | UI Component | Default State | Behavior & Purpose |
|---|---|---|---|
| **Status Code** | `MultiSelectFilterButton` or editable `JComboBox<String>` | "All Statuses" | Filters responses by status code, range (`2xx`, `3xx`, `4xx`, `5xx`), or comma-separated lists (`200, 302, 403`). Isolates bypasses and server errors. |
| **Method** | `MultiSelectFilterButton` (`"Method"`) | "All Methods" | Multi-select popup for standard HTTP verbs (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `HEAD`). Empty set or "All" passes all verbs. |
| **In-Scope** | `JCheckBox` (`"In-Scope Only"`) | `false` (or `true`) | Non-destructive view filter evaluated live against Burp's target scope via `api.scope().isInScope(url)`. Eliminates third-party noise. |
| **Domain** | `JTextField` (or dynamic `JComboBox<String>`) | Empty / `"All"` | Isolates traffic to a specific target host or subdomain pattern. Auto-sanitizes pasted URLs and supports exact, subdomain, and substring matches. |

#### 2. Detailed Filter Mechanics

##### A. Status Code Filter
- **Workflow Value**: In vulnerability research, isolating status codes is critical for identifying transitions (e.g., `403 Forbidden -> 200 OK` bypasses), monitoring server-side crashes (`500 Internal Server Error`), or filtering out uninteresting redirection chains (`301`/`302`) and cached responses (`304 Not Modified`).
- **Input Modes**:
  - Exact status codes: `200`, `401`, `403`, `500`
  - Range masks: `2xx` (200–299), `3xx` (300–399), `4xx` (400–499), `5xx` (500–599)
  - Delimited sets: Comma, slash, or space-separated values (`200, 302`, `401 / 403`)
- **Missing Response Guard**: Requests awaiting response or failing at the socket layer have status code 0 or -1; guard against them safely.
- **Parsing & Matching Logic**:
```java
public static boolean matchesStatusCode(int statusCode, String filter) {
    if (filter == null || filter.trim().isEmpty() || filter.equalsIgnoreCase("All") || filter.equalsIgnoreCase("All Statuses")) {
        return true;
    }
    if (statusCode <= 0) return false;

    // Split on commas, slashes, or whitespace
    String[] tokens = filter.split("[,/\\s]+");
    for (String rawToken : tokens) {
        String token = rawToken.trim();
        if (token.isEmpty()) continue;

        // Range checks: 2xx, 3xx, 4xx, 5xx
        if (token.equalsIgnoreCase("2xx") && statusCode >= 200 && statusCode < 300) return true;
        if (token.equalsIgnoreCase("3xx") && statusCode >= 300 && statusCode < 400) return true;
        if (token.equalsIgnoreCase("4xx") && statusCode >= 400 && statusCode < 500) return true;
        if (token.equalsIgnoreCase("5xx") && statusCode >= 500 && statusCode < 600) return true;

        // Exact numeric match
        try {
            int targetCode = Integer.parseInt(token);
            if (statusCode == targetCode) return true;
        } catch (NumberFormatException ignored) {}
    }
    return false;
}
```

##### B. Method Filter
- **Workflow Value**: Web applications and REST/GraphQL APIs expose radically different attack surfaces per HTTP method. Testers frequently isolate state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) when testing for CSRF, mass assignment, or authorization flaws, isolate `GET` requests for caching and reflection issues, or isolate `OPTIONS` for CORS misconfigurations.
- **Multi-Select Preference**: Use `MultiSelectFilterButton` over single-selection dropdowns so testers can inspect multiple methods concurrently (e.g., viewing both `POST` and `PUT` simultaneously).
- **Matching Logic**:
```java
public static boolean matchesMethod(String method, Set<String> selectedMethods) {
    if (selectedMethods == null || selectedMethods.isEmpty() || selectedMethods.contains("All Methods")) {
        return true;
    }
    if (method == null) return false;
    return selectedMethods.contains(method.toUpperCase());
}
```

##### C. In-Scope Filter
- **Workflow Value**: Modern web apps load assets from dozens of third-party domains (analytics, CDNs, ad networks, chat widgets). Without an in-scope filter, thousands of irrelevant requests flood the extension. Burp Suite's Target Scope (`api.scope().isInScope(url)`) provides the authoritative boundary.
- **Dual-Stage Architecture**:
  1. **Optional Ingestion Pre-Filter**: During heavy proxy history loading (`Load Proxy History`), skipping out-of-scope items inside the background `SwingWorker` prevents unnecessary heap memory allocation.
  2. **Non-Destructive View Filter**: Stored items in the extension's data store remain intact. Toggling the `In-Scope Only` checkbox simply re-evaluates the view predicate, allowing the tester to review out-of-scope traffic without re-importing.
- **Composition with Row Pinning**: Manual item pinning (`hasPins()`) takes precedence over scope gating. If a row is pinned, it remains visible even if outside project scope.
- **Matching Logic**:
```java
public static boolean matchesScope(MontoyaApi api, String url, boolean inScopeOnly) {
    if (!inScopeOnly) return true;
    if (url == null || api == null) return false;
    return api.scope().isInScope(url);
}
```

##### D. Domain Filter
- **Workflow Value**: Large scopes often contain multiple target microservices or sister domains (`api.example.com`, `auth.example.com`, `admin.example.com`, `partner.net`). Testers need to focus analysis on one specific host or subdomain tier.
- **URL Sanitization**: Testers frequently copy and paste full URLs into the filter field (e.g. `https://api.target.com:8443/v1/users`). The domain filter must automatically sanitize the input by stripping protocol prefixes (`http://`, `https://`), port numbers (`:8443`), and path segments (`/v1/...`).
- **Flexible Matching Modes**:
  - **Exact Host Match**: `host.equalsIgnoreCase(cleanDomain)`
  - **Subdomain / Suffix Match**: Supports wildcard prefixes (`*.example.com`) and subdomains (`api.target.com` matches `target.com`)
  - **Substring Contains Match**: Case-insensitive substring matching for quick fuzzy filtering
- **Matching Logic**:
```java
public static boolean matchesDomain(String entryHost, String domainFilter) {
    if (domainFilter == null || domainFilter.trim().isEmpty() || domainFilter.equalsIgnoreCase("All")) {
        return true;
    }
    if (entryHost == null) return false;

    // 1. Sanitize user input (strips protocol, port, paths, and wildcard prefixes)
    String cleanFilter = domainFilter.trim().toLowerCase();
    if (cleanFilter.startsWith("http://")) cleanFilter = cleanFilter.substring(7);
    if (cleanFilter.startsWith("https://")) cleanFilter = cleanFilter.substring(8);
    int slashIdx = cleanFilter.indexOf('/');
    if (slashIdx != -1) cleanFilter = cleanFilter.substring(0, slashIdx);
    int colonIdx = cleanFilter.indexOf(':');
    if (colonIdx != -1) cleanFilter = cleanFilter.substring(0, colonIdx);
    if (cleanFilter.startsWith("*.")) cleanFilter = cleanFilter.substring(2);

    // 2. Sanitize entry host (strips port if present)
    String host = entryHost.toLowerCase();
    int hostColon = host.indexOf(':');
    if (hostColon != -1) host = host.substring(0, hostColon);

    // 3. Match: Exact host, subdomain suffix, or contains
    return host.equalsIgnoreCase(cleanFilter)
        || host.endsWith("." + cleanFilter)
        || host.contains(cleanFilter);
}
```

#### 3. Integrated Filtering Pipeline (DataStore / TableModel)

Combine all four filters into a clean, unified predicate chain. The evaluation pipeline executes sequentially on the in-memory dataset:

```java
public List<TrafficEntry> getFilteredEntries(
    String domainFilter,
    Set<String> selectedMethods,
    String statusFilter,
    boolean inScopeOnly,
    Set<Integer> pinnedIds
) {
    // 1. Row Pinning Gate: If pins are active, show pinned items only
    if (pinnedIds != null && !pinnedIds.isEmpty()) {
        return allEntries.stream()
            .filter(e -> pinnedIds.contains(e.id()))
            .collect(Collectors.toList());
    }

    // 2. Core Four Triage Pipeline
    return allEntries.stream()
        .filter(entry -> matchesDomain(entry.host(), domainFilter))
        .filter(entry -> matchesMethod(entry.method(), selectedMethods))
        .filter(entry -> matchesStatusCode(entry.statusCode(), statusFilter))
        .filter(entry -> matchesScope(api, entry.url(), inScopeOnly))
        .collect(Collectors.toList());
}
```

#### 4. UI Toolbar Construction with Debouncing & One-Click Reset

When combining text inputs (`JTextField`) with selection controls (`MultiSelectFilterButton`, `JCheckBox`), wire them through a **300ms debounce timer**. This prevents CPU thrashing and EDT freezes during rapid typing:

```java
// ─── Debounce Timer (Prevents EDT congestion during typing) ────────
private final javax.swing.Timer filterDebounceTimer = new javax.swing.Timer(300, e -> refreshView());
{
    filterDebounceTimer.setRepeats(false);
}

private void triggerDebouncedFilter() {
    filterDebounceTimer.restart();
}

// ─── Toolbar Construction ──────────────────────────────────────────
private JPanel createFilterToolbar() {
    JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

    // 1. Domain Filter Input
    JTextField domainField = new JTextField(14);
    domainField.setToolTipText("Filter by domain or host (e.g. api.target.com, *.target.com)");
    domainField.getDocument().addDocumentListener(new SimpleDocumentListener(this::triggerDebouncedFilter));

    // 2. Method Multi-Select Button
    MultiSelectFilterButton methodBtn = new MultiSelectFilterButton(
        "Method",
        List.of("All Methods", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"),
        sel -> refreshView()
    );

    // 3. Status Code Dropdown (Editable for custom code input)
    JComboBox<String> statusCombo = new JComboBox<>(new String[]{
        "All Statuses", "2xx Success", "200 OK", "3xx Redirection",
        "4xx Client Error", "401 Unauthorized", "403 Forbidden", "404 Not Found", "5xx Server Error"
    });
    statusCombo.setEditable(true);
    statusCombo.addActionListener(e -> triggerDebouncedFilter());

    // 4. In-Scope Only Checkbox
    JCheckBox inScopeCheckBox = new JCheckBox("In-Scope Only", false);
    inScopeCheckBox.addActionListener(e -> refreshView());

    // 5. One-Click Reset Button
    JButton resetBtn = new JButton("Reset Filters");
    resetBtn.setToolTipText("Clear all filters and restore full dataset view");
    resetBtn.addActionListener(e -> {
        domainField.setText("");
        methodBtn.clearSelection();
        statusCombo.setSelectedIndex(0);
        inScopeCheckBox.setSelected(false);
        refreshView();
    });

    // 6. Live Metrics Counter Label
    JLabel statsLabel = new JLabel("Total: 0 | Displayed: 0");
    statsLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));

    // Assemble components into toolbar
    toolbar.add(new JLabel("Domain:"));
    toolbar.add(domainField);
    toolbar.add(methodBtn);
    toolbar.add(new JLabel("Status:"));
    toolbar.add(statusCombo);
    toolbar.add(inScopeCheckBox);
    toolbar.add(resetBtn);
    toolbar.add(new JSeparator(SwingConstants.VERTICAL));
    toolbar.add(statsLabel);

    return toolbar;
}
```

#### 5. Best Practices & Pitfalls to Avoid

1. **Always Normalize Casing:** Normalize HTTP methods to uppercase (`method.toUpperCase()`) and domain names to lowercase (`domain.toLowerCase()`) before comparison to prevent false misses on mixed-case headers or URLs.
2. **Non-Destructive View Filtering:** Never delete entries from the master `allEntries` list when filters are applied. Keep the master cache intact and filter into a `displayedEntries` list so clearing filters is instantaneous and lossless.
3. **Handle Missing Responses Safely:** Captured requests without a response (e.g. pending requests, timed-out connections) return `null` or code `0` from `response.statusCode()`. Ensure `matchesStatusCode()` guards against non-positive integers.
4. **Scope Cache in High-Volume Loops:** For large datasets (>10,000 items), evaluating `api.scope().isInScope(url)` repeatedly can introduce overhead. Cache evaluated URLs or host prefixes in a temporary `Map<String, Boolean>` during each `getFilteredEntries()` pass.
5. **Debounce Interactive Text Inputs:** Always attach a `javax.swing.Timer` debounce listener (250–350ms) to text fields like Domain and Status. Firing full table rebuilds on every individual keystroke freezes the Swing EDT.
6. **Synchronize Live Counter Feedback:** Always update the count label (`"Total: " + allEntries.size() + " | Displayed: " + displayed.size()`) at the conclusion of `refreshView()` so the tester immediately knows whether the active filter set is too broad or too restrictive.

### Pre-Execution Preview Probe Button

Every tool provides a "Preview" step before sending traffic:

- **Probe Preview:** Button shows exact requests for a selected candidate in a
  monospace modal dialog.
- **Attack Scope:** Checkboxes with Check All / Uncheck All so the tester controls exactly which technique families run.
- **Payload Preview:** Shows every generated payload value, encoding, and
  category in a formatted preview table.

The preview uses the same generator path as execution — it is the source of truth for what
will actually run.

### Custom Auth & Session Token Injection Button

In real-world security assessments, automated tests or fuzzer runs are often executed at
the end of an assessment when previously captured sessions in Proxy history may have expired.

**Implementation Pattern:**
- In each session tab, provide a **`Custom Headers & Auth... (N)`** button on the top toolbar.
- The button badge reflects the number of active injected headers (e.g. `Custom Headers & Auth... (2)`).
- Clicking the button opens a modal editor supporting:
  - Preset snippets: `+ Add Bearer Token` (`Authorization: Bearer <token>`), `+ Add Session Cookie` (`Cookie: session=<id>; auth=<token>`), `+ Add X-API-Key` (`X-API-Key: <key>`).
  - Freeform text area supporting any `Header-Name: value` format (one per line).
- **Uniform Injection:** When the attack/fuzz engine runs, these configured headers are
  automatically injected into both baseline control requests and all generated mutation probes,
  overriding or updating existing headers.

### Checkbox-Driven Batch Session Launching

Extensions operating across multiple endpoints should provide deliberate, batch-aware
target selection controls rather than forcing one-by-one testing:

**Workflow:**
- **`Select All`**: Checks all checkboxes for currently filtered/visible candidate rows.
- **`Deselect All`**: Unchecks all candidate checkboxes.
- **Strict Checkbox-Driven `Execute` Button**:
  - Clicking **`Execute`** verifies that at least one candidate is checked. If nothing is checked, a prompt warns the user to select target endpoints.
  - Spawns an isolated session tab:
    - Single target checked: `METHOD /path... x`
    - Multiple targets checked: `Run (N targets) x`
  - The session tab engine processes all N targets sequentially or concurrently, streaming findings into a unified results table with live progress tracking (`"Target 2/5 (POST /profile) | 18/48 probes"`).

### Auto-Navigation & Deep-Linking to Findings in Request/Response Editors

When extensions discover security findings inside HTTP traffic — such as leaked API keys, tokens, endpoints, reflected parameters, SSRF canaries, or error stack traces — the corresponding requests or responses are often hundreds or thousands of lines long (e.g. minified 1MB JavaScript bundles, massive JSON responses, or complex GraphQL schemas).

Simply loading the message into Montoya's `HttpRequestEditor` or `HttpResponseEditor` resets the viewport to position 0 (line 1). The tester is forced to manually scroll or search through thousands of lines to locate what was flagged, severely degrading triage efficiency.

To solve this, extensions should implement the **Deep-Linking Quad**: an automated 4-pillar navigation pipeline that transports the tester directly to the exact match.

#### The 4-Pillar Deep-Linking Architecture

```
User selects finding row in JTable
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Active Tab Auto-Switching                                │
│    Switches JTabbedPane to [Request] or [Response] tab       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Native Marker Highlighting                               │
│    Applies Marker.marker(Range.range(start, end)) via       │
│    withMarkers() for native Burp yellow/orange highlights    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Search Bar Expression Populating                         │
│    Calls editor.setSearchExpression(matchedText) to trigger │
│    the native search bar & enable Enter/Shift+Enter jumping │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Caret Positioning & Viewport Auto-Scroll                 │
│    Calls editor.setCaretPosition(startOffset) to scroll the  │
│    editor viewport vertically & horizontally to the target  │
└─────────────────────────────────────────────────────────────┘
```

1. **Active Tab Auto-Switching**: Determine whether the finding originated in the HTTP Request or HTTP Response, and programmatically switch the active sub-tab via `editorTabs.setSelectedComponent(...)` so the tester doesn't have to guess where the match lives.
2. **Native Marker Range Highlighting**: Montoya's `HttpRequest` and `HttpResponse` support `withMarkers(List<Marker> markers)`. When loaded into the editor, Burp Suite natively paints marked ranges with vibrant yellow/orange highlight boxes across Pretty, Raw, and Hex modes.
3. **Search Bar Expression Populating**: Calling `editor.setSearchExpression(targetString)` populates Burp's native bottom search bar, highlights all occurrences in the active view, and enables instant `Enter` / `Shift+Enter` keyboard jumping.
4. **Caret Positioning & Viewport Auto-Scroll**: Calling `editor.setCaretPosition(startOffset)` moves the text component's cursor directly to the character offset, forcing Swing and Burp's internal scrollpane to auto-scroll both horizontally and vertically so the finding is centered on screen.

#### Standard Data Model

To support automatic navigation, every finding record must store its provenance, match value, and byte/character offsets:

```java
public enum FindingLocation {
    REQUEST_URL,
    REQUEST_HEADER,
    REQUEST_BODY,
    RESPONSE_HEADER,
    RESPONSE_BODY
}

public record DiscoveredFinding(
    int id,
    String ruleName,
    String matchedValue,
    FindingLocation location,
    int startOffset,         // Offset within the respective message or body
    int endOffset,
    HttpRequestResponse requestResponse
) {
    public boolean isResponseFinding() {
        return location == FindingLocation.RESPONSE_HEADER ||
               location == FindingLocation.RESPONSE_BODY;
    }
}
```

#### Standard Implementation Code

Wire this logic into your findings table selection listener:

```java
// ─── Table Selection Listener ──────────────────────────────────
findingsTable.getSelectionModel().addListSelectionListener(e -> {
    if (e.getValueIsAdjusting()) return;

    int selectedRow = findingsTable.getSelectedRow();
    if (selectedRow < 0) return;

    int modelRow = findingsTable.convertRowIndexToModel(selectedRow);
    DiscoveredFinding finding = findingsTableModel.getFindingAt(modelRow);
    if (finding != null) {
        navigateToFinding(finding);
    }
});

// ─── Deep-Linking Navigation Engine ─────────────────────────────
private void navigateToFinding(DiscoveredFinding finding) {
    HttpRequestResponse message = finding.requestResponse();
    if (message == null) return;

    String query = finding.matchedValue();

    if (finding.isResponseFinding()) {
        HttpResponse response = message.response();
        if (response == null) return;

        // Pillar 1: Auto-switch tab to Response
        editorTabs.setSelectedComponent(responseEditor.uiComponent());

        // Calculate absolute raw message offsets if finding was relative to body
        int rawStart = finding.startOffset();
        int rawEnd = finding.endOffset();
        if (finding.location() == FindingLocation.RESPONSE_BODY) {
            int bodyOffset = response.bodyOffset();
            rawStart += bodyOffset;
            rawEnd += bodyOffset;
        }

        // Fallback: If exact offsets are unknown or 0, locate in raw response
        if (rawStart <= 0 && query != null && !query.isEmpty()) {
            String rawStr = response.toString();
            int idx = rawStr.indexOf(query);
            if (idx >= 0) {
                rawStart = idx;
                rawEnd = idx + query.length();
            }
        }

        // Pillar 2: Apply native Montoya Markers
        if (rawStart >= 0 && rawEnd > rawStart) {
            Marker marker = Marker.marker(Range.range(rawStart, rawEnd));
            response = response.withMarkers(marker);
        }
        responseEditor.setResponse(response);

        // Pillar 3: Populate native editor search bar
        if (query != null && !query.isEmpty()) {
            responseEditor.setSearchExpression(query);
        }

        // Pillar 4: Auto-scroll viewport to match location via Caret
        if (rawStart >= 0) {
            final int targetCaret = rawStart;
            SwingUtilities.invokeLater(() -> responseEditor.setCaretPosition(targetCaret));
        }

    } else {
        // Request Finding
        HttpRequest request = message.request();
        if (request == null) return;

        // Pillar 1: Auto-switch tab to Request
        editorTabs.setSelectedComponent(requestEditor.uiComponent());

        int rawStart = finding.startOffset();
        int rawEnd = finding.endOffset();
        if (finding.location() == FindingLocation.REQUEST_BODY) {
            int bodyOffset = request.bodyOffset();
            rawStart += bodyOffset;
            rawEnd += bodyOffset;
        }

        // Fallback: Locate in raw request string
        if (rawStart <= 0 && query != null && !query.isEmpty()) {
            String rawStr = request.toString();
            int idx = rawStr.indexOf(query);
            if (idx >= 0) {
                rawStart = idx;
                rawEnd = idx + query.length();
            }
        }

        // Pillar 2: Apply native Montoya Markers
        if (rawStart >= 0 && rawEnd > rawStart) {
            Marker marker = Marker.marker(Range.range(rawStart, rawEnd));
            request = request.withMarkers(marker);
        }
        requestEditor.setRequest(request);

        // Pillar 3: Populate native search bar
        if (query != null && !query.isEmpty()) {
            requestEditor.setSearchExpression(query);
        }

        // Pillar 4: Auto-scroll viewport via Caret
        if (rawStart >= 0) {
            final int targetCaret = rawStart;
            SwingUtilities.invokeLater(() -> requestEditor.setCaretPosition(targetCaret));
        }
    }
}
```

#### Best Practices & Gotchas

- **Header Offset Adjustment (`bodyOffset()`):** Regex matchers operating on `response.bodyToString()` report indices relative to the body start. Because Montoya's `Marker` indexes the entire raw HTTP message (headers + body), always add `response.bodyOffset()` to body-relative offsets before creating markers or moving the caret.
- **`SwingUtilities.invokeLater()` for Caret Scrolling:** Setting message content (`setResponse`) initiates asynchronous syntax highlighting and rendering in FlatLaf. Calling `setCaretPosition()` inside `SwingUtilities.invokeLater()` ensures the editor has completely measured and laid out the text before adjusting the scroll position.
- **Resilience Against Minified Bundles:** When a single line contains 100KB+ of minified code, vertical scroll alone is insufficient. Setting both the caret position and search expression forces Burp's text viewport to scroll horizontally to the exact match column.
- **Preserve User Modifications:** If an editor is configured to allow user edits, check `editor.isModified()` before re-setting contents programmatically to avoid silently discarding tester alterations.

### Welcome & Onboarding Dashboard

- A static first tab with `GridLayout(0, 2, 24, 18)` displaying modular tutorial cards.
- Documents testing playbooks and workflow guidelines inside the extension itself.
- Non-intrusive update banner (dismissible `JPanel` at `BorderLayout.NORTH`) alerts users
  to newer GitHub releases without blocking workflow.
- Banner styling: Background `Color(255, 244, 214)`, Border `Color(214, 173, 82)`.

### Sending Requests to Other Burp Tools (Repeater, Intruder, Organizer)

When an extension displays a table of captured HTTP requests, always give the user a way to send one or more rows to other Burp tools. Without this, testers must go back to the Proxy history and right-click there — an unnecessary context switch that breaks flow.

**Montoya API methods:**
```java
// Repeater — opens a new tab
api.repeater().sendToRepeater(httpRequest);
// With a descriptive tab name so tabs don't all look the same:
api.repeater().sendToRepeater(httpRequest, "GET api.example.com/users");

// Intruder
api.intruder().sendToIntruder(httpRequest);

// Organizer (request archive / notes tool)
api.organizer().sendToOrganizer(requestResponse);
```

**Tab naming convention for Repeater** — build the name as `METHOD host/path` so each tab is immediately identifiable:
```java
String tabName = entry.method() + " " + entry.host() + entry.path();
api.repeater().sendToRepeater(entry.request(), tabName);
```

**Where to wire it up** — a right-click `JPopupMenu` on the entries table is the most natural placement, especially because it composes cleanly with the multi-row selection:

```java
JPopupMenu popup = new JPopupMenu();

JMenuItem sendRepeater = new JMenuItem("Send to Repeater");
sendRepeater.addActionListener(e -> {
    for (int viewRow : entryTable.getSelectedRows()) {
        int modelRow = entryTable.convertRowIndexToModel(viewRow);
        MyEntry entry = tableModel.getEntryAt(modelRow);
        if (entry != null && entry.request() != null) {
            String tabName = entry.method() + " " + entry.host() + entry.path();
            api.repeater().sendToRepeater(entry.request(), tabName);
        }
    }
});

JMenuItem sendIntruder = new JMenuItem("Send to Intruder");
sendIntruder.addActionListener(e -> {
    for (int viewRow : entryTable.getSelectedRows()) {
        int modelRow = entryTable.convertRowIndexToModel(viewRow);
        MyEntry entry = tableModel.getEntryAt(modelRow);
        if (entry != null && entry.request() != null) {
            api.intruder().sendToIntruder(entry.request());
        }
    }
});

JMenuItem sendOrganizer = new JMenuItem("Send to Organizer");
sendOrganizer.addActionListener(e -> {
    for (int viewRow : entryTable.getSelectedRows()) {
        int modelRow = entryTable.convertRowIndexToModel(viewRow);
        MyEntry entry = tableModel.getEntryAt(modelRow);
        if (entry != null && entry.requestResponse() != null) {
            api.organizer().sendToOrganizer(entry.requestResponse());
        }
    }
});

popup.add(sendRepeater);
popup.add(sendIntruder);
popup.add(sendOrganizer);
entryTable.setComponentPopupMenu(popup);
```

**Required: multi-row table selection** — switch any results table that exposes Send To actions from `SINGLE_SELECTION` to `MULTIPLE_INTERVAL_SELECTION` so users can shift-click or ctrl-click a range and batch-send:
```java
entryTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
```

**Why this matters:** Without Send To, testers must manually copy-paste URLs or hunt for
the request back in the Proxy history — a workflow break that costs time and context.

### Manual Item Selection (Row Pinning) — Complement to In-Scope Filter

`api.scope().isInScope(url)` is coarse-grained: it gates on entire host/path prefixes defined in Burp's Target Scope settings. Users frequently want to **narrow down further within the filtered results** without changing the project scope — for example, picking three specific endpoints from a list of 200 in-scope URLs.

Implement this as a **Pin / Unpin toggle** backed by a `Set<Integer>` of pinned entry IDs. When any rows are pinned, the view shows only pinned rows. Clearing all pins restores the full filtered view.

**Data model** (lives in the DataStore or directly on the Tab class):
```java
private final Set<Integer> pinnedIds = new LinkedHashSet<>();

public boolean isPinned(int entryId)  { return pinnedIds.contains(entryId); }
public void    pin(int entryId)        { pinnedIds.add(entryId); }
public void    unpin(int entryId)      { pinnedIds.remove(entryId); }
public void    clearPins()             { pinnedIds.clear(); }
public boolean hasPins()               { return !pinnedIds.isEmpty(); }
```

**UI wire-up** — "Pin Selected" and "Clear Pins" work well both as toolbar buttons and as entries in the same right-click context menu as Send To:
```java
JButton pinBtn = new JButton("Pin Selected");
pinBtn.setToolTipText("Show only the selected rows (ignores scope filter)");
pinBtn.addActionListener(e -> {
    for (int viewRow : entryTable.getSelectedRows()) {
        int modelRow = entryTable.convertRowIndexToModel(viewRow);
        MyEntry entry = tableModel.getEntryAt(modelRow);
        if (entry != null) pinnedIds.add(entry.id());
    }
    refreshView();
});

JButton clearPinsBtn = new JButton("Clear Pins");
clearPinsBtn.addActionListener(e -> { pinnedIds.clear(); refreshView(); });
```

**Filter pipeline** — pin gate fires first, before scope, keyword, status, and method filters. If `hasPins()` is true, skip all other filters entirely:
```java
// At the top of getFilteredEntries() / groupByMode():
if (hasPins()) {
    return allEntries.stream()
        .filter(e -> pinnedIds.contains(e.id()))
        .collect(Collectors.toList());
}
// Otherwise fall through to the normal scope + keyword + status/method filters.
```

**Stats label** — signal "pinned mode" prominently so users are not confused by the reduced count:
```java
String modeLabel = hasPins()
    ? "Pinned: " + pinnedIds.size()
    : "Displayed: " + displayedCount;
statsLabel.setText("Total: " + totalCount + " | " + modeLabel);
```

**Lifecycle rules:**
- The pin set must survive `refreshView()` calls (don't clear it on filter changes).
- Clear pins when the user clicks **Clear All Data**, since the underlying entries are gone.

### Progress Bar & Live Ingestion Status (Proxy History Loading)

When building extensions that ingest traffic via a **`Load Proxy History`** button, projects during real-world engagements often hold tens of thousands of items (10,000+ to 50,000+ requests). Scraping, URL parsing, scope checking (`isInScope`), parameter extraction, and deduplication run asynchronously via `SwingWorker`.

Without immediate visual progress feedback, users are left wondering whether their click registered or if Burp Suite has frozen. This often triggers repeated clicks, overlapping scraping workers, and wasted CPU.

#### 1. Visual Placement & Layout

Place a dedicated **status strip** directly below the main action/filter toolbar or at the top/bottom boundary of the tab:
- **Left (`BorderLayout.WEST`)**: A `JLabel` describing the current activity (e.g. `"Scanning Proxy history for in-scope traffic..."`).
- **Right (`BorderLayout.EAST`)**: A `JProgressBar` with fixed dimensions (e.g. `220x16`), preventing UI layout shifts when its visibility is toggled.
- **Hidden by Default**: Keep the progress bar hidden (`progressBar.setVisible(false)`) when idle to maintain a clean, uncluttered interface, revealing it only during active ingestion or background work.

```
+---------------------------------------------------------------------------------+
| [Load Proxy History]  [Deduplicate]  [Select All]  [Deselect All]  [Preview]     |
| Method: [All  v]  Status: [All  v]  Search: [                        ]          |
|---------------------------------------------------------------------------------|
| Scanning Proxy history for in-scope traffic...          [======||||||||||]     |
| (statusLabel at WEST)                                   (progressBar at EAST)   |
+---------------------------------------------------------------------------------+
```

#### 2. Workflow & State Management Pattern

1. **Immediate Debounce & Trigger**: On click, immediately disable `loadButton.setEnabled(false)` to prevent duplicate concurrent worker threads.
2. **Reveal Progress Bar**: Make `progressBar.setVisible(true)` and set it to indeterminate mode (`progressBar.setIndeterminate(true)`) if total match count is unknown, or determinate mode (`progressBar.setMaximum(total)`) when iterating a fixed collection.
3. **Background Worker Execution**: The `SwingWorker` parses `api.proxy().history()` on a background thread without freezing the Swing Event Dispatch Thread (EDT).
4. **Guaranteed Reset (`finally` block)**: In `SwingWorker.done()`, always re-enable the load button and hide the progress bar inside a `finally` block so the UI never gets stuck in a disabled state if an exception occurs.
5. **Metric Summary on Completion**: Update the status label with loaded and deduplicated counts.

#### 3. Standard Implementation Code

```java
// ─── UI Setup (Inside Panel Constructor) ────────────────────────
JLabel statusLabel = new JLabel("Ready. Click 'Load Proxy History' to begin.");
JProgressBar progressBar = new JProgressBar();
progressBar.setPreferredSize(new Dimension(220, 16));
progressBar.setVisible(false);

JPanel statusRow = new JPanel(new BorderLayout(5, 5));
statusRow.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
statusRow.add(statusLabel, BorderLayout.WEST);
statusRow.add(progressBar, BorderLayout.EAST);
topContainer.add(statusRow);

// ─── Execution & Worker Wire-up ──────────────────────────────────
private void loadProxyHistory() {
    // 1. Debounce and show progress
    loadButton.setEnabled(false);
    progressBar.setVisible(true);
    progressBar.setIndeterminate(true);
    statusLabel.setText("Scanning Proxy history for in-scope traffic...");

    SwingWorker<List<TrafficEntry>, Void> worker = new SwingWorker<>() {
        @Override
        protected List<TrafficEntry> doInBackground() {
            List<TrafficEntry> results = new ArrayList<>();
            List<ProxyHttpRequestResponse> history = api.proxy().history();

            for (ProxyHttpRequestResponse item : history) {
                HttpRequest req = item.finalRequest();
                if (req == null || !api.scope().isInScope(req.url())) {
                    continue;
                }
                // Custom extraction & filtering logic
                results.add(new TrafficEntry(req, item.response()));
            }
            return results;
        }

        @Override
        protected void done() {
            try {
                List<TrafficEntry> entries = get();
                dataStore.setEntries(entries);
                refreshView();
                statusLabel.setText("Loaded " + entries.size() + " items from Proxy history.");
            } catch (Exception ex) {
                api.logging().logToError("Error loading Proxy history: " + ex.getMessage());
                statusLabel.setText("Error loading history: " + ex.getMessage());
            } finally {
                // Guaranteed UI recovery
                loadButton.setEnabled(true);
                progressBar.setVisible(false);
            }
        }
    };
    worker.execute();
}
```

#### 4. Best Practices

- **Determinate Stepping for Massive Datasets:** When operating on very large histories (e.g. >20,000 entries), you can switch from indeterminate to determinate mode by calling `progressBar.setIndeterminate(false)` and publishing progress chunks via `publish()` / `process()` or `setProgress((int) ((i * 100.0) / total))`.
- **Preserve Filter State:** Loading new history should update the backing data store and re-evaluate active toolbar filters without resetting user-selected filter checkboxes or dropdowns.
- **Fail-Safe UI State:** Always wrap `done()` logic in `try-finally` to ensure `progressBar.setVisible(false)` and `loadButton.setEnabled(true)` are executed even when an unhandled exception or cancellation occurs.

---

## Swing Patterns & Layout Reference

### Layout Managers

| Context | Layout | Why |
|---|---|---|
| Root panels | `BorderLayout` | Clean top/center/bottom structure |
| Form sections | `BoxLayout(Y_AXIS)` with `TitledBorder` | Stacked filter groups |
| Toolbar rows | `FlowLayout(FlowLayout.LEFT)` | Horizontal button bars |
| Master-detail | `JSplitPane(VERTICAL_SPLIT)` | Table above, editors below |
| Sidebar + content | `JSplitPane(HORIZONTAL_SPLIT)` | Collapsible filter drawer |
| Tutorial cards | `GridLayout(0, 2, 24, 18)` | Even grid of onboarding tiles |
| Tab close buttons | `FlowLayout(FlowLayout.LEFT, 5, 0)` | Title + x button pair |

### Table Cell Rendering

Override `DefaultTableCellRenderer.getTableCellRendererComponent()` for:
- Status code color coding (2xx/3xx/4xx/5xx)
- Baseline/control row badges for comparison testing
- User-applied highlight colors
- Font weight changes for important rows

### Dialog Patterns

| Dialog | Type | Size |
|---|---|---|
| Options/config | Modeless `JDialog` | `520x260` minimum |
| Probe preview | Modal `JDialog` with `JTextArea` | Monospace font, scrollable |
| Close confirmation | `JOptionPane.showConfirmDialog()` | Standard OK/Cancel |
| Host exclusion | Multi-checkbox list in `JDialog` | Grouped by host |

### Action Buttons with Live Badges

```java
JButton headerBtn = new JButton("Request Headers... (" + count + ")");
// Updates count dynamically as headers are added/removed
```

### Keyboard Shortcuts

```java
int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_C, mask), "copy");
table.getActionMap().put("copy", new AbstractAction() {
    public void actionPerformed(ActionEvent e) {
        // Copy selected rows as TSV to clipboard
    }
});
```

---

## Workflow Methodology

These workflow patterns should be replicated in new extensions.

### 1. One-Click Target Ingestion

**On-Demand Ingestion**
- Extensions analyzing proxy traffic, caching behavior, or discovering endpoints should default to **on-demand user-triggered loading** via a dedicated **`Load Proxy History`** button rather than registering passive `HttpHandler` listeners.
- **Why:** Passive background listeners add CPU/memory overhead, pollute the UI with unrelated traffic, and risk memory exhaustion during long engagements. On-demand ingestion gives testers deterministic control over when snapshots are imported.
- **Background loading & progress feedback:** Always execute history scraping via `SwingWorker` — never block the Swing EDT. Display an auto-hiding `JProgressBar` alongside a dynamic status label during ingestion, and disable the ingestion button on click to prevent concurrent duplicate jobs.
- **Proxy history scraping:**
  - Pull in-scope items from `api.proxy().history()`.
  - Filter by target status codes or content types relevant to the tool's purpose.
  - Exclude unneeded static assets (images, fonts, stylesheets, scripts) by Content-Type and file extension if not relevant to the tool.

### 2. Automatic Deduplication

Before showing candidates, populating UI tables, or sending probes, deduplication collapses thousands of history
items into unique endpoint records:

**Deduplication Strategy:**
- **URL / Endpoint Dedupe Key:** `HTTP Method + " " + URL` (e.g. `GET https://example.com/api/v1/users`).
- **Normalized Shape Key (for Fuzzing/Sweeps):**
  - Scheme + host + port
  - HTTP method
  - Normalized path shape (collapse parameter values into patterns, e.g. `/users/{id}`)
  - Sorted query parameter names
  - Request Content-Type
- **Keyed Data Store:** In-memory stores should use keyed collections (such as `LinkedHashMap<String, Entry>`) to automatically consolidate repeat visits into unique endpoint records and maintain clean insertion order.

**Why:** Without deduplication, visiting `/api/v1/profile` 50 times in a browser creates 50 redundant rows. Deduplication ensures each unique endpoint is analyzed and tested exactly once.

### 3. External Tool Feature Extraction & Integration (Porting Methodology)

Security testers frequently want to extract and integrate features from standalone tools or scripts (e.g., Python tools like **LinkFinder**, **Arjun**, **Param Miner**, **Katana**) into their Burp Suite extensions. Rather than spawning fragile external processes or blindly copying code, follow a structured 3-phase methodology:

#### Phase 1: Deep Tool & Codebase Analysis (Before Asking or Proposing)

Before designing the integration or writing code, thoroughly analyze the target tool's codebase:
1. **Core Algorithms & Regexes:** Identify the exact logic (e.g., regex patterns, tokenizer logic, heuristic algorithms, parameter mutation strategies).
2. **Dependencies & Feasibility:** Map external libraries (e.g., Python `jsbeautifier`, `requests`, `BeautifulSoup`) to lightweight, native Java equivalents (e.g., `java.util.regex`, delimiter splitting, Montoya HTTP utilities) to keep the extension self-contained with zero external runtime dependencies.
3. **Current Extension Overlap:** Determine what the existing Burp extension already extracts and where the external tool fills gaps or provides higher coverage.

#### Phase 2: Mandatory User Consultation (Ask a Series of Targeted Questions)

Once analysis of the external tool is complete, **DO NOT jump straight into writing code or proposing a monolithic plan**. Present a concise summary of what was discovered in the tool and ask the user a tailored series of questions to align on the optimal architecture:

1. **Feature Scope & Extraction Depth:**
   - *"Which specific components or methods from [Tool Name] do you want integrated?"* (e.g., in LinkFinder: all 5 regex arms vs only relative paths vs endpoint context snippets?)
   - *"Should we incorporate the tool's noise-filtering rules, or customize them to avoid false positives in Burp?"*
2. **Data Pipeline & Findings Provenance:**
   - *"Where should the extracted data be displayed?"* (Merged into an existing findings table, or placed into a dedicated new tab/panel?)
   - *"Should findings be tagged with their extraction source?"* (e.g., adding an `Extractor` column or tag like `"ToolName"` vs `"Existing"` so you can distinguish and filter net-new discoveries?)
   - *"How should deduplication be handled?"* (Merge with existing findings, or allow multiple entries if discovered across different files/endpoints?)
3. **Trigger Mechanism & Execution Flow:**
   - *"How should this feature be triggered?"* (Passively on captured proxy traffic, via an on-demand toolbar button, or via a right-click context menu item?)
4. **Performance & Preprocessing Trade-offs:**
   - *"How should large or minified inputs be handled?"* (e.g., lightweight delimiter splitting `;` / `,` vs heavy full-file beautification to prevent Event Dispatch Thread freezes?)
5. **UI & Filter Controls:**
   - *"Do you need new UI controls for the integrated data?"* (e.g., dedicated filter dropdowns by extractor, status codes, search filters, or clipboard/TSV export?)

#### Phase 3: Native Porting & Architecture Alignment

When the user confirms their requirements:
- **Pure Java Implementation:** Port the core algorithms directly into Java using standard library utilities. Avoid external process invocations (`ProcessBuilder` running Python scripts) which break cross-platform portability.
- **Provenance in Data Model:** Add an `extractor` attribute to the record/model (e.g., `record DiscoveredEndpoint(..., String extractor)`) so the UI and filters can distinguish data sources.
- **Zero-Freeze Concurrency:** Execute all extraction and parsing in background worker threads (`SwingWorker` or executor pools), never on the Swing Event Dispatch Thread (EDT).
- **Graceful Fallbacks & Noise Control:** Implement noise filters for false positives (pure numeric tokens, static asset extensions, CSS selectors) common in raw regex extraction.

---

## Results Presentation & Filtering

### Dynamic Multi-Layout Tables

`ResultsTableModel` supports **multiple distinct table layouts**, switching columns and
extraction logic based on the active tool:

| Layout | Key Columns |
|---|---|
| `PRIMARY` | Technique, Payload, Status, Length, Content-Type |
| `COMPARISON` | Variant Label, Playbook, Status, Length, Content-Type |
| `VALIDATION` | Payload, Encoding, Category, Status, Length |
| `SWEEP` | Method, URL, Status, Length, Content-Type, Signal |

**Dual result storage:**
- `allResults` — complete, unfiltered history (never deleted)
- `results` — currently visible filtered rows

This allows instant re-filtering without data loss.

**Stable result IDs:** Monotonically increasing integer IDs via
`Map<AttackResult, Integer>` so row identities persist across sort and filter operations.

### Signal Column

The `Signal` column (Sweep mode) shows only concrete interesting changes:

```
403 -> 200              (status code flip — likely bypass)
401 -> 302              (redirect to different location)
Content-Type text/html -> application/json   (parser switch)
Length +347             (significant body size change)
LIKELY PUBLIC           (endpoint accessible without auth)
UNAUTHENTICATED ACCESS  (anonymous blocked, probe succeeded)
BYPASS?                 (3-response: auth 200 -> anon 403 -> probe 200)
```

Probe responses with `4xx` status codes are shown but **not** marked with a signal. This
suppresses the noise of error pages.

### Smart Filter (Auto Pattern Suppression)

Based on a common heuristic approach for suppressing repetitive noise:

1. Generate a fingerprint for each result: `statusCode + contentLength + contentType`.
2. Track occurrence count per fingerprint.
3. Show only the first N occurrences (default N=1) of each pattern.
4. Automatically hides hundreds of identical "403 Forbidden" responses while guaranteeing
   zero missed unique responses.

### Manual Filter (Granular Rule Engine)

Multi-dimensional sequential match pipeline:

1. Hidden status codes (blacklist, e.g., `404,403,500`)
2. Shown status codes (whitelist, e.g., `200,302`)
3. Min / Max content length boundaries
4. Hidden / Shown content length sets
5. Content-Type substring match (case-insensitive)
6. Host substring match
7. Payload substring match
8. Signal text match (literal or regex with `Pattern.CASE_INSENSITIVE | Pattern.DOTALL`)
9. Response body text match (literal or regex)
10. Highlight color filter

### Standard Triage Filters (Status Code, Content-Type, Scope & Directives)

Every extension presenting discovered endpoints, cache directives, or fuzzing results MUST incorporate standard rapid-triage toolbar filters:

- **Status Code Dropdown (`JComboBox<String>` with `setEditable(true)`):**
  - Provides quick presets: `All Status Codes`, `2xx Success`, `200 OK`, `3xx Redirection`, `301 / 302 Redirect`, `304 Not Modified`, `4xx Client Error`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `5xx Server Error`, `500 Internal Error`.
  - Supports direct user typing for custom codes or comma-separated lists (e.g., `429, 503`, `200, 302`).
- **Content-Type Dropdown (`JComboBox<String>` with `setEditable(true)`):**
  - Provides quick presets: `All Content-Types`, `HTML (text/html)`, `JSON (application/json)`, `JavaScript (text/javascript)`, `CSS (text/css)`, `XML (application/xml)`, `Plain Text (text/plain)`, `Images (image/*)`, `PDF / Documents (application/pdf)`.
  - Supports direct user typing for custom MIME types (e.g., `application/graphql`, `text/event-stream`).
- **In-Scope Toggle**: Immediate filter evaluation against `api.scope().isInScope(url)`.
- **Directive / Attribute Chips & Search**: Free-form text filter and quick-preset buttons (e.g. `no-store`, `unsafe-inline`, `HIT`, `MISS`, `(not set)`) to instantly highlight interesting directives.
- **Reset Filters**: One-click button (`Reset Filters`) clearing all text fields, resetting dropdowns to index 0, and restoring the full unconstrained view.

### Visual Status Badging

Custom `DefaultTableCellRenderer` provides:

- **HTTP status colors:** 2xx green, 3xx blue, 4xx orange, 5xx red
- **Comparison badges:** Control `(46, 86, 132)`, Baseline `(122, 88, 32)`
- **Success highlight:** `(108, 214, 152)` green for confirmed findings
- **User highlights:** 8 standard triage colors (Red, Orange, Yellow, Green, Blue, Cyan,
  Magenta, Gray)
- Right-click context menu to color any row for identification/filtering

### Clipboard TSV Export

`Ctrl+C` / `Cmd+C` copies selected rows as tab-separated values to system clipboard.
Implemented via Action Map binding with `menuShortcutMask()` for cross-platform support.

---

## Threading & Performance

### Zero-Freeze UI Rule

**Never block the EDT (Event Dispatch Thread).** Every expensive operation runs on a
background thread or `SwingWorker`:

| Operation | Thread Strategy |
|---|---|
| Proxy history scraping | `SwingWorker` (background loader) |
| Probe generation | `SwingWorker` (preparation worker) |
| Remote OpenAPI download | `SwingWorker` (remote import worker) |
| Probe preview rendering | `SwingWorker` (preview worker) |
| Attack execution | Dedicated daemon thread + thread pool |
| Playbook execution | Dedicated runner thread |
| Throttle retries | `SwingWorker<Void, RetryOutcome>` |

### EDT Dispatching

All UI updates go through `SwingUtilities.invokeLater()`:

```java
// From worker thread:
SwingUtilities.invokeLater(() -> {
    tableModel.addResult(result);
    statusLabel.setText("Running: " + count + " results");
});
```

### Synchronized Table Models

`ResultsTableModel` synchronizes every read and write method:

```java
public synchronized void addResult(AttackResult result) { ... }
public synchronized Object getValueAt(int row, int col) { ... }
public synchronized void applyFilter(ResponseFilter filter) { ... }
```

This eliminates race conditions between worker thread streaming and Swing table
sorting/filtering.

### Generation Tokens for Retry Races

`ResultsWorkspace` uses `queueGeneration` tokens to prevent race conditions when
multiple retry passes overlap. Each retry batch stamps its generation; stale results from
prior generations are ignored.

### Multi-Threaded Ingestion Pool & Concurrent History Analysis

When processing large volumes of historical HTTP traffic (such as Burp's Proxy HTTP history with thousands of messages), a single-threaded loop introduces noticeable latency. Adopting a bounded worker pool guarantees maximum CPU utilization while maintaining a responsive, zero-freeze UI:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       SwingWorker Coordinator (EDT)                     │
│               Controls JProgressBar & Dispatches Status Chunks          │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                    Submits tasks to Bounded Executor
                                     │
                                     ▼
        ┌─────────────────────────────────────────────────────────┐
        │  Fixed Thread Pool: min(8, max(2, availableProcessors)) │
        │      Worker 1      Worker 2      ...      Worker N      │
        └────────────────────────────┬────────────────────────────┘
                                     │
           Atomic Counters: processed.incrementAndGet()
                            findingsCount.addAndGet(n)
                                     │
                                     ▼
        ┌─────────────────────────────────────────────────────────┐
        │  Pre-Filtering Guard (Bypass before regex or parsing):  │
        │  1. MIME-Type Blacklist (images, audio, video, fonts)   │
        │  2. Response Size Ceiling (skip bodies > 10MB)          │
        │  3. Null/Empty Response Body Guard                      │
        └─────────────────────────────────────────────────────────┘
```

#### Key Implementation Pillars:

1. **Bounded Thread Pool Sizing**:
   Use `Executors.newFixedThreadPool(threads)` where:
   `int threads = Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()));`
   Never spawn unbounded thread pools which exhaust Burp Suite's JVM heap during large project imports.

2. **Atomic Progress & Chunked EDT Dispatching**:
   Use `AtomicInteger processed = new AtomicInteger(0)` and `AtomicInteger findingsCount = new AtomicInteger(0)`.
   Do **not** invoke `SwingUtilities.invokeLater()` on every single processed message, as 10,000 rapid calls will congest the Event Dispatch Thread (EDT). Instead, publish batches or throttle progress dispatches (e.g. every 50ms or every 25 items):
   ```java
   int current = processed.incrementAndGet();
   if (current % 25 == 0 || current == total) {
       publish(new ProgressStatus(current, total, findingsCount.get()));
   }
   ```

3. **Pre-Filtering Early Exit Guard**:
   Skip expensive regex matching and UTF-8 string conversions for irrelevant messages:
   - **MIME Blacklisting**: Inspect `response.statedMimeType()` / `inferredMimeType()`. Skip non-textual assets (`IMAGE_*`, `VIDEO`, `SOUND`, `FONT_*`, `APPLICATION_FLASH`).
   - **Size Guard**: Skip bodies larger than 10MB (`response.body().length() > 10 * 1024 * 1024`) to prevent catastrophic backtracking and heap spikes.
   - **Empty Response Guard**: Bypass if `response == null` or response body is empty.

4. **Cooperative Cancellation**:
   Maintain a `volatile boolean interruptScan` or rely on `SwingWorker.isCancelled()`. On user cancellation or tab unload, trigger `executor.shutdownNow()` and immediately restore UI controls.

5. **Thread-Safe Deduplication & Data Stores**:
   Underlying finding storage must utilize thread-safe collections (`ConcurrentHashMap`, atomic counter IDs, or synchronized data stores) so concurrent worker threads can insert findings simultaneously without race conditions.

---


## User Controls & Rate Limiting

### Cooperative Pause / Resume

`PauseController` provides non-blocking worker thread gating:

- Uses `wait()` / `notifyAll()` synchronized monitors.
- `awaitIfPaused(BooleanSupplier shouldContinue)` checks run/abort predicates inside the
  wait loop — prevents deadlocks when user clicks "Stop" while paused.
- In-flight requests finish naturally. No socket interruptions.
- Resume after 30+ seconds cold-starts each host at the safe initial adaptive rate.

### Adaptive Rate Control

Per-host adaptive controller (one per `scheme://host:port`):

1. **Slow start** — Begin with a conservative rate.
2. **Ramp up** — Increase until the first throttle reveals the ceiling.
3. **Converge** — Hold just below the ceiling. Gentle backoff on throttle, probe upward.
4. **Auto-retry** — Throttled requests are re-queued, never dropped. Coverage stays 100%.
5. **Honor Retry-After** — Server-provided values are respected as hard pauses.
6. **Parallel hosts** — All hosts swept concurrently, each at its own discovered speed.

### Pacing Postures

| Posture | Behavior |
|---|---|
| **Aggressive** (default) | Drive right at the rate limit ceiling. Max throughput. Auto-retry throttled. |
| **Conservative** | Wide safety buffer below the ceiling. Fewer blocked requests. |

### Pause Modes (for Sweep-wide CDN/WAF protection)

| Mode | Behavior |
|---|---|
| **No global pause** | Per-host adaptive backoff only (default). |
| **Fixed pause** | Stop all hosts for N seconds on any throttle code. |
| **Smart Pause** | Escalating cooldowns (10s to 20s to 40s to 80s to 120s). Tolerates isolated throttles. Pauses sweep-wide only when throttles span multiple hosts (shared CDN/WAF). Requires 5 consecutive successful recovery probes before reopening. |

### Throttle Settings UI

`ThrottleSettingsPanel` — Reusable button that opens a modeless `JDialog`:
- Concurrency (global + per-host)
- Throttle status codes (default: `429, 503`)
- Fixed pause duration
- Smart Pause toggle
- Explanatory `JTextArea` instructions inside the dialog

### Throttle Retry Queue

`ResultsWorkspace` captures all `429` and `503` responses into a retry queue:
- **Canary-based classification** before retrying: sends an unmodified control request to
  distinguish transient rate limits from stable WAF pattern-blocks.
- Quarantines permanently pattern-blocked requests to prevent infinite loops.
- Prompts user confirmation before retrying state-changing methods (POST, PUT, DELETE, PATCH).
- 3-pass automatic drain with exponential backoff.
- Export throttled requests to JSON packages or wordlists for offline re-testing.

---
