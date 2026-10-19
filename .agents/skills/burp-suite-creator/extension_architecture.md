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
  - [Tab Hierarchy (Multi-Session Model)](#tab-hierarchy-multi-session-model)
  - [Tab Naming Convention & Double-Click In-Place Header Renaming (No Popups)](#tab-naming-convention--double-click-in-place-header-renaming-no-popups)
  - [Persistent Session Storage & State Recovery (Across Restarts)](#persistent-session-storage--state-recovery-across-restarts)
  - [Core Toolbar Triage Filters (Status Code, Method, In-Scope, Domain)](#core-toolbar-triage-filters-status-code-method-in-scope-domain)
  - [Universal Table Column Sorting & Right-Aligned In-Cell Copy Actions](#universal-table-column-sorting--right-aligned-in-cell-copy-actions)
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
- Tab title follows a strict default naming convention: `#<ID> <METHOD> <truncated_path>` (e.g., `#1 GET /api/v1/users`).
- Double-clicking the tab title opens an inline text field directly in the tab header to rename the tab in-place with zero modal popups.
- Close button prompts `JOptionPane.showConfirmDialog()` for user confirmation if a test is running.

**Why this matters:** Most extensions create a single tab. Supporting multiple concurrent
sessions — each with its own request, results, and controls — gives the tester
dramatically better workflow. They can run tests on one endpoint while sweeping another.

### Tab Naming Convention & Double-Click In-Place Header Renaming (No Popups)

Burp extensions supporting dynamic multi-session testing (e.g. sending requests from Proxy History, Repeater, Logger, or Scanner into dedicated testing/fuzzing/auditing tabs) must provide a predictable default naming convention and seamless in-place tab renaming.

#### 1. Default Tab Naming Convention When Sending to Extension

Whenever a user sends an HTTP request or traffic item to create a new session tab:

- **Structured Default Name**: Always assign a clean, structured name:
  `#<ID> <METHOD> <truncated_path>`
  - Examples: `#1 GET /api/v1/users`, `#2 POST /login`, `#3 PUT /profile/avatar`
- **Auto-Incrementing Session Counter**: Maintain an atomic session counter (`AtomicInteger sessionCounter = new AtomicInteger(1)`) so every newly dispatched session tab receives a distinct, sequential ID. This allows testers to instantly distinguish between multiple requests sent to identical endpoints (e.g., `#1 POST /api/checkout` vs `#2 POST /api/checkout`).
- **Clean Path Truncation**: Truncate long URLs or endpoint paths to 20-25 characters with trailing ellipsis (`...`) so the tab bar remains compact, avoiding horizontal tab overflow.
- **Detailed Tooltip**: Always assign the full, untruncated HTTP method, host, and path as the tab's tooltip via `tabbedPane.setToolTipTextAt(index, fullEndpointDescription)`.
- **Zero Emojis**: Tab titles, prefixes, and status badges must use plain ASCII text only (e.g., `[Running]`, `[Done]`, `[Alert]`). Never use emojis or decorative unicode symbols.

#### 2. Double-Click In-Place Header Renaming (Zero Modal Popups)

Testers frequently need to customize session tab names to reflect their specific test context (e.g. `admin-bypass`, `idor-user2`, `sqli-probe`).

- **Strict Popup Prohibition**: Never open a modal dialog or popup (`JOptionPane.showInputDialog`, floating dialogs, or prompt windows) when a user wants to rename a tab. Modal popups steal focus, disrupt workflow, and require unnecessary mouse clicks.
- **In-Place Tab Header Editing**: When the user double-clicks the tab title label, the tab header must switch directly into an inline editing mode inside the tab bar itself, mirroring native Burp Suite tab editing (such as in Repeater).
- **Interactive Controls**:
  - **Double-Click Activation**: Double-clicking the `JLabel` title triggers edit mode, swapping the label with an active `JTextField`.
  - **Auto-Focus & Text Selection**: The text field immediately requests focus (`requestFocusInWindow()`) and pre-selects its content (`selectAll()`).
  - **Commit on Enter**: Pressing `Enter` commits the new title, updates `titleLabel.setText(newTitle)`, updates `tabbedPane.setTitleAt(tabIndex, newTitle)`, and switches back to the label view.
  - **Cancel on Escape**: Pressing `Escape` cancels editing without modifying the tab title and restores the label view.
  - **Focus-Lost Auto-Commit**: Clicking outside or switching away automatically commits the edit gracefully and returns to the label view.
  - **Persistent Close Action**: The close button (`x`) remains present and functional in the tab header throughout editing.

#### 3. Complete Swing Implementation Pattern

```java
// --- 1. Inline Editable Tab Header Component (Zero Popups) ---------
public class EditableTabHeader extends JPanel {
    private final JTabbedPane tabbedPane;
    private final Component tabContent;
    private final JLabel titleLabel;
    private final JTextField editField;
    private final JButton closeButton;
    private boolean isEditing = false;

    public EditableTabHeader(JTabbedPane tabbedPane, Component tabContent, String defaultTitle) {
        super(new FlowLayout(FlowLayout.LEFT, 4, 0));
        setOpaque(false);
        this.tabbedPane = tabbedPane;
        this.tabContent = tabContent;

        // Display label
        this.titleLabel = new JLabel(defaultTitle);
        this.titleLabel.setToolTipText("Double-click to rename tab");

        // Inline text field editor (hidden until double-click)
        this.editField = new JTextField();
        this.editField.setVisible(false);
        this.editField.setFont(titleLabel.getFont());
        this.editField.setColumns(Math.max(10, defaultTitle.length()));

        // Double-click to initiate inline editing
        this.titleLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    startEditing();
                }
            }
        });

        // Key bindings: Enter to commit, Escape to cancel
        this.editField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    commitEditing();
                } else if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                    cancelEditing();
                }
            }
        });

        // Commit on focus loss
        this.editField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                if (isEditing) {
                    commitEditing();
                }
            }
        });

        // Close button (plain ASCII 'x')
        this.closeButton = new JButton("x");
        this.closeButton.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 2));
        this.closeButton.setContentAreaFilled(false);
        this.closeButton.setFocusable(false);
        this.closeButton.setToolTipText("Close tab");
        this.closeButton.addActionListener(e -> {
            int idx = tabbedPane.indexOfComponent(tabContent);
            if (idx != -1) {
                tabbedPane.removeTabAt(idx);
            }
        });

        add(titleLabel);
        add(editField);
        add(closeButton);
    }

    private void startEditing() {
        isEditing = true;
        editField.setText(titleLabel.getText());
        editField.setColumns(Math.max(8, titleLabel.getText().length()));
        titleLabel.setVisible(false);
        editField.setVisible(true);
        revalidate();
        editField.requestFocusInWindow();
        editField.selectAll();
    }

    private void commitEditing() {
        if (!isEditing) return;
        isEditing = false;
        String newTitle = editField.getText().trim();
        if (!newTitle.isEmpty()) {
            titleLabel.setText(newTitle);
            int idx = tabbedPane.indexOfComponent(tabContent);
            if (idx != -1) {
                tabbedPane.setTitleAt(idx, newTitle);
            }
        }
        editField.setVisible(false);
        titleLabel.setVisible(true);
        revalidate();
        repaint();
    }

    private void cancelEditing() {
        if (!isEditing) return;
        isEditing = false;
        editField.setVisible(false);
        titleLabel.setVisible(true);
        revalidate();
        repaint();
    }

    public void updateTitle(String text) {
        titleLabel.setText(text);
        int idx = tabbedPane.indexOfComponent(tabContent);
        if (idx != -1) {
            tabbedPane.setTitleAt(idx, text);
        }
    }

    public String getTitle() {
        return titleLabel.getText();
    }
}

// --- 2. Dispatching Session Tab with Default Naming & Inline Header -
public class SessionTabManager {
    private final JTabbedPane rootTabbedPane;
    private final AtomicInteger sessionCounter = new AtomicInteger(1);

    public SessionTabManager(JTabbedPane rootTabbedPane) {
        this.rootTabbedPane = rootTabbedPane;
    }

    public void addSessionTab(String method, String path, JPanel sessionContent) {
        // Step 1: Apply default naming convention: #<ID> <METHOD> <truncated_path>
        int sessionId = sessionCounter.getAndIncrement();
        String truncatedPath = path.length() > 22 ? path.substring(0, 19) + "..." : path;
        String defaultTitle = "#" + sessionId + " " + method.toUpperCase() + " " + truncatedPath;

        int index = rootTabbedPane.getTabCount();
        rootTabbedPane.addTab(defaultTitle, sessionContent);

        // Step 2: Attach inline editable tab header (zero popups)
        EditableTabHeader tabHeader = new EditableTabHeader(rootTabbedPane, sessionContent, defaultTitle);
        rootTabbedPane.setTabComponentAt(index, tabHeader);
        rootTabbedPane.setToolTipTextAt(index, method.toUpperCase() + " " + path);
        rootTabbedPane.setSelectedIndex(index);
    }

    // Step 3: Status update without emojis (plain ASCII text tags)
    public void setSessionStatus(Component sessionContent, String statusTag) {
        int idx = rootTabbedPane.indexOfComponent(sessionContent);
        if (idx != -1 && rootTabbedPane.getTabComponentAt(idx) instanceof EditableTabHeader header) {
            String currentTitle = header.getTitle();
            // Remove previous tag if present, then prepend new ASCII status tag
            String cleanTitle = currentTitle.replaceAll("\\[.*?\\]", "").trim();
            header.updateTitle("[" + statusTag + "] " + cleanTitle);
        }
    }
}
```

### Persistent Session Storage & State Recovery (Across Restarts)

Every Burp Suite extension must provide robust session storage capabilities so testers can pause and resume their work, preserve historical findings, retain custom tabs, baselines, and configuration data, and continue seamlessly across testing sessions.

#### 1. Core Architecture Principles

1. **Mandatory Session Storage for Every Extension**:
   - All extensions that collect findings, manage session tabs, store injected payloads, or maintain test results must implement persistent session storage.
   - Testers must be able to preserve their complete testing context and continue with their data whenever they choose.

2. **Explicit User Decision on Load (Strictly No Auto-Load by Default)**:
   - **Never Load Silently by Default**: When the extension is loaded or reloaded into Burp Suite, it must **never** automatically or silently load a previous session file or create a file without user intervention.
   - **User Choice on Startup**: The user must explicitly decide what to do every time the extension loads.
   - Upon extension initialization, the extension displays an interactive modal startup prompt on the Swing EDT (`SwingUtilities.invokeLater`) asking how the user wishes to proceed:
     - **Open Previous Session File**: Opens a file chooser dialog (`JFileChooser`) allowing the tester to select an existing session JSON file from disk to restore tabs, findings, baselines, and settings.
     - **Create New Session File**: Prompts the user to specify the target directory (via `JFileChooser` set to `DIRECTORIES_ONLY`) and enter the session filename. The new session workspace is initialized and bound to that destination.
     - **Start Temporary Session (Decide Later)**: Starts with a clean, in-memory workspace without binding to a file immediately. The user can bind, save, or export a session file at any time later from the toolbar.

3. **Explicit Directory Selection for New Sessions**:
   - When creating a new session file, the user must explicitly specify the directory.
   - The extension must never write session files into arbitrary, hidden, or unexpected system folders.
   - Previously selected directories may be remembered in Montoya preferences (`api.persistence().preferences().setString(...)`) strictly as the default starting directory in the file chooser dialog, but never used to silently auto-load data.

4. **Toolbar Session Management Controls**:
   - The top toolbar of the extension must display persistent session controls:
     - **Active Session Indicator**: Displays the current session file path or `[Temporary / In-Memory]`.
     - **[New Session]**: Allows creating a new session file (prompting for save confirmation if dirty, then prompting for directory and filename).
     - **[Open Session]**: Opens an existing session file via `JFileChooser`.
     - **[Save As...]**: Exports or binds the current session to a new file location.
     - **[Save Now]**: Immediately flushes in-memory data to the bound session file synchronously.

5. **Debounced Atomic Auto-Save Engine**:
   - Never block the Swing Event Dispatch Thread (EDT) or trigger heavy disk I/O on every table event.
   - When a session file is bound, auto-save state changes using a single-threaded daemon `ScheduledExecutorService` with a 1500-2000ms debounce delay.
   - Always write data to a temporary file (`<filename>.tmp`) first, then commit via atomic replacement (`StandardCopyOption.ATOMIC_MOVE` with fallback to `REPLACE_EXISTING`) to guarantee zero file corruption.

6. **High-Fidelity HTTP Message Serialization**:
   - Montoya API `HttpRequest` and `HttpResponse` objects cannot be blindly serialized directly by standard reflection serializers.
   - Convert raw message bytes to Base64 (`Base64.getEncoder().encodeToString(req.toByteArray().getBytes())`).
   - Store the associated `HttpService` metadata (host, port, and secure boolean) alongside the Base64 payload.
   - On deserialization, rebuild exact byte-accurate messages using `HttpRequest.httpRequest(service, ByteArray.byteArray(bytes))` and `HttpResponse.httpResponse(ByteArray.byteArray(bytes))`.

7. **Lifecycle Unloading Hook**:
   - Register `api.extension().registerUnloadingHandler(...)` to perform an immediate synchronous save (`saveSync`) before Burp unloads the extension, but only if an active session file is bound.
   - Release background executor threads cleanly on unload.

#### 2. Implementation Pattern: Startup Session Chooser Dialog

Display this dialog on the Swing EDT during extension initialization. Never load any session file prior to the user making an explicit choice:

```java
// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.common.session;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;

public class SessionStartupDialog {

    public enum StartupAction {
        OPEN_EXISTING,
        CREATE_NEW,
        TEMPORARY
    }

    public record StartupResult(StartupAction action, File sessionFile) {}

    public static StartupResult promptUser(MontoyaApi api, Component parent) {
        String lastDir = api.persistence().preferences().getString("extension_last_session_dir");
        File defaultDir = (lastDir != null && !lastDir.isBlank()) ? new File(lastDir) : new File(System.getProperty("user.home"));

        String[] options = {"Open Previous Session", "Create New Session", "Start Temporary Session"};
        int choice = JOptionPane.showOptionDialog(
            parent,
            "Select how you would like to initialize your session:\n\n" +
            "- Open Previous Session: Load saved results, tabs, and configurations from disk.\n" +
            "- Create New Session: Specify a directory to store and auto-save new session data.\n" +
            "- Start Temporary Session: Work in-memory without binding to a file.\n",
            "Extension Session Storage Initialization",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            null,
            options,
            options[0]
        );

        if (choice == 0) {
            // Option 1: Open Previous Session
            JFileChooser chooser = new JFileChooser(defaultDir);
            chooser.setDialogTitle("Select Existing Session File to Open");
            chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
            int fileRes = chooser.showOpenDialog(parent);
            if (fileRes == JFileChooser.APPROVE_OPTION) {
                File selected = chooser.getSelectedFile();
                api.persistence().preferences().setString("extension_last_session_dir", selected.getParent());
                return new StartupResult(StartupAction.OPEN_EXISTING, selected);
            }
        } else if (choice == 1) {
            // Option 2: Create New Session - User must specify the directory
            JFileChooser dirChooser = new JFileChooser(defaultDir);
            dirChooser.setDialogTitle("Select Directory For New Session File");
            dirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int dirRes = dirChooser.showOpenDialog(parent);
            if (dirRes == JFileChooser.APPROVE_OPTION) {
                File chosenDir = dirChooser.getSelectedFile();
                api.persistence().preferences().setString("extension_last_session_dir", chosenDir.getAbsolutePath());

                String fileName = JOptionPane.showInputDialog(
                    parent,
                    "Enter filename for the new session:",
                    "session_data.json"
                );

                if (fileName != null && !fileName.isBlank()) {
                    if (!fileName.toLowerCase().endsWith(".json")) {
                        fileName = fileName + ".json";
                    }
                    File newFile = new File(chosenDir, fileName);
                    return new StartupResult(StartupAction.CREATE_NEW, newFile);
                }
            }
        }

        // Option 3 or cancelled dialog: Start Temporary Session
        return new StartupResult(StartupAction.TEMPORARY, null);
    }
}
```

#### 3. Implementation Pattern: SessionManager & Toolbar Integration

```java
// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.common.session;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class SessionManager {
    private final MontoyaApi api;
    private final SessionPersistenceCallback callback;
    private final ScheduledExecutorService autoSaveExecutor;
    private final JLabel sessionStatusLabel;

    private File activeSessionFile;
    private ScheduledFuture<?> pendingSaveTask;
    private boolean isDirty = false;

    public interface SessionPersistenceCallback {
        String serializeSessionToJson();
        void deserializeSessionFromJson(String json);
        void resetSessionState();
    }

    public SessionManager(MontoyaApi api, SessionPersistenceCallback callback) {
        this.api = api;
        this.callback = callback;
        this.sessionStatusLabel = new JLabel("Session: [Temporary / In-Memory]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        this.autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "Extension-Session-AutoSave-Thread");
            t.setDaemon(true);
            return t;
        });

        // Register unload handler for final synchronous flush
        api.extension().registerUnloadingHandler(this::handleUnload);
    }

    public void initializeOnStartup(Component parent) {
        SessionStartupDialog.StartupResult result = SessionStartupDialog.promptUser(api, parent);
        switch (result.action()) {
            case OPEN_EXISTING -> openSessionFile(result.sessionFile());
            case CREATE_NEW -> createNewSessionFile(result.sessionFile());
            case TEMPORARY -> startTemporarySession();
        }
    }

    public synchronized void markDirty() {
        this.isDirty = true;
        if (activeSessionFile == null) return;

        if (pendingSaveTask != null && !pendingSaveTask.isDone()) {
            pendingSaveTask.cancel(false);
        }
        pendingSaveTask = autoSaveExecutor.schedule(this::saveSync, 1500, TimeUnit.MILLISECONDS);
    }

    public synchronized void saveSync() {
        if (activeSessionFile == null || !isDirty) return;
        try {
            String json = callback.serializeSessionToJson();
            File tempFile = new File(activeSessionFile.getAbsolutePath() + ".tmp");
            Files.writeString(tempFile.toPath(), json);
            try {
                Files.move(tempFile.toPath(), activeSessionFile.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception e) {
                Files.move(tempFile.toPath(), activeSessionFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
            isDirty = false;
        } catch (Exception ex) {
            api.logging().logToError("Failed to save session to " + activeSessionFile.getAbsolutePath() + ": " + ex.getMessage());
        }
    }

    public void openSessionFile(File file) {
        if (file == null || !file.exists()) return;
        try {
            String json = Files.readString(file.toPath());
            callback.deserializeSessionFromJson(json);
            this.activeSessionFile = file;
            this.isDirty = false;
            updateStatusLabel();
            api.logging().logToOutput("Session successfully loaded: " + file.getAbsolutePath());
        } catch (Exception ex) {
            api.logging().logToError("Failed to load session from " + file.getAbsolutePath() + ": " + ex.getMessage());
            JOptionPane.showMessageDialog(null, "Error loading session file:\n" + ex.getMessage(), "Session Load Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public void createNewSessionFile(File file) {
        if (file == null) return;
        callback.resetSessionState();
        this.activeSessionFile = file;
        this.isDirty = true;
        saveSync();
        updateStatusLabel();
        api.logging().logToOutput("New session created and bound: " + file.getAbsolutePath());
    }

    public void startTemporarySession() {
        callback.resetSessionState();
        this.activeSessionFile = null;
        this.isDirty = false;
        updateStatusLabel();
        api.logging().logToOutput("Temporary in-memory session started.");
    }

    private void updateStatusLabel() {
        SwingUtilities.invokeLater(() -> {
            if (activeSessionFile != null) {
                sessionStatusLabel.setText("Session: " + activeSessionFile.getName() + " (" + activeSessionFile.getParent() + ")");
                sessionStatusLabel.setToolTipText(activeSessionFile.getAbsolutePath());
            } else {
                sessionStatusLabel.setText("Session: [Temporary / In-Memory]");
                sessionStatusLabel.setToolTipText("Data is currently in-memory. Use 'Save As...' to bind to a file.");
            }
        });
    }

    public JPanel createSessionToolbarComponent(Component parent) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        JButton newBtn = new JButton("New Session");
        newBtn.addActionListener(e -> {
            if (isDirty && activeSessionFile != null) {
                int res = JOptionPane.showConfirmDialog(parent, "Save current session before creating a new one?", "Unsaved Changes", JOptionPane.YES_NO_CANCEL_OPTION);
                if (res == JOptionPane.YES_OPTION) saveSync();
                else if (res == JOptionPane.CANCEL_OPTION) return;
            }

            JFileChooser dirChooser = new JFileChooser(getLastDirectory());
            dirChooser.setDialogTitle("Select Directory For New Session");
            dirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (dirChooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION) {
                File dir = dirChooser.getSelectedFile();
                api.persistence().preferences().setString("extension_last_session_dir", dir.getAbsolutePath());
                String name = JOptionPane.showInputDialog(parent, "Enter session filename:", "session.json");
                if (name != null && !name.isBlank()) {
                    if (!name.toLowerCase().endsWith(".json")) name += ".json";
                    createNewSessionFile(new File(dir, name));
                }
            }
        });

        JButton openBtn = new JButton("Open Session");
        openBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser(getLastDirectory());
            chooser.setDialogTitle("Select Session File to Open");
            chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
            if (chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION) {
                File sel = chooser.getSelectedFile();
                api.persistence().preferences().setString("extension_last_session_dir", sel.getParent());
                openSessionFile(sel);
            }
        });

        JButton saveAsBtn = new JButton("Save As...");
        saveAsBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser(getLastDirectory());
            chooser.setDialogTitle("Save Session As");
            chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
            if (chooser.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION) {
                File sel = chooser.getSelectedFile();
                if (!sel.getName().toLowerCase().endsWith(".json")) {
                    sel = new File(sel.getParentFile(), sel.getName() + ".json");
                }
                this.activeSessionFile = sel;
                this.isDirty = true;
                saveSync();
                updateStatusLabel();
            }
        });

        panel.add(sessionStatusLabel);
        panel.add(newBtn);
        panel.add(openBtn);
        panel.add(saveAsBtn);
        return panel;
    }

    private File getLastDirectory() {
        String lastDir = api.persistence().preferences().getString("extension_last_session_dir");
        if (lastDir != null && !lastDir.isBlank()) {
            File dir = new File(lastDir);
            if (dir.exists()) return dir;
        }
        return new File(System.getProperty("user.home"));
    }

    private void handleUnload() {
        if (activeSessionFile != null && isDirty) {
            saveSync();
        }
        autoSaveExecutor.shutdownNow();
    }
}
```

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

### Universal Table Column Sorting & Right-Aligned In-Cell Copy Actions

In Burp Suite security workflows, tables (such as HTTP Proxy history, Logger, and Intruder results) serve as the primary triage workbench for testers. Any table displayed by an extension must strictly adhere to Burp Suite's native table architecture standards:

#### 1. Mandatory Universal Column Sorting (HTTP Proxy History Standard)
- **Always Sortable**: Whenever there is a column in any extension table (candidate endpoints, findings, logs, parameters, headers, or sweep results), **every column must always be interactive and sortable**, exactly mirroring the sorting behavior in Burp Suite's HTTP Proxy History.
- **Bi-Directional Header Clicking**: Clicking a column header must cycle through ascending sort, descending sort, and restoration of natural order.
- **Accurate Type-Aware Ordering**: Columns must sort by their underlying semantic data type rather than raw string representations:
  - Numeric columns (request index `#`, HTTP status code, response length, timing/latency) must sort strictly numerically (`20` before `100`), not lexicographically (`100` before `20`).
  - String columns (Method, Host, Path, MIME type) sort lexicographically (case-insensitive).
  - Date/Timestamp columns sort chronologically.
- **Live Stream Stability**: As background workers stream new traffic or findings into the table, active sort ordering must be preserved automatically (`sorter.setSortsOnUpdates(true)`).
- **Index Translation**: Every row access for detail views, selection listeners, and right-click context menus must convert view row indices to model row indices via `table.convertRowIndexToModel(viewRow)`.

#### 2. In-Cell Column Copy Button Placement (Right Side Column Border Edge)
- **Positioned on Right Border Edge**: Whenever an in-cell copy action or button is used within a column (e.g. copying a full URL, endpoint path, secret token, header value, or cell excerpt), the copy symbol/trigger **must always be positioned on the right side of the column border edge**.
- **Edge Alignment & Padding**: The copy trigger must be pinned flush against the right margin (`BorderLayout.EAST` in the cell layout) with a small, clean padding (e.g., 2 to 4 pixels) from the column border divider line. The primary cell text occupies the center/west region and truncates cleanly so text never collides with or hides behind the copy symbol.
- **Direct Clipboard Interaction**: Clicking the right-aligned copy trigger immediately copies the cell's raw string or target value to the system clipboard and provides immediate visual feedback (e.g., status bar label update: `"Copied: <value>"`).
- **Preserve Row Selection**: Triggering the copy action should not inadvertently break row selection or cause erratic editor focus changes.

#### 3. Strict Emoji Prohibition (No Emojis Rule)
- **Zero Emojis Everywhere**: Under no circumstances should emojis or decorative unicode symbols (such as clipboard icons, document emojis, checkmark emojis, or scissors) be used in column headers, cells, buttons, or tooltips.
- **Plain ASCII & Java 2D Graphics Only**: The copy symbol on the right border edge must be rendered using:
  - Plain ASCII text (such as `[Copy]`, `"Copy"`, or `"CP"`), or
  - Pure Java 2D vector drawing via an `Icon` component (`Graphics2D.drawRect` rendering clean rectangular document outlines), ensuring 100% platform-independent, monochrome rendering with zero unicode font dependencies.

#### 4. Direct In-Place Table Editing (No Modal Edit Dialogs)
- **Edit Directly in the Row**: Whenever a user needs to edit a column value (e.g. payload templates, target file paths, categories, descriptions, or header values), the table must support direct in-place editing inside the cell. Never force the user to open a modal popup dialog to edit row values.
- **Double-Click & Keyboard Activation**: Double-clicking a cell or selecting a row and pressing Enter immediately activates the cell's in-place editor.
- **In-Cell Constrained Selectors**: For columns with constrained choices (such as Platform: `Linux` / `Windows`, HTTP Method: `GET` / `POST`, or Category), bind an in-row `DefaultCellEditor` wrapping a `JComboBox` directly to the column model rather than opening a popup form.
- **Immediate Model & Persistence Commit**: Committing the edit (`setValueAt`) immediately updates the underlying data model, fires table change events, and persists the update directly to the storage JSON file on disk.

#### 5. Multi-Row Selection & Fast Batch Deletion (Shift + Arrow, Delete Key)
- **Multiple Interval Selection**: Extension tables must configure `table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)` to allow users to select ranges of rows using `Shift + Up/Down Arrow` or non-contiguous rows using `Ctrl + Click`.
- **Keyboard Delete Binding**: Tables must bind the `Delete` and `Backspace` keys (`KeyEvent.VK_DELETE`, `KeyEvent.VK_BACK_SPACE`) via `InputMap` / `ActionMap` to invoke the delete routine directly.
- **Single-Pass Batch Removal**: Batch deletion routines must convert view row indices to model row indices (`table.convertRowIndexToModel`), sort descending, and remove all selected rows from memory in a single pass. The underlying store must provide a batch delete method (e.g. `removeEntries(int[] modelIndices)`) that writes to disk only once after all items are removed, avoiding costly repetitive disk writes.
- **Safe Confirmation Prompt**: When multiple rows are selected, display a single clear confirmation dialog stating the count of items to be deleted (e.g., `"Delete 5 selected items?"`).

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

### Interactive Table Column Sorting (Proxy History & Intruder Behavior)

When an extension displays a results table (such as an activity log, scan findings, or HTTP traffic history), **always enable interactive column sorting** so testers can sort and reverse-sort columns by clicking the column headers, mirroring the sorting behavior in Burp's Proxy History and Intruder tabs.

**Key Requirements**:
1. **TableRowSorter**: Attach a `TableRowSorter` to the table and enable live updates:
```java
TableRowSorter<MyTableModel> sorter = new TableRowSorter<>(tableModel);
sorter.setSortsOnUpdates(true);
table.setRowSorter(sorter);
```
2. **Typed Column Classes**: Ensure the `TableModel` returns exact data types (`Integer.class`, `String.class`, `Long.class`, etc.) in `getColumnClass(int columnIndex)`. If `Object.class` or `String.class` is returned for numeric values (such as `#`, `Status`, `Length`), sorting will occur lexicographically (`100` before `20`) instead of numerically (`20` before `100`):
```java
@Override
public Class<?> getColumnClass(int columnIndex) {
    switch (columnIndex) {
        case 0: return Integer.class; // ID / #
        case 3: return Integer.class; // Status code
        case 5: return Integer.class; // Length (B)
        default: return String.class;
    }
}
```
3. **Model Index Conversion**: Always convert view indices to model indices (`table.convertRowIndexToModel(viewRow)`) whenever reading selected rows for master-detail viewer updates, context menus, or export actions:
```java
int selectedViewRow = table.getSelectedRow();
if (selectedViewRow != -1) {
    int modelRow = table.convertRowIndexToModel(selectedViewRow);
    MyEntry entry = tableModel.getEntry(modelRow);
    reqEditor.setRequest(entry.request());
    respEditor.setResponse(entry.response());
}
```
4. **Custom Renderer Registration**: When `getColumnClass` returns explicit classes (e.g. `Integer.class`), Swing default renderers can take precedence over renderers registered only for `Object.class`. Explicitly register custom renderers across all applicable column classes:
```java
table.setDefaultRenderer(Object.class, customRenderer);
table.setDefaultRenderer(Integer.class, customRenderer);
table.setDefaultRenderer(String.class, customRenderer);
```

### In-Cell Column Copy Action (Right-Aligned Border Edge Pattern)

When rendering an actionable copy button inside a table cell (such as an endpoint URL, path, or secret value), follow this Swing pattern:
1. **Right Border Edge Alignment**: Place the copy symbol in `BorderLayout.EAST` of the cell renderer panel, pinned against the right column border edge with a small margin (e.g. 4px).
2. **Zero Emojis**: Never use unicode emoji glyphs. Render the copy symbol via plain ASCII text (such as `[Copy]`) or a lightweight Java 2D vector `Icon` that draws rectangular document outlines.
3. **Decoupled Click Handling**: Detect mouse clicks inside the rightmost copy region to perform clipboard copying without disrupting row selection or sorting.

```java
// --- 1. Pure Java 2D Document Copy Icon (Zero Emojis) -------------
public class AsciiDocCopyIcon implements Icon {
    private final int width = 12;
    private final int height = 14;

    @Override
    public void paintIcon(Component c, Graphics g, int x, int y) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setColor(c.getForeground());
        // Clean double-sheet outline using standard Java 2D graphics - no emojis!
        g2.drawRect(x + 3, y, 7, 9);     // Back sheet
        g2.drawRect(x, y + 3, 7, 9);     // Front sheet
        g2.dispose();
    }

    @Override
    public int getIconWidth() { return width; }

    @Override
    public int getIconHeight() { return height; }
}

// --- 2. Cell Renderer with Copy Symbol on Right Border Edge -------
public class CopyableCellRenderer extends DefaultTableCellRenderer {
    private final JPanel panel = new JPanel(new BorderLayout(4, 0));
    private final JLabel textLabel = new JLabel();
    private final JLabel copySymbolLabel = new JLabel("[Copy]"); // Or: new JLabel(new AsciiDocCopyIcon())

    public CopyableCellRenderer() {
        panel.setOpaque(true);
        textLabel.setOpaque(false);
        copySymbolLabel.setOpaque(false);
        copySymbolLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 10));
        copySymbolLabel.setToolTipText("Copy value to clipboard");
        // Pin flush against right column border edge with 4px padding
        copySymbolLabel.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 4));

        panel.add(textLabel, BorderLayout.CENTER);
        panel.add(copySymbolLabel, BorderLayout.EAST);
    }

    @Override
    public Component getTableCellRendererComponent(
        JTable table, Object value, boolean isSelected,
        boolean hasFocus, int row, int column
    ) {
        String text = value == null ? "" : value.toString();
        textLabel.setText(text);

        if (isSelected) {
            panel.setBackground(table.getSelectionBackground());
            textLabel.setForeground(table.getSelectionForeground());
            copySymbolLabel.setForeground(table.getSelectionForeground());
        } else {
            panel.setBackground(table.getBackground());
            textLabel.setForeground(table.getForeground());
            copySymbolLabel.setForeground(Color.GRAY);
        }
        return panel;
    }
}

// --- 3. Right-Edge Click Detection & Clipboard Copy ----------------
table.addMouseListener(new MouseAdapter() {
    @Override
    public void mouseClicked(MouseEvent e) {
        int viewRow = table.rowAtPoint(e.getPoint());
        int viewCol = table.columnAtPoint(e.getPoint());
        if (viewRow < 0 || viewCol < 0) return;

        int modelCol = table.convertColumnIndexToModel(viewCol);
        if (modelCol == TARGET_COPYABLE_COLUMN) {
            Rectangle cellBounds = table.getCellRect(viewRow, viewCol, false);
            int triggerWidth = 45; // Width of right-aligned copy trigger region
            int triggerStartX = cellBounds.x + cellBounds.width - triggerWidth;

            // Trigger copy only when click occurs on right side of column border edge
            if (e.getX() >= triggerStartX) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                Object val = table.getModel().getValueAt(modelRow, modelCol);
                if (val != null) {
                    String text = val.toString();
                    StringSelection selection = new StringSelection(text);
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
                    statusLabel.setText("Copied: " + text);
                }
            }
        }
    }
});
```

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
