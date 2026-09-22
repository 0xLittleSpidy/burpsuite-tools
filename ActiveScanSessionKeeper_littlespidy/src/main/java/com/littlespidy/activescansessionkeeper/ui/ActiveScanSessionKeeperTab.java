// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.activescansessionkeeper.config.CookieMode;
import com.littlespidy.activescansessionkeeper.config.SessionKeeperConfig;
import com.littlespidy.activescansessionkeeper.engine.ScanSessionCoordinator;
import com.littlespidy.activescansessionkeeper.model.ScanActivityDataStore;
import com.littlespidy.activescansessionkeeper.model.ScanActivityEntry;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Main suite tab for Active Scan Session Keeper.
 * Contains the real-time status banner, settings configurators, activity log with
 * multi-select filtering, and native Montoya HTTP message editors.
 *
 * @author littlespidy
 */
public class ActiveScanSessionKeeperTab extends JPanel {

    private final MontoyaApi api;
    private final SessionKeeperConfig config;
    private final ScanSessionCoordinator coordinator;
    private final ScanActivityDataStore dataStore;

    // Status Banner Components
    private JLabel statusBadge;
    private JLabel countersBadge;
    private JButton pauseResumeBtn;
    private JToggleButton enableToggle;

    // Filter Controls
    private MultiSelectFilterButton toolFilterBtn;
    private MultiSelectFilterButton statusFilterBtn;
    private MultiSelectFilterButton eventFilterBtn;
    private JTextField searchField;

    // Table & Editors
    private ActivityTableModel tableModel;
    private JTable activityTable;
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;

    // Counters
    private final AtomicInteger interceptedCount = new AtomicInteger(0);
    private final AtomicInteger expiredCount = new AtomicInteger(0);
    private final AtomicInteger retriedCount = new AtomicInteger(0);

    public ActiveScanSessionKeeperTab(MontoyaApi api, SessionKeeperConfig config,
                                     ScanSessionCoordinator coordinator,
                                     ScanActivityDataStore dataStore) {
        super(new BorderLayout(4, 4));
        this.api = api;
        this.config = config;
        this.coordinator = coordinator;
        this.dataStore = dataStore;

        initComponents();

        // Register listeners
        dataStore.addListener(entry -> SwingUtilities.invokeLater(this::handleNewLogEntry));
        config.addChangeListener(() -> SwingUtilities.invokeLater(this::updateStatusBanner));
    }

    private void initComponents() {
        setBorder(new EmptyBorder(8, 8, 8, 8));

        // ── 1. Top Status & Control Banner ──────────────────────────────────
        add(createStatusBanner(), BorderLayout.NORTH);

        // ── 2. Split Workspace: Left (Settings) / Right (Log & Inspector) ──
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setDividerLocation(420);
        mainSplit.setResizeWeight(0.3);

        mainSplit.setLeftComponent(createSettingsPanel());
        mainSplit.setRightComponent(createLogAndInspectorPanel());

        add(mainSplit, BorderLayout.CENTER);

        updateStatusBanner();
    }

    private JPanel createStatusBanner() {
        JPanel banner = new JPanel(new BorderLayout(8, 6));
        banner.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                new EmptyBorder(4, 4, 8, 4)
        ));

        JPanel leftInfo = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));

        statusBadge = new JLabel("🟢 MONITORING (Active)");
        statusBadge.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));

        countersBadge = new JLabel("Intercepted: 0 | Expired: 0 | Retried: 0");
        countersBadge.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        countersBadge.setForeground(Color.DARK_GRAY);

        leftInfo.add(statusBadge);
        leftInfo.add(new JSeparator(SwingConstants.VERTICAL));
        leftInfo.add(countersBadge);

        JPanel rightControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));

        enableToggle = new JToggleButton("Enabled", config.isEnabled());
        enableToggle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        enableToggle.addActionListener(e -> {
            config.setEnabled(enableToggle.isSelected());
            updateStatusBanner();
        });

        pauseResumeBtn = new JButton("⏸ Pause Scanner");
        pauseResumeBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        pauseResumeBtn.addActionListener(e -> {
            if (coordinator.isPaused()) {
                coordinator.resumeScan();
            } else {
                coordinator.pauseScanManually();
            }
            updateStatusBanner();
        });

        JButton updateCookieBtn = new JButton("🍪 Update Cookie...");
        updateCookieBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        updateCookieBtn.addActionListener(e -> {
            Window win = api.userInterface().swingUtils().suiteFrame();
            ManualCookieDialog dialog = new ManualCookieDialog(win, config);
            dialog.setVisible(true);
        });

        JButton testCookieBtn = new JButton("🧪 Test Cookie");
        testCookieBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        testCookieBtn.addActionListener(e -> runCookieTest());

        rightControls.add(enableToggle);
        rightControls.add(pauseResumeBtn);
        rightControls.add(updateCookieBtn);
        rightControls.add(testCookieBtn);

        banner.add(leftInfo, BorderLayout.WEST);
        banner.add(rightControls, BorderLayout.EAST);

        return banner;
    }

    private JTabbedPane createSettingsPanel() {
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));

        tabbedPane.addTab("🍪 Cookie & Scope", createCookieAndScopeTab());
        tabbedPane.addTab("🔍 Expiration Rules", createExpirationRulesTab());
        tabbedPane.addTab("📖 Guide", createGuideTab());

        return tabbedPane;
    }

    private JPanel createCookieAndScopeTab() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        // Scope Box
        JPanel scopeBox = new JPanel(new GridBagLayout());
        scopeBox.setBorder(BorderFactory.createTitledBorder("Target Scope & Tools"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0;
        JCheckBox inScopeCb = new JCheckBox("Burp In-Scope Only", config.isInScopeOnly());
        inScopeCb.addActionListener(e -> config.setInScopeOnly(inScopeCb.isSelected()));
        scopeBox.add(inScopeCb, gbc);

        gbc.gridx = 0; gbc.gridy = 1;
        scopeBox.add(new JLabel("Target Host Filter (* for all):"), gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        JTextField hostField = new JTextField(config.getTargetHostFilter());
        hostField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { config.setTargetHostFilter(hostField.getText().trim()); }
            public void removeUpdate(DocumentEvent e) { config.setTargetHostFilter(hostField.getText().trim()); }
            public void changedUpdate(DocumentEvent e) { config.setTargetHostFilter(hostField.getText().trim()); }
        });
        scopeBox.add(hostField, gbc);

        gbc.gridx = 0; gbc.gridy = 3;
        JPanel toolsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JCheckBox scanCb = new JCheckBox("Scanner", config.isMonitorScanner());
        scanCb.addActionListener(e -> config.setMonitorScanner(scanCb.isSelected()));
        JCheckBox repCb = new JCheckBox("Repeater", config.isMonitorRepeater());
        repCb.addActionListener(e -> config.setMonitorRepeater(repCb.isSelected()));
        JCheckBox intrCb = new JCheckBox("Intruder", config.isMonitorIntruder());
        intrCb.addActionListener(e -> config.setMonitorIntruder(intrCb.isSelected()));
        toolsRow.add(scanCb);
        toolsRow.add(repCb);
        toolsRow.add(intrCb);
        scopeBox.add(toolsRow, gbc);

        panel.add(scopeBox);
        panel.add(Box.createVerticalStrut(8));

        // Cookie Configuration Box
        JPanel cookieBox = new JPanel(new BorderLayout(6, 6));
        cookieBox.setBorder(BorderFactory.createTitledBorder("Active Session Credentials"));

        JPanel modeRow = new JPanel(new GridLayout(0, 1, 2, 2));
        JRadioButton fullHeaderRadio = new JRadioButton("Replace Full Cookie Header", config.getCookieMode() == CookieMode.FULL_COOKIE_HEADER);
        JRadioButton namedRadio = new JRadioButton("Replace Specific Named Cookie(s)", config.getCookieMode() == CookieMode.NAMED_COOKIES);
        JRadioButton bearerRadio = new JRadioButton("Replace Authorization: Bearer Header", config.getCookieMode() == CookieMode.AUTHORIZATION_BEARER);

        ButtonGroup bg = new ButtonGroup();
        bg.add(fullHeaderRadio);
        bg.add(namedRadio);
        bg.add(bearerRadio);

        modeRow.add(fullHeaderRadio);
        modeRow.add(namedRadio);
        modeRow.add(bearerRadio);
        cookieBox.add(modeRow, BorderLayout.NORTH);

        JPanel fieldPanel = new JPanel();
        fieldPanel.setLayout(new BoxLayout(fieldPanel, BoxLayout.Y_AXIS));

        JLabel namesLabel = new JLabel("Cookie Names (comma separated):");
        JTextField namesField = new JTextField(config.getTargetCookieNames());
        namesField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { config.setTargetCookieNames(namesField.getText().trim()); }
            public void removeUpdate(DocumentEvent e) { config.setTargetCookieNames(namesField.getText().trim()); }
            public void changedUpdate(DocumentEvent e) { config.setTargetCookieNames(namesField.getText().trim()); }
        });

        JLabel valLabel = new JLabel("Cookie Value / Header Content:");
        JTextArea cookieArea = new JTextArea(4, 20);
        cookieArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        cookieArea.setLineWrap(true);
        cookieArea.setText(config.getFullCookieHeader().isEmpty() ? config.getCookieValue() : config.getFullCookieHeader());

        fullHeaderRadio.addActionListener(e -> {
            config.setCookieMode(CookieMode.FULL_COOKIE_HEADER);
            cookieArea.setText(config.getFullCookieHeader());
        });
        namedRadio.addActionListener(e -> {
            config.setCookieMode(CookieMode.NAMED_COOKIES);
            cookieArea.setText(config.getCookieValue());
        });
        bearerRadio.addActionListener(e -> {
            config.setCookieMode(CookieMode.AUTHORIZATION_BEARER);
            cookieArea.setText(config.getAuthBearerToken());
        });

        JButton saveCookieBtn = new JButton("Save Cookie Content");
        saveCookieBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        saveCookieBtn.addActionListener(e -> {
            String text = cookieArea.getText().trim();
            if (fullHeaderRadio.isSelected()) {
                config.setFullCookieHeader(text);
            } else if (namedRadio.isSelected()) {
                config.setCookieValue(text);
            } else {
                config.setAuthBearerToken(text);
            }
            JOptionPane.showMessageDialog(this, "Session credentials saved successfully!", "Saved", JOptionPane.INFORMATION_MESSAGE);
        });

        fieldPanel.add(namesLabel);
        fieldPanel.add(namesField);
        fieldPanel.add(Box.createVerticalStrut(4));
        fieldPanel.add(valLabel);
        fieldPanel.add(new JScrollPane(cookieArea));
        fieldPanel.add(Box.createVerticalStrut(4));
        fieldPanel.add(saveCookieBtn);

        cookieBox.add(fieldPanel, BorderLayout.CENTER);
        panel.add(cookieBox);
        panel.add(Box.createVerticalStrut(8));

        // Options Box
        JPanel optBox = new JPanel(new GridLayout(0, 1, 2, 2));
        optBox.setBorder(BorderFactory.createTitledBorder("Options"));

        JCheckBox retryCb = new JCheckBox("Auto-retry expired request with new cookie", config.isAutoRetryOnExpire());
        retryCb.addActionListener(e -> config.setAutoRetryOnExpire(retryCb.isSelected()));

        JCheckBox soundCb = new JCheckBox("Audio alert / beep when session expires", config.isSoundAlertOnExpire());
        soundCb.addActionListener(e -> config.setSoundAlertOnExpire(soundCb.isSelected()));

        optBox.add(retryCb);
        optBox.add(soundCb);

        panel.add(optBox);
        panel.add(Box.createVerticalGlue());

        return panel;
    }

    private JPanel createExpirationRulesTab() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        // Status codes
        JPanel scPanel = new JPanel(new BorderLayout(4, 4));
        scPanel.setBorder(BorderFactory.createTitledBorder("1. HTTP Status Codes"));
        JCheckBox scCb = new JCheckBox("Check Status Codes", config.isCheckStatusCodes());
        JTextField scField = new JTextField(config.getStatusCodes());
        scCb.addActionListener(e -> config.setCheckStatusCodes(scCb.isSelected()));
        scField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { config.setStatusCodes(scField.getText()); }
            public void removeUpdate(DocumentEvent e) { config.setStatusCodes(scField.getText()); }
            public void changedUpdate(DocumentEvent e) { config.setStatusCodes(scField.getText()); }
        });
        scPanel.add(scCb, BorderLayout.NORTH);
        scPanel.add(scField, BorderLayout.CENTER);
        panel.add(scPanel);
        panel.add(Box.createVerticalStrut(6));

        // Redirects
        JPanel redPanel = new JPanel(new BorderLayout(4, 4));
        redPanel.setBorder(BorderFactory.createTitledBorder("2. Redirect Location Regex"));
        JCheckBox redCb = new JCheckBox("Check 3xx Redirect Location", config.isCheckRedirects());
        JTextField redField = new JTextField(config.getRedirectLocationRegex());
        redCb.addActionListener(e -> config.setCheckRedirects(redCb.isSelected()));
        redField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { config.setRedirectLocationRegex(redField.getText()); }
            public void removeUpdate(DocumentEvent e) { config.setRedirectLocationRegex(redField.getText()); }
            public void changedUpdate(DocumentEvent e) { config.setRedirectLocationRegex(redField.getText()); }
        });
        redPanel.add(redCb, BorderLayout.NORTH);
        redPanel.add(redField, BorderLayout.CENTER);
        panel.add(redPanel);
        panel.add(Box.createVerticalStrut(6));

        // Body Keywords
        JPanel bodyPanel = new JPanel(new BorderLayout(4, 4));
        bodyPanel.setBorder(BorderFactory.createTitledBorder("3. Response Body Expiration Patterns"));
        JCheckBox bodyCb = new JCheckBox("Check Response Body Signatures", config.isCheckBodyKeywords());
        JTextArea bodyArea = new JTextArea(5, 20);
        bodyArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        bodyArea.setText(config.getBodyKeywords());
        bodyCb.addActionListener(e -> config.setCheckBodyKeywords(bodyCb.isSelected()));
        bodyPanel.add(bodyCb, BorderLayout.NORTH);
        bodyPanel.add(new JScrollPane(bodyArea), BorderLayout.CENTER);
        panel.add(bodyPanel);
        panel.add(Box.createVerticalStrut(6));

        // Set-Cookie & Body Drop
        JPanel miscPanel = new JPanel(new GridLayout(0, 1, 4, 4));
        miscPanel.setBorder(BorderFactory.createTitledBorder("4. Headers & Length Signals"));

        JCheckBox setCookieCb = new JCheckBox("Detect Set-Cookie Invalidation (Max-Age=0 / expired 1970)", config.isCheckSetCookieInvalidation());
        setCookieCb.addActionListener(e -> config.setCheckSetCookieInvalidation(setCookieCb.isSelected()));

        JCheckBox lenDropCb = new JCheckBox("Detect Sudden Body Length Drop (<= " + config.getBodyLengthDropThreshold() + " bytes)", config.isCheckBodyLengthDrop());
        lenDropCb.addActionListener(e -> config.setCheckBodyLengthDrop(lenDropCb.isSelected()));

        miscPanel.add(setCookieCb);
        miscPanel.add(lenDropCb);
        panel.add(miscPanel);
        panel.add(Box.createVerticalStrut(6));

        // Save Button
        JButton saveRulesBtn = new JButton("Save All Detection Rules");
        saveRulesBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        saveRulesBtn.addActionListener(e -> {
            config.setBodyKeywords(bodyArea.getText());
            JOptionPane.showMessageDialog(this, "Expiration detection criteria saved!", "Saved", JOptionPane.INFORMATION_MESSAGE);
        });
        panel.add(saveRulesBtn);
        panel.add(Box.createVerticalGlue());

        return panel;
    }

    private JPanel createGuideTab() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JEditorPane guidePane = new JEditorPane();
        guidePane.setContentType("text/html");
        guidePane.setEditable(false);
        guidePane.setText("<html><body style='font-family:sans-serif; font-size:11px; padding:6px;'>"
                + "<h3 style='margin-top:0;'>🍪 Active Scan Session Keeper Guide</h3>"
                + "<p>This extension prevents Burp Active Scans from failing when web application sessions expire.</p>"
                + "<h4>Workflow:</h4>"
                + "<ol>"
                + "<li><b>Set Initial Cookie:</b> Right-click your authenticated request in Proxy/Repeater and select <i>'🍪 Set as Session Keeper Cookie'</i>, or paste it in the Cookie tab.</li>"
                + "<li><b>Launch Active Scan:</b> Start your Burp Active Scan as usual. The extension will automatically inject fresh cookies and monitor every response.</li>"
                + "<li><b>Automated Pause & Prompt:</b> When the session expires (e.g. 401, redirect to login, or 'session expired' text), the extension <b>pauses all scan threads</b> and pops up a modal dialog.</li>"
                + "<li><b>Resume with Fresh Cookie:</b> Copy a new cookie from your browser, paste it into the prompt, and click <i>'Update & Resume'</i>. The scanner retries the failed check and continues scanning seamlessly!</li>"
                + "</ol>"
                + "<h4>Key Features:</h4>"
                + "<ul>"
                + "<li>Multi-factor expiration criteria (Status codes, Redirects, Body regex, Set-Cookie invalidations).</li>"
                + "<li>Thread-safe synchronization: Only 1 prompt pops up even with 20 active scan threads.</li>"
                + "<li>Auto-retry failed requests so no vulnerability checks are missed.</li>"
                + "<li>Full activity triage log with MultiSelectFilterButton and native Montoya HTTP editors.</li>"
                + "</ul>"
                + "</body></html>");

        panel.add(new JScrollPane(guidePane), BorderLayout.CENTER);
        return panel;
    }

    private JPanel createLogAndInspectorPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));

        // ── Triage Toolbar ──
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY));

        toolFilterBtn = new MultiSelectFilterButton(
                "Tool",
                Arrays.asList("All Tools", "Scanner", "Repeater", "Intruder", "Manual", "User"),
                sel -> refreshTableFilter()
        );

        statusFilterBtn = new MultiSelectFilterButton(
                "Status",
                Arrays.asList("All Status", "2xx", "3xx", "4xx", "5xx"),
                sel -> refreshTableFilter()
        );

        eventFilterBtn = new MultiSelectFilterButton(
                "Event",
                Arrays.asList("All Events", "SESSION_EXPIRED", "REQUEST_RETRIED", "SCAN_PAUSED", "SCAN_RESUMED", "COOKIE_UPDATED"),
                sel -> refreshTableFilter()
        );

        searchField = new JTextField(16);
        searchField.setToolTipText("Search URL, Host, or Details...");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { refreshTableFilter(); }
            public void removeUpdate(DocumentEvent e) { refreshTableFilter(); }
            public void changedUpdate(DocumentEvent e) { refreshTableFilter(); }
        });

        JButton clearBtn = new JButton("Clear Log");
        clearBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        clearBtn.addActionListener(e -> {
            dataStore.clear();
            interceptedCount.set(0);
            expiredCount.set(0);
            retriedCount.set(0);
            updateStatusBanner();
            tableModel.setEntries(null);
            clearEditors();
        });

        JButton exportBtn = new JButton("Export TSV");
        exportBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        exportBtn.addActionListener(e -> {
            String tsv = dataStore.exportToTsv();
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(tsv), null);
            JOptionPane.showMessageDialog(this, "Copied " + dataStore.size() + " activity rows to clipboard as TSV!", "Export TSV", JOptionPane.INFORMATION_MESSAGE);
        });

        toolbar.add(toolFilterBtn);
        toolbar.add(statusFilterBtn);
        toolbar.add(eventFilterBtn);
        toolbar.add(new JLabel("🔍"));
        toolbar.add(searchField);
        toolbar.add(clearBtn);
        toolbar.add(exportBtn);

        panel.add(toolbar, BorderLayout.NORTH);

        // ── Table & Montoya Editors SplitPane ──
        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        verticalSplit.setDividerLocation(260);
        verticalSplit.setResizeWeight(0.45);

        tableModel = new ActivityTableModel();
        activityTable = new JTable(tableModel);
        activityTable.setDefaultRenderer(Object.class, new ActivityCellRenderer());
        activityTable.setDefaultRenderer(Integer.class, new ActivityCellRenderer());
        activityTable.setRowHeight(22);
        activityTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Column widths
        activityTable.getColumnModel().getColumn(0).setPreferredWidth(45);  // #
        activityTable.getColumnModel().getColumn(1).setPreferredWidth(70);  // Time
        activityTable.getColumnModel().getColumn(2).setPreferredWidth(70);  // Tool
        activityTable.getColumnModel().getColumn(3).setPreferredWidth(55);  // Method
        activityTable.getColumnModel().getColumn(4).setPreferredWidth(140); // Host
        activityTable.getColumnModel().getColumn(5).setPreferredWidth(260); // URL
        activityTable.getColumnModel().getColumn(6).setPreferredWidth(55);  // Status
        activityTable.getColumnModel().getColumn(7).setPreferredWidth(140); // Event
        activityTable.getColumnModel().getColumn(8).setPreferredWidth(240); // Details

        activityTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = activityTable.getSelectedRow();
                if (selectedRow >= 0) {
                    ScanActivityEntry entry = tableModel.getEntryAt(selectedRow);
                    if (entry != null && entry.getRequestResponse() != null) {
                        HttpRequestResponse rr = entry.getRequestResponse();
                        if (rr.request() != null) requestEditor.setRequest(rr.request());
                        if (rr.response() != null) responseEditor.setResponse(rr.response());
                    } else {
                        clearEditors();
                    }
                }
            }
        });

        verticalSplit.setTopComponent(new JScrollPane(activityTable));

        // Montoya Message Editors
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        JTabbedPane editorTabs = new JTabbedPane();
        editorTabs.addTab("📤 Request", requestEditor.uiComponent());
        editorTabs.addTab("📥 Response", responseEditor.uiComponent());

        verticalSplit.setBottomComponent(editorTabs);

        panel.add(verticalSplit, BorderLayout.CENTER);

        return panel;
    }

    private void handleNewLogEntry() {
        ScanActivityEntry latest = null;
        List<ScanActivityEntry> all = dataStore.getEntries();
        if (!all.isEmpty()) {
            latest = all.get(all.size() - 1);
            interceptedCount.incrementAndGet();
            if (latest.getEventType().contains("EXPIRED")) expiredCount.incrementAndGet();
            if (latest.getEventType().contains("RETRIED")) retriedCount.incrementAndGet();
        }
        updateStatusBanner();
        refreshTableFilter();
    }

    private void refreshTableFilter() {
        Set<String> tools = toolFilterBtn.getSelected();
        Set<String> statuses = statusFilterBtn.getSelected();
        Set<String> events = eventFilterBtn.getSelected();
        String query = searchField.getText().trim();

        List<ScanActivityEntry> filtered = dataStore.getFilteredEntries(query, tools, statuses, events);
        tableModel.setEntries(filtered);
    }

    private void updateStatusBanner() {
        if (!config.isEnabled()) {
            statusBadge.setText("⚪ DISABLED");
            statusBadge.setForeground(Color.GRAY);
            enableToggle.setSelected(false);
            enableToggle.setText("Disabled");
            pauseResumeBtn.setEnabled(false);
        } else if (coordinator.isPaused()) {
            statusBadge.setText("⏸️ PAUSED (Waiting for Fresh Cookie)");
            statusBadge.setForeground(new Color(180, 83, 9)); // Amber
            enableToggle.setSelected(true);
            enableToggle.setText("Enabled");
            pauseResumeBtn.setEnabled(true);
            pauseResumeBtn.setText("▶ Resume Scanner");
        } else {
            statusBadge.setText("🟢 MONITORING (Active)");
            statusBadge.setForeground(new Color(22, 101, 52)); // Green
            enableToggle.setSelected(true);
            enableToggle.setText("Enabled");
            pauseResumeBtn.setEnabled(true);
            pauseResumeBtn.setText("⏸ Pause Scanner");
        }

        countersBadge.setText("Intercepted: " + interceptedCount.get() +
                " | Expired: " + expiredCount.get() +
                " | Retried: " + retriedCount.get());
    }

    private void runCookieTest() {
        String testUrl = JOptionPane.showInputDialog(this,
                "Enter target URL to test current credentials:",
                "Test Cookie Probe", JOptionPane.PLAIN_MESSAGE);
        if (testUrl == null || testUrl.trim().isEmpty()) {
            return;
        }

        new Thread(() -> {
            try {
                HttpRequest probe = HttpRequest.httpRequestFromUrl(testUrl.trim());
                HttpRequest modified = coordinator.applySessionCredentials(probe);
                HttpRequestResponse rr = api.http().sendRequest(modified);
                HttpResponse resp = rr.response();

                SwingUtilities.invokeLater(() -> {
                    dataStore.addEntry(new ScanActivityEntry(
                            dataStore.nextId(), "Manual", modified.method(), modified.httpService().host(),
                            testUrl, resp.statusCode(), "TEST_PROBE", "Test probe response status: " + resp.statusCode(), rr
                    ));

                    String snippet = (resp.bodyToString() != null && resp.bodyToString().length() > 200)
                            ? resp.bodyToString().substring(0, 200) + "..."
                            : resp.bodyToString();

                    JOptionPane.showMessageDialog(this,
                            "Test Probe Completed!\nStatus: " + resp.statusCode() + " " + resp.reasonPhrase() +
                            "\nLength: " + resp.body().length() + " bytes\n\nPreview:\n" + snippet,
                            "Cookie Test Result", (resp.statusCode() == 200) ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this,
                        "Probe failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE));
            }
        }).start();
    }

    public void setCookieFromExternal(String cookieStr, String host) {
        config.setCookieMode(CookieMode.FULL_COOKIE_HEADER);
        config.setFullCookieHeader(cookieStr);
        if (host != null && !host.isEmpty()) {
            config.setTargetHostFilter(host);
        }
        updateStatusBanner();
    }

    private void clearEditors() {
        // Clear editor contents by setting empty request/response or leaving as-is
    }
}
