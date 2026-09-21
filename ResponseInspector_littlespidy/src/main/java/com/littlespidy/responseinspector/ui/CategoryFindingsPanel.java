// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.responseinspector.engine.CommentScanner;
import com.littlespidy.responseinspector.engine.ResponseScanEngine;
import com.littlespidy.responseinspector.engine.ScannerUtils;
import com.littlespidy.responseinspector.engine.SecretScanner;
import com.littlespidy.responseinspector.engine.SecretVerifierService;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InScopeDomainManager;
import com.littlespidy.responseinspector.model.InspectorDataStore;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Reusable findings panel supporting master-detail layout, multi-select toolbar filters,
 * in-scope domain selection, live ingestion progress bar, deep-linking navigation quad,
 * dedicated Finding Type filter per category, KeyHacks credential verification for secrets,
 * and inter-tool integration (Repeater/Intruder/Organizer).
 *
 * @author littlespidy
 */
public class CategoryFindingsPanel extends JPanel {

    private final MontoyaApi api;
    private final FindingCategory category;
    private final InspectorDataStore dataStore;
    private final ResponseScanEngine scanEngine;
    private final InScopeDomainManager domainManager;
    private final Runnable refreshAllTabsCallback;

    private final FindingsTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<FindingsTableModel> sorter;

    private final HttpRequestEditor reqEditor;
    private final HttpResponseEditor respEditor;
    private final JTabbedPane editorTabs;

    private final JLabel statsLabel;
    private final JLabel liveStatusLabel;
    private final JProgressBar progressBar;
    private final JTextField searchField;
    private final JCheckBox inScopeCb;
    private final JButton inScopeDomainsBtn;
    private final MultiSelectFilterButton methodFilterBtn;
    private final MultiSelectFilterButton statusFilterBtn;
    private final MultiSelectFilterButton contentTypeFilterBtn;

    // Dedicated Finding Type filter button on every tab
    private final MultiSelectFilterButton findingTypeFilterBtn;

    // COMMENT-only: semantic category filter (TODO, Creds, Debug, General)
    private final MultiSelectFilterButton commentCategoryFilterBtn;

    private final JButton loadProxyBtn;
    private final JButton loadRepeaterBtn;
    private JButton configPasswordsBtn;

    public CategoryFindingsPanel(
            MontoyaApi api,
            FindingCategory category,
            InspectorDataStore dataStore,
            ResponseScanEngine scanEngine,
            InScopeDomainManager domainManager,
            Runnable refreshAllTabsCallback
    ) {
        this.api = api;
        this.category = category;
        this.dataStore = dataStore;
        this.scanEngine = scanEngine;
        this.domainManager = domainManager;
        this.refreshAllTabsCallback = refreshAllTabsCallback;

        setLayout(new BorderLayout());

        // Table Model & Sorter (Pin column removed completely)
        tableModel = new FindingsTableModel(dataStore);
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        // Column widths
        // Cols: 0=#, 1=Method, 2=Status, 3=Finding Type, 4=Match Excerpt, 5=Location, 6=Length, 7=Content-Type, 8=URL, 9=Time
        table.getColumnModel().getColumn(0).setPreferredWidth(45);   // #
        table.getColumnModel().getColumn(0).setMaxWidth(60);
        table.getColumnModel().getColumn(1).setPreferredWidth(60);   // Method
        table.getColumnModel().getColumn(1).setMaxWidth(80);
        table.getColumnModel().getColumn(2).setPreferredWidth(60);   // Status
        table.getColumnModel().getColumn(2).setMaxWidth(75);
        table.getColumnModel().getColumn(2).setCellRenderer(new StatusCodeRenderer());
        table.getColumnModel().getColumn(3).setPreferredWidth(180);  // Finding Type
        table.getColumnModel().getColumn(4).setPreferredWidth(260);  // Match Excerpt
        table.getColumnModel().getColumn(5).setPreferredWidth(130);  // Location
        table.getColumnModel().getColumn(6).setPreferredWidth(65);   // Length
        table.getColumnModel().getColumn(7).setPreferredWidth(110);  // Content-Type
        table.getColumnModel().getColumn(8).setPreferredWidth(320);  // URL
        table.getColumnModel().getColumn(9).setPreferredWidth(70);   // Time

        // Montoya Built-in Editors (Pretty/Raw/Hex)
        reqEditor = api.userInterface().createHttpRequestEditor();
        respEditor = api.userInterface().createHttpResponseEditor();

        editorTabs = new JTabbedPane();
        editorTabs.addTab("Request", reqEditor.uiComponent());
        editorTabs.addTab("Response", respEditor.uiComponent());

        // Deep-Linking Table Selection Listener
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = table.getSelectedRow();
                if (viewRow != -1) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    FindingEntry entry = tableModel.getEntryAt(modelRow);
                    if (entry != null) {
                        navigateToFinding(entry);
                    }
                }
            }
        });

        // Double-click secret row to verify in Burp Repeater
        if (category == FindingCategory.SECRET) {
            table.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                        verifySelectedSecret();
                    }
                }
            });
        }

        // ─── Top Toolbar ──────────────────────────────────────────────────────────
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        toolbar.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));

        loadProxyBtn = new JButton("Load Proxy");
        loadProxyBtn.setFont(loadProxyBtn.getFont().deriveFont(Font.BOLD));
        loadProxyBtn.setToolTipText("Scan all HTTP responses currently in Burp Proxy history (static files excluded)");
        loadProxyBtn.addActionListener(e -> runProxyHistoryScan());
        toolbar.add(loadProxyBtn);

        loadRepeaterBtn = new JButton("Load from Repeater");
        loadRepeaterBtn.setFont(loadRepeaterBtn.getFont().deriveFont(Font.BOLD));
        loadRepeaterBtn.setToolTipText("Scan all HTTP responses sent from Burp Repeater (static files excluded)");
        loadRepeaterBtn.addActionListener(e -> runRepeaterScan());
        toolbar.add(loadRepeaterBtn);

        // Prominent Password Configuration Button on Password tab
        if (category == FindingCategory.PASSWORD) {
            configPasswordsBtn = new JButton(getPasswordButtonLabel());
            configPasswordsBtn.setFont(configPasswordsBtn.getFont().deriveFont(Font.BOLD));
            configPasswordsBtn.setToolTipText("Configure target passwords to scan for in responses");
            configPasswordsBtn.addActionListener(e -> openPasswordConfigDialog());
            toolbar.add(configPasswordsBtn);
        }

        // Secret-specific toolbar buttons (Signatures Catalog & KeyHacks Repeater verification)
        if (category == FindingCategory.SECRET) {
            JButton catalogBtn = new JButton("📋 Signatures Catalog (" + scanEngine.getSecretScanner().getCuratedSignatures().size() + ")");
            catalogBtn.setToolTipText("View complete catalog of all curated secret signatures, match patterns, and categories");
            catalogBtn.addActionListener(e -> showSignaturesCatalogDialog());
            toolbar.add(catalogBtn);

            JButton verifyBtn = new JButton("🧪 Verify Secret (Repeater)");
            verifyBtn.setToolTipText("Send non-destructive verification request directly to Burp Repeater");
            verifyBtn.addActionListener(e -> verifySelectedSecret());
            toolbar.add(verifyBtn);
        }

        toolbar.add(new JSeparator(JSeparator.VERTICAL));

        inScopeDomainsBtn = new JButton(getDomainButtonLabel());
        inScopeDomainsBtn.setToolTipText("Select specific in-scope target domains to include/exclude");
        inScopeDomainsBtn.setEnabled(false);
        inScopeDomainsBtn.addActionListener(e -> openInScopeDomainDialog());

        inScopeCb = new JCheckBox("In-Scope Only");
        inScopeCb.addActionListener(e -> {
            inScopeDomainsBtn.setEnabled(inScopeCb.isSelected());
            refreshView();
        });
        toolbar.add(inScopeCb);
        toolbar.add(inScopeDomainsBtn);

        toolbar.add(new JSeparator(JSeparator.VERTICAL));

        // ── Tab-specific Finding Type filter on every tab ──
        List<String> findingTypes = new ArrayList<>();
        findingTypes.add("All Finding Types");
        if (category == FindingCategory.PASSWORD) {
            findingTypes.add("Configured Password");
        } else if (category == FindingCategory.PII_NETWORK_PATH) {
            findingTypes.addAll(List.of("Social Security Number (SSN)", "RFC1918 Internal IP", "Server File Path"));
        } else if (category == FindingCategory.ERROR) {
            findingTypes.addAll(List.of(
                    "Apache Server Error", "NGINX Server Error", "JBoss / WildFly Error",
                    "Waitress Python Server Error", "WebSEAL Error",
                    "ASP.NET Exception / Stack Trace",
                    "MySQL / MariaDB Error", "PostgreSQL Error", "Oracle DB Error",
                    "Microsoft SQL Server Error", "SQLite Error", "IBM DB2 Error",
                    "MongoDB Error", "LDAP Leakage",
                    "PHP Error / Stack Trace", "Java Exception / Stack Trace",
                    "Python Traceback / Error", "Ruby / Rails Error",
                    "Node.js / JavaScript Error", "Go Panic / Stack Trace",
                    "Django ORM Error", "Hibernate / JPA Error"
            ));
        } else if (category == FindingCategory.SECRET) {
            findingTypes.addAll(scanEngine.getSecretScanner().getRuleNames());
        } else if (category == FindingCategory.COMMENT) {
            findingTypes.addAll(CommentScanner.getCommentTypes().stream().filter(s -> !s.startsWith("All")).toList());
        }

        findingTypeFilterBtn = new MultiSelectFilterButton(
                "Finding Type",
                findingTypes,
                sel -> refreshView()
        );
        toolbar.add(findingTypeFilterBtn);

        // ── COMMENT-only: Comment Category filter (TODO, Credentials, Debug, General) ──
        if (category == FindingCategory.COMMENT) {
            commentCategoryFilterBtn = new MultiSelectFilterButton(
                    "Category",
                    CommentScanner.getCommentCategories(),
                    sel -> refreshView()
            );
            toolbar.add(commentCategoryFilterBtn);
        } else {
            commentCategoryFilterBtn = null;
        }

        // ── Standard Burp-architecture filters ──
        methodFilterBtn = new MultiSelectFilterButton(
                "Method",
                List.of("All Methods", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"),
                sel -> refreshView()
        );
        toolbar.add(methodFilterBtn);

        statusFilterBtn = new MultiSelectFilterButton(
                "Status",
                List.of("All Status Codes", "2xx", "200", "3xx", "301", "302", "4xx", "401", "403", "404", "5xx", "500"),
                sel -> refreshView()
        );
        toolbar.add(statusFilterBtn);

        contentTypeFilterBtn = new MultiSelectFilterButton(
                "Content-Type",
                List.of("All Types", "JSON", "HTML", "XML", "Plain"),
                sel -> refreshView()
        );
        toolbar.add(contentTypeFilterBtn);

        toolbar.add(new JLabel("Search:"));
        searchField = new JTextField(12);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { refreshView(); }
            @Override public void removeUpdate(DocumentEvent e) { refreshView(); }
            @Override public void changedUpdate(DocumentEvent e) { refreshView(); }
        });
        toolbar.add(searchField);

        JButton clearDataBtn = new JButton("Clear");
        clearDataBtn.addActionListener(e -> {
            dataStore.clear();
            refreshView();
        });
        toolbar.add(clearDataBtn);

        JButton exportTsvBtn = new JButton("Export TSV");
        exportTsvBtn.setToolTipText("Export currently displayed findings to a Tab-Separated Values (.tsv) file");
        exportTsvBtn.addActionListener(e -> exportFindingsToTsv());
        toolbar.add(exportTsvBtn);

        statsLabel = new JLabel("Total: 0 | Displayed: 0");
        statsLabel.setFont(statsLabel.getFont().deriveFont(Font.BOLD));
        toolbar.add(statsLabel);

        // Dedicated Live Ingestion Status Strip
        JPanel statusRow = new JPanel(new BorderLayout(6, 2));
        statusRow.setBorder(BorderFactory.createEmptyBorder(2, 8, 4, 8));

        liveStatusLabel = new JLabel("Ready. Click 'Load Proxy' or 'Load from Repeater' to begin analysis.");
        liveStatusLabel.setFont(liveStatusLabel.getFont().deriveFont(Font.PLAIN, 12f));

        progressBar = new JProgressBar();
        progressBar.setPreferredSize(new Dimension(240, 18));
        progressBar.setVisible(false);

        statusRow.add(liveStatusLabel, BorderLayout.WEST);
        statusRow.add(progressBar, BorderLayout.EAST);

        JPanel topContainer = new JPanel(new BorderLayout());
        topContainer.add(toolbar, BorderLayout.NORTH);
        topContainer.add(statusRow, BorderLayout.SOUTH);

        add(topContainer, BorderLayout.NORTH);

        // Master-Detail Split Pane
        JScrollPane tableScroll = new JScrollPane(table);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, editorTabs);
        splitPane.setResizeWeight(0.55);
        splitPane.setDividerLocation(320);

        add(splitPane, BorderLayout.CENTER);

        // Context Menu & Shortcuts
        setupContextMenu();
        setupClipboardShortcut();

        // Initial populate
        refreshView();
    }

    public void refreshView() {
        boolean inScope = inScopeCb.isSelected();
        String search = searchField.getText();
        Set<String> methods = methodFilterBtn.getSelected();
        Set<String> statuses = statusFilterBtn.getSelected();
        Set<String> contentTypes = contentTypeFilterBtn.getSelected();
        Set<String> patternFilter = findingTypeFilterBtn.getSelected();

        List<FindingEntry> filtered = dataStore.getFilteredEntries(
                search,
                statuses,
                contentTypes,
                methods,
                patternFilter,
                inScope,
                url -> api.scope().isInScope(url),
                domainManager
        );

        // Post-filter: comment semantic category (TODO, Credentials, Debug, General)
        if (category == FindingCategory.COMMENT && commentCategoryFilterBtn != null) {
            Set<String> selectedCategories = commentCategoryFilterBtn.getSelected();
            if (!selectedCategories.isEmpty()) {
                filtered = filtered.stream()
                        .filter(e -> selectedCategories.contains(e.matchLocation()))
                        .collect(Collectors.toList());
            }
        }

        tableModel.setEntries(filtered);

        statsLabel.setText("Total: " + dataStore.size() + " | Displayed: " + filtered.size());

        inScopeDomainsBtn.setText(getDomainButtonLabel());
        inScopeDomainsBtn.setEnabled(inScope);

        if (configPasswordsBtn != null) {
            configPasswordsBtn.setText(getPasswordButtonLabel());
        }
    }

    // ─── Deep-Linking Quad Navigation Engine ─────────────────────────────────────

    private void navigateToFinding(FindingEntry finding) {
        if (finding == null || finding.requestResponse() == null) return;

        HttpRequestResponse message = finding.requestResponse();
        String query = finding.matchValue();

        if (finding.isResponseFinding()) {
            HttpResponse response = message.response();
            if (response == null) return;

            editorTabs.setSelectedComponent(respEditor.uiComponent());

            int rawStart = finding.startOffset();
            int rawEnd = finding.endOffset();
            int bodyOffset = response.bodyOffset();

            if (rawStart >= 0 && rawEnd > rawStart) {
                if (!finding.isHeaderFinding()) {
                    rawStart += bodyOffset;
                    rawEnd += bodyOffset;
                }
            } else if (query != null && !query.isEmpty()) {
                String rawStr = response.toString();
                int idx = rawStr.indexOf(query);
                if (idx >= 0) {
                    rawStart = idx;
                    rawEnd = idx + query.length();
                }
            }

            if (rawStart >= 0 && rawEnd > rawStart && rawEnd <= response.toByteArray().length()) {
                try {
                    Marker marker = Marker.marker(rawStart, rawEnd);
                    response = response.withMarkers(marker);
                } catch (Exception ignored) {}
            }
            respEditor.setResponse(response);

            if (message.request() != null) {
                reqEditor.setRequest(message.request());
            }

            if (query != null && !query.isEmpty()) {
                try {
                    respEditor.setSearchExpression(query);
                } catch (Exception ignored) {}
            }

            if (rawStart >= 0) {
                final int targetCaret = rawStart;
                SwingUtilities.invokeLater(() -> scrollTextComponent(respEditor.uiComponent(), targetCaret));
            }

        } else {
            HttpRequest request = message.request();
            if (request == null) return;

            editorTabs.setSelectedComponent(reqEditor.uiComponent());

            int rawStart = finding.startOffset();
            int rawEnd = finding.endOffset();
            int bodyOffset = request.bodyOffset();

            if (rawStart >= 0 && rawEnd > rawStart) {
                if (!finding.isHeaderFinding()) {
                    rawStart += bodyOffset;
                    rawEnd += bodyOffset;
                }
            } else if (query != null && !query.isEmpty()) {
                String rawStr = request.toString();
                int idx = rawStr.indexOf(query);
                if (idx >= 0) {
                    rawStart = idx;
                    rawEnd = idx + query.length();
                }
            }

            if (rawStart >= 0 && rawEnd > rawStart && rawEnd <= request.toByteArray().length()) {
                try {
                    Marker marker = Marker.marker(rawStart, rawEnd);
                    request = request.withMarkers(marker);
                } catch (Exception ignored) {}
            }
            reqEditor.setRequest(request);

            if (message.response() != null) {
                respEditor.setResponse(message.response());
            }

            if (query != null && !query.isEmpty()) {
                try {
                    reqEditor.setSearchExpression(query);
                } catch (Exception ignored) {}
            }

            if (rawStart >= 0) {
                final int targetCaret = rawStart;
                SwingUtilities.invokeLater(() -> scrollTextComponent(reqEditor.uiComponent(), targetCaret));
            }
        }
    }

    private static void scrollTextComponent(Component root, int position) {
        if (root == null) return;
        if (root instanceof javax.swing.text.JTextComponent tc) {
            try {
                if (position >= 0 && position <= tc.getText().length()) {
                    tc.setCaretPosition(position);
                }
            } catch (Exception ignored) {}
            return;
        }
        if (root instanceof Container container) {
            for (Component child : container.getComponents()) {
                scrollTextComponent(child, position);
            }
        }
    }

    // ─── KeyHacks Credential Verification & Signatures Catalog ───────────────────

    private void verifySelectedSecret() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a secret row to verify.", "No Secret Selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        FindingEntry entry = tableModel.getEntryAt(modelRow);
        if (entry != null) {
            verifySecret(entry);
        }
    }

    public void verifySecret(FindingEntry sec) {
        if (sec == null) return;
        try {
            HttpRequest req = SecretVerifierService.buildVerificationRequest(sec);
            if (req != null) {
                String ruleName = sec.patternName() != null ? sec.patternName() : "Secret";
                String tabName = "Verify: " + (ruleName.length() > 16 ? ruleName.substring(0, 16) : ruleName);
                api.repeater().sendToRepeater(req, tabName);
                api.logging().logToOutput("[Secret Verifier] Dispatched verification request for '" + ruleName + "' to Repeater tab '" + tabName + "'");
                JOptionPane.showMessageDialog(
                    this,
                    "Verification request for '" + ruleName + "' sent to Burp Repeater (Tab: " + tabName + ").",
                    "Sent to Repeater",
                    JOptionPane.INFORMATION_MESSAGE
                );
            } else {
                JOptionPane.showMessageDialog(
                    this,
                    "Could not construct an HTTP verification request for this secret.",
                    "Verification Error",
                    JOptionPane.ERROR_MESSAGE
                );
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(
                this,
                "Failed to send to Repeater: " + ex.getMessage(),
                "Repeater Error",
                JOptionPane.ERROR_MESSAGE
            );
        }
    }

    private void showSignaturesCatalogDialog() {
        Window parentWin = SwingUtilities.getWindowAncestor(this);
        List<SecretScanner.SecretSignatureInfo> allSigs = scanEngine.getSecretScanner().getCuratedSignatures();
        JDialog dialog = new JDialog(parentWin, "📋 Curated Secret Signatures & Match Patterns Catalog (" + allSigs.size() + " Signatures)", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(1050, 600);
        dialog.setLocationRelativeTo(parentWin);

        JPanel contentPanel = new JPanel(new BorderLayout(8, 8));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel topBar = new JPanel(new BorderLayout(8, 8));
        JLabel headerLbl = new JLabel("Curated Secret Signatures & Pattern Catalog (" + allSigs.size() + " signatures with Shannon entropy & FP suppression)");
        headerLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));

        JPanel searchRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        searchRow.add(new JLabel("Quick Filter:"));
        JTextField catalogSearchField = new JTextField(22);
        searchRow.add(catalogSearchField);

        topBar.add(headerLbl, BorderLayout.WEST);
        topBar.add(searchRow, BorderLayout.EAST);
        contentPanel.add(topBar, BorderLayout.NORTH);

        String[] cols = {"#", "Signature / Rule Name", "Category", "Matching Regex Pattern", "Confidence", "Shannon Entropy Guard"};

        DefaultTableModel catModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
            @Override public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Integer.class : String.class;
            }
        };

        for (int i = 0; i < allSigs.size(); i++) {
            SecretScanner.SecretSignatureInfo s = allSigs.get(i);
            catModel.addRow(new Object[]{
                i + 1,
                s.name(),
                s.category(),
                s.pattern(),
                s.confidence() + "%",
                s.needsEntropy() ? "Yes (Entropy \u2265 3.0)" : "Exact Pattern Match"
            });
        }

        JTable catTable = new JTable(catModel);
        catTable.setRowHeight(24);
        catTable.getColumnModel().getColumn(0).setPreferredWidth(35);
        catTable.getColumnModel().getColumn(1).setPreferredWidth(200);
        catTable.getColumnModel().getColumn(2).setPreferredWidth(160);
        catTable.getColumnModel().getColumn(3).setPreferredWidth(400);
        catTable.getColumnModel().getColumn(4).setPreferredWidth(85);
        catTable.getColumnModel().getColumn(5).setPreferredWidth(170);

        catTable.getColumnModel().getColumn(3).setCellRenderer(new javax.swing.table.DefaultTableCellRenderer() {
            private final Font monoFont = new Font(Font.MONOSPACED, Font.PLAIN, 11);
            @Override
            public Component getTableCellRendererComponent(JTable tbl, Object val, boolean isSel, boolean hasFoc, int row, int col) {
                Component comp = super.getTableCellRendererComponent(tbl, val, isSel, hasFoc, row, col);
                comp.setFont(monoFont);
                ((JComponent) comp).setToolTipText(null);
                return comp;
            }
        });

        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(catModel);
        catTable.setRowSorter(sorter);

        catalogSearchField.getDocument().addDocumentListener(new DocumentListener() {
            private void updateFilter() {
                String text = catalogSearchField.getText().trim();
                if (text.isEmpty()) {
                    sorter.setRowFilter(null);
                } else {
                    sorter.setRowFilter(RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(text)));
                }
            }
            @Override public void insertUpdate(DocumentEvent e) { updateFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { updateFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { updateFilter(); }
        });

        contentPanel.add(new JScrollPane(catTable), BorderLayout.CENTER);

        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dialog.dispose());
        bottomBar.add(closeBtn);
        contentPanel.add(bottomBar, BorderLayout.SOUTH);

        dialog.setContentPane(contentPanel);
        dialog.setVisible(true);
    }

    // ─── Helpers & Event Handlers ────────────────────────────────────────────────

    private String getPasswordButtonLabel() {
        int count = scanEngine.getPasswordScanner().getPasswordCount();
        return "Configure Passwords... (" + count + " active)";
    }

    private String getDomainButtonLabel() {
        if (domainManager == null || domainManager.getTotalDomainCount() == 0) {
            return "In-Scope Domains...";
        }
        if (domainManager.isAllSelected()) {
            return "In-Scope Domains (All " + domainManager.getTotalDomainCount() + ")";
        }
        return "In-Scope Domains (" + domainManager.getSelectedDomainCount() + "/" + domainManager.getTotalDomainCount() + ")";
    }

    private void openInScopeDomainDialog() {
        Frame topFrame = (Frame) SwingUtilities.getWindowAncestor(this);
        InScopeDomainDialog dialog = new InScopeDomainDialog(topFrame, domainManager, () -> {
            if (refreshAllTabsCallback != null) {
                refreshAllTabsCallback.run();
            } else {
                refreshView();
            }
        });
        dialog.setVisible(true);
    }

    private void openPasswordConfigDialog() {
        Frame topFrame = (Frame) SwingUtilities.getWindowAncestor(this);
        PasswordConfigDialog dialog = new PasswordConfigDialog(topFrame, scanEngine.getPasswordScanner(), () -> {
            if (configPasswordsBtn != null) {
                configPasswordsBtn.setText(getPasswordButtonLabel());
            }
        });
        dialog.setVisible(true);
    }

    // ─── Proxy History Scan with Live Progress Bar & Scope Architecture ──────────

    private record ProgressChunk(int processed, int total, int newFindings) {}

    private void runProxyHistoryScan() {
        if (category == FindingCategory.PASSWORD && scanEngine.getPasswordScanner().getPasswordCount() == 0) {
            int opt = JOptionPane.showConfirmDialog(
                    this,
                    "No target passwords have been configured yet.\nWould you like to configure passwords before analyzing proxy history?",
                    "Configure Passwords",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE
            );
            if (opt == JOptionPane.YES_OPTION) {
                openPasswordConfigDialog();
            }
        }

        loadProxyBtn.setEnabled(false);
        loadRepeaterBtn.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(false);
        progressBar.setValue(0);
        liveStatusLabel.setText("Scanning Proxy history for traffic (static files excluded)...");

        final boolean inScopeOnlyIngestion = inScopeCb.isSelected();

        SwingWorker<Integer, ProgressChunk> worker = new SwingWorker<>() {
            @Override
            protected Integer doInBackground() {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                int total = history.size();
                if (total == 0) return 0;

                // Pre-discovery pass for in-scope domains (excluding static resources)
                for (ProxyHttpRequestResponse item : history) {
                    if (item.request() != null) {
                        var req = item.finalRequest() != null ? item.finalRequest() : item.request();
                        if (ScannerUtils.isStaticResource(req, item.response())) {
                            continue;
                        }
                        String url = req.url();
                        if (api.scope().isInScope(url)) {
                            String host = req.httpService() != null ? req.httpService().host() : "";
                            domainManager.addDomain(host);
                        }
                    }
                }

                int numThreads = Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()));
                ExecutorService executor = Executors.newFixedThreadPool(numThreads);
                AtomicInteger processed = new AtomicInteger(0);
                AtomicInteger newFindings = new AtomicInteger(0);

                try {
                    List<Future<?>> futures = new ArrayList<>(total);
                    for (ProxyHttpRequestResponse item : history) {
                        if (isCancelled()) break;
                        futures.add(executor.submit(() -> {
                            if (isCancelled()) return;
                            var req = item.finalRequest() != null ? item.finalRequest() : item.request();

                            // 1. Strict Static Resource Exclusion (JS, CSS, PNG, images, fonts, binaries)
                            if (ScannerUtils.isStaticResource(req, item.response())) {
                                int cur = processed.incrementAndGet();
                                if (cur % 25 == 0 || cur == total) {
                                    publish(new ProgressChunk(cur, total, newFindings.get()));
                                }
                                return;
                            }

                            // 2. Dual-stage Ingestion Pre-Filter (when in-scope only is selected)
                            if (inScopeOnlyIngestion && (req == null || !api.scope().isInScope(req.url()))) {
                                int cur = processed.incrementAndGet();
                                if (cur % 25 == 0 || cur == total) {
                                    publish(new ProgressChunk(cur, total, newFindings.get()));
                                }
                                return;
                            }

                            if (item.hasResponse()) {
                                String host = (req != null && req.httpService() != null)
                                        ? req.httpService().host() : "";
                                int added = scanEngine.scanProxyItem(item);
                                if (added > 0 && !host.isBlank()) {
                                    domainManager.registerFinding(host);
                                }
                                newFindings.addAndGet(added);
                            }
                            int cur = processed.incrementAndGet();
                            if (cur % 25 == 0 || cur == total) {
                                publish(new ProgressChunk(cur, total, newFindings.get()));
                            }
                        }));
                    }

                    for (Future<?> f : futures) {
                        if (isCancelled()) break;
                        try { f.get(); } catch (Exception ignored) {}
                    }
                } finally {
                    executor.shutdownNow();
                }

                return newFindings.get();
            }

            @Override
            protected void process(List<ProgressChunk> chunks) {
                if (!chunks.isEmpty()) {
                    ProgressChunk latest = chunks.get(chunks.size() - 1);
                    progressBar.setMaximum(latest.total());
                    progressBar.setValue(latest.processed());
                    liveStatusLabel.setText("Scanning Proxy history: " + latest.processed() + " / " + latest.total()
                            + " items (" + latest.newFindings() + " findings)...");
                }
            }

            @Override
            protected void done() {
                try {
                    int count = get();
                    liveStatusLabel.setText("Analysis complete: scanned Proxy history | Discovered " + count + " new findings.");
                    api.logging().logToOutput("Response Inspector: Proxy history analysis complete. New findings: " + count);
                } catch (Exception ex) {
                    liveStatusLabel.setText("Scan encountered an issue: " + ex.getMessage());
                } finally {
                    progressBar.setVisible(false);
                    loadProxyBtn.setEnabled(true);
                    loadRepeaterBtn.setEnabled(true);
                    if (refreshAllTabsCallback != null) {
                        refreshAllTabsCallback.run();
                    } else {
                        refreshView();
                    }
                }
            }
        };

        worker.execute();
    }

    private void runRepeaterScan() {
        if (category == FindingCategory.PASSWORD && scanEngine.getPasswordScanner().getPasswordCount() == 0) {
            int opt = JOptionPane.showConfirmDialog(
                    this,
                    "No target passwords have been configured yet.\nWould you like to configure passwords before analyzing Repeater traffic?",
                    "Configure Passwords",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE
            );
            if (opt == JOptionPane.YES_OPTION) {
                openPasswordConfigDialog();
            }
        }

        List<HttpRequestResponse> repeaterItems = scanEngine.getRepeaterTraffic();
        if (repeaterItems.isEmpty()) {
            liveStatusLabel.setText("No Repeater traffic recorded yet. Send requests in Repeater or right-click 'Send to Response Inspector'.");
            JOptionPane.showMessageDialog(
                    this,
                    "No Repeater traffic has been captured yet.\n\n"
                    + "Requests sent from Burp Repeater while Response Inspector is active will appear here.\n"
                    + "You can also right-click any request in Repeater or Proxy and choose 'Send to Response Inspector'.",
                    "No Repeater Traffic",
                    JOptionPane.INFORMATION_MESSAGE
            );
            return;
        }

        loadProxyBtn.setEnabled(false);
        loadRepeaterBtn.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(false);
        progressBar.setValue(0);
        liveStatusLabel.setText("Scanning Repeater traffic (static files excluded)...");

        final boolean inScopeOnlyIngestion = inScopeCb.isSelected();

        SwingWorker<Integer, ProgressChunk> worker = new SwingWorker<>() {
            @Override
            protected Integer doInBackground() {
                int total = repeaterItems.size();
                if (total == 0) return 0;

                // Pre-discovery pass for in-scope domains (excluding static resources)
                for (HttpRequestResponse item : repeaterItems) {
                    if (item.request() != null) {
                        var req = item.request();
                        if (ScannerUtils.isStaticResource(req, item.response())) {
                            continue;
                        }
                        String url = req.url();
                        if (api.scope().isInScope(url)) {
                            String host = req.httpService() != null ? req.httpService().host() : "";
                            domainManager.addDomain(host);
                        }
                    }
                }

                int numThreads = Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()));
                ExecutorService executor = Executors.newFixedThreadPool(numThreads);
                AtomicInteger processed = new AtomicInteger(0);
                AtomicInteger newFindings = new AtomicInteger(0);

                try {
                    List<Future<?>> futures = new ArrayList<>(total);
                    for (HttpRequestResponse item : repeaterItems) {
                        if (isCancelled()) break;
                        futures.add(executor.submit(() -> {
                            if (isCancelled()) return;
                            var req = item.request();

                            // 1. Strict Static Resource Exclusion (JS, CSS, PNG, images, fonts, binaries)
                            if (ScannerUtils.isStaticResource(req, item.response())) {
                                int cur = processed.incrementAndGet();
                                if (cur % 25 == 0 || cur == total) {
                                    publish(new ProgressChunk(cur, total, newFindings.get()));
                                }
                                return;
                            }

                            // 2. Dual-stage Ingestion Pre-Filter (when in-scope only is selected)
                            if (inScopeOnlyIngestion && (req == null || !api.scope().isInScope(req.url()))) {
                                int cur = processed.incrementAndGet();
                                if (cur % 25 == 0 || cur == total) {
                                    publish(new ProgressChunk(cur, total, newFindings.get()));
                                }
                                return;
                            }

                            if (item.hasResponse()) {
                                String host = (req != null && req.httpService() != null)
                                        ? req.httpService().host() : "";
                                int added = scanEngine.scanItem(item);
                                if (added > 0 && !host.isBlank()) {
                                    domainManager.registerFinding(host);
                                }
                                newFindings.addAndGet(added);
                            }
                            int cur = processed.incrementAndGet();
                            if (cur % 25 == 0 || cur == total) {
                                publish(new ProgressChunk(cur, total, newFindings.get()));
                            }
                        }));
                    }

                    for (Future<?> f : futures) {
                        if (isCancelled()) break;
                        try { f.get(); } catch (Exception ignored) {}
                    }
                } finally {
                    executor.shutdownNow();
                }

                return newFindings.get();
            }

            @Override
            protected void process(List<ProgressChunk> chunks) {
                if (!chunks.isEmpty()) {
                    ProgressChunk latest = chunks.get(chunks.size() - 1);
                    progressBar.setMaximum(latest.total());
                    progressBar.setValue(latest.processed());
                    liveStatusLabel.setText("Scanning Repeater traffic: " + latest.processed() + " / " + latest.total()
                            + " items (" + latest.newFindings() + " findings)...");
                }
            }

            @Override
            protected void done() {
                try {
                    int count = get();
                    liveStatusLabel.setText("Analysis complete: scanned Repeater traffic | Discovered " + count + " new findings.");
                    api.logging().logToOutput("Response Inspector: Repeater traffic analysis complete. New findings: " + count);
                } catch (Exception ex) {
                    liveStatusLabel.setText("Repeater scan encountered an issue: " + ex.getMessage());
                } finally {
                    progressBar.setVisible(false);
                    loadProxyBtn.setEnabled(true);
                    loadRepeaterBtn.setEnabled(true);
                    if (refreshAllTabsCallback != null) {
                        refreshAllTabsCallback.run();
                    } else {
                        refreshView();
                    }
                }
            }
        };

        worker.execute();
    }

    // ─── Export Findings as TSV ──────────────────────────────────────────────────

    private void exportFindingsToTsv() {
        Set<String> patternFilter = findingTypeFilterBtn.getSelected();

        List<FindingEntry> currentFindings = dataStore.getFilteredEntries(
                searchField.getText(),
                statusFilterBtn.getSelected(),
                contentTypeFilterBtn.getSelected(),
                methodFilterBtn.getSelected(),
                patternFilter,
                inScopeCb.isSelected(),
                url -> api.scope().isInScope(url),
                domainManager
        );

        // Apply comment category post-filter for export
        if (category == FindingCategory.COMMENT && commentCategoryFilterBtn != null) {
            Set<String> selectedCategories = commentCategoryFilterBtn.getSelected();
            if (!selectedCategories.isEmpty()) {
                currentFindings = currentFindings.stream()
                        .filter(e -> selectedCategories.contains(e.matchLocation()))
                        .collect(Collectors.toList());
            }
        }

        if (currentFindings.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No findings available to export.", "Export TSV", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        String defaultFileName = String.format("response_inspector_%s_%s.tsv",
                category.name().toLowerCase(), timestamp);
        fileChooser.setSelectedFile(new File(defaultFileName));
        fileChooser.setDialogTitle("Export Findings as TSV");

        int userSelection = fileChooser.showSaveDialog(this);
        if (userSelection != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File fileToSave = fileChooser.getSelectedFile();
        if (!fileToSave.getName().toLowerCase().endsWith(".tsv")) {
            fileToSave = new File(fileToSave.getParentFile(), fileToSave.getName() + ".tsv");
        }

        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(fileToSave), StandardCharsets.UTF_8))) {
            writer.println("#\tMethod\tStatus\tFinding Type\tMatch Excerpt\tLocation\tLength\tContent-Type\tURL\tTime");

            for (FindingEntry e : currentFindings) {
                writer.printf("%d\t%s\t%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s%n",
                        e.id(),
                        e.method(),
                        e.statusCode(),
                        e.patternName().replace("\t", " "),
                        e.matchValue().replace("\t", " ").replace("\n", " "),
                        e.matchLocation().replace("\t", " "),
                        e.contentLength(),
                        e.contentType().replace("\t", " "),
                        e.url().replace("\t", " "),
                        e.timeString()
                );
            }

            JOptionPane.showMessageDialog(
                    this,
                    String.format("Successfully exported %d findings to:\n%s", currentFindings.size(), fileToSave.getAbsolutePath()),
                    "Export Successful",
                    JOptionPane.INFORMATION_MESSAGE
            );
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(
                    this,
                    "Failed to export TSV: " + ex.getMessage(),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }

    private void setupContextMenu() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem sendRepeater = new JMenuItem("Send to Repeater");
        sendRepeater.addActionListener(e -> {
            int viewRow = table.getSelectedRow();
            if (viewRow != -1) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                FindingEntry entry = tableModel.getEntryAt(modelRow);
                if (entry != null && entry.requestResponse() != null && entry.requestResponse().request() != null) {
                    HttpRequest req = entry.requestResponse().request();
                    String tabName = entry.method() + " " + entry.host() + entry.path();
                    if (tabName.length() > 30) {
                        tabName = tabName.substring(0, 27) + "...";
                    }
                    api.repeater().sendToRepeater(req, tabName);
                }
            }
        });

        JMenuItem sendIntruder = new JMenuItem("Send to Intruder");
        sendIntruder.addActionListener(e -> {
            int viewRow = table.getSelectedRow();
            if (viewRow != -1) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                FindingEntry entry = tableModel.getEntryAt(modelRow);
                if (entry != null && entry.requestResponse() != null && entry.requestResponse().request() != null) {
                    api.intruder().sendToIntruder(entry.requestResponse().request());
                }
            }
        });

        JMenuItem sendOrganizer = new JMenuItem("Send to Organizer");
        sendOrganizer.addActionListener(e -> {
            int viewRow = table.getSelectedRow();
            if (viewRow != -1) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                FindingEntry entry = tableModel.getEntryAt(modelRow);
                if (entry != null && entry.requestResponse() != null) {
                    api.organizer().sendToOrganizer(entry.requestResponse());
                }
            }
        });

        JMenuItem copyMatch = new JMenuItem("Copy Match Excerpt");
        copyMatch.addActionListener(e -> {
            int viewRow = table.getSelectedRow();
            if (viewRow != -1) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                FindingEntry entry = tableModel.getEntryAt(modelRow);
                if (entry != null) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                            new StringSelection(entry.matchValue()), null
                    );
                }
            }
        });

        popup.add(sendRepeater);
        popup.add(sendIntruder);
        popup.add(sendOrganizer);
        popup.addSeparator();

        // Secret-specific context menu items
        if (category == FindingCategory.SECRET) {
            JMenuItem verifySecretItem = new JMenuItem("🧪 Verify Secret (Repeater)");
            verifySecretItem.addActionListener(e -> verifySelectedSecret());
            popup.add(verifySecretItem);

            JMenuItem copySecretItem = new JMenuItem("Copy Secret Value");
            copySecretItem.addActionListener(e -> {
                int viewRow = table.getSelectedRow();
                if (viewRow != -1) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    FindingEntry entry = tableModel.getEntryAt(modelRow);
                    if (entry != null) {
                        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                                new StringSelection(entry.matchValue()), null
                        );
                    }
                }
            });
            popup.add(copySecretItem);
            popup.addSeparator();
        }

        popup.add(copyMatch);
        JMenuItem exportTsvItem = new JMenuItem("Export Findings as TSV...");
        exportTsvItem.addActionListener(e -> exportFindingsToTsv());
        popup.add(exportTsvItem);

        table.setComponentPopupMenu(popup);
    }

    private void setupClipboardShortcut() {
        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_C, mask), "copyTsv");
        table.getActionMap().put("copyTsv", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = table.getSelectedRows();
                if (selectedRows.length == 0) return;

                StringBuilder sb = new StringBuilder();
                for (int c = 0; c < table.getColumnCount(); c++) {
                    sb.append(table.getColumnName(c)).append(c < table.getColumnCount() - 1 ? "\t" : "\n");
                }
                for (int viewRow : selectedRows) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    for (int c = 0; c < table.getColumnCount(); c++) {
                        Object val = tableModel.getValueAt(modelRow, c);
                        sb.append(val != null ? val.toString().replace("\t", " ") : "");
                        sb.append(c < table.getColumnCount() - 1 ? "\t" : "\n");
                    }
                }
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
            }
        });
    }
}
