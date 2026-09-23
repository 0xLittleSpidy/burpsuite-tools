// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiestore.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieNameGroup;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieSource;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieStoreDataStore;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieValueRecord;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Locale;

/**
 * Suite tab for Cookie Store.
 * Displays all discovered cookies grouped by cookie name and direction,
 * lists unique cookie values with exact repetition counts, and embeds
 * native Montoya HTTP request/response viewers with marker highlighting.
 *
 * @author littlespidy
 */
public class CookieStoreTab extends JPanel {

    private final MontoyaApi api;
    private final CookieStoreDataStore dataStore;

    // Table Models & Components
    private final CookieGroupTableModel groupTableModel = new CookieGroupTableModel();
    private final JTable groupTable = new JTable(groupTableModel);

    private final CookieValueTableModel valueTableModel = new CookieValueTableModel();
    private final JTable valueTable = new JTable(valueTableModel);
    private final CookieValueHeaderRenderer cookieValueHeaderRenderer = new CookieValueHeaderRenderer();

    // Native Montoya HTTP Editors
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JTabbedPane editorTabs = new JTabbedPane();

    // Toolbar Controls
    private final JButton loadHistoryBtn = new JButton("📥 Load Proxy History");
    private final JCheckBox inScopeOnlyCheck = new JCheckBox("In-Scope Only", true);
    private final JComboBox<String> sourceFilterCombo = new JComboBox<>(new String[]{"All Cookies", "Request Cookies (Cookie)", "Response Cookies (Set-Cookie)"});
    private final JTextField domainFilterField = new JTextField(14);
    private final JTextField searchFilterField = new JTextField(14);
    private final JButton resetFiltersBtn = new JButton("Reset Filters");
    private final JButton exportTsvBtn = new JButton("Export TSV");
    private final JButton clearDataBtn = new JButton("Clear Store");

    // Status strip
    private final JLabel statusLabel = new JLabel("Ready. Click 'Load Proxy History' or right-click requests to store cookies.");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel statsLabel = new JLabel("Cookies: 0 | Unique Values: 0 | Total Seen: 0 | Domains: 0");

    // Debounce Timer for text filtering
    private final Timer debounceTimer;
    private CookieNameGroup selectedGroup = null;

    public CookieStoreTab(MontoyaApi api, CookieStoreDataStore dataStore) {
        super(new BorderLayout(5, 5));
        this.api = api;
        this.dataStore = dataStore;

        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();

        this.debounceTimer = new Timer(300, e -> refreshView());
        this.debounceTimer.setRepeats(false);

        initComponents();
        setupListeners();
    }

    private void initComponents() {
        setBorder(new EmptyBorder(6, 8, 6, 8));

        // ── 1. Top Toolbar ──────────────────────────────────────────────────
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY));

        loadHistoryBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(loadHistoryBtn);
        toolbar.add(inScopeOnlyCheck);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));

        toolbar.add(new JLabel("Source:"));
        toolbar.add(sourceFilterCombo);

        toolbar.add(new JLabel("Domain:"));
        domainFilterField.setToolTipText("Filter by hostname (e.g., example.com)");
        toolbar.add(domainFilterField);

        toolbar.add(new JLabel("Search:"));
        searchFilterField.setToolTipText("Search cookie names, values, or attributes");
        toolbar.add(searchFilterField);

        toolbar.add(resetFiltersBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(exportTsvBtn);
        toolbar.add(clearDataBtn);

        add(toolbar, BorderLayout.NORTH);

        // ── 2. Center SplitPane: Left (Cookie Names) / Right (Values & Editors) ──
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setDividerLocation(400);
        mainSplit.setResizeWeight(0.35);

        // Left Panel: Cookie Names Group Table
        JPanel leftPanel = new JPanel(new BorderLayout(4, 4));
        leftPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Discovered Cookies (Grouped by Name)",
                TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 11)
        ));

        groupTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        groupTable.setRowHeight(22);
        groupTable.getColumnModel().getColumn(0).setPreferredWidth(40);  // #
        groupTable.getColumnModel().getColumn(1).setPreferredWidth(160); // Cookie Name
        groupTable.getColumnModel().getColumn(2).setPreferredWidth(70);  // Source
        groupTable.getColumnModel().getColumn(3).setPreferredWidth(80);  // Unique Values
        groupTable.getColumnModel().getColumn(4).setPreferredWidth(80);  // Total Seen
        groupTable.getColumnModel().getColumn(5).setPreferredWidth(60);  // Domains

        leftPanel.add(new JScrollPane(groupTable), BorderLayout.CENTER);
        leftPanel.add(statsLabel, BorderLayout.SOUTH);

        // Right Panel: Split (Top = Cookie Values & Repetitions, Bottom = Editors)
        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplit.setDividerLocation(260);
        rightSplit.setResizeWeight(0.45);

        JPanel valuePanel = new JPanel(new BorderLayout(4, 4));
        valuePanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Observed Cookie Values & Repetition Count",
                TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 11)
        ));

        valueTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        valueTable.setRowHeight(22);
        valueTable.getColumnModel().getColumn(0).setPreferredWidth(35);  // #
        valueTable.getColumnModel().getColumn(1).setPreferredWidth(220); // Value
        valueTable.getColumnModel().getColumn(1).setHeaderRenderer(cookieValueHeaderRenderer);
        valueTable.getColumnModel().getColumn(2).setPreferredWidth(110); // Repeated (Count)
        valueTable.getColumnModel().getColumn(3).setPreferredWidth(130); // Domains
        valueTable.getColumnModel().getColumn(4).setPreferredWidth(140); // Attributes
        valueTable.getColumnModel().getColumn(5).setPreferredWidth(55);  // Method
        valueTable.getColumnModel().getColumn(6).setPreferredWidth(200); // URL
        valueTable.getColumnModel().getColumn(7).setPreferredWidth(50);  // Status

        valuePanel.add(new JScrollPane(valueTable), BorderLayout.CENTER);

        // Bottom: Montoya Message Editors
        editorTabs.addTab("📤 Request", requestEditor.uiComponent());
        editorTabs.addTab("📥 Response", responseEditor.uiComponent());

        rightSplit.setTopComponent(valuePanel);
        rightSplit.setBottomComponent(editorTabs);

        mainSplit.setLeftComponent(leftPanel);
        mainSplit.setRightComponent(rightSplit);

        add(mainSplit, BorderLayout.CENTER);

        // ── 3. Bottom Status Strip ──────────────────────────────────────────
        JPanel statusPanel = new JPanel(new BorderLayout(6, 2));
        statusPanel.setBorder(new EmptyBorder(4, 2, 2, 2));
        progressBar.setVisible(false);
        progressBar.setPreferredSize(new Dimension(160, 16));

        statusPanel.add(statusLabel, BorderLayout.WEST);
        statusPanel.add(progressBar, BorderLayout.EAST);

        add(statusPanel, BorderLayout.SOUTH);
    }

    private void setupListeners() {
        // Toolbar actions
        loadHistoryBtn.addActionListener(e -> loadProxyHistory());

        inScopeOnlyCheck.addActionListener(e -> refreshView());

        sourceFilterCombo.addActionListener(e -> refreshView());

        DocumentListener dl = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { debounceTimer.restart(); }
            public void removeUpdate(DocumentEvent e) { debounceTimer.restart(); }
            public void changedUpdate(DocumentEvent e) { debounceTimer.restart(); }
        };
        domainFilterField.getDocument().addDocumentListener(dl);
        searchFilterField.getDocument().addDocumentListener(dl);

        resetFiltersBtn.addActionListener(e -> {
            sourceFilterCombo.setSelectedIndex(0);
            domainFilterField.setText("");
            searchFilterField.setText("");
            inScopeOnlyCheck.setSelected(true);
            refreshView();
        });

        exportTsvBtn.addActionListener(e -> {
            String tsv = dataStore.exportToTsv();
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(tsv), null);
            JOptionPane.showMessageDialog(this, "Copied cookie store inventory to clipboard as TSV!", "Export TSV", JOptionPane.INFORMATION_MESSAGE);
        });

        clearDataBtn.addActionListener(e -> {
            dataStore.clear();
            selectedGroup = null;
            refreshView();
            clearEditors();
        });

        // Group Table selection
        groupTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = groupTable.getSelectedRow();
                if (row >= 0) {
                    selectedGroup = groupTableModel.getGroupAt(row);
                    updateValueTableForSelectedGroup();
                } else {
                    selectedGroup = null;
                    valueTableModel.setRecords(null);
                }
            }
        });

        // Value Table selection
        valueTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = valueTable.getSelectedRow();
                if (row >= 0) {
                    CookieValueRecord record = valueTableModel.getRecordAt(row);
                    if (record != null) {
                        displaySampleMessage(record);
                    }
                }
            }
        });

        // Value Table header listener for "Cookie Value" copy button
        valueTable.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (isPointOverCopyButton(e.getPoint())) {
                    cookieValueHeaderRenderer.setButtonState(true, true);
                    valueTable.getTableHeader().repaint();
                }
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (cookieValueHeaderRenderer.isButtonPressed()) {
                    boolean over = isPointOverCopyButton(e.getPoint());
                    cookieValueHeaderRenderer.setButtonState(over, false);
                    valueTable.getTableHeader().repaint();
                    if (over) {
                        copyAllCookieValues();
                    }
                }
            }

            @Override
            public void mouseExited(MouseEvent e) {
                valueTable.getTableHeader().setCursor(Cursor.getDefaultCursor());
                cookieValueHeaderRenderer.setButtonState(false, false);
                valueTable.getTableHeader().repaint();
            }
        });

        valueTable.getTableHeader().addMouseMotionListener(new MouseAdapter() {
            @Override
            public void mouseMoved(MouseEvent e) {
                if (isPointOverCopyButton(e.getPoint())) {
                    valueTable.getTableHeader().setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                    cookieValueHeaderRenderer.setButtonState(true, false);
                    valueTable.getTableHeader().repaint();
                } else {
                    valueTable.getTableHeader().setCursor(Cursor.getDefaultCursor());
                    cookieValueHeaderRenderer.setButtonState(false, false);
                    valueTable.getTableHeader().repaint();
                }
            }
        });

        // Context menu on valueTable for extra convenience
        JPopupMenu valueMenu = new JPopupMenu();
        JMenuItem copyAllItem = new JMenuItem("📋 Copy All Cookie Values (One by One)");
        copyAllItem.addActionListener(e -> copyAllCookieValues());
        valueMenu.add(copyAllItem);

        JMenuItem copySelectedItem = new JMenuItem("📋 Copy Selected Cookie Value");
        copySelectedItem.addActionListener(e -> {
            int row = valueTable.getSelectedRow();
            if (row >= 0) {
                CookieValueRecord record = valueTableModel.getRecordAt(row);
                if (record != null && !record.value().isEmpty()) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(record.value()), null);
                    statusLabel.setText("✓ Copied selected cookie value to clipboard.");
                }
            }
        });
        valueMenu.add(copySelectedItem);
        valueTable.setComponentPopupMenu(valueMenu);
    }

    public void loadProxyHistory() {
        loadHistoryBtn.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        statusLabel.setText("Ingesting cookies from Burp Proxy history...");

        boolean inScopeOnly = inScopeOnlyCheck.isSelected();

        SwingWorker<Integer, Void> worker = new SwingWorker<>() {
            @Override
            protected Integer doInBackground() {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                int ingested = 0;
                for (ProxyHttpRequestResponse item : history) {
                    if (item == null || item.request() == null) continue;
                    if (inScopeOnly && !api.scope().isInScope(item.request().url())) {
                        continue;
                    }
                    dataStore.ingest(item);
                    ingested++;
                }
                return ingested;
            }

            @Override
            protected void done() {
                try {
                    int count = get();
                    statusLabel.setText("Ingestion complete. Processed " + count + " proxy messages.");
                } catch (Exception ex) {
                    statusLabel.setText("Error ingesting proxy history: " + ex.getMessage());
                } finally {
                    progressBar.setVisible(false);
                    loadHistoryBtn.setEnabled(true);
                    refreshView();
                }
            }
        };

        worker.execute();
    }

    public void ingestMessage(HttpRequestResponse message) {
        if (message == null) return;
        dataStore.ingest(message);
        refreshView();
    }

    public void refreshView() {
        CookieSource sourceFilter = null;
        int srcIdx = sourceFilterCombo.getSelectedIndex();
        if (srcIdx == 1) sourceFilter = CookieSource.REQUEST;
        else if (srcIdx == 2) sourceFilter = CookieSource.RESPONSE;

        String domainFilter = domainFilterField.getText().trim();
        String searchFilter = searchFilterField.getText().trim();

        List<CookieNameGroup> filtered = dataStore.getFilteredGroups(sourceFilter, domainFilter, searchFilter);
        groupTableModel.setGroups(filtered);

        // Update stats
        statsLabel.setText("Cookies: " + dataStore.totalCookiesCount() +
                " | Unique Values: " + dataStore.totalUniqueValuesCount() +
                " | Total Seen: " + dataStore.totalOccurrences() +
                " | Domains: " + dataStore.totalDomainsCount());

        // Restore selection if possible
        if (selectedGroup != null) {
            int foundIdx = -1;
            for (int i = 0; i < filtered.size(); i++) {
                if (filtered.get(i).lowercaseName().equals(selectedGroup.lowercaseName())) {
                    foundIdx = i;
                    break;
                }
            }
            if (foundIdx >= 0) {
                groupTable.setRowSelectionInterval(foundIdx, foundIdx);
            } else if (!filtered.isEmpty()) {
                groupTable.setRowSelectionInterval(0, 0);
            } else {
                valueTableModel.setRecords(null);
            }
        } else if (!filtered.isEmpty()) {
            groupTable.setRowSelectionInterval(0, 0);
        } else {
            valueTableModel.setRecords(null);
        }
    }

    private void updateValueTableForSelectedGroup() {
        if (selectedGroup == null) {
            valueTableModel.setRecords(null);
            return;
        }

        String domainFilter = domainFilterField.getText().trim();
        String searchFilter = searchFilterField.getText().trim();
        List<CookieValueRecord> values = selectedGroup.getValuesFiltered(domainFilter, searchFilter);
        valueTableModel.setRecords(values);

        if (!values.isEmpty()) {
            valueTable.setRowSelectionInterval(0, 0);
            displaySampleMessage(values.get(0));
        } else {
            clearEditors();
        }
    }

    private void displaySampleMessage(CookieValueRecord record) {
        HttpRequestResponse message = record.sampleMessage();
        if (message == null) return;

        String cookieName = record.cookieName();
        String value = record.value();

        if (record.source() == CookieSource.REQUEST && message.request() != null) {
            HttpRequest req = message.request();
            editorTabs.setSelectedComponent(requestEditor.uiComponent());

            // Apply highlight marker on the cookie
            String rawStr = req.toString();
            int idx = rawStr.indexOf(cookieName);
            if (idx >= 0) {
                int endIdx = rawStr.indexOf(";", idx);
                if (endIdx < 0) endIdx = rawStr.indexOf("\n", idx);
                if (endIdx < 0) endIdx = idx + cookieName.length();
                if (endIdx > idx) {
                    req = req.withMarkers(Marker.marker(Range.range(idx, endIdx)));
                }
            }

            requestEditor.setRequest(req);
            if (!value.isEmpty()) requestEditor.setSearchExpression(value);

            if (message.hasResponse()) {
                responseEditor.setResponse(message.response());
            }
        } else if (message.hasResponse()) {
            HttpResponse resp = message.response();
            editorTabs.setSelectedComponent(responseEditor.uiComponent());

            // Apply highlight marker on Set-Cookie
            String rawStr = resp.toString();
            int idx = rawStr.indexOf(cookieName);
            if (idx >= 0) {
                int endIdx = rawStr.indexOf("\n", idx);
                if (endIdx < 0) endIdx = idx + cookieName.length();
                if (endIdx > idx) {
                    resp = resp.withMarkers(Marker.marker(Range.range(idx, endIdx)));
                }
            }

            responseEditor.setResponse(resp);
            if (!value.isEmpty()) responseEditor.setSearchExpression(value);

            if (message.request() != null) {
                requestEditor.setRequest(message.request());
            }
        }
    }

    private void clearEditors() {
        // Clear or leave previous messages
    }

    private boolean isPointOverCopyButton(Point p) {
        int col = valueTable.getTableHeader().columnAtPoint(p);
        if (col < 0) return false;
        int modelCol = valueTable.convertColumnIndexToModel(col);
        if (modelCol != 1) return false;

        Rectangle headerRect = valueTable.getTableHeader().getHeaderRect(col);
        JButton btn = cookieValueHeaderRenderer.getCopyButton();
        Dimension btnPref = btn.getPreferredSize();
        int btnWidth = btnPref.width + 6;
        int btnHeight = Math.min(btnPref.height, Math.max(16, headerRect.height - 4));
        int btnX = (headerRect.x + headerRect.width) - btnWidth - 4;
        int btnY = headerRect.y + Math.max(0, (headerRect.height - btnHeight) / 2);

        Rectangle btnBounds = new Rectangle(btnX, btnY, btnWidth, btnHeight);
        return btnBounds.contains(p);
    }

    public void copyAllCookieValues() {
        List<String> values = valueTableModel.getAllCookieValues();
        if (values.isEmpty()) {
            statusLabel.setText("No cookie values to copy for the selected cookie.");
            return;
        }

        String joined = String.join("\n", values);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(joined), null);

        statusLabel.setText("✓ Copied " + values.size() + " cookie value(s) to clipboard (one per line).");

        // Temporary visual feedback on the header button
        cookieValueHeaderRenderer.setCopiedFeedback(true);
        valueTable.getTableHeader().repaint();

        Timer revertTimer = new Timer(1500, evt -> {
            cookieValueHeaderRenderer.setCopiedFeedback(false);
            valueTable.getTableHeader().repaint();
        });
        revertTimer.setRepeats(false);
        revertTimer.start();
    }

    /**
     * Custom TableCellRenderer for the "Cookie Value" column header that displays
     * the column title and an interactive "📋 Copy" button to copy all values.
     */
    private static class CookieValueHeaderRenderer implements TableCellRenderer {
        private final JPanel panel = new JPanel(new BorderLayout(6, 0));
        private final JLabel titleLabel = new JLabel("Cookie Value");
        private final JButton copyBtn = new JButton("📋 Copy");
        private boolean isHovered = false;
        private boolean isPressed = false;

        public CookieValueHeaderRenderer() {
            panel.setOpaque(false);
            titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
            copyBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
            copyBtn.setMargin(new Insets(1, 5, 1, 5));
            copyBtn.setFocusable(false);
            copyBtn.setToolTipText("Copy all cookie values (one per line) to clipboard");

            panel.add(titleLabel, BorderLayout.CENTER);
            panel.add(copyBtn, BorderLayout.EAST);
        }

        public void setCopiedFeedback(boolean copied) {
            if (copied) {
                copyBtn.setText("✓ Copied!");
                copyBtn.setForeground(new Color(0, 140, 0));
            } else {
                copyBtn.setText("📋 Copy");
                copyBtn.setForeground(null);
            }
        }

        public void setButtonState(boolean hovered, boolean pressed) {
            this.isHovered = hovered;
            this.isPressed = pressed;
            copyBtn.getModel().setRollover(hovered);
            copyBtn.getModel().setArmed(pressed);
            copyBtn.getModel().setPressed(pressed);
        }

        public boolean isButtonPressed() {
            return isPressed;
        }

        public JButton getCopyButton() {
            return copyBtn;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int column) {
            TableCellRenderer defaultRenderer = (table != null && table.getTableHeader() != null)
                    ? table.getTableHeader().getDefaultRenderer()
                    : null;
            if (defaultRenderer != null) {
                Component comp = defaultRenderer.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (comp instanceof JComponent jc) {
                    panel.setBorder(jc.getBorder());
                    panel.setBackground(jc.getBackground());
                    panel.setOpaque(jc.isOpaque());
                    titleLabel.setForeground(jc.getForeground());
                }
            }
            if (panel.getBorder() == null) {
                panel.setBorder(UIManager.getBorder("TableHeader.cellBorder"));
            }
            return panel;
        }
    }
}
