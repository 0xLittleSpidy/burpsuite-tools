// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.status.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.headerinspector.ProxyHistoryCoordinator;
import com.littlespidy.headerinspector.status.knowledge.HttpDevStatusDoc;
import com.littlespidy.headerinspector.status.knowledge.HttpDevStatusKnowledgeBase;
import com.littlespidy.headerinspector.status.model.StatusCollectorDataStore;
import com.littlespidy.headerinspector.status.model.StatusEndpointRecord;
import com.littlespidy.headerinspector.status.model.StatusGroup;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.net.URI;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Top-level UI tab for Status Collector. Displays all captured HTTP response status codes,
 * classifies them by official IANA/http.dev semantics and classes (1xx-5xx, vendor codes),
 * correlates unique endpoints, methods, and target domains, and embeds native Montoya
 * master-detail HTTP request/response editors with deep-linking and offline status knowledge base.
 *
 * @author littlespidy
 */
public class StatusCollectorTab extends JPanel {

    private final MontoyaApi api;
    private final StatusCollectorDataStore dataStore;
    private ProxyHistoryCoordinator coordinator;

    // Table Models & Components
    private final StatusGroupTableModel groupTableModel = new StatusGroupTableModel();
    private final JTable groupTable = new JTable(groupTableModel);

    private final StatusEndpointTableModel endpointTableModel = new StatusEndpointTableModel();
    private final JTable endpointTable = new JTable(endpointTableModel);

    // Native Montoya HTTP Editors & Documentation Panel
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final StatusDocPanel statusDocPanel = new StatusDocPanel();
    private final JTabbedPane editorTabs = new JTabbedPane();

    // Quick-Info Banner above endpoint table
    private final JPanel quickInfoPanel = new JPanel(new BorderLayout(6, 2));
    private final JLabel quickInfoLabel = new JLabel("Select an HTTP status code to view explanation from http.dev");
    private final JButton quickInfoDocsBtn = new JButton("View Full Explanation ↗");

    // Toolbar Controls
    private final JButton loadHistoryBtn = new JButton("Load Proxy History");
    private final JCheckBox inScopeOnlyCheck = new JCheckBox("In-Scope Only", true);
    private final JComboBox<String> classFilterCombo = new JComboBox<>(new String[]{
            "All Status Codes", "1xx Informational", "2xx Success", "3xx Redirection",
            "4xx Client Error", "5xx Server Error", "Vendor / Extended"
    });
    private final JTextField domainFilterField = new JTextField(12);
    private final JTextField searchFilterField = new JTextField(12);
    private final JButton resetFiltersBtn = new JButton("Reset Filters");
    private final JButton exportTsvBtn = new JButton("Export TSV");
    private final JButton clearDataBtn = new JButton("Clear Data");

    // Status strip
    private final JLabel statusLabel = new JLabel("Ready. Click 'Load Proxy History' to ingest status codes.");
    private final JProgressBar progressBar = new JProgressBar();

    // Debounce Timer for text filtering
    private final Timer debounceTimer;
    private StatusGroup selectedGroup = null;

    public StatusCollectorTab(MontoyaApi api, StatusCollectorDataStore dataStore) {
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

    public void setCoordinator(ProxyHistoryCoordinator coordinator) {
        this.coordinator = coordinator;
    }

    private void initComponents() {
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        // ── 1. Top Panel: Toolbar + Status Strip ──
        JPanel topContainer = new JPanel(new BorderLayout(4, 4));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        inScopeOnlyCheck.setToolTipText("When checked, only responses matching Burp Target Scope are loaded.");
        domainFilterField.setToolTipText("Filter by domain or host (e.g. api.target.com)");
        searchFilterField.setToolTipText("Search across status code, reason phrase, URL, or domain");

        toolbar.add(loadHistoryBtn);
        toolbar.add(inScopeOnlyCheck);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(new JLabel("Class:"));
        toolbar.add(classFilterCombo);
        toolbar.add(new JLabel("Domain:"));
        toolbar.add(domainFilterField);
        toolbar.add(new JLabel("Search:"));
        toolbar.add(searchFilterField);
        toolbar.add(resetFiltersBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(exportTsvBtn);
        toolbar.add(clearDataBtn);

        JPanel statusRow = new JPanel(new BorderLayout(5, 5));
        statusRow.setBorder(BorderFactory.createEmptyBorder(2, 6, 4, 6));
        progressBar.setPreferredSize(new Dimension(220, 16));
        progressBar.setVisible(false);

        statusRow.add(statusLabel, BorderLayout.WEST);
        statusRow.add(progressBar, BorderLayout.EAST);

        topContainer.add(toolbar, BorderLayout.NORTH);
        topContainer.add(statusRow, BorderLayout.SOUTH);
        add(topContainer, BorderLayout.NORTH);

        // ── 2. Tables & Master-Detail Setup ──
        groupTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        groupTable.setRowSorter(new TableRowSorter<>(groupTableModel));

        endpointTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        endpointTable.setRowSorter(new TableRowSorter<>(endpointTableModel));

        JScrollPane groupScroll = new JScrollPane(groupTable);
        groupScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "HTTP Status Codes (Grouped)", TitledBorder.LEFT, TitledBorder.TOP
        ));

        JScrollPane endpointScroll = new JScrollPane(endpointTable);
        endpointScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Endpoints & Responses for Selected Status Code", TitledBorder.LEFT, TitledBorder.TOP
        ));

        // Quick-info Banner configuration
        quickInfoPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(210, 215, 220)),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)
        ));
        quickInfoDocsBtn.setFont(quickInfoDocsBtn.getFont().deriveFont(11f));
        quickInfoDocsBtn.setMargin(new Insets(2, 6, 2, 6));
        quickInfoDocsBtn.setEnabled(false);
        quickInfoDocsBtn.addActionListener(e -> {
            editorTabs.setSelectedComponent(statusDocPanel);
        });
        quickInfoPanel.add(quickInfoLabel, BorderLayout.CENTER);
        quickInfoPanel.add(quickInfoDocsBtn, BorderLayout.EAST);

        JPanel endpointContainer = new JPanel(new BorderLayout(0, 2));
        endpointContainer.add(quickInfoPanel, BorderLayout.NORTH);
        endpointContainer.add(endpointScroll, BorderLayout.CENTER);

        // Horizontal Split: Status Codes on Left, Endpoints on Right
        JSplitPane tablesSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, groupScroll, endpointContainer);
        tablesSplit.setResizeWeight(0.42);

        // Editors Tabbed Pane
        editorTabs.addTab("📤 Request", requestEditor.uiComponent());
        editorTabs.addTab("📥 Response", responseEditor.uiComponent());
        editorTabs.addTab("📖 Status Explained (http.dev)", statusDocPanel);

        // Vertical Split: Tables on Top, Request/Response Editors on Bottom
        JSplitPane rootSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablesSplit, editorTabs);
        rootSplit.setResizeWeight(0.55);

        add(rootSplit, BorderLayout.CENTER);

        setupTableContextMenus();
    }

    private void setupListeners() {
        DocumentListener debouncedDocListener = new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { debounceTimer.restart(); }
            @Override public void removeUpdate(DocumentEvent e)  { debounceTimer.restart(); }
            @Override public void changedUpdate(DocumentEvent e) { debounceTimer.restart(); }
        };

        domainFilterField.getDocument().addDocumentListener(debouncedDocListener);
        searchFilterField.getDocument().addDocumentListener(debouncedDocListener);
        classFilterCombo.addActionListener(e -> refreshView());

        resetFiltersBtn.addActionListener(e -> {
            classFilterCombo.setSelectedIndex(0);
            domainFilterField.setText("");
            searchFilterField.setText("");
            refreshView();
        });

        loadHistoryBtn.addActionListener(e -> {
            if (coordinator != null) {
                coordinator.loadAllProxyHistory(inScopeOnlyCheck.isSelected());
            }
        });

        clearDataBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(
                    this,
                    "Are you sure you want to clear all collected status codes?",
                    "Clear Status Data",
                    JOptionPane.YES_NO_OPTION
            );
            if (confirm == JOptionPane.YES_OPTION) {
                dataStore.clear();
                selectedGroup = null;
                refreshView();
                statusDocPanel.resetView();
                quickInfoLabel.setText("Select an HTTP status code to view explanation from http.dev");
                quickInfoDocsBtn.setEnabled(false);
                requestEditor.setRequest(null);
                responseEditor.setResponse(null);
            }
        });

        exportTsvBtn.addActionListener(e -> exportToTsv());

        // Group Selection Listener
        groupTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = groupTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = groupTable.convertRowIndexToModel(row);
                    selectedGroup = groupTableModel.getGroupAt(modelRow);
                    updateDetailForGroup(selectedGroup);
                } else {
                    selectedGroup = null;
                    endpointTableModel.setRecords(null);
                    quickInfoLabel.setText("Select an HTTP status code to view explanation from http.dev");
                    quickInfoDocsBtn.setEnabled(false);
                    statusDocPanel.resetView();
                }
            }
        });

        // Endpoint Selection Listener (Master-Detail Deep-Linking)
        endpointTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = endpointTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = endpointTable.convertRowIndexToModel(row);
                    StatusEndpointRecord record = endpointTableModel.getRecordAt(modelRow);
                    if (record != null && record.sampleMessage() != null) {
                        displayMessageWithDeepLink(record);
                    }
                }
            }
        });
    }

    private void updateDetailForGroup(StatusGroup group) {
        if (group == null) {
            endpointTableModel.setRecords(null);
            quickInfoLabel.setText("Select an HTTP status code to view explanation from http.dev");
            quickInfoDocsBtn.setEnabled(false);
            statusDocPanel.resetView();
            return;
        }

        endpointTableModel.setRecords(group.getEndpoints());
        statusDocPanel.setStatus(group.statusCode());

        HttpDevStatusDoc doc = HttpDevStatusKnowledgeBase.get(group.statusCode());
        if (doc != null) {
            quickInfoLabel.setText("<html><b>" + group.statusCode() + " " + group.reasonPhrase() + "</b> (" + group.statusClass() + "): "
                    + "<i>" + escapeHtml(doc.summary()) + "</i></html>");
            quickInfoDocsBtn.setEnabled(true);
        } else {
            quickInfoLabel.setText("<html><b>" + group.statusCode() + " " + group.reasonPhrase() + "</b> (" + group.statusClass() + ")</html>");
            quickInfoDocsBtn.setEnabled(false);
        }

        // Auto-select first endpoint if available
        if (endpointTable.getRowCount() > 0) {
            endpointTable.setRowSelectionInterval(0, 0);
        }
    }

    private void displayMessageWithDeepLink(StatusEndpointRecord record) {
        ProxyHttpRequestResponse msg = record.sampleMessage();
        if (msg == null) return;

        HttpRequest req = msg.request();
        HttpResponse resp = msg.response();

        if (req != null) {
            requestEditor.setRequest(req);
        } else {
            requestEditor.setRequest(null);
        }

        if (resp != null) {
            String codeStr = String.valueOf(record.statusCode());
            String respStr = resp.toString();
            // Highlight status code in the HTTP status line (e.g. HTTP/1.1 200 OK)
            int codeIndex = respStr.indexOf(" " + codeStr + " ");
            if (codeIndex >= 0) {
                Range codeRange = Range.range(codeIndex + 1, codeIndex + 1 + codeStr.length());
                HttpResponse markedResp = resp.withMarkers(Marker.marker(codeRange));
                responseEditor.setResponse(markedResp);
            } else {
                responseEditor.setResponse(resp);
            }
        } else {
            responseEditor.setResponse(null);
        }

        if (editorTabs.getSelectedIndex() != 2) {
            editorTabs.setSelectedIndex(1); // Default to response editor for status inspection
        }
    }

    public void refreshView() {
        String classFilter = (String) classFilterCombo.getSelectedItem();
        String domainFilter = domainFilterField.getText().trim();
        String searchFilter = searchFilterField.getText().trim();

        List<StatusGroup> filtered = dataStore.getFilteredGroups(
                domainFilter,
                searchFilter,
                classFilter
        );

        groupTableModel.setGroups(filtered);

        statusLabel.setText(String.format(
                "Displaying %d HTTP Status Codes (%d Total Responses across %d Domains)",
                filtered.size(),
                dataStore.totalResponsesCount(),
                dataStore.totalDomainsCount()
        ));

        if (!filtered.isEmpty()) {
            groupTable.setRowSelectionInterval(0, 0);
        } else {
            endpointTableModel.setRecords(null);
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            statusDocPanel.resetView();
        }
    }

    public void setLoading(boolean loading, String message) {
        SwingUtilities.invokeLater(() -> setLoadingState(loading, message));
    }

    public void setLoadingState(boolean loading, String message) {
        progressBar.setIndeterminate(loading);
        progressBar.setVisible(loading);
        loadHistoryBtn.setEnabled(!loading);
        clearDataBtn.setEnabled(!loading);
        if (message != null && !message.isBlank()) {
            statusLabel.setText(message);
        }
    }

    private void setupTableContextMenus() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem repeaterItem = new JMenuItem("Send to Repeater");
        repeaterItem.addActionListener(e -> {
            StatusEndpointRecord r = getSelectedEndpoint();
            if (r != null && r.sampleMessage() != null && r.sampleMessage().request() != null) {
                api.repeater().sendToRepeater(r.sampleMessage().request(), r.method() + " " + r.path());
            }
        });

        JMenuItem intruderItem = new JMenuItem("Send to Intruder");
        intruderItem.addActionListener(e -> {
            StatusEndpointRecord r = getSelectedEndpoint();
            if (r != null && r.sampleMessage() != null && r.sampleMessage().request() != null) {
                api.intruder().sendToIntruder(r.sampleMessage().request());
            }
        });

        JMenuItem organizerItem = new JMenuItem("Send to Organizer");
        organizerItem.addActionListener(e -> {
            StatusEndpointRecord r = getSelectedEndpoint();
            if (r != null && r.sampleMessage() != null && r.sampleMessage().request() != null) {
                api.organizer().sendToOrganizer(r.sampleMessage().request());
            }
        });

        JMenuItem copyUrlItem = new JMenuItem("Copy URL");
        copyUrlItem.addActionListener(e -> {
            StatusEndpointRecord r = getSelectedEndpoint();
            if (r != null && r.url() != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(r.url()), null);
            }
        });

        JMenuItem copyTsvItem = new JMenuItem("Copy as TSV");
        copyTsvItem.addActionListener(e -> exportToTsv());

        menu.add(repeaterItem);
        menu.add(intruderItem);
        menu.add(organizerItem);
        menu.addSeparator();
        menu.add(copyUrlItem);
        menu.add(copyTsvItem);

        endpointTable.setComponentPopupMenu(menu);
    }

    private StatusEndpointRecord getSelectedEndpoint() {
        int row = endpointTable.getSelectedRow();
        if (row >= 0) {
            int modelRow = endpointTable.convertRowIndexToModel(row);
            return endpointTableModel.getRecordAt(modelRow);
        }
        return null;
    }

    private void exportToTsv() {
        if (selectedGroup == null) {
            JOptionPane.showMessageDialog(this, "Select an HTTP status code to export its endpoints.", "Export TSV", JOptionPane.WARNING_MESSAGE);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Status Code\tMethod\tURL\tDomain\tResponses\n");
        for (StatusEndpointRecord rec : selectedGroup.getEndpoints()) {
            sb.append(selectedGroup.statusCode()).append("\t")
              .append(rec.method()).append("\t")
              .append(rec.url()).append("\t")
              .append(rec.domain()).append("\t")
              .append(rec.occurrences()).append("\n");
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
        JOptionPane.showMessageDialog(this, "Exported " + selectedGroup.uniqueEndpointsCount() + " endpoints for status " + selectedGroup.statusCode() + " to clipboard (TSV format).", "TSV Exported", JOptionPane.INFORMATION_MESSAGE);
    }

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
