// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.attacker.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.jwtcomparator.attacker.engine.JwtAttackEngine;
import com.littlespidy.jwtcomparator.attacker.model.AttackedRequestEntry;
import com.littlespidy.jwtcomparator.attacker.model.TokenAttackResult;
import com.littlespidy.jwtcomparator.model.JWTTokenModel;
import com.littlespidy.jwtcomparator.ui.TokenSlotsContainer;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * Main UI Tab for Token Attacker / Access Matrix.
 * Allows replaying queued requests across all active JWT tokens and inspecting responses side-by-side.
 */
public class TokenAttackerPanel extends JPanel implements TokenSlotsContainer.SlotsChangeListener, JwtAttackEngine.AttackListener {

    private final MontoyaApi api;
    private final TokenSlotsContainer slotsContainer;
    private final JwtAttackEngine attackEngine;
    private final TokenAttackTableModel tableModel;
    private final JTable attackTable;

    // Controls
    private final JButton startButton;
    private final JButton pauseButton;
    private final JButton stopButton;
    private final JButton clearButton;
    private final JButton exportTsvBtn;
    private final JSpinner threadSpinner;
    private final JSpinner delaySpinner;
    private final JCheckBox testUnauthCheckBox;
    private final JProgressBar progressBar;

    // Filters
    private final JTextField searchField;
    private final JComboBox<String> viewFilterCombo;
    private final JLabel statusSummaryLabel;

    // Inspector
    private final JTabbedPane inspectorTabs;
    private final List<EditorTab> currentEditorTabs = new ArrayList<>();

    private int nextRequestId = 1;

    public TokenAttackerPanel(MontoyaApi api, TokenSlotsContainer slotsContainer) {
        this.api = api;
        this.slotsContainer = slotsContainer;
        this.attackEngine = new JwtAttackEngine(api);
        this.tableModel = new TokenAttackTableModel();

        setLayout(new BorderLayout(0, 5));
        setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        // 1. Top Section: Toolbar & Settings
        JPanel topContainer = new JPanel(new BorderLayout(0, 4));

        JPanel mainToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        startButton = new JButton("🚀 Start Attack");
        startButton.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        startButton.setToolTipText("Replay all queued requests with all active JWT tokens");
        startButton.addActionListener(e -> startAttack());

        pauseButton = new JButton("⏸️ Pause");
        pauseButton.setEnabled(false);
        pauseButton.setToolTipText("Pause replay execution");
        pauseButton.addActionListener(e -> {
            if (attackEngine.isPaused()) {
                attackEngine.resumeAttack(this);
                pauseButton.setText("⏸️ Pause");
            } else {
                attackEngine.pauseAttack(this);
                pauseButton.setText("▶️ Resume");
            }
        });

        stopButton = new JButton("⏹️ Stop");
        stopButton.setEnabled(false);
        stopButton.setToolTipText("Stop attack and cancel remaining requests");
        stopButton.addActionListener(e -> attackEngine.stopAttack(this));

        clearButton = new JButton("🧹 Clear Queue");
        clearButton.setToolTipText("Remove all queued requests");
        clearButton.addActionListener(e -> clearQueue());

        exportTsvBtn = new JButton("💾 Download TSV");
        exportTsvBtn.setToolTipText("Download the attack access matrix as TSV file");
        exportTsvBtn.addActionListener(e -> downloadTsvReport());

        JButton copyTsvBtn = new JButton("📋 Copy TSV");
        copyTsvBtn.setToolTipText("Copy the attack access matrix to clipboard");
        copyTsvBtn.addActionListener(e -> copyTsvReport());

        mainToolbar.add(startButton);
        mainToolbar.add(pauseButton);
        mainToolbar.add(stopButton);
        mainToolbar.add(new JSeparator(SwingConstants.VERTICAL));
        mainToolbar.add(clearButton);
        mainToolbar.add(new JSeparator(SwingConstants.VERTICAL));
        mainToolbar.add(exportTsvBtn);
        mainToolbar.add(copyTsvBtn);

        // Right side of main toolbar: Settings
        JPanel settingsToolbar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 2));
        settingsToolbar.add(new JLabel("Threads:"));
        threadSpinner = new JSpinner(new SpinnerNumberModel(4, 1, 32, 1));
        settingsToolbar.add(threadSpinner);

        settingsToolbar.add(new JLabel("Delay (ms):"));
        delaySpinner = new JSpinner(new SpinnerNumberModel(0, 0, 5000, 50));
        settingsToolbar.add(delaySpinner);

        testUnauthCheckBox = new JCheckBox("Probe Unauthenticated", true);
        testUnauthCheckBox.setToolTipText("Include unauthenticated probe (strips Authorization & auth cookies) to verify access control baseline");
        testUnauthCheckBox.addActionListener(e -> updateTableSchema());
        settingsToolbar.add(testUnauthCheckBox);

        JPanel toolbarRow = new JPanel(new BorderLayout());
        toolbarRow.add(mainToolbar, BorderLayout.WEST);
        toolbarRow.add(settingsToolbar, BorderLayout.EAST);
        topContainer.add(toolbarRow, BorderLayout.NORTH);

        // Filter and Progress Row
        JPanel filterRow = new JPanel(new BorderLayout(8, 2));
        filterRow.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));

        JPanel leftFilters = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        leftFilters.add(new JLabel("Search:"));
        searchField = new JTextField(14);
        searchField.setToolTipText("Filter by URL, path, method, or assessment text");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyFilters(); }
            @Override public void removeUpdate(DocumentEvent e) { applyFilters(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilters(); }
        });
        leftFilters.add(searchField);

        leftFilters.add(new JLabel("View:"));
        viewFilterCombo = new JComboBox<>(new String[]{
                "All Requests",
                "Vulnerabilities / Bypasses Only",
                "Accepted by Multiple Tokens",
                "Unauthenticated Allowed"
        });
        viewFilterCombo.addActionListener(e -> applyFilters());
        leftFilters.add(viewFilterCombo);

        statusSummaryLabel = new JLabel("Queue: 0 requests loaded | Ready to attack");
        statusSummaryLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        leftFilters.add(statusSummaryLabel);

        filterRow.add(leftFilters, BorderLayout.WEST);

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setString("Ready");
        progressBar.setPreferredSize(new Dimension(220, 22));
        filterRow.add(progressBar, BorderLayout.EAST);

        topContainer.add(filterRow, BorderLayout.SOUTH);
        add(topContainer, BorderLayout.NORTH);

        // 2. Center: Access Matrix Table
        attackTable = new JTable(tableModel);
        attackTable.setDefaultRenderer(Object.class, new AttackCellRenderer());
        attackTable.setDefaultRenderer(Integer.class, new AttackCellRenderer());
        attackTable.setDefaultRenderer(TokenAttackResult.class, new AttackCellRenderer());
        attackTable.setRowHeight(24);
        attackTable.setAutoCreateRowSorter(true);
        attackTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        attackTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateInspectorSelection();
            }
        });

        setupTableContextMenu();

        JScrollPane tableScroll = new JScrollPane(attackTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Token Access Matrix (Replay Results)"));

        // 3. Bottom: Inspector Panel with Montoya Editors
        inspectorTabs = new JTabbedPane();
        inspectorTabs.setBorder(BorderFactory.createTitledBorder("Request & Response Inspector by Token"));
        inspectorTabs.setPreferredSize(new Dimension(800, 260));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, inspectorTabs);
        splitPane.setResizeWeight(0.55);
        splitPane.setContinuousLayout(true);
        add(splitPane, BorderLayout.CENTER);

        updateTableSchema();
        rebuildInspectorTabs();
    }

    private void setupTableContextMenu() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem deleteItem = new JMenuItem("🗑️ Remove Selected Request");
        deleteItem.addActionListener(e -> {
            int selected = attackTable.getSelectedRow();
            if (selected >= 0) {
                int modelIdx = attackTable.convertRowIndexToModel(selected);
                AttackedRequestEntry entry = tableModel.getEntryAt(modelIdx);
                if (entry != null) {
                    List<AttackedRequestEntry> list = tableModel.getAllEntries();
                    list.remove(entry);
                    tableModel.setRequests(list);
                    updateSummaryStatus();
                }
            }
        });
        popup.add(deleteItem);

        JMenuItem rerunItem = new JMenuItem("🔄 Re-run Selected Request");
        rerunItem.addActionListener(e -> {
            int selected = attackTable.getSelectedRow();
            if (selected >= 0) {
                int modelIdx = attackTable.convertRowIndexToModel(selected);
                AttackedRequestEntry entry = tableModel.getEntryAt(modelIdx);
                if (entry != null && !attackEngine.isRunning()) {
                    List<JWTTokenModel> tokens = slotsContainer != null ? slotsContainer.getTokens() : List.of();
                    int threads = (int) threadSpinner.getValue();
                    int delay = (int) delaySpinner.getValue();
                    boolean unauth = testUnauthCheckBox.isSelected();
                    attackEngine.startAttack(List.of(entry), tokens, unauth, threads, delay, this);
                }
            }
        });
        popup.add(rerunItem);

        popup.addSeparator();

        JMenuItem copyUrlItem = new JMenuItem("📋 Copy URL");
        copyUrlItem.addActionListener(e -> {
            int selected = attackTable.getSelectedRow();
            if (selected >= 0) {
                int modelIdx = attackTable.convertRowIndexToModel(selected);
                AttackedRequestEntry entry = tableModel.getEntryAt(modelIdx);
                if (entry != null && !entry.getUrl().isEmpty()) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(entry.getUrl()), null);
                }
            }
        });
        popup.add(copyUrlItem);

        attackTable.setComponentPopupMenu(popup);
    }

    public synchronized void addRequests(List<HttpRequestResponse> items) {
        if (items == null || items.isEmpty()) return;

        List<AttackedRequestEntry> newEntries = new ArrayList<>();
        for (HttpRequestResponse item : items) {
            newEntries.add(AttackedRequestEntry.from(nextRequestId++, item));
        }

        tableModel.addRequests(newEntries);
        updateSummaryStatus();

        if (attackTable.getSelectedRow() < 0 && tableModel.getRowCount() > 0) {
            attackTable.setRowSelectionInterval(0, 0);
        }
    }

    public synchronized void addRequest(HttpRequest request, HttpResponse response) {
        if (request == null) return;
        AttackedRequestEntry entry = new AttackedRequestEntry(nextRequestId++, request, response);
        tableModel.addRequest(entry);
        updateSummaryStatus();
    }

    public synchronized void clearQueue() {
        if (attackEngine.isRunning()) {
            int res = JOptionPane.showConfirmDialog(this,
                    "An attack is currently running. Stop attack and clear queue?",
                    "Confirm Clear", JOptionPane.YES_NO_OPTION);
            if (res != JOptionPane.YES_OPTION) return;
            attackEngine.stopAttack(this);
        }
        tableModel.clear();
        nextRequestId = 1;
        progressBar.setValue(0);
        progressBar.setString("Ready");
        updateSummaryStatus();
        clearInspector();
    }

    private void startAttack() {
        List<AttackedRequestEntry> entries = tableModel.getAllEntries();
        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "No requests in queue. Right-click any HTTP request in Burp (Proxy/Repeater/Logger)\nand select '⚔️ Send Request to Token Attacker'.",
                    "Queue Empty", JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<JWTTokenModel> tokens = slotsContainer != null ? slotsContainer.getTokens() : List.of();
        boolean testUnauth = testUnauthCheckBox.isSelected();

        // Check if at least one token is valid or unauth is enabled
        boolean hasValidToken = false;
        for (JWTTokenModel tm : tokens) {
            if (tm.getRawToken() != null && !tm.getRawToken().trim().isEmpty()) {
                hasValidToken = true;
                break;
            }
        }

        if (!hasValidToken && !testUnauth) {
            JOptionPane.showMessageDialog(this,
                    "No active JWT tokens loaded in Token Slots, and 'Probe Unauthenticated' is unchecked.\nPaste a JWT in Tab 1 (JWT Comparator) or enable Unauthenticated probe.",
                    "No Tokens Configured", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int threads = (int) threadSpinner.getValue();
        int delay = (int) delaySpinner.getValue();

        updateTableSchema();
        attackEngine.startAttack(entries, tokens, testUnauth, threads, delay, this);
    }

    public synchronized void updateTableSchema() {
        List<JWTTokenModel> tokens = slotsContainer != null ? slotsContainer.getTokens() : List.of();
        boolean testUnauth = testUnauthCheckBox.isSelected();
        tableModel.updateSchema(tokens, testUnauth);
        rebuildInspectorTabs();
    }

    private synchronized void rebuildInspectorTabs() {
        int selectedTabIdx = Math.max(0, inspectorTabs.getSelectedIndex());
        inspectorTabs.removeAll();
        currentEditorTabs.clear();

        // 1. Baseline tab (Original Request / Response)
        EditorTab baselineTab = createEditorTab("Baseline (Orig)", -1);
        currentEditorTabs.add(baselineTab);
        inspectorTabs.addTab(baselineTab.title, baselineTab.component);

        // 2. Tabs for each active token slot
        if (slotsContainer != null) {
            List<JWTTokenModel> tokens = slotsContainer.getTokens();
            for (JWTTokenModel tm : tokens) {
                if (tm.getRawToken() != null && !tm.getRawToken().trim().isEmpty()) {
                    String title = "T" + tm.getSlotIndex() + ": " + tm.getLabel();
                    EditorTab tab = createEditorTab(title, tm.getSlotIndex());
                    currentEditorTabs.add(tab);
                    inspectorTabs.addTab(tab.title, tab.component);
                }
            }
        }

        // 3. Unauthenticated probe tab
        if (testUnauthCheckBox.isSelected()) {
            EditorTab unauthTab = createEditorTab("Unauthenticated", 0);
            currentEditorTabs.add(unauthTab);
            inspectorTabs.addTab(unauthTab.title, unauthTab.component);
        }

        if (selectedTabIdx < inspectorTabs.getTabCount()) {
            inspectorTabs.setSelectedIndex(selectedTabIdx);
        }

        updateInspectorSelection();
    }

    private EditorTab createEditorTab(String title, int slotIndex) {
        HttpRequestEditor reqEditor = null;
        HttpResponseEditor respEditor = null;
        JTextArea reqArea = null;
        JTextArea respArea = null;
        Component content;

        if (api != null && api.userInterface() != null) {
            try {
                reqEditor = api.userInterface().createHttpRequestEditor();
                respEditor = api.userInterface().createHttpResponseEditor();

                JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                        reqEditor.uiComponent(), respEditor.uiComponent());
                split.setResizeWeight(0.5);
                split.setContinuousLayout(true);
                content = split;
            } catch (Exception ex) {
                // Fallback for headless environments or unsupported UI calls
                reqArea = new JTextArea();
                reqArea.setEditable(false);
                respArea = new JTextArea();
                respArea.setEditable(false);
                JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                        new JScrollPane(reqArea), new JScrollPane(respArea));
                split.setResizeWeight(0.5);
                content = split;
            }
        } else {
            reqArea = new JTextArea();
            reqArea.setEditable(false);
            respArea = new JTextArea();
            respArea.setEditable(false);
            JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                    new JScrollPane(reqArea), new JScrollPane(respArea));
            split.setResizeWeight(0.5);
            content = split;
        }

        return new EditorTab(title, slotIndex, content, reqEditor, respEditor, reqArea, respArea);
    }

    private synchronized void updateInspectorSelection() {
        int selected = attackTable.getSelectedRow();
        if (selected < 0) {
            clearInspector();
            return;
        }

        int modelIdx = attackTable.convertRowIndexToModel(selected);
        AttackedRequestEntry entry = tableModel.getEntryAt(modelIdx);
        if (entry == null) {
            clearInspector();
            return;
        }

        for (EditorTab tab : currentEditorTabs) {
            if (tab.slotIndex == -1) {
                // Baseline original
                tab.setRequest(entry.getOriginalRequest());
                tab.setResponse(entry.getOriginalResponse());
            } else if (tab.slotIndex == 0) {
                // Unauthenticated probe
                TokenAttackResult unauth = entry.getUnauthenticatedResult();
                tab.setRequest(unauth != null ? unauth.getRequest() : null);
                tab.setResponse(unauth != null ? unauth.getResponse() : null);
            } else {
                // Token probe
                TokenAttackResult res = entry.getTokenResult(tab.slotIndex);
                tab.setRequest(res != null ? res.getRequest() : null);
                tab.setResponse(res != null ? res.getResponse() : null);
            }
        }
    }

    private synchronized void clearInspector() {
        for (EditorTab tab : currentEditorTabs) {
            tab.setRequest(null);
            tab.setResponse(null);
        }
    }

    private void applyFilters() {
        String view = (String) viewFilterCombo.getSelectedItem();
        String search = searchField.getText();
        tableModel.applyFilter(view, search);
        updateSummaryStatus();
    }

    private void updateSummaryStatus() {
        int total = tableModel.getAllEntries().size();
        int bolaCount = 0;
        int unauthCount = 0;
        int enforcedCount = 0;

        for (AttackedRequestEntry entry : tableModel.getAllEntries()) {
            String assess = entry.getAssessment();
            if (assess.contains("🚨")) {
                bolaCount++;
            } else if (assess.contains("⚠️")) {
                unauthCount++;
            } else if (assess.contains("✔")) {
                enforcedCount++;
            }
        }

        if (total == 0) {
            statusSummaryLabel.setText("Queue: 0 requests loaded | Ready to attack");
        } else if (bolaCount > 0 || unauthCount > 0) {
            statusSummaryLabel.setText(String.format("Queue: %d requests | 🚨 %d Potential BOLA | ⚠️ %d Unauth Access | ✔ %d Enforced",
                    total, bolaCount, unauthCount, enforcedCount));
        } else {
            statusSummaryLabel.setText(String.format("Queue: %d requests | ✔ %d Enforced / Pending", total, total));
        }
    }

    // --- SlotsChangeListener ---
    @Override
    public void onSlotsChanged() {
        SwingUtilities.invokeLater(() -> {
            updateTableSchema();
        });
    }

    // --- AttackListener ---
    @Override
    public void onProgress(int completedTasks, int totalTasks) {
        SwingUtilities.invokeLater(() -> {
            if (totalTasks > 0) {
                int pct = (completedTasks * 100) / totalTasks;
                progressBar.setValue(pct);
                progressBar.setString(String.format("%d / %d tasks (%d%%)", completedTasks, totalTasks, pct));
            }
        });
    }

    @Override
    public void onRequestUpdated(AttackedRequestEntry entry) {
        SwingUtilities.invokeLater(() -> {
            int row = tableModel.getEntryRowIndex(entry);
            if (row >= 0) {
                tableModel.fireTableRowsUpdated(row, row);
            }
            updateSummaryStatus();

            int selected = attackTable.getSelectedRow();
            if (selected >= 0 && attackTable.convertRowIndexToModel(selected) == row) {
                updateInspectorSelection();
            }
        });
    }

    @Override
    public void onAttackFinished() {
        SwingUtilities.invokeLater(() -> {
            progressBar.setString("Attack Finished");
            updateSummaryStatus();
        });
    }

    @Override
    public void onAttackStatusChanged(boolean isRunning, boolean isPaused) {
        SwingUtilities.invokeLater(() -> {
            startButton.setEnabled(!isRunning);
            clearButton.setEnabled(!isRunning);
            pauseButton.setEnabled(isRunning);
            stopButton.setEnabled(isRunning);

            if (!isRunning) {
                pauseButton.setText("⏸️ Pause");
            } else if (isPaused) {
                pauseButton.setText("▶️ Resume");
                progressBar.setString("Paused");
            }
        });
    }

    // --- TSV Export ---
    public String generateTsvContent() {
        StringBuilder sb = new StringBuilder();
        int colCount = tableModel.getColumnCount();

        for (int c = 0; c < colCount; c++) {
            sb.append(tableModel.getColumnName(c));
            if (c < colCount - 1) sb.append("\t");
        }
        sb.append("\n");

        for (int r = 0; r < tableModel.getRowCount(); r++) {
            for (int c = 0; c < colCount; c++) {
                Object val = tableModel.getValueAt(r, c);
                String str = "";
                if (val instanceof TokenAttackResult) {
                    str = ((TokenAttackResult) val).getDisplayText();
                } else if (val != null) {
                    str = val.toString();
                }
                sb.append(str.replace("\t", " ").replace("\n", " "));
                if (c < colCount - 1) sb.append("\t");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    public void copyTsvReport() {
        String tsv = generateTsvContent();
        if (GraphicsEnvironment.isHeadless()) return;

        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(tsv), null);
        JOptionPane.showMessageDialog(this,
                "Token Attacker matrix copied to clipboard as TSV!",
                "TSV Copied", JOptionPane.INFORMATION_MESSAGE);
    }

    public void downloadTsvReport() {
        if (GraphicsEnvironment.isHeadless()) return;

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Token Access Matrix as TSV");
        chooser.setSelectedFile(new File("jwt-access-matrix.tsv"));
        chooser.setFileFilter(new FileNameExtensionFilter("Tab-Separated Values (*.tsv)", "tsv"));

        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            if (!file.getName().toLowerCase().endsWith(".tsv")) {
                file = new File(file.getAbsolutePath() + ".tsv");
            }
            try {
                String tsv = generateTsvContent();
                Files.writeString(file.toPath(), tsv, StandardCharsets.UTF_8);
                JOptionPane.showMessageDialog(this,
                        "Saved access matrix report to:\n" + file.getAbsolutePath(),
                        "TSV Saved", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Error writing TSV: " + ex.getMessage(),
                        "Save Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public TokenAttackTableModel getTableModel() {
        return tableModel;
    }

    // --- Helper class for Inspector Tab ---
    private static class EditorTab {
        final String title;
        final int slotIndex;
        final Component component;
        final HttpRequestEditor requestEditor;
        final HttpResponseEditor responseEditor;
        final JTextArea fallbackReqArea;
        final JTextArea fallbackRespArea;

        EditorTab(String title, int slotIndex, Component component,
                  HttpRequestEditor requestEditor, HttpResponseEditor responseEditor,
                  JTextArea fallbackReqArea, JTextArea fallbackRespArea) {
            this.title = title;
            this.slotIndex = slotIndex;
            this.component = component;
            this.requestEditor = requestEditor;
            this.responseEditor = responseEditor;
            this.fallbackReqArea = fallbackReqArea;
            this.fallbackRespArea = fallbackRespArea;
        }

        void setRequest(HttpRequest req) {
            if (requestEditor != null) {
                requestEditor.setRequest(req);
            } else if (fallbackReqArea != null) {
                fallbackReqArea.setText(req != null ? req.toString() : "");
                fallbackReqArea.setCaretPosition(0);
            }
        }

        void setResponse(HttpResponse resp) {
            if (responseEditor != null) {
                responseEditor.setResponse(resp);
            } else if (fallbackRespArea != null) {
                fallbackRespArea.setText(resp != null ? resp.toString() : "");
                fallbackRespArea.setCaretPosition(0);
            }
        }
    }
}
