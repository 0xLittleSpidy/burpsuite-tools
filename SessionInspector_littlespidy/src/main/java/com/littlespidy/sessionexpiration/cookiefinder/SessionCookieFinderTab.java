// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiefinder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.sessionexpiration.engine.SessionTimerEngine;
import com.littlespidy.sessionexpiration.model.SessionDataStore;
import com.littlespidy.sessionexpiration.model.SessionTask;
import com.littlespidy.sessionexpiration.ui.SessionExpirationTab;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Set;

/**
 * Suite tab for Session Cookie & Auth Header Finder.
 * Enables testers to systematically strip cookies, standard authorization headers,
 * and custom authentication tokens one by one to determine which credentials control the session.
 *
 * @author littlespidy
 */
public class SessionCookieFinderTab extends JPanel {

    private final MontoyaApi api;
    private final SessionDataStore dataStore;
    private final SessionTimerEngine timerEngine;
    private final SessionExpirationTab parentTab;
    private final CookieFinderEngine engine;

    // Target Request State
    private HttpRequest targetRequest;
    private HttpRequestResponse targetRequestResponse;

    // UI Components
    private final JLabel targetLabel = new JLabel("Target: No request loaded (Right-click any request -> '🍪 Send to Session Cookie Finder')");
    private final JTextField customHeadersField = new JTextField("X-Access-Token, X-Auth-Token, X-User-Token, X-API-Key, ApiKey, X-Session-Token", 26);
    private final JCheckBox anonBenchmarkBox = new JCheckBox("Test Anonymous Control (Strip All)", true);
    private final JCheckBox groupTestsBox = new JCheckBox("Test Group Isolation (All Cookies / All Headers)", true);

    private final JButton startBtn = new JButton("▶️ Run Cookie & Auth Finder");
    private final JButton stopBtn = new JButton("⏹️ Stop");
    private final JButton clearBtn = new JButton("Clear");
    private final JButton pasteBtn = new JButton("📋 Paste from Clipboard");

    private final JLabel findingsBanner = new JLabel("Ready. Load an authenticated request to identify session tokens.");
    private final JProgressBar progressBar = new JProgressBar();

    // Table & Inspector
    private final CookieFinderTableModel tableModel = new CookieFinderTableModel();
    private final JTable resultsTable = new JTable(tableModel);

    private final HttpRequestEditor testRequestEditor;
    private final HttpResponseEditor testResponseEditor;
    private final JTabbedPane inspectorTabs = new JTabbedPane();

    public SessionCookieFinderTab(MontoyaApi api, SessionDataStore dataStore,
                                  SessionTimerEngine timerEngine, SessionExpirationTab parentTab) {
        this.api = api;
        this.dataStore = dataStore;
        this.timerEngine = timerEngine;
        this.parentTab = parentTab;
        this.engine = new CookieFinderEngine(api);

        this.testRequestEditor = api.userInterface().createHttpRequestEditor();
        this.testResponseEditor = api.userInterface().createHttpResponseEditor();

        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        add(createTopControlPanel(), BorderLayout.NORTH);
        add(createMainSplitPane(), BorderLayout.CENTER);
        add(createBottomStatusPanel(), BorderLayout.SOUTH);
    }

    private JPanel createTopControlPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));

        // Row 1: Target Header & Load Buttons
        JPanel row1 = new JPanel(new BorderLayout(8, 4));
        targetLabel.setFont(targetLabel.getFont().deriveFont(Font.BOLD, 12f));
        row1.add(targetLabel, BorderLayout.CENTER);

        JPanel row1Buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        pasteBtn.setToolTipText("Load raw HTTP request from system clipboard");
        pasteBtn.addActionListener(e -> loadRequestFromClipboard());

        JButton loadSelectedBtn = new JButton("⏱️ Load from Monitor Task");
        loadSelectedBtn.setToolTipText("Load the request currently selected in Session Monitor tab");
        loadSelectedBtn.addActionListener(e -> loadFromMonitorTab());

        row1Buttons.add(pasteBtn);
        row1Buttons.add(loadSelectedBtn);
        row1.add(row1Buttons, BorderLayout.EAST);

        // Row 2: Configuration & Actions Toolbar
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row2.setBorder(BorderFactory.createTitledBorder("Session Credential Configuration & Actions"));

        row2.add(new JLabel("Suspect Custom Headers:"));
        customHeadersField.setToolTipText("Comma-separated list of custom headers suspect for authentication (e.g. X-Custom-Auth, Token, AppKey)");
        row2.add(customHeadersField);

        row2.add(anonBenchmarkBox);
        row2.add(groupTestsBox);

        startBtn.setFont(startBtn.getFont().deriveFont(Font.BOLD));
        startBtn.addActionListener(e -> runAnalysis());
        row2.add(startBtn);

        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> {
            engine.cancel();
            stopBtn.setEnabled(false);
            findingsBanner.setText("Analysis cancelled by user.");
        });
        row2.add(stopBtn);

        clearBtn.addActionListener(e -> {
            tableModel.clear();
            testRequestEditor.setRequest(null);
            testResponseEditor.setResponse(null);
            findingsBanner.setText("Results cleared.");
            progressBar.setValue(0);
        });
        row2.add(clearBtn);

        panel.add(row1, BorderLayout.NORTH);
        panel.add(row2, BorderLayout.SOUTH);
        return panel;
    }

    private JSplitPane createMainSplitPane() {
        // Results Table Setup
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.setAutoCreateRowSorter(true);

        CookieFinderCellRenderer renderer = new CookieFinderCellRenderer();
        for (int i = 0; i < resultsTable.getColumnCount(); i++) {
            resultsTable.getColumnModel().getColumn(i).setCellRenderer(renderer);
        }

        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(35);  // #
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(160); // Component
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(110); // Type
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(120); // Value preview
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(75);  // Status
        resultsTable.getColumnModel().getColumn(5).setPreferredWidth(75);  // Length
        resultsTable.getColumnModel().getColumn(6).setPreferredWidth(75);  // Delta
        resultsTable.getColumnModel().getColumn(7).setPreferredWidth(180); // Verdict
        resultsTable.getColumnModel().getColumn(8).setPreferredWidth(260); // Signal Details
        resultsTable.getColumnModel().getColumn(9).setPreferredWidth(70);  // Latency

        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onRowSelected();
            }
        });

        setupContextMenu();

        JScrollPane tableScroll = new JScrollPane(resultsTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Systematic Isolation & Fuzzing Results"));

        // Inspector Tabs
        inspectorTabs.addTab("📤 Test Request Sent (Credential Removed)", testRequestEditor.uiComponent());
        inspectorTabs.addTab("📥 Server Response Received", testResponseEditor.uiComponent());
        inspectorTabs.setBorder(BorderFactory.createTitledBorder("Message Inspector for Selected Test Case"));

        // Vertical Split: Top = Results Table, Bottom = Message Inspector
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, inspectorTabs);
        splitPane.setResizeWeight(0.52);
        splitPane.setDividerLocation(310);
        splitPane.setContinuousLayout(true);

        return splitPane;
    }

    private JPanel createBottomStatusPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 4));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        findingsBanner.setFont(findingsBanner.getFont().deriveFont(Font.BOLD, 12f));
        panel.add(findingsBanner, BorderLayout.CENTER);

        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(180, 20));
        panel.add(progressBar, BorderLayout.EAST);

        return panel;
    }

    private void setupContextMenu() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem sendRepeaterItem = new JMenuItem("Send Test Request to Repeater");
        sendRepeaterItem.addActionListener(e -> {
            FinderResult res = getSelectedResult();
            if (res != null && res.getRequestResponse() != null && res.getRequestResponse().request() != null) {
                String tabName = "Finder: " + res.getComponentName();
                api.repeater().sendToRepeater(res.getRequestResponse().request(), tabName);
            }
        });

        JMenuItem sendIntruderItem = new JMenuItem("Send Test Request to Intruder");
        sendIntruderItem.addActionListener(e -> {
            FinderResult res = getSelectedResult();
            if (res != null && res.getRequestResponse() != null && res.getRequestResponse().request() != null) {
                api.intruder().sendToIntruder(res.getRequestResponse().request());
            }
        });

        JMenuItem sendOrganizerItem = new JMenuItem("Send to Organizer");
        sendOrganizerItem.addActionListener(e -> {
            FinderResult res = getSelectedResult();
            if (res != null && res.getRequestResponse() != null) {
                api.organizer().sendToOrganizer(res.getRequestResponse());
            }
        });

        JMenuItem trackExpirationItem = new JMenuItem("⏱️ Track Expiration in Session Monitor");
        trackExpirationItem.setToolTipText("Send this authenticated target request to Session Monitor to track timeout");
        trackExpirationItem.addActionListener(e -> {
            if (targetRequest != null) {
                SessionTask task = new SessionTask(dataStore.nextId(), targetRequest, targetRequestResponse);
                dataStore.addTask(task);
                parentTab.openConfigDialogForTask(task);
            }
        });

        popup.add(sendRepeaterItem);
        popup.add(sendIntruderItem);
        popup.add(sendOrganizerItem);
        popup.addSeparator();
        popup.add(trackExpirationItem);

        resultsTable.setComponentPopupMenu(popup);

        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int r = resultsTable.rowAtPoint(e.getPoint());
                    if (r >= 0 && !resultsTable.isRowSelected(r)) {
                        resultsTable.setRowSelectionInterval(r, r);
                    }
                }
            }
        });
    }

    private FinderResult getSelectedResult() {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow < 0) return null;
        int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
        return tableModel.getResultAt(modelRow);
    }

    private void onRowSelected() {
        FinderResult res = getSelectedResult();
        if (res != null && res.getRequestResponse() != null) {
            HttpRequestResponse rr = res.getRequestResponse();
            if (rr.request() != null) {
                testRequestEditor.setRequest(rr.request());
            } else {
                testRequestEditor.setRequest(null);
            }

            if (rr.hasResponse()) {
                testResponseEditor.setResponse(rr.response());
            } else {
                testResponseEditor.setResponse(null);
            }
            inspectorTabs.setTitleAt(0, "📤 Test Request (" + res.getComponentName() + " removed)");
        } else {
            testRequestEditor.setRequest(null);
            testResponseEditor.setResponse(null);
            inspectorTabs.setTitleAt(0, "📤 Test Request Sent");
        }
    }

    /**
     * Ingests a target request into the cookie finder tab and updates the UI.
     */
    public void setTargetRequest(HttpRequest request, HttpRequestResponse requestResponse) {
        this.targetRequest = request;
        this.targetRequestResponse = requestResponse;

        if (request != null) {
            String method = request.method();
            String url = request.url();
            targetLabel.setText("Target: " + method + " " + url);
            findingsBanner.setText("Loaded target request. Click '▶️ Run Cookie & Auth Finder' to start isolation.");
            testRequestEditor.setRequest(request);
            if (requestResponse != null && requestResponse.hasResponse()) {
                testResponseEditor.setResponse(requestResponse.response());
            }
        }
    }

    public void runAnalysis() {
        if (targetRequest == null) {
            JOptionPane.showMessageDialog(this,
                    "Please load an HTTP request first (Right-click any request -> '🍪 Send to Session Cookie Finder' or click 'Paste from Clipboard').",
                    "No Target Request", JOptionPane.WARNING_MESSAGE);
            return;
        }

        tableModel.clear();
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        progressBar.setValue(0);
        findingsBanner.setText("Starting systematic cookie and header isolation...");

        String customHeaders = customHeadersField.getText();
        boolean anon = anonBenchmarkBox.isSelected();
        boolean groups = groupTestsBox.isSelected();

        engine.startAnalysis(targetRequest, customHeaders, anon, groups, new CookieFinderEngine.ExecutionListener() {
            private int total = 0;
            private int current = 0;

            @Override
            public void onTestStarted(int totalTests) {
                this.total = totalTests;
                progressBar.setMaximum(totalTests);
                progressBar.setValue(0);
                progressBar.setString("0 / " + totalTests);
            }

            @Override
            public void onResultAvailable(FinderResult result) {
                current++;
                progressBar.setValue(current);
                progressBar.setString(current + " / " + total);
                tableModel.addResult(result);

                if (resultsTable.getRowCount() == 1) {
                    resultsTable.setRowSelectionInterval(0, 0);
                }
            }

            @Override
            public void onFinished(List<FinderResult> allResults, Set<String> identifiedSessionTokens) {
                startBtn.setEnabled(true);
                stopBtn.setEnabled(false);
                progressBar.setValue(total);
                progressBar.setString("Completed (" + total + "/" + total + ")");

                if (identifiedSessionTokens.isEmpty()) {
                    findingsBanner.setText("⚠️ Finished: No single cookie or header was uniquely required. Application may accept alternate tokens or rely on IP/client state.");
                } else {
                    findingsBanner.setText("🚨 IDENTIFIED SESSION TOKENS: " + String.join(", ", identifiedSessionTokens));
                }
            }

            @Override
            public void onError(String errorMessage) {
                startBtn.setEnabled(true);
                stopBtn.setEnabled(false);
                findingsBanner.setText("❌ Error: " + errorMessage);
                JOptionPane.showMessageDialog(SessionCookieFinderTab.this,
                        errorMessage, "Analysis Error", JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    private void loadRequestFromClipboard() {
        try {
            String text = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
            if (text != null && !text.trim().isEmpty()) {
                HttpRequest req = HttpRequest.httpRequest(text);
                setTargetRequest(req, null);
            } else {
                JOptionPane.showMessageDialog(this, "Clipboard is empty.", "Clipboard Empty", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Failed to parse HTTP request from clipboard: " + ex.getMessage(),
                    "Invalid Request", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void loadFromMonitorTab() {
        SessionTask task = parentTab.getSelectedTaskFromMonitor();
        if (task != null) {
            setTargetRequest(task.getOriginalRequest(), task.getOriginalRequestResponse());
        } else {
            JOptionPane.showMessageDialog(this,
                    "Please select a session task in the '⏱️ Session Monitor' tab first.",
                    "No Task Selected", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    public void cleanup() {
        if (engine != null) {
            engine.shutdown();
        }
    }

    public void restoreState(HttpRequestResponse target, String customHeaders, List<FinderResult> results) {
        if (target != null) {
            setTargetRequest(target.request(), target);
        }
        if (customHeaders != null && !customHeaders.isBlank()) {
            this.customHeadersField.setText(customHeaders);
        }
        if (results != null && !results.isEmpty()) {
            this.tableModel.setResults(results);
            this.findingsBanner.setText("Restored " + results.size() + " cookie and auth isolation test results.");
        }
    }

    public HttpRequestResponse getTargetRequestResponse() {
        return targetRequestResponse;
    }

    public String getCustomHeaders() {
        return customHeadersField.getText();
    }

    public List<FinderResult> getAllResults() {
        return tableModel.getAllResults();
    }

    public void clearAll() {
        tableModel.clear();
        testRequestEditor.setRequest(null);
        testResponseEditor.setResponse(null);
        targetRequest = null;
        targetRequestResponse = null;
        targetLabel.setText("Target: No request loaded (Right-click any request -> '🍪 Send to Session Cookie Finder')");
        findingsBanner.setText("Ready. Load an authenticated request to identify session tokens.");
        progressBar.setValue(0);
    }
}
