// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.sessionexpiration.engine.SessionTimerEngine;
import com.littlespidy.sessionexpiration.model.ProbeResult;
import com.littlespidy.sessionexpiration.model.SessionDataStore;
import com.littlespidy.sessionexpiration.model.SessionState;
import com.littlespidy.sessionexpiration.model.SessionTask;
import com.littlespidy.sessionexpiration.model.TimerInterval;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Main Suite Tab UI for Session Expiration Checker.
 *
 * Provides a top-level tab hierarchy:
 * 1. 📖 Welcome & Guide - Onboarding, workflow playbooks, and methodology cards.
 * 2. ⏱️ Session Monitor - Master-detail dashboard with real-time countdowns, triage filters,
 *    side-by-side milestone history, and dedicated Montoya editors for Probe Request, Probe Response,
 *    Baseline Request, and Baseline Response.
 *
 * @author littlespidy
 */
public class SessionExpirationTab extends JPanel {

    private final MontoyaApi api;
    private final SessionDataStore dataStore;
    private final SessionTimerEngine timerEngine;

    // Root Tabbed Pane
    private final JTabbedPane rootTabbedPane = new JTabbedPane();
    private final WelcomeGuidePanel welcomeGuidePanel;

    // Master Table Components
    private final SessionTableModel sessionTableModel = new SessionTableModel();
    private final JTable sessionTable = new JTable(sessionTableModel);

    // Detail Components
    private final ProbeHistoryTableModel probeHistoryModel = new ProbeHistoryTableModel();
    private final JTable probeHistoryTable = new JTable(probeHistoryModel);

    // Dedicated Montoya Editors
    private final HttpRequestEditor probeRequestEditor;
    private final HttpResponseEditor probeResponseEditor;
    private final HttpRequestEditor baselineRequestEditor;
    private final HttpResponseEditor baselineResponseEditor;
    private final JTabbedPane inspectorTabs = new JTabbedPane();

    // Filters
    private final JTextField domainField = new JTextField(12);
    private final MultiSelectFilterButton methodFilterBtn;
    private final JComboBox<String> statusFilterCombo;
    private final JComboBox<String> stateFilterCombo;
    private final JLabel statsLabel = new JLabel("Total: 0 | Active: 0 | Expired: 0 | Pending: 0");

    // Timers
    private final Timer filterDebounceTimer;
    private final Timer countdownTimer;

    public SessionExpirationTab(MontoyaApi api, SessionDataStore dataStore, SessionTimerEngine timerEngine) {
        this.api = api;
        this.dataStore = dataStore;
        this.timerEngine = timerEngine;

        setLayout(new BorderLayout());

        // Create Montoya Editors
        this.probeRequestEditor = api.userInterface().createHttpRequestEditor();
        this.probeResponseEditor = api.userInterface().createHttpResponseEditor();
        this.baselineRequestEditor = api.userInterface().createHttpRequestEditor();
        this.baselineResponseEditor = api.userInterface().createHttpResponseEditor();

        // 1. Debounce Timer (300ms) for filter text fields
        this.filterDebounceTimer = new Timer(300, e -> refreshView());
        this.filterDebounceTimer.setRepeats(false);

        // 2. Countdown Timer (1000ms) to tick remaining times
        this.countdownTimer = new Timer(1000, e -> sessionTableModel.updateCountdowns());
        this.countdownTimer.start();

        // 3. Method Filter
        this.methodFilterBtn = new MultiSelectFilterButton(
                "Method",
                List.of("All Methods", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"),
                sel -> refreshView()
        );

        // 4. Status Filter
        this.statusFilterCombo = new JComboBox<>(new String[]{
                "All Statuses", "2xx Success", "200 OK", "3xx Redirection",
                "4xx Client Error", "401 Unauthorized", "403 Forbidden", "5xx Server Error"
        });
        this.statusFilterCombo.setEditable(true);
        this.statusFilterCombo.addActionListener(e -> triggerDebouncedFilter());

        // 5. State Filter
        this.stateFilterCombo = new JComboBox<>(new String[]{
                "All States", "Active", "Expired", "Pending", "Running", "Completed", "Cancelled"
        });
        this.stateFilterCombo.addActionListener(e -> refreshView());

        // 6. Assemble Session Monitor Panel
        JPanel monitorPanel = new JPanel(new BorderLayout(5, 5));
        monitorPanel.add(createToolbar(), BorderLayout.NORTH);
        monitorPanel.add(createMainSplitPane(), BorderLayout.CENTER);

        // 7. Assemble Root Tabbed Pane
        this.welcomeGuidePanel = new WelcomeGuidePanel(this);
        rootTabbedPane.addTab("📖 Welcome & Guide", welcomeGuidePanel);
        rootTabbedPane.addTab("⏱️ Session Monitor", monitorPanel);

        add(rootTabbedPane, BorderLayout.CENTER);

        // Register DataStore listener
        this.dataStore.addChangeListener(this::refreshView);

        refreshView();
    }

    public void selectWelcomeTab() {
        rootTabbedPane.setSelectedIndex(0);
    }

    public void selectMonitorTab() {
        rootTabbedPane.setSelectedIndex(1);
    }

    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        domainField.setToolTipText("Filter by host/domain (e.g. target.com, *.target.com)");
        domainField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { triggerDebouncedFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { triggerDebouncedFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { triggerDebouncedFilter(); }
        });

        JButton resetBtn = new JButton("Reset Filters");
        resetBtn.setToolTipText("Reset all active filters");
        resetBtn.addActionListener(e -> {
            domainField.setText("");
            methodFilterBtn.clearSelection();
            statusFilterCombo.setSelectedIndex(0);
            stateFilterCombo.setSelectedIndex(0);
            refreshView();
        });

        JButton clearAllBtn = new JButton("Clear All");
        clearAllBtn.setToolTipText("Stop all timers and remove all session tasks");
        clearAllBtn.addActionListener(e -> {
            int conf = JOptionPane.showConfirmDialog(this,
                    "Stop and clear all session tasks?",
                    "Confirm Clear All", JOptionPane.YES_NO_OPTION);
            if (conf == JOptionPane.YES_OPTION) {
                dataStore.clearAll();
            }
        });

        statsLabel.setFont(statsLabel.getFont().deriveFont(Font.ITALIC, 11f));

        toolbar.add(new JLabel("Domain:"));
        toolbar.add(domainField);
        toolbar.add(methodFilterBtn);
        toolbar.add(new JLabel("Status:"));
        toolbar.add(statusFilterCombo);
        toolbar.add(new JLabel("State:"));
        toolbar.add(stateFilterCombo);
        toolbar.add(resetBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(clearAllBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(statsLabel);

        return toolbar;
    }

    private JSplitPane createMainSplitPane() {
        // Master Table Setup
        sessionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        sessionTable.setAutoCreateRowSorter(true);

        StatusCellRenderer statusRenderer = new StatusCellRenderer();
        sessionTable.getColumnModel().getColumn(4).setCellRenderer(statusRenderer); // Baseline
        sessionTable.getColumnModel().getColumn(5).setCellRenderer(statusRenderer); // State
        sessionTable.getColumnModel().getColumn(8).setCellRenderer(statusRenderer); // Verdict

        sessionTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onSessionSelected();
            }
        });

        setupSessionContextMenu();

        JScrollPane masterScroll = new JScrollPane(sessionTable);
        masterScroll.setBorder(BorderFactory.createTitledBorder("Tracked Sessions"));

        // Detail View: Milestones Table
        probeHistoryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        probeHistoryTable.getColumnModel().getColumn(4).setCellRenderer(statusRenderer); // Interval Status
        probeHistoryTable.getColumnModel().getColumn(5).setCellRenderer(statusRenderer); // HTTP Status
        probeHistoryTable.getColumnModel().getColumn(8).setCellRenderer(statusRenderer); // Signal

        probeHistoryTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onMilestoneSelected();
            }
        });

        // Double-click listener on milestone row to auto-switch to Probe Response tab
        probeHistoryTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    inspectorTabs.setSelectedIndex(1); // Switch to Probe Response tab
                }
            }
        });

        setupProbeContextMenu();

        JScrollPane historyScroll = new JScrollPane(probeHistoryTable);
        historyScroll.setBorder(BorderFactory.createTitledBorder("Milestones & History"));

        // Detail View: Tabbed Message Editors
        inspectorTabs.addTab("📤 Probe Request", probeRequestEditor.uiComponent());
        inspectorTabs.addTab("📥 Probe Response", probeResponseEditor.uiComponent());
        inspectorTabs.addTab("🎯 Baseline Request", baselineRequestEditor.uiComponent());
        inspectorTabs.addTab("🎯 Baseline Response", baselineResponseEditor.uiComponent());
        inspectorTabs.setBorder(BorderFactory.createTitledBorder("Request & Response Inspector"));

        // Horizontal Split: Left = Milestones Table, Right = Message Editors
        JSplitPane detailSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, historyScroll, inspectorTabs);
        detailSplitPane.setResizeWeight(0.38);
        detailSplitPane.setDividerLocation(380);
        detailSplitPane.setContinuousLayout(true);

        // Vertical Split: Top = Tracked Sessions, Bottom = Detail Split
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, masterScroll, detailSplitPane);
        splitPane.setResizeWeight(0.45);
        splitPane.setDividerLocation(260);
        splitPane.setContinuousLayout(true);

        return splitPane;
    }

    private void setupSessionContextMenu() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem runNowItem = new JMenuItem("▶️ Run Probe Now");
        runNowItem.addActionListener(e -> {
            SessionTask task = getSelectedTask();
            if (task != null) {
                TimerInterval next = task.getNextScheduledInterval();
                if (next == null && !task.getIntervals().isEmpty()) {
                    next = task.getIntervals().get(task.getIntervals().size() - 1);
                }
                if (next != null) {
                    timerEngine.runProbeNow(task, next, this::refreshView);
                }
            }
        });

        JMenuItem refreshBaselineItem = new JMenuItem("🔄 Refresh Baseline");
        refreshBaselineItem.addActionListener(e -> {
            SessionTask task = getSelectedTask();
            if (task != null) {
                timerEngine.refreshBaseline(task, this::refreshView);
            }
        });

        JMenuItem configTimersItem = new JMenuItem("⏱️ Configure Timers...");
        configTimersItem.addActionListener(e -> {
            SessionTask task = getSelectedTask();
            if (task != null) {
                openConfigDialogForTask(task);
            }
        });

        JMenuItem cancelTimersItem = new JMenuItem("⏹️ Cancel Timers");
        cancelTimersItem.addActionListener(e -> {
            SessionTask task = getSelectedTask();
            if (task != null) {
                timerEngine.cancelTask(task, this::refreshView);
            }
        });

        JMenuItem sendRepeaterItem = new JMenuItem("Send to Repeater");
        sendRepeaterItem.addActionListener(e -> {
            SessionTask task = getSelectedTask();
            if (task != null && task.getOriginalRequest() != null) {
                String tabName = task.getMethod() + " " + task.getHost() + task.getPath();
                api.repeater().sendToRepeater(task.getOriginalRequest(), tabName);
            }
        });

        JMenuItem sendIntruderItem = new JMenuItem("Send to Intruder");
        sendIntruderItem.addActionListener(e -> {
            SessionTask task = getSelectedTask();
            if (task != null && task.getOriginalRequest() != null) {
                api.intruder().sendToIntruder(task.getOriginalRequest());
            }
        });

        JMenuItem sendOrganizerItem = new JMenuItem("Send to Organizer");
        sendOrganizerItem.addActionListener(e -> {
            SessionTask task = getSelectedTask();
            if (task != null) {
                HttpRequestResponse rr = null;
                ProbeResult pr = task.getLatestProbeResult();
                if (pr != null && pr.getRequestResponse() != null) {
                    rr = pr.getRequestResponse();
                } else if (task.getBaseline() != null) {
                    rr = task.getBaseline();
                }
                if (rr != null) {
                    api.organizer().sendToOrganizer(rr);
                }
            }
        });

        JMenuItem deleteItem = new JMenuItem("🗑️ Delete Session");
        deleteItem.addActionListener(e -> {
            SessionTask task = getSelectedTask();
            if (task != null) {
                task.cancelRemainingFutures();
                dataStore.removeTask(task.getId());
            }
        });

        popup.add(runNowItem);
        popup.add(refreshBaselineItem);
        popup.add(configTimersItem);
        popup.add(cancelTimersItem);
        popup.addSeparator();
        popup.add(sendRepeaterItem);
        popup.add(sendIntruderItem);
        popup.add(sendOrganizerItem);
        popup.addSeparator();
        popup.add(deleteItem);

        sessionTable.setComponentPopupMenu(popup);

        sessionTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = sessionTable.rowAtPoint(e.getPoint());
                    if (row >= 0 && !sessionTable.isRowSelected(row)) {
                        sessionTable.setRowSelectionInterval(row, row);
                    }
                }
            }
        });
    }

    private void setupProbeContextMenu() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem runThisItem = new JMenuItem("▶️ Run This Milestone Now");
        runThisItem.addActionListener(e -> {
            SessionTask task = getSelectedTask();
            int selectedRow = probeHistoryTable.getSelectedRow();
            if (task != null && selectedRow >= 0) {
                int modelRow = probeHistoryTable.convertRowIndexToModel(selectedRow);
                TimerInterval interval = probeHistoryModel.getIntervalAt(modelRow);
                if (interval != null) {
                    timerEngine.runProbeNow(task, interval, this::refreshView);
                }
            }
        });

        JMenuItem sendRepeaterItem = new JMenuItem("Send Probe to Repeater");
        sendRepeaterItem.addActionListener(e -> {
            SessionTask task = getSelectedTask();
            int selectedRow = probeHistoryTable.getSelectedRow();
            if (task != null && selectedRow >= 0) {
                int modelRow = probeHistoryTable.convertRowIndexToModel(selectedRow);
                TimerInterval interval = probeHistoryModel.getIntervalAt(modelRow);
                if (interval != null && interval.getProbeResult() != null
                        && interval.getProbeResult().getRequestResponse() != null) {
                    String tabName = interval.getLabel() + " " + task.getMethod() + " " + task.getPath();
                    api.repeater().sendToRepeater(interval.getProbeResult().getRequestResponse().request(), tabName);
                }
            }
        });

        popup.add(runThisItem);
        popup.add(sendRepeaterItem);
        probeHistoryTable.setComponentPopupMenu(popup);
    }

    private SessionTask getSelectedTask() {
        int selectedRow = sessionTable.getSelectedRow();
        if (selectedRow < 0) return null;
        int modelRow = sessionTable.convertRowIndexToModel(selectedRow);
        return sessionTableModel.getTaskAt(modelRow);
    }

    private void onSessionSelected() {
        SessionTask task = getSelectedTask();
        probeHistoryModel.setTask(task);

        if (task != null) {
            // 1. Populate Baseline Editors
            if (task.getBaseline() != null) {
                if (task.getBaseline().request() != null) {
                    baselineRequestEditor.setRequest(task.getBaseline().request());
                } else {
                    baselineRequestEditor.setRequest(task.getOriginalRequest());
                }

                if (task.getBaseline().hasResponse()) {
                    baselineResponseEditor.setResponse(applyDateTimeMarkers(task.getBaseline().response()));
                } else {
                    baselineResponseEditor.setResponse(null);
                }
            } else {
                baselineRequestEditor.setRequest(task.getOriginalRequest());
                baselineResponseEditor.setResponse(null);
            }

            // 2. Automatically select the latest executed milestone or the first milestone
            int targetRow = -1;
            List<TimerInterval> intervals = task.getIntervals();
            for (int i = intervals.size() - 1; i >= 0; i--) {
                if (intervals.get(i).getProbeResult() != null) {
                    targetRow = i;
                    break;
                }
            }
            if (targetRow == -1 && !intervals.isEmpty()) {
                targetRow = 0;
            }

            if (targetRow >= 0 && targetRow < probeHistoryTable.getRowCount()) {
                int viewRow = probeHistoryTable.convertRowIndexToView(targetRow);
                probeHistoryTable.setRowSelectionInterval(viewRow, viewRow);
            } else {
                probeRequestEditor.setRequest(task.getOriginalRequest());
                probeResponseEditor.setResponse(null);
                inspectorTabs.setTitleAt(0, "📤 Probe Request");
                inspectorTabs.setTitleAt(1, "📥 Probe Response");
            }
        } else {
            probeRequestEditor.setRequest(null);
            probeResponseEditor.setResponse(null);
            baselineRequestEditor.setRequest(null);
            baselineResponseEditor.setResponse(null);
            inspectorTabs.setTitleAt(0, "📤 Probe Request");
            inspectorTabs.setTitleAt(1, "📥 Probe Response");
        }
    }

    private void onMilestoneSelected() {
        int selectedRow = probeHistoryTable.getSelectedRow();
        if (selectedRow < 0) return;

        SessionTask task = getSelectedTask();
        int modelRow = probeHistoryTable.convertRowIndexToModel(selectedRow);
        TimerInterval interval = probeHistoryModel.getIntervalAt(modelRow);

        if (interval != null) {
            String label = interval.getLabel();
            inspectorTabs.setTitleAt(0, "📤 Probe Request (" + label + ")");
            inspectorTabs.setTitleAt(1, "📥 Probe Response (" + label + ")");

            if (interval.getProbeResult() != null) {
                HttpRequestResponse rr = interval.getProbeResult().getRequestResponse();
                if (rr != null) {
                    if (rr.request() != null) {
                        probeRequestEditor.setRequest(rr.request());
                    } else if (task != null) {
                        probeRequestEditor.setRequest(task.getOriginalRequest());
                    }

                    if (rr.hasResponse()) {
                        probeResponseEditor.setResponse(applyDateTimeMarkers(rr.response()));
                    } else {
                        probeResponseEditor.setResponse(null);
                    }
                } else {
                    if (task != null) {
                        probeRequestEditor.setRequest(task.getOriginalRequest());
                    }
                    probeResponseEditor.setResponse(null);
                }
            } else {
                // Milestone has not executed yet: display original request template and null response
                if (task != null) {
                    probeRequestEditor.setRequest(task.getOriginalRequest());
                }
                probeResponseEditor.setResponse(null);
            }
        }
    }

    /**
     * Applies native Montoya markers to highlight the Date and Time in the response header section
     * (Date:, Expires:, Last-Modified:).
     */
    private HttpResponse applyDateTimeMarkers(HttpResponse response) {
        if (response == null) return null;
        try {
            List<Marker> markers = new ArrayList<>();
            String rawStr = response.toString();
            int bodyOffset = response.bodyOffset();
            String headerBlock = (bodyOffset > 0 && bodyOffset <= rawStr.length())
                    ? rawStr.substring(0, bodyOffset)
                    : rawStr;

            // 1. Date: header
            String dateVal = response.headerValue("Date");
            if (dateVal != null && !dateVal.trim().isEmpty()) {
                Pattern p = Pattern.compile("(?i)^Date:\\s*(.+?)\\r?$", Pattern.MULTILINE);
                Matcher m = p.matcher(headerBlock);
                if (m.find()) {
                    int start = m.start(1);
                    int end = m.end(1);
                    if (start >= 0 && end > start && end <= response.toByteArray().length()) {
                        markers.add(Marker.marker(Range.range(start, end)));
                    }
                } else {
                    int idx = headerBlock.indexOf(dateVal);
                    if (idx >= 0 && (idx + dateVal.length()) <= response.toByteArray().length()) {
                        markers.add(Marker.marker(Range.range(idx, idx + dateVal.length())));
                    }
                }
            }

            // 2. Secondary headers (Expires, Last-Modified)
            for (String hdr : List.of("Expires", "Last-Modified")) {
                String val = response.headerValue(hdr);
                if (val != null && !val.trim().isEmpty()) {
                    Pattern p = Pattern.compile("(?i)^" + Pattern.quote(hdr) + ":\\s*(.+?)\\r?$", Pattern.MULTILINE);
                    Matcher m = p.matcher(headerBlock);
                    if (m.find()) {
                        int start = m.start(1);
                        int end = m.end(1);
                        if (start >= 0 && end > start && end <= response.toByteArray().length()) {
                            markers.add(Marker.marker(Range.range(start, end)));
                        }
                    }
                }
            }

            if (!markers.isEmpty()) {
                return response.withMarkers(markers);
            }
        } catch (Exception ignored) {
        }
        return response;
    }

    public void openConfigDialogForTask(SessionTask task) {
        selectMonitorTab();
        Window ancestor = SwingUtilities.getWindowAncestor(this);
        TimerConfigDialog dialog = new TimerConfigDialog(ancestor, task);
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            task.setIntervals(dialog.getSelectedIntervals());
            task.setCancelOnExpire(dialog.isCancelOnExpire());

            if (dialog.isRefreshBaseline()) {
                timerEngine.refreshBaseline(task, () -> timerEngine.startSession(task, this::refreshView));
            } else {
                timerEngine.startSession(task, this::refreshView);
            }
            refreshView();
        }
    }

    private void triggerDebouncedFilter() {
        filterDebounceTimer.restart();
    }

    public void refreshView() {
        SwingUtilities.invokeLater(() -> {
            String domain = domainField.getText();
            Set<String> methods = methodFilterBtn.getSelected();
            String status = (String) statusFilterCombo.getSelectedItem();
            String state = (String) stateFilterCombo.getSelectedItem();

            List<SessionTask> filtered = dataStore.getFilteredTasks(domain, methods, status, state);

            int selectedModelId = -1;
            SessionTask current = getSelectedTask();
            if (current != null) {
                selectedModelId = current.getId();
            }

            sessionTableModel.setTasks(filtered);

            // Restore selection if possible
            if (selectedModelId != -1) {
                for (int i = 0; i < filtered.size(); i++) {
                    if (filtered.get(i).getId() == selectedModelId) {
                        int viewRow = sessionTable.convertRowIndexToView(i);
                        sessionTable.setRowSelectionInterval(viewRow, viewRow);
                        break;
                    }
                }
            }

            // Update stats
            int total = dataStore.getAllTasks().size();
            int active = 0, expired = 0, pending = 0;
            for (SessionTask t : dataStore.getAllTasks()) {
                if (t.getState() == SessionState.ACTIVE || t.getState() == SessionState.COMPLETED) active++;
                else if (t.getState() == SessionState.EXPIRED) expired++;
                else if (t.getState() == SessionState.PENDING || t.getState() == SessionState.RUNNING) pending++;
            }

            statsLabel.setText("Total: " + total + " | Active: " + active + " | Expired: " + expired + " | Pending: " + pending);
        });
    }

    public void cleanup() {
        if (countdownTimer != null) {
            countdownTimer.stop();
        }
        if (filterDebounceTimer != null) {
            filterDebounceTimer.stop();
        }
    }
}
