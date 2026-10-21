// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.runner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.sqlmapanalyzer.api.SqlmapApiClient;
import com.littlespidy.sqlmapanalyzer.api.SqlmapProcessManager;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;
import com.littlespidy.sqlmapanalyzer.runner.ScanRequestSession;
import com.littlespidy.sqlmapanalyzer.runner.ScanTaskManager;
import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Root panel for the SQLMap Scanner feature.
 * Houses the API server control bar and manages per-request child tabs.
 * Plain ASCII text only.
 */
public class SqlmapRunnerRootPanel extends JPanel {

    private final MontoyaApi api;
    private final SqlmapApiClient apiClient;
    private final SqlmapProcessManager processManager;
    private final ScanTaskManager taskManager;

    private final ApiServerControlBar apiControlBar;
    private final JTabbedPane requestTabbedPane;
    private final JPanel emptyPlaceholderPanel;

    private final List<RequestScanTabPanel> childTabs = new ArrayList<>();
    private final AtomicInteger sessionCounter = new AtomicInteger(1);

    public SqlmapRunnerRootPanel(MontoyaApi api, SqlmapApiClient apiClient, SqlmapProcessManager processManager, ScanTaskManager taskManager) {
        this.api = api;
        this.apiClient = apiClient;
        this.processManager = processManager;
        this.taskManager = taskManager;

        setLayout(new BorderLayout());

        // Top: API Server Control Bar
        apiControlBar = new ApiServerControlBar(api, apiClient, processManager);
        add(apiControlBar, BorderLayout.NORTH);

        // Center: JTabbedPane for per-request child tabs
        requestTabbedPane = new JTabbedPane();

        // Empty placeholder panel
        emptyPlaceholderPanel = createEmptyPlaceholderPanel();
        add(emptyPlaceholderPanel, BorderLayout.CENTER);
    }

    private JPanel createEmptyPlaceholderPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(30, 30, 30, 30));

        JPanel inner = new JPanel();
        inner.setLayout(new BoxLayout(inner, BoxLayout.Y_AXIS));
        inner.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel title = new JLabel("ng-sqlmap littlespidy (Montoya Java Integration)");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 16));
        title.setAlignmentX(Component.CENTER_ALIGNMENT);
        inner.add(title);
        inner.add(Box.createVerticalStrut(12));

        JLabel info1 = new JLabel("No requests loaded yet.");
        info1.setAlignmentX(Component.CENTER_ALIGNMENT);
        inner.add(info1);

        JLabel info2 = new JLabel("Right-click any request in Proxy History, Repeater, or Logger and select 'Send to ng-sqlmap'.");
        info2.setForeground(Color.DARK_GRAY);
        info2.setAlignmentX(Component.CENTER_ALIGNMENT);
        inner.add(info2);
        inner.add(Box.createVerticalStrut(16));

        JButton btnManual = SwingUtils.createStyledButton("+ Add Manual Request Target");
        btnManual.setAlignmentX(Component.CENTER_ALIGNMENT);
        btnManual.addActionListener(e -> promptManualRequest());
        inner.add(btnManual);

        panel.add(inner);
        return panel;
    }

    public void addOrFocusRequest(HttpRequest request) {
        if (request == null) return;

        String method = request.method();
        String url = request.url();
        byte[] rawBytes = request.toByteArray().getBytes();

        SqlmapTaskOptions options = extractOptionsFromRequest(request);

        // Check if an existing tab matches this method & URL
        for (int i = 0; i < childTabs.size(); i++) {
            RequestScanTabPanel tab = childTabs.get(i);
            ScanRequestSession session = tab.getSession();
            if (session.getMethod().equalsIgnoreCase(method) && session.getUrl().equalsIgnoreCase(url)) {
                // Focus existing tab and create a new execution run
                requestTabbedPane.setSelectedIndex(i);
                session.createNewExecution();
                return;
            }
        }

        // New request tab
        int sessionId = sessionCounter.getAndIncrement();
        ScanRequestSession session = new ScanRequestSession(sessionId, method, url, rawBytes, options);
        RequestScanTabPanel tab = new RequestScanTabPanel(api, session, taskManager);

        childTabs.add(tab);

        if (childTabs.size() == 1) {
            remove(emptyPlaceholderPanel);
            add(requestTabbedPane, BorderLayout.CENTER);
            revalidate();
            repaint();
        }

        int tabIndex = requestTabbedPane.getTabCount();
        requestTabbedPane.addTab(session.getTabTitle(), tab);

        CloseableTabHeader_littlespidy header = new CloseableTabHeader_littlespidy(
                session.getTabTitle(),
                newTitle -> {
                    session.setCustomTabTitle(newTitle);
                    int idx = requestTabbedPane.indexOfComponent(tab);
                    if (idx != -1) {
                        requestTabbedPane.setTitleAt(idx, newTitle);
                    }
                },
                h -> closeTab(tab));
        requestTabbedPane.setTabComponentAt(tabIndex, header);
        requestTabbedPane.setSelectedIndex(tabIndex);
    }

    private void closeTab(RequestScanTabPanel tab) {
        tab.cleanup();
        int idx = requestTabbedPane.indexOfComponent(tab);
        if (idx != -1) {
            requestTabbedPane.removeTabAt(idx);
            childTabs.remove(tab);
        }

        if (childTabs.isEmpty()) {
            remove(requestTabbedPane);
            add(emptyPlaceholderPanel, BorderLayout.CENTER);
            revalidate();
            repaint();
        }
    }

    private void promptManualRequest() {
        String url = JOptionPane.showInputDialog(this, "Enter target URL to scan:", "http://example.com/item.php?id=1");
        if (url != null && !url.isBlank()) {
            SqlmapTaskOptions options = new SqlmapTaskOptions();
            options.setUrl(url.trim());
            options.setMethod("GET");

            int sessionId = sessionCounter.getAndIncrement();
            ScanRequestSession session = new ScanRequestSession(sessionId, "GET", url.trim(), new byte[0], options);
            RequestScanTabPanel tab = new RequestScanTabPanel(api, session, taskManager);

            childTabs.add(tab);
            if (childTabs.size() == 1) {
                remove(emptyPlaceholderPanel);
                add(requestTabbedPane, BorderLayout.CENTER);
                revalidate();
                repaint();
            }

            int tabIndex = requestTabbedPane.getTabCount();
            requestTabbedPane.addTab(session.getTabTitle(), tab);
            CloseableTabHeader_littlespidy header = new CloseableTabHeader_littlespidy(
                    session.getTabTitle(),
                    newTitle -> {
                        session.setCustomTabTitle(newTitle);
                        int idx = requestTabbedPane.indexOfComponent(tab);
                        if (idx != -1) {
                            requestTabbedPane.setTitleAt(idx, newTitle);
                        }
                    },
                    h -> closeTab(tab));
            requestTabbedPane.setTabComponentAt(tabIndex, header);
            requestTabbedPane.setSelectedIndex(tabIndex);
        }
    }

    private SqlmapTaskOptions extractOptionsFromRequest(HttpRequest request) {
        SqlmapTaskOptions opt = new SqlmapTaskOptions();
        opt.setUrl(request.url());
        opt.setMethod(request.method());

        // Extract body data if present
        if (request.body() != null && request.body().length() > 0) {
            opt.setData(request.body().toString());
        }

        // Extract headers & cookies
        StringBuilder customHeaders = new StringBuilder();
        for (var h : request.headers()) {
            String name = h.name();
            String val = h.value();
            if ("cookie".equalsIgnoreCase(name)) {
                opt.setCookie(val);
            } else if ("user-agent".equalsIgnoreCase(name)) {
                opt.setAgent(val);
            } else if ("referer".equalsIgnoreCase(name)) {
                opt.setReferer(val);
            } else if (!"content-length".equalsIgnoreCase(name) && !"host".equalsIgnoreCase(name)) {
                customHeaders.append(name).append(": ").append(val).append("\n");
            }
        }

        if (customHeaders.length() > 0) {
            opt.setHeaders(customHeaders.toString().trim());
        }

        return opt;
    }

    public void cleanup() {
        for (RequestScanTabPanel tab : childTabs) {
            tab.cleanup();
        }
        processManager.stopServer();
        taskManager.shutdown();
    }

    public synchronized List<ScanRequestSession> getSessions() {
        List<ScanRequestSession> sessions = new ArrayList<>();
        for (RequestScanTabPanel tab : childTabs) {
            sessions.add(tab.getSession());
        }
        return sessions;
    }

    public synchronized void clearAllTabs() {
        for (RequestScanTabPanel tab : childTabs) {
            tab.cleanup();
        }
        childTabs.clear();
        requestTabbedPane.removeAll();
        remove(requestTabbedPane);
        add(emptyPlaceholderPanel, BorderLayout.CENTER);
        revalidate();
        repaint();
    }

    public synchronized void restoreSessions(List<ScanRequestSession> restoredSessions) {
        clearAllTabs();
        if (restoredSessions == null || restoredSessions.isEmpty()) {
            return;
        }

        remove(emptyPlaceholderPanel);
        add(requestTabbedPane, BorderLayout.CENTER);

        int maxId = 0;
        for (ScanRequestSession session : restoredSessions) {
            if (session.getSessionId() > maxId) {
                maxId = session.getSessionId();
            }

            RequestScanTabPanel tab = new RequestScanTabPanel(api, session, taskManager);
            childTabs.add(tab);

            int tabIndex = requestTabbedPane.getTabCount();
            requestTabbedPane.addTab(session.getTabTitle(), tab);

            CloseableTabHeader_littlespidy header = new CloseableTabHeader_littlespidy(
                    session.getTabTitle(),
                    newTitle -> {
                        session.setCustomTabTitle(newTitle);
                        int idx = requestTabbedPane.indexOfComponent(tab);
                        if (idx != -1) {
                            requestTabbedPane.setTitleAt(idx, newTitle);
                        }
                    },
                    h -> closeTab(tab));
            requestTabbedPane.setTabComponentAt(tabIndex, header);
        }

        sessionCounter.set(maxId + 1);
        if (requestTabbedPane.getTabCount() > 0) {
            requestTabbedPane.setSelectedIndex(0);
        }
        revalidate();
        repaint();
    }
}
