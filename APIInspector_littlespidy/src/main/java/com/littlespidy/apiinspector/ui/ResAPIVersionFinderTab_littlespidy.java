// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.apiinspector.model.ProbeResult_littlespidy;
import com.littlespidy.apiinspector.persistence.APIInspectorPersistenceManager_littlespidy;
import com.littlespidy.apiinspector.persistence.SessionStateDTO_littlespidy.ProbeResultDTO;
import com.littlespidy.apiinspector.persistence.SessionStateDTO_littlespidy.SessionTabDTO;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Primary UI tab for the ResAPI Version Finder tool.
 * Manages dedicated sub-tabs per request session with double-click inline renaming
 * and persistent session state.
 */
public class ResAPIVersionFinderTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final JTabbedPane sessionTabbedPane;
    private final AtomicInteger sessionCounter = new AtomicInteger(1);

    private APIInspectorPersistenceManager_littlespidy persistenceManager;

    private JTextField manualUrlField;
    private JComboBox<String> methodCombo;
    private JLabel storageLabel;

    public ResAPIVersionFinderTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;

        // --- 1. Top Manual Request Launcher Bar ---
        JPanel topBar = new JPanel(new BorderLayout(8, 4));
        topBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                new EmptyBorder(8, 10, 8, 10)
        ));

        JPanel launcherControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        launcherControls.add(new JLabel("API Endpoint:"));

        manualUrlField = new JTextField("https://api.example.com/v1/users", 35);
        manualUrlField.setToolTipText("Enter full API URL to inspect versions");
        launcherControls.add(manualUrlField);

        launcherControls.add(new JLabel("Method:"));
        methodCombo = new JComboBox<>(new String[]{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"});
        launcherControls.add(methodCombo);

        JButton createSessionBtn = new JButton("+ New Session");
        createSessionBtn.setFont(createSessionBtn.getFont().deriveFont(Font.BOLD));
        createSessionBtn.setToolTipText("Open a new dedicated sub-tab for this API endpoint");
        createSessionBtn.addActionListener(e -> createSessionFromManualInput());
        launcherControls.add(createSessionBtn);

        JButton closeAllBtn = new JButton("Close All Tabs");
        closeAllBtn.setToolTipText("Close all active request sub-tabs");
        closeAllBtn.addActionListener(e -> closeAllTabs());
        launcherControls.add(closeAllBtn);

        topBar.add(launcherControls, BorderLayout.CENTER);

        // Storage status & Change Folder panel on the right
        JPanel storagePanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        storageLabel = new JLabel("Storage: [Not Set]");
        storageLabel.setFont(storageLabel.getFont().deriveFont(Font.PLAIN, 11f));

        JButton changeStorageBtn = new JButton("Change Folder");
        changeStorageBtn.setFont(changeStorageBtn.getFont().deriveFont(Font.PLAIN, 11f));
        changeStorageBtn.setToolTipText("Change persistent session storage directory");
        changeStorageBtn.addActionListener(e -> {
            if (persistenceManager != null) {
                File chosen = persistenceManager.promptUserForDirectory(this, persistenceManager.getStorageDirectory().getAbsolutePath());
                if (chosen != null) {
                    persistenceManager.setStorageDirectory(chosen);
                    updateStorageDisplay();
                    notifyStateChanged();
                }
            }
        });

        storagePanel.add(storageLabel);
        storagePanel.add(changeStorageBtn);
        topBar.add(storagePanel, BorderLayout.EAST);

        add(topBar, BorderLayout.NORTH);

        // --- 2. Center: Dynamic Sub-Tabs Container ---
        sessionTabbedPane = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);
        add(sessionTabbedPane, BorderLayout.CENTER);
    }

    public void setPersistenceManager(APIInspectorPersistenceManager_littlespidy manager) {
        this.persistenceManager = manager;
        updateStorageDisplay();
    }

    public void updateStorageDisplay() {
        if (storageLabel != null && persistenceManager != null) {
            File dir = persistenceManager.getStorageDirectory();
            storageLabel.setText("Storage: " + dir.getName());
            storageLabel.setToolTipText("Storage directory: " + dir.getAbsolutePath());
        }
    }

    public void notifyStateChanged() {
        if (persistenceManager != null) {
            persistenceManager.saveAsync(this);
        }
    }

    /**
     * Creates a new dedicated sub-tab for the given HTTP request and response.
     */
    public void addNewSession(HttpRequest request, HttpResponse response) {
        int sessionId = sessionCounter.getAndIncrement();
        String method = (request != null && request.method() != null) ? request.method() : "GET";
        String path = (request != null && request.path() != null) ? request.path() : "/";

        String truncatedPath = truncatePath(path, 22);
        String defaultTitle = "#" + sessionId + " " + method + " " + truncatedPath;

        RequestSessionPanel_littlespidy sessionPanel = new RequestSessionPanel_littlespidy(api, request, response);
        sessionTabbedPane.addTab(defaultTitle, sessionPanel);

        int tabIndex = sessionTabbedPane.indexOfComponent(sessionPanel);
        EditableTabHeader_littlespidy tabHeader = new EditableTabHeader_littlespidy(sessionTabbedPane, sessionPanel, defaultTitle);
        tabHeader.setOnCloseCallback(this::notifyStateChanged);
        tabHeader.setOnRenameCallback(newTitle -> notifyStateChanged());
        sessionTabbedPane.setTabComponentAt(tabIndex, tabHeader);

        String fullTooltip = (request != null && request.url() != null) ? (method + " " + request.url()) : defaultTitle;
        sessionTabbedPane.setToolTipTextAt(tabIndex, fullTooltip);

        sessionPanel.setOnStateChangedCallback(this::notifyStateChanged);

        sessionTabbedPane.setSelectedComponent(sessionPanel);
        notifyStateChanged();
    }

    /**
     * Restores a session sub-tab from stored persistence DTO.
     */
    public void restoreSession(SessionTabDTO dto) {
        if (dto == null) return;

        HttpRequest baseReq = APIInspectorPersistenceManager_littlespidy.deserializeHttpRequest(dto.baselineRequest);
        HttpResponse baseResp = APIInspectorPersistenceManager_littlespidy.deserializeHttpResponse(dto.baselineResponse);

        RequestSessionPanel_littlespidy sessionPanel = new RequestSessionPanel_littlespidy(api, baseReq, baseResp);

        if (dto.strategies != null) {
            sessionPanel.setUriPathSelected(dto.strategies.uriPath);
            sessionPanel.setHeadersSelected(dto.strategies.headers);
            sessionPanel.setQueryParamsSelected(dto.strategies.queryParams);
            sessionPanel.setContentNegotiationSelected(dto.strategies.contentNegotiation);
            sessionPanel.setSubdomainsSelected(dto.strategies.subdomains);
            sessionPanel.setCookiesSelected(dto.strategies.cookies);
        }

        sessionPanel.setCandidatesText(dto.candidates);
        sessionPanel.setThreadCount(dto.threads > 0 ? dto.threads : 5);
        sessionPanel.setDelayMs(dto.delayMs);

        if (dto.results != null) {
            for (ProbeResultDTO prDto : dto.results) {
                HttpRequest probeReq = APIInspectorPersistenceManager_littlespidy.deserializeHttpRequest(prDto.request);
                HttpResponse probeResp = APIInspectorPersistenceManager_littlespidy.deserializeHttpResponse(prDto.response);
                ProbeResult_littlespidy result = new ProbeResult_littlespidy(
                        prDto.id,
                        prDto.strategyName,
                        prDto.variation,
                        prDto.statusCode,
                        prDto.responseLength,
                        prDto.mimeType,
                        prDto.diffAnalysis,
                        prDto.latencyMs,
                        probeReq,
                        probeResp
                );
                sessionPanel.addRestoredResult(result);
            }
        }

        String title = dto.tabTitle != null && !dto.tabTitle.isBlank() ? dto.tabTitle : ("#" + sessionCounter.getAndIncrement() + " Restored");
        sessionTabbedPane.addTab(title, sessionPanel);

        int tabIndex = sessionTabbedPane.indexOfComponent(sessionPanel);
        EditableTabHeader_littlespidy tabHeader = new EditableTabHeader_littlespidy(sessionTabbedPane, sessionPanel, title);
        tabHeader.setOnCloseCallback(this::notifyStateChanged);
        tabHeader.setOnRenameCallback(newTitle -> notifyStateChanged());
        sessionTabbedPane.setTabComponentAt(tabIndex, tabHeader);

        String fullTooltip = dto.targetUrl != null ? (dto.method + " " + dto.targetUrl) : title;
        sessionTabbedPane.setToolTipTextAt(tabIndex, fullTooltip);

        sessionPanel.setOnStateChangedCallback(this::notifyStateChanged);
    }

    public List<RequestSessionPanel_littlespidy> getAllSessionPanels() {
        List<RequestSessionPanel_littlespidy> list = new ArrayList<>();
        int count = sessionTabbedPane.getTabCount();
        for (int i = 0; i < count; i++) {
            Component c = sessionTabbedPane.getComponentAt(i);
            if (c instanceof RequestSessionPanel_littlespidy p) {
                list.add(p);
            }
        }
        return list;
    }

    public String getTabTitleAt(int index) {
        if (index < 0 || index >= sessionTabbedPane.getTabCount()) {
            return "";
        }
        Component headerComp = sessionTabbedPane.getTabComponentAt(index);
        if (headerComp instanceof EditableTabHeader_littlespidy header) {
            return header.getTitle();
        }
        return sessionTabbedPane.getTitleAt(index);
    }

    private void createSessionFromManualInput() {
        String rawUrl = manualUrlField.getText().trim();
        if (rawUrl.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter an API URL.", "Input Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            URI uri = URI.create(rawUrl);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Invalid URL host: " + rawUrl, "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            boolean isHttps = "https".equalsIgnoreCase(uri.getScheme()) || uri.getScheme() == null;
            int port = uri.getPort() != -1 ? uri.getPort() : (isHttps ? 443 : 80);
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            if (uri.getRawQuery() != null) {
                path += "?" + uri.getRawQuery();
            }

            String selectedMethod = (String) methodCombo.getSelectedItem();
            if (selectedMethod == null) selectedMethod = "GET";

            HttpService service = HttpService.httpService(host, port, isHttps);
            HttpRequest request = HttpRequest.httpRequest(service, selectedMethod + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: APIInspector/1.0\r\nAccept: */*\r\n\r\n");

            addNewSession(request, null);

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to parse API URL: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void closeAllTabs() {
        if (sessionTabbedPane.getTabCount() == 0) return;
        int opt = JOptionPane.showConfirmDialog(this, "Close all " + sessionTabbedPane.getTabCount() + " session tabs?", "Confirm Close All", JOptionPane.YES_NO_OPTION);
        if (opt == JOptionPane.YES_OPTION) {
            sessionTabbedPane.removeAll();
            notifyStateChanged();
        }
    }

    private String truncatePath(String path, int maxLen) {
        if (path == null) return "/";
        if (path.length() <= maxLen) return path;
        return path.substring(0, maxLen - 3) + "...";
    }

    public JTabbedPane getSessionTabbedPane() {
        return sessionTabbedPane;
    }
}
