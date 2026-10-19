// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.net.URI;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Primary UI tab for the ResAPI Version Finder tool.
 * Manages dedicated sub-tabs per request session with double-click inline renaming.
 */
public class ResAPIVersionFinderTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final JTabbedPane sessionTabbedPane;
    private final AtomicInteger sessionCounter = new AtomicInteger(1);

    private JTextField manualUrlField;
    private JComboBox<String> methodCombo;

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
        add(topBar, BorderLayout.NORTH);

        // --- 2. Center: Dynamic Sub-Tabs Container ---
        sessionTabbedPane = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);
        add(sessionTabbedPane, BorderLayout.CENTER);
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
        sessionTabbedPane.setTabComponentAt(tabIndex, tabHeader);

        String fullTooltip = (request != null && request.url() != null) ? (method + " " + request.url()) : defaultTitle;
        sessionTabbedPane.setToolTipTextAt(tabIndex, fullTooltip);

        sessionTabbedPane.setSelectedComponent(sessionPanel);
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
