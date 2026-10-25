// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.responseinspector.engine.ResponseScanEngine;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.InScopeDomainManager;
import com.littlespidy.responseinspector.storage.PersistentStorageManager;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.EnumMap;
import java.util.Map;

/**
 * Root Suite Tab for Response Inspector containing:
 * - Top: Global Session Management toolbar (New, Open, Offboard, Save As, Save Now, Analyze File)
 * - Tab 0: Welcome & Guide onboarding dashboard
 * - Tab 1: Passwords
 * - Tab 2: PII, Network & Paths
 * - Tab 3: Errors & Exceptions
 * - Tab 4: Secrets & Tokens
 * - Tab 5: Comments
 */
public class ResponseInspectorTab extends JPanel {

    private final MontoyaApi api;
    private final ResponseScanEngine scanEngine;
    private final InScopeDomainManager domainManager;
    private final PersistentStorageManager storageManager;
    private final JTabbedPane tabbedPane;
    private final Map<FindingCategory, CategoryFindingsPanel> panels = new EnumMap<>(FindingCategory.class);

    public ResponseInspectorTab(MontoyaApi api, ResponseScanEngine scanEngine, PersistentStorageManager storageManager) {
        this.api = api;
        this.scanEngine = scanEngine;
        this.storageManager = storageManager;
        this.domainManager = new InScopeDomainManager();

        setLayout(new BorderLayout());

        // Top: Global Session Management Toolbar
        if (storageManager != null) {
            JPanel sessionToolbar = storageManager.createSessionToolbarComponent(this, this::refreshAllTabs, this::analyzeLocalFile);
            sessionToolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY));
            add(sessionToolbar, BorderLayout.NORTH);
        }

        tabbedPane = new JTabbedPane();

        // Category Findings Panels
        for (FindingCategory category : FindingCategory.values()) {
            CategoryFindingsPanel panel = new CategoryFindingsPanel(
                    api,
                    category,
                    scanEngine.getDataStore(category),
                    scanEngine,
                    domainManager,
                    this::refreshAllTabs
            );
            panels.put(category, panel);
            tabbedPane.addTab(getTabTitle(category), panel);
        }

        add(tabbedPane, BorderLayout.CENTER);
    }

    public void analyzeLocalFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select File for Automatic Response Analysis");
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            if (file != null && file.exists()) {
                try {
                    byte[] fileBytes = Files.readAllBytes(file.toPath());
                    String fileName = file.getName();
                    String host = "localfile";
                    String path = "/" + fileName;

                    HttpService service = HttpService.httpService(host, 443, true);
                    HttpRequest req = HttpRequest.httpRequest(service, ByteArray.byteArray("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n".getBytes()));

                    StringBuilder sb = new StringBuilder();
                    sb.append("HTTP/1.1 200 OK\r\n");
                    sb.append("Server: LocalFile\r\n");
                    sb.append("Content-Length: ").append(fileBytes.length).append("\r\n");
                    sb.append("Content-Type: application/octet-stream\r\n\r\n");
                    byte[] headerBytes = sb.toString().getBytes();

                    byte[] fullRespBytes = new byte[headerBytes.length + fileBytes.length];
                    System.arraycopy(headerBytes, 0, fullRespBytes, 0, headerBytes.length);
                    System.arraycopy(fileBytes, 0, fullRespBytes, headerBytes.length, fileBytes.length);

                    HttpResponse resp = HttpResponse.httpResponse(ByteArray.byteArray(fullRespBytes));
                    HttpRequestResponse item = HttpRequestResponse.httpRequestResponse(req, resp);

                    scanEngine.addRepeaterItem(item);
                    int findings = scanEngine.scanItem(item);

                    refreshAllTabs();
                    if (storageManager != null) {
                        storageManager.scheduleAutoSave();
                    }

                    if (api != null && api.logging() != null) {
                        api.logging().logToOutput("[Response Inspector] Local file analyzed: " + file.getAbsolutePath() + " (" + findings + " new findings)");
                    }

                    JOptionPane.showMessageDialog(
                            this,
                            "File Analysis Complete:\n"
                                    + "File: " + file.getName() + " (" + fileBytes.length + " bytes)\n"
                                    + "New Findings Discovered: " + findings,
                            "Analysis Complete",
                            JOptionPane.INFORMATION_MESSAGE
                    );
                } catch (Exception ex) {
                    if (api != null && api.logging() != null) {
                        api.logging().logToError("Failed to analyze file: " + ex.getMessage());
                    }
                    JOptionPane.showMessageDialog(this, "Failed to analyze file:\n" + ex.getMessage(), "Analysis Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    public void refreshAllTabs() {
        SwingUtilities.invokeLater(() -> {
            int index = 0;
            for (FindingCategory category : FindingCategory.values()) {
                CategoryFindingsPanel panel = panels.get(category);
                if (panel != null) {
                    panel.refreshView();
                }
                tabbedPane.setTitleAt(index++, getTabTitle(category));
            }
        });
    }

    public InScopeDomainManager getDomainManager() {
        return domainManager;
    }

    private String getTabTitle(FindingCategory category) {
        int count = scanEngine.getDataStore(category).size();
        String badge = count > 0 ? " (" + count + ")" : "";
        return switch (category) {
            case PASSWORD -> "Passwords" + badge;
            case PII_NETWORK_PATH -> "PII, Network & Paths" + badge;
            case ERROR -> "Errors & Exceptions" + badge;
            case SECRET -> "Secrets" + badge;
            case COMMENT -> "Comments" + badge;
        };
    }
}
