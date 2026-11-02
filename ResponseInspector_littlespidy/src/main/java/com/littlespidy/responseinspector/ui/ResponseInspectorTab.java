// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.littlespidy.responseinspector.engine.ResponseScanEngine;
import com.littlespidy.responseinspector.engine.ScannerUtils;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.InScopeDomainManager;
import com.littlespidy.responseinspector.storage.PersistentStorageManager;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Root Suite Tab for Response Inspector containing:
 * - Top Left: Global Session Management toolbar (New, Open, Offboard, Save As, Save Now, Analyze File)
 * - Top Right: Global Traffic Cache Controls (Traffic Count, Load Proxy, Load from Repeater, In-Scope Only, In-Scope Domains)
 * - Category Tabs: Passwords, PII & Paths, Errors, Secrets, Comments
 * - Parameter Collector Tab: Grouped parameter extraction & multi-occurrence switcher
 */
public class ResponseInspectorTab extends JPanel {

    private final MontoyaApi api;
    private final ResponseScanEngine scanEngine;
    private final InScopeDomainManager domainManager;
    private final PersistentStorageManager storageManager;
    private final JTabbedPane tabbedPane;
    private final Map<FindingCategory, CategoryFindingsPanel> panels = new EnumMap<>(FindingCategory.class);
    private final ParameterCollectorPanel_littlespidy parameterPanel;

    private final JLabel trafficCountLabel;
    private final JButton loadProxyBtn;
    private final JButton loadRepeaterBtn;
    private final JCheckBox inScopeOnlyCb;
    private final JButton inScopeDomainsBtn;

    public ResponseInspectorTab(MontoyaApi api, ResponseScanEngine scanEngine, PersistentStorageManager storageManager) {
        this.api = api;
        this.scanEngine = scanEngine;
        this.storageManager = storageManager;
        this.domainManager = new InScopeDomainManager();

        setLayout(new BorderLayout());

        // ─── Top Global Toolbar ─────────────────────────────────────────────
        JPanel globalToolbar = new JPanel(new BorderLayout(8, 0));
        globalToolbar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(200, 200, 200)),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ));

        // Top Left: Session Management
        if (storageManager != null) {
            JPanel leftSessionPanel = storageManager.createSessionLeftActions(this, this::refreshAllTabs, this::analyzeLocalFile);
            globalToolbar.add(leftSessionPanel, BorderLayout.WEST);
        }

        // Top Right: Global Traffic Ingestion Controls
        JPanel rightControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));

        trafficCountLabel = new JLabel("Traffic Cache: 0 items");
        trafficCountLabel.setFont(trafficCountLabel.getFont().deriveFont(Font.BOLD));
        trafficCountLabel.setForeground(new Color(40, 100, 170));
        rightControls.add(trafficCountLabel);

        loadProxyBtn = new JButton("Load Proxy");
        loadProxyBtn.setFont(loadProxyBtn.getFont().deriveFont(Font.BOLD));
        loadProxyBtn.setToolTipText("Load HTTP traffic from Burp Proxy history into extension cache without analyzing");
        loadProxyBtn.addActionListener(e -> loadProxyTraffic());
        rightControls.add(loadProxyBtn);

        loadRepeaterBtn = new JButton("Load from Repeater");
        loadRepeaterBtn.setFont(loadRepeaterBtn.getFont().deriveFont(Font.BOLD));
        loadRepeaterBtn.setToolTipText("Load recorded Repeater traffic into extension cache without analyzing");
        loadRepeaterBtn.addActionListener(e -> loadRepeaterTraffic());
        rightControls.add(loadRepeaterBtn);

        rightControls.add(new JSeparator(SwingConstants.VERTICAL));

        inScopeDomainsBtn = new JButton("In-Scope Domains...");
        inScopeDomainsBtn.setToolTipText("Select specific in-scope target domains to include/exclude");
        inScopeDomainsBtn.setEnabled(false);
        inScopeDomainsBtn.addActionListener(e -> openInScopeDomainDialog());

        inScopeOnlyCb = new JCheckBox("In-Scope Only");
        inScopeOnlyCb.setToolTipText("Filter loaded traffic and findings to Burp target in-scope items only");
        inScopeOnlyCb.addActionListener(e -> {
            inScopeDomainsBtn.setEnabled(inScopeOnlyCb.isSelected());
            refreshAllTabs();
        });
        rightControls.add(inScopeOnlyCb);
        rightControls.add(inScopeDomainsBtn);

        if (storageManager != null) {
            rightControls.add(new JSeparator(SwingConstants.VERTICAL));
            rightControls.add(storageManager.getSessionStatusLabel());
        }

        globalToolbar.add(rightControls, BorderLayout.EAST);
        add(globalToolbar, BorderLayout.NORTH);

        // ─── Tabs ───────────────────────────────────────────────────────────
        tabbedPane = new JTabbedPane();

        // 1-5: Category Findings Panels
        for (FindingCategory category : FindingCategory.values()) {
            CategoryFindingsPanel panel = new CategoryFindingsPanel(
                    api,
                    category,
                    scanEngine.getDataStore(category),
                    scanEngine,
                    domainManager,
                    () -> inScopeOnlyCb.isSelected(),
                    this::refreshAllTabs
            );
            panels.put(category, panel);
            tabbedPane.addTab(getTabTitle(category), panel);
        }

        // 6: Parameter Collector Panel
        parameterPanel = new ParameterCollectorPanel_littlespidy(api, scanEngine, this::refreshAllTabs);
        tabbedPane.addTab(getParameterTabTitle(), parameterPanel);

        add(tabbedPane, BorderLayout.CENTER);
    }

    private void loadProxyTraffic() {
        if (api == null || api.proxy() == null) {
            return;
        }

        loadProxyBtn.setEnabled(false);
        loadRepeaterBtn.setEnabled(false);
        trafficCountLabel.setText("Loading Proxy history...");

        final boolean inScopeOnly = inScopeOnlyCb.isSelected();

        SwingWorker<Integer, Void> worker = new SwingWorker<>() {
            @Override
            protected Integer doInBackground() {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                if (history == null || history.isEmpty()) {
                    return 0;
                }

                List<HttpRequestResponse> toAdd = new ArrayList<>();
                for (ProxyHttpRequestResponse item : history) {
                    if (item == null || !item.hasResponse()) {
                        continue;
                    }
                    var req = item.finalRequest() != null ? item.finalRequest() : item.request();
                    if (req == null) {
                        continue;
                    }

                    if (ScannerUtils.isStaticResource(req, item.response())) {
                        continue;
                    }

                    String url = req.url() != null ? req.url() : "";
                    String host = req.httpService() != null ? req.httpService().host() : "";

                    if (!url.isBlank() && api.scope().isInScope(url)) {
                        domainManager.addDomain(host);
                    }

                    if (inScopeOnly) {
                        if (!api.scope().isInScope(url) || !domainManager.matchesDomain(host)) {
                            continue;
                        }
                    }

                    HttpRequestResponse hrr = HttpRequestResponse.httpRequestResponse(req, item.response(), item.annotations());
                    toAdd.add(hrr);
                }

                scanEngine.addLoadedTraffic(toAdd);
                return toAdd.size();
            }

            @Override
            protected void done() {
                try {
                    int added = get();
                    updateTrafficStatus();
                    updateDomainButtonLabel();
                    if (api.logging() != null) {
                        api.logging().logToOutput("[Response Inspector] Loaded " + added + " items from Proxy history. Total traffic cache: " + scanEngine.getLoadedTrafficCount());
                    }
                } catch (Exception ex) {
                    trafficCountLabel.setText("Error loading: " + ex.getMessage());
                } finally {
                    loadProxyBtn.setEnabled(true);
                    loadRepeaterBtn.setEnabled(true);
                }
            }
        };

        worker.execute();
    }

    private void loadRepeaterTraffic() {
        List<HttpRequestResponse> repeaterItems = scanEngine.getRepeaterTraffic();
        if (repeaterItems.isEmpty()) {
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
        trafficCountLabel.setText("Loading Repeater traffic...");

        final boolean inScopeOnly = inScopeOnlyCb.isSelected();

        SwingWorker<Integer, Void> worker = new SwingWorker<>() {
            @Override
            protected Integer doInBackground() {
                List<HttpRequestResponse> toAdd = new ArrayList<>();
                for (HttpRequestResponse item : repeaterItems) {
                    if (item == null || !item.hasResponse() || item.request() == null) {
                        continue;
                    }
                    var req = item.request();
                    if (ScannerUtils.isStaticResource(req, item.response())) {
                        continue;
                    }

                    String url = req.url() != null ? req.url() : "";
                    String host = req.httpService() != null ? req.httpService().host() : "";

                    if (!url.isBlank() && api.scope().isInScope(url)) {
                        domainManager.addDomain(host);
                    }

                    if (inScopeOnly) {
                        if (!api.scope().isInScope(url) || !domainManager.matchesDomain(host)) {
                            continue;
                        }
                    }

                    toAdd.add(item);
                }

                scanEngine.addLoadedTraffic(toAdd);
                return toAdd.size();
            }

            @Override
            protected void done() {
                try {
                    int added = get();
                    updateTrafficStatus();
                    updateDomainButtonLabel();
                    if (api.logging() != null) {
                        api.logging().logToOutput("[Response Inspector] Loaded " + added + " items from Repeater. Total traffic cache: " + scanEngine.getLoadedTrafficCount());
                    }
                } catch (Exception ex) {
                    trafficCountLabel.setText("Error loading: " + ex.getMessage());
                } finally {
                    loadProxyBtn.setEnabled(true);
                    loadRepeaterBtn.setEnabled(true);
                }
            }
        };

        worker.execute();
    }

    private void updateTrafficStatus() {
        int count = scanEngine.getLoadedTrafficCount();
        trafficCountLabel.setText("Traffic Cache: " + count + " items");
    }

    private void updateDomainButtonLabel() {
        if (domainManager == null || domainManager.getTotalDomainCount() == 0) {
            inScopeDomainsBtn.setText("In-Scope Domains...");
            return;
        }
        if (domainManager.isAllSelected()) {
            inScopeDomainsBtn.setText("In-Scope Domains (All " + domainManager.getTotalDomainCount() + ")");
        } else {
            inScopeDomainsBtn.setText("In-Scope Domains (" + domainManager.getSelectedDomainCount() + "/" + domainManager.getTotalDomainCount() + ")");
        }
    }

    private void openInScopeDomainDialog() {
        Frame topFrame = (Frame) SwingUtilities.getWindowAncestor(this);
        InScopeDomainDialog dialog = new InScopeDomainDialog(topFrame, domainManager, () -> {
            updateDomainButtonLabel();
            refreshAllTabs();
        });
        dialog.setVisible(true);
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
                    scanEngine.addLoadedTraffic(List.of(item));
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
            if (parameterPanel != null) {
                tabbedPane.setTitleAt(index, getParameterTabTitle());
            }
            updateDomainButtonLabel();
            updateTrafficStatus();
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

    private String getParameterTabTitle() {
        int count = parameterPanel != null ? parameterPanel.getParameterCount() : 0;
        String badge = count > 0 ? " (" + count + ")" : "";
        return "Parameters" + badge;
    }
}
