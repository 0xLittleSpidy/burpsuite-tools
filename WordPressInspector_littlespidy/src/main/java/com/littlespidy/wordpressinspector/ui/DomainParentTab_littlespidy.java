// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.wordpressinspector.engine.*;
import com.littlespidy.wordpressinspector.model.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Dedicated Parent Domain Tab component.
 * Allows the user to provide/modify the target domain URL and provides sub-tabs
 * for Overview & Core, Plugins, Themes, Users & Recon, and Scan Logs.
 */
public class DomainParentTab_littlespidy extends JPanel implements WordPressTarget_littlespidy.TargetUpdateListener {

    private final MontoyaApi api;
    private final WordPressDataStore_littlespidy dataStore;
    private final WordPressTarget_littlespidy target;
    private final WPScanApiClient_littlespidy apiClient;

    private JTextField targetUrlField;
    private JLabel statusBadge;
    private JLabel versionBadge;
    private JLabel xmlRpcBadge;

    // Sub-tab tables & components
    private DefaultTableModel coreVulnsModel;
    private DefaultTableModel pluginsModel;
    private DefaultTableModel pluginVulnsModel;
    private DefaultTableModel themesModel;
    private DefaultTableModel themeVulnsModel;
    private DefaultTableModel usersModel;
    private DefaultTableModel restEndpointsModel;
    private JTextArea hardeningArea;
    private JTextArea logArea;
    private JLabel selectedPluginLabel;
    private JLabel selectedThemeLabel;

    public DomainParentTab_littlespidy(MontoyaApi api, WordPressDataStore_littlespidy dataStore, WordPressTarget_littlespidy target) {
        super(new BorderLayout(0, 0));
        this.api = api;
        this.dataStore = dataStore;
        this.target = target;
        this.apiClient = new WPScanApiClient_littlespidy(dataStore);

        target.addListener(this);

        buildTopToolbar();
        buildSubTabs();
        refreshAllViews();
    }

    private void buildTopToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        toolbar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.GRAY),
                new EmptyBorder(4, 8, 4, 8)
        ));

        toolbar.add(new JLabel("Target URL:"));
        targetUrlField = new JTextField(target.getTargetUrl(), 28);
        targetUrlField.setToolTipText("Enter or modify the root WordPress target URL (e.g. https://example.com/)");
        toolbar.add(targetUrlField);

        JButton scanBtn = new JButton("Run Full Scan");
        scanBtn.setFont(scanBtn.getFont().deriveFont(Font.BOLD));
        scanBtn.addActionListener(e -> runFullScan());
        toolbar.add(scanBtn);

        JButton scanPluginsBtn = new JButton("Scan Plugins");
        scanPluginsBtn.addActionListener(e -> runPluginsScan());
        toolbar.add(scanPluginsBtn);

        JButton scanThemesBtn = new JButton("Scan Themes");
        scanThemesBtn.addActionListener(e -> runThemesScan());
        toolbar.add(scanThemesBtn);

        JButton enumUsersBtn = new JButton("Enumerate Users");
        enumUsersBtn.addActionListener(e -> runUsersEnumeration());
        toolbar.add(enumUsersBtn);

        JButton exportBtn = new JButton("Export Report");
        exportBtn.addActionListener(e -> {
            ExportReportDialog_littlespidy dlg = new ExportReportDialog_littlespidy(
                    SwingUtilities.getWindowAncestor(this), target
            );
            dlg.setVisible(true);
        });
        toolbar.add(exportBtn);

        toolbar.add(Box.createHorizontalStrut(10));

        statusBadge = new JLabel("[Detected]");
        statusBadge.setFont(statusBadge.getFont().deriveFont(Font.BOLD));
        toolbar.add(statusBadge);

        versionBadge = new JLabel("WP: Unknown");
        toolbar.add(versionBadge);

        xmlRpcBadge = new JLabel("XML-RPC: Not Tested");
        toolbar.add(xmlRpcBadge);

        add(toolbar, BorderLayout.NORTH);
    }

    private void buildSubTabs() {
        JTabbedPane subTabs = new JTabbedPane();

        subTabs.addTab("Overview & Core", buildOverviewSubTab());
        subTabs.addTab("Plugins (" + target.getPlugins().size() + ")", buildPluginsSubTab());
        subTabs.addTab("Theme Detection (" + target.getThemes().size() + ")", buildThemesSubTab());
        subTabs.addTab("Users & Recon (" + target.getUsers().size() + ")", buildUsersReconSubTab());
        subTabs.addTab("Scan Logs", buildScanLogsSubTab());

        add(subTabs, BorderLayout.CENTER);
    }

    private JPanel buildOverviewSubTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        // Center: Core Vulnerabilities Table
        String[] cols = {"Vulnerability Title", "Type", "Fixed In", "CVE(s)", "CVSS", "References"};
        coreVulnsModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        JTable coreTable = new JTable(coreVulnsModel);
        coreTable.setFillsViewportHeight(true);
        JScrollPane scrollTable = new JScrollPane(coreTable);
        scrollTable.setBorder(BorderFactory.createTitledBorder("WordPress Core Vulnerabilities (WPScan Database)"));

        // South: Security Hardening & Endpoints summary
        hardeningArea = new JTextArea(5, 40);
        hardeningArea.setEditable(false);
        hardeningArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        JScrollPane scrollHardening = new JScrollPane(hardeningArea);
        scrollHardening.setBorder(BorderFactory.createTitledBorder("Security Hardening & Endpoint Audit Findings"));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, scrollTable, scrollHardening);
        splitPane.setResizeWeight(0.65);

        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildPluginsSubTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        // Action Toolbar
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton scanSelectedBtn = new JButton("Scan Selected Plugin");
        JButton scanHighRiskBtn = new JButton("Scan All High-Risk");
        JButton checkUpdatesBtn = new JButton("Check WP.org Updates");

        actions.add(scanSelectedBtn);
        actions.add(scanHighRiskBtn);
        actions.add(checkUpdatesBtn);
        panel.add(actions, BorderLayout.NORTH);

        // Top Table: Plugins
        String[] pluginCols = {"Slug", "Detected Version", "Latest (WP.org)", "High-Risk Category", "Scan Status", "Vulnerabilities"};
        pluginsModel = new DefaultTableModel(pluginCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        JTable pluginsTable = new JTable(pluginsModel);
        pluginsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane pluginsScroll = new JScrollPane(pluginsTable);
        pluginsScroll.setBorder(BorderFactory.createTitledBorder("Detected WordPress Plugins"));

        // Bottom Detail: Selected Plugin Vulnerabilities
        String[] vulnCols = {"Title", "Type", "Fixed In", "CVE(s)", "References"};
        pluginVulnsModel = new DefaultTableModel(vulnCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        JTable vulnsTable = new JTable(pluginVulnsModel);
        JScrollPane vulnsScroll = new JScrollPane(vulnsTable);
        selectedPluginLabel = new JLabel("Vulnerabilities for Selected Plugin");
        JPanel detailContainer = new JPanel(new BorderLayout(4, 4));
        detailContainer.add(selectedPluginLabel, BorderLayout.NORTH);
        detailContainer.add(vulnsScroll, BorderLayout.CENTER);
        detailContainer.setBorder(new EmptyBorder(4, 0, 0, 0));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, pluginsScroll, detailContainer);
        split.setResizeWeight(0.55);
        panel.add(split, BorderLayout.CENTER);

        // Selection Listener
        pluginsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = pluginsTable.getSelectedRow();
                if (row >= 0 && row < target.getPlugins().size()) {
                    PluginFinding_littlespidy selected = target.getPlugins().get(row);
                    displayPluginVulnerabilities(selected);
                }
            }
        });

        // Action Handlers
        scanSelectedBtn.addActionListener(e -> {
            int row = pluginsTable.getSelectedRow();
            if (row >= 0 && row < target.getPlugins().size()) {
                scanSinglePlugin(target.getPlugins().get(row));
            } else {
                JOptionPane.showMessageDialog(this, "Please select a plugin row to scan.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        scanHighRiskBtn.addActionListener(e -> scanAllHighRiskPlugins());

        checkUpdatesBtn.addActionListener(e -> checkPluginUpdatesWpOrg());

        return panel;
    }

    private JPanel buildThemesSubTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton scanThemeBtn = new JButton("Scan Active Theme (WPScan API)");
        actions.add(scanThemeBtn);
        panel.add(actions, BorderLayout.NORTH);

        String[] themeCols = {"Slug", "Detected Version", "Active Theme", "Scan Status", "Vulnerabilities", "Path"};
        themesModel = new DefaultTableModel(themeCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        JTable themesTable = new JTable(themesModel);
        themesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane themesScroll = new JScrollPane(themesTable);
        themesScroll.setBorder(BorderFactory.createTitledBorder("Detected WordPress Themes"));

        String[] vulnCols = {"Title", "Type", "Fixed In", "CVE(s)", "References"};
        themeVulnsModel = new DefaultTableModel(vulnCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        JTable themeVulnTable = new JTable(themeVulnsModel);
        JScrollPane themeVulnScroll = new JScrollPane(themeVulnTable);
        selectedThemeLabel = new JLabel("Vulnerabilities for Selected Theme");
        JPanel detailContainer = new JPanel(new BorderLayout(4, 4));
        detailContainer.add(selectedThemeLabel, BorderLayout.NORTH);
        detailContainer.add(themeVulnScroll, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, themesScroll, detailContainer);
        split.setResizeWeight(0.55);
        panel.add(split, BorderLayout.CENTER);

        themesTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = themesTable.getSelectedRow();
                if (row >= 0 && row < target.getThemes().size()) {
                    ThemeFinding_littlespidy selected = target.getThemes().get(row);
                    displayThemeVulnerabilities(selected);
                }
            }
        });

        scanThemeBtn.addActionListener(e -> {
            int row = themesTable.getSelectedRow();
            if (row >= 0 && row < target.getThemes().size()) {
                scanSingleTheme(target.getThemes().get(row));
            } else if (!target.getThemes().isEmpty()) {
                scanSingleTheme(target.getThemes().get(0));
            } else {
                JOptionPane.showMessageDialog(this, "No detected theme to scan.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        return panel;
    }

    private JPanel buildUsersReconSubTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        JPanel topActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton copyUsersBtn = new JButton("Copy Usernames");
        topActions.add(copyUsersBtn);
        panel.add(topActions, BorderLayout.NORTH);

        String[] userCols = {"ID", "Username", "Display Name", "Slug", "Extraction Vector", "Profile URL"};
        usersModel = new DefaultTableModel(userCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        JTable usersTable = new JTable(usersModel);
        JScrollPane usersScroll = new JScrollPane(usersTable);
        usersScroll.setBorder(BorderFactory.createTitledBorder("Enumerated WordPress Accounts"));

        String[] endpointCols = {"Path", "Description", "Accessible"};
        restEndpointsModel = new DefaultTableModel(endpointCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        JTable endpointsTable = new JTable(restEndpointsModel);
        JScrollPane endpointsScroll = new JScrollPane(endpointsTable);
        endpointsScroll.setBorder(BorderFactory.createTitledBorder("Exposed REST API Endpoints"));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, usersScroll, endpointsScroll);
        split.setResizeWeight(0.55);
        panel.add(split, BorderLayout.CENTER);

        copyUsersBtn.addActionListener(e -> {
            StringBuilder sb = new StringBuilder();
            for (UserFinding_littlespidy u : target.getUsers()) {
                sb.append(u.getUsername()).append("\n");
            }
            if (sb.length() > 0) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
                JOptionPane.showMessageDialog(this, "Copied " + target.getUsers().size() + " usernames to clipboard.", "Copied", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "No enumerated usernames to copy.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        return panel;
    }

    private JPanel buildScanLogsSubTab() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 4));
        JButton clearBtn = new JButton("Clear Log");
        clearBtn.addActionListener(e -> logArea.setText(""));
        JButton copyBtn = new JButton("Copy Log");
        copyBtn.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(logArea.getText()), null);
            JOptionPane.showMessageDialog(this, "Log contents copied to clipboard.", "Copied", JOptionPane.INFORMATION_MESSAGE);
        });
        toolbar.add(clearBtn);
        toolbar.add(copyBtn);
        panel.add(toolbar, BorderLayout.NORTH);

        logArea = new JTextArea();
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        logArea.setEditable(false);
        JScrollPane scroll = new JScrollPane(logArea);
        panel.add(scroll, BorderLayout.CENTER);

        return panel;
    }

    private void displayPluginVulnerabilities(PluginFinding_littlespidy plugin) {
        selectedPluginLabel.setText("Vulnerabilities for '" + plugin.getSlug() + "' (" + plugin.getVulnerabilities().size() + " found):");
        pluginVulnsModel.setRowCount(0);
        for (VulnerabilityEntry_littlespidy v : plugin.getVulnerabilities()) {
            pluginVulnsModel.addRow(new Object[]{
                    v.getTitle(),
                    v.getVulnType(),
                    v.getFixedIn(),
                    v.getPrimaryCve(),
                    String.join(", ", v.getReferences())
            });
        }
    }

    private void displayThemeVulnerabilities(ThemeFinding_littlespidy theme) {
        selectedThemeLabel.setText("Vulnerabilities for '" + theme.getSlug() + "' (" + theme.getVulnerabilities().size() + " found):");
        themeVulnsModel.setRowCount(0);
        for (VulnerabilityEntry_littlespidy v : theme.getVulnerabilities()) {
            themeVulnsModel.addRow(new Object[]{
                    v.getTitle(),
                    v.getVulnType(),
                    v.getFixedIn(),
                    v.getPrimaryCve(),
                    String.join(", ", v.getReferences())
            });
        }
    }

    // ── Scanning Workflows ──

    public void runFullScan() {
        String inputUrl = targetUrlField.getText().trim();
        if (inputUrl.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a valid target URL.", "Input Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        target.setTargetUrl(inputUrl);

        Thread worker = new Thread(() -> {
            target.setScanStatus("Scanning...");
            target.appendLog("[*] Starting full WordPress scan for: " + inputUrl);
            SwingUtilities.invokeLater(this::refreshStatusBadges);

            try {
                // 1. Fetch homepage
                String homepageContent = fetchUrlContent(inputUrl);
                if (homepageContent != null) {
                    target.appendLog("[+] Homepage fetched successfully (" + homepageContent.length() + " chars)");
                    
                    // Extract version
                    String v = WordPressDetectionEngine_littlespidy.extractVersion(homepageContent);
                    if (v != null) {
                        target.setDetectedVersion(v);
                        target.appendLog("[+] WordPress Core Version detected: " + v);
                    }

                    // Extract plugins & themes
                    Set<String> plugins = WordPressDetectionEngine_littlespidy.extractPlugins(homepageContent);
                    for (String slug : plugins) {
                        PluginFinding_littlespidy p = new PluginFinding_littlespidy(slug);
                        p.setHighRisk(WordPressDetectionEngine_littlespidy.isHighRiskPlugin(slug));
                        target.addPlugin(p);
                    }
                    target.appendLog("[+] Extracted " + plugins.size() + " plugin(s) from homepage DOM");

                    Set<String> themes = WordPressDetectionEngine_littlespidy.extractThemes(homepageContent);
                    for (String slug : themes) {
                        target.addTheme(new ThemeFinding_littlespidy(slug));
                    }
                    target.appendLog("[+] Extracted " + themes.size() + " theme(s) from homepage DOM");

                    // Security Hardening
                    List<String> hardening = SecurityHardeningAnalyzer_littlespidy.analyzeHardening(inputUrl, homepageContent);
                    for (String h : hardening) {
                        target.addHardeningFinding(h);
                    }
                }

                // 2. XML-RPC probe
                target.appendLog("[*] Probing XML-RPC endpoint...");
                XmlRpcResult_littlespidy xmlResult = XmlRpcProber_littlespidy.probeXmlRpc(inputUrl);
                target.setXmlRpcResult(xmlResult);
                target.appendLog("[+] XML-RPC: " + xmlResult.getStatusSummary());

                // 3. REST API probe
                target.appendLog("[*] Probing WordPress REST API routes...");
                RestApiResult_littlespidy restResult = RestApiProber_littlespidy.probeRestApi(inputUrl);
                target.setRestApiResult(restResult);
                target.appendLog("[+] REST API Users exposed: " + (restResult.isUsersExposed() ? "YES" : "NO"));

                // 4. User Enumeration
                target.appendLog("[*] Enumerating WordPress user accounts...");
                List<UserFinding_littlespidy> users = UserEnumerator_littlespidy.enumerateUsers(inputUrl);
                for (UserFinding_littlespidy u : users) {
                    target.addUser(u);
                    target.appendLog("    [+] User found: " + u.getUsername() + " (ID: " + u.getId() + ")");
                }

                // 5. Query WPScan for Core Vulnerabilities
                String apiKey = dataStore.getConfig().getWpscanApiKey();
                if (!apiKey.isEmpty() && target.getDetectedVersion() != null && !target.getDetectedVersion().equals("Unknown")) {
                    target.appendLog("[*] Querying WPScan API for core version " + target.getDetectedVersion() + "...");
                    try {
                        List<VulnerabilityEntry_littlespidy> coreVulns = apiClient.scanCoreVersion(target.getDetectedVersion(), apiKey);
                        target.setCoreVulnerabilities(coreVulns);
                        target.appendLog("[+] Found " + coreVulns.size() + " WordPress Core vulnerability advisory(ies)");
                    } catch (Exception ex) {
                        target.appendLog("[!] WPScan Core query error: " + ex.getMessage());
                    }
                } else if (apiKey.isEmpty()) {
                    target.appendLog("[!] WPScan API Key not configured; skipping core vulnerability lookup.");
                }

                // 6. Scan High-Risk Plugins
                if (!apiKey.isEmpty()) {
                    target.appendLog("[*] Scanning detected high-risk plugins via WPScan API...");
                    for (PluginFinding_littlespidy plugin : target.getPlugins()) {
                        if (plugin.isHighRisk()) {
                            try {
                                List<VulnerabilityEntry_littlespidy> pVulns = apiClient.scanPlugin(plugin.getSlug(), apiKey);
                                plugin.setVulnerabilities(pVulns);
                                plugin.setScanStatus(pVulns.isEmpty() ? "Clean" : "Vulnerable");
                                target.appendLog("    [+] Plugin '" + plugin.getSlug() + "': " + pVulns.size() + " vulnerabilities found");
                            } catch (Exception ex) {
                                plugin.setScanStatus("Error");
                                target.appendLog("    [!] Plugin '" + plugin.getSlug() + "' error: " + ex.getMessage());
                            }
                        }
                    }
                }

                // 7. Check updates on WordPress.org
                if (dataStore.getConfig().isCheckWpOrgUpdates()) {
                    target.appendLog("[*] Checking latest plugin versions on WordPress.org...");
                    for (PluginFinding_littlespidy p : target.getPlugins()) {
                        String latest = WordPressOrgClient_littlespidy.fetchLatestPluginVersion(p.getSlug());
                        if (latest != null) {
                            p.setLatestWpOrgVersion(latest);
                        }
                    }
                }

                int totalVulns = target.getTotalVulnerabilityCount();
                target.setScanStatus(totalVulns > 0 ? "Vulnerable (" + totalVulns + ")" : "Clean");
                target.appendLog("[+] Scan Complete. Total vulnerabilities: " + totalVulns);

            } catch (Exception e) {
                target.setScanStatus("Scan Error");
                target.appendLog("[!] Scan error: " + e.getMessage());
            }

            SwingUtilities.invokeLater(() -> {
                target.notifyUpdate();
                refreshAllViews();
            });
        });
        worker.setDaemon(true);
        worker.start();
    }

    public void runPluginsScan() {
        String apiKey = dataStore.getConfig().getWpscanApiKey();
        if (apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(this, "WPScan API key is required in Configuration tab to scan plugins.", "API Key Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        Thread worker = new Thread(() -> {
            target.appendLog("[*] Scanning all detected plugins via WPScan API...");
            for (PluginFinding_littlespidy plugin : target.getPlugins()) {
                try {
                    List<VulnerabilityEntry_littlespidy> vulns = apiClient.scanPlugin(plugin.getSlug(), apiKey);
                    plugin.setVulnerabilities(vulns);
                    plugin.setScanStatus(vulns.isEmpty() ? "Clean" : "Vulnerable");
                    target.appendLog("    [+] Plugin '" + plugin.getSlug() + "': " + vulns.size() + " vulnerabilities");
                } catch (Exception ex) {
                    plugin.setScanStatus("Error");
                    target.appendLog("    [!] Plugin '" + plugin.getSlug() + "' error: " + ex.getMessage());
                }
            }
            SwingUtilities.invokeLater(this::refreshAllViews);
        });
        worker.setDaemon(true);
        worker.start();
    }

    private void scanSinglePlugin(PluginFinding_littlespidy plugin) {
        String apiKey = dataStore.getConfig().getWpscanApiKey();
        if (apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(this, "WPScan API key is required in Configuration tab.", "API Key Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        Thread worker = new Thread(() -> {
            target.appendLog("[*] Scanning plugin '" + plugin.getSlug() + "' via WPScan API...");
            try {
                List<VulnerabilityEntry_littlespidy> vulns = apiClient.scanPlugin(plugin.getSlug(), apiKey);
                plugin.setVulnerabilities(vulns);
                plugin.setScanStatus(vulns.isEmpty() ? "Clean" : "Vulnerable");
                target.appendLog("[+] Plugin '" + plugin.getSlug() + "': " + vulns.size() + " vulnerabilities");
            } catch (Exception ex) {
                plugin.setScanStatus("Error");
                target.appendLog("[!] Plugin '" + plugin.getSlug() + "' error: " + ex.getMessage());
            }
            SwingUtilities.invokeLater(() -> {
                refreshAllViews();
                displayPluginVulnerabilities(plugin);
            });
        });
        worker.setDaemon(true);
        worker.start();
    }

    private void scanAllHighRiskPlugins() {
        String apiKey = dataStore.getConfig().getWpscanApiKey();
        if (apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(this, "WPScan API key is required in Configuration tab.", "API Key Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        Thread worker = new Thread(() -> {
            target.appendLog("[*] Scanning all high-risk plugins...");
            for (PluginFinding_littlespidy p : target.getPlugins()) {
                if (p.isHighRisk()) {
                    try {
                        List<VulnerabilityEntry_littlespidy> vulns = apiClient.scanPlugin(p.getSlug(), apiKey);
                        p.setVulnerabilities(vulns);
                        p.setScanStatus(vulns.isEmpty() ? "Clean" : "Vulnerable");
                        target.appendLog("    [+] High-risk plugin '" + p.getSlug() + "': " + vulns.size() + " vulnerabilities");
                    } catch (Exception ex) {
                        p.setScanStatus("Error");
                    }
                }
            }
            SwingUtilities.invokeLater(this::refreshAllViews);
        });
        worker.setDaemon(true);
        worker.start();
    }

    private void checkPluginUpdatesWpOrg() {
        Thread worker = new Thread(() -> {
            target.appendLog("[*] Querying WordPress.org for plugin version updates...");
            for (PluginFinding_littlespidy p : target.getPlugins()) {
                String latest = WordPressOrgClient_littlespidy.fetchLatestPluginVersion(p.getSlug());
                if (latest != null) {
                    p.setLatestWpOrgVersion(latest);
                }
            }
            target.appendLog("[+] WordPress.org updates refreshed.");
            SwingUtilities.invokeLater(this::refreshAllViews);
        });
        worker.setDaemon(true);
        worker.start();
    }

    public void runThemesScan() {
        String apiKey = dataStore.getConfig().getWpscanApiKey();
        if (apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(this, "WPScan API key is required in Configuration tab.", "API Key Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        Thread worker = new Thread(() -> {
            target.appendLog("[*] Scanning detected themes via WPScan API...");
            for (ThemeFinding_littlespidy theme : target.getThemes()) {
                scanSingleTheme(theme);
            }
        });
        worker.setDaemon(true);
        worker.start();
    }

    private void scanSingleTheme(ThemeFinding_littlespidy theme) {
        String apiKey = dataStore.getConfig().getWpscanApiKey();
        if (apiKey.isEmpty()) return;

        target.appendLog("[*] Querying WPScan API for theme: " + theme.getSlug() + "...");
        try {
            List<VulnerabilityEntry_littlespidy> vulns = apiClient.scanTheme(theme.getSlug(), apiKey);
            theme.setVulnerabilities(vulns);
            theme.setScanStatus(vulns.isEmpty() ? "Clean" : "Vulnerable");
            target.appendLog("[+] Theme '" + theme.getSlug() + "': " + vulns.size() + " vulnerabilities");
        } catch (Exception ex) {
            theme.setScanStatus("Error");
            target.appendLog("[!] Theme '" + theme.getSlug() + "' error: " + ex.getMessage());
        }
        SwingUtilities.invokeLater(() -> {
            refreshAllViews();
            displayThemeVulnerabilities(theme);
        });
    }

    public void runUsersEnumeration() {
        String inputUrl = targetUrlField.getText().trim();
        Thread worker = new Thread(() -> {
            target.appendLog("[*] Starting dedicated user enumeration...");
            List<UserFinding_littlespidy> users = UserEnumerator_littlespidy.enumerateUsers(inputUrl);
            for (UserFinding_littlespidy u : users) {
                target.addUser(u);
                target.appendLog("    [+] User: " + u.getUsername() + " (ID: " + u.getId() + ")");
            }
            target.appendLog("[+] Enumeration finished. Found " + users.size() + " users.");
            SwingUtilities.invokeLater(this::refreshAllViews);
        });
        worker.setDaemon(true);
        worker.start();
    }

    private String fetchUrlContent(String targetUrl) {
        try {
            URL url = URI.create(targetUrl).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);

            try (InputStream is = conn.getInputStream();
                 BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                return sb.toString();
            }
        } catch (Exception e) {
            return null;
        }
    }

    public void refreshAllViews() {
        refreshStatusBadges();

        // Refresh Core Vulns
        coreVulnsModel.setRowCount(0);
        for (VulnerabilityEntry_littlespidy v : target.getCoreVulnerabilities()) {
            coreVulnsModel.addRow(new Object[]{
                    v.getTitle(),
                    v.getVulnType(),
                    v.getFixedIn(),
                    v.getPrimaryCve(),
                    v.getCvssScore(),
                    String.join(", ", v.getReferences())
            });
        }

        // Refresh Hardening
        StringBuilder hsb = new StringBuilder();
        for (String h : target.getHardeningFindings()) {
            hsb.append("- ").append(h).append("\n");
        }
        hardeningArea.setText(hsb.toString());

        // Refresh Plugins Table
        pluginsModel.setRowCount(0);
        for (PluginFinding_littlespidy p : target.getPlugins()) {
            pluginsModel.addRow(new Object[]{
                    p.getSlug(),
                    p.getDetectedVersion(),
                    p.getLatestWpOrgVersion(),
                    p.isHighRisk() ? "Yes" : "No",
                    p.getScanStatus(),
                    p.getVulnerabilityCount()
            });
        }

        // Refresh Themes Table
        themesModel.setRowCount(0);
        for (ThemeFinding_littlespidy t : target.getThemes()) {
            themesModel.addRow(new Object[]{
                    t.getSlug(),
                    t.getDetectedVersion(),
                    t.isActive() ? "Yes" : "No",
                    t.getScanStatus(),
                    t.getVulnerabilityCount(),
                    t.getDetectionPath()
            });
        }

        // Refresh Users Table
        usersModel.setRowCount(0);
        for (UserFinding_littlespidy u : target.getUsers()) {
            usersModel.addRow(new Object[]{
                    u.getId(),
                    u.getUsername(),
                    u.getDisplayName(),
                    u.getSlug(),
                    u.getVector(),
                    u.getProfileUrl()
            });
        }

        // Refresh REST Endpoints Table
        restEndpointsModel.setRowCount(0);
        for (RestApiResult_littlespidy.RestEndpoint_littlespidy ep : target.getRestApiResult().getEndpoints()) {
            restEndpointsModel.addRow(new Object[]{
                    ep.getPath(),
                    ep.getName(),
                    ep.isAccessible() ? "Accessible" : "Blocked / Hidden"
            });
        }
    }

    private void refreshStatusBadges() {
        statusBadge.setText("[" + target.getScanStatus() + "]");
        versionBadge.setText("WP: " + target.getDetectedVersion());
        xmlRpcBadge.setText("XML-RPC: " + target.getXmlRpcResult().getStatusSummary());
    }

    @Override
    public void onTargetUpdated(WordPressTarget_littlespidy target) {
        SwingUtilities.invokeLater(this::refreshAllViews);
    }

    @Override
    public void onLogAdded(WordPressTarget_littlespidy target, String logLine) {
        SwingUtilities.invokeLater(() -> {
            if (logArea != null) {
                logArea.append(logLine + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
            }
        });
    }
}
