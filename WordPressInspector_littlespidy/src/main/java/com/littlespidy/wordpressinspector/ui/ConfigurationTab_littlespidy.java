// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.littlespidy.wordpressinspector.engine.WPScanApiClient_littlespidy;
import com.littlespidy.wordpressinspector.engine.WordPressDetectionEngine_littlespidy;
import com.littlespidy.wordpressinspector.model.PluginFinding_littlespidy;
import com.littlespidy.wordpressinspector.model.ScanConfig_littlespidy;
import com.littlespidy.wordpressinspector.model.ThemeFinding_littlespidy;
import com.littlespidy.wordpressinspector.model.WordPressDataStore_littlespidy;
import com.littlespidy.wordpressinspector.model.WordPressTarget_littlespidy;
import com.littlespidy.wordpressinspector.storage.WordPressPreferencesManager_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.List;
import java.util.Set;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Dedicated permanent Configuration tab for WPScan API credentials, daily quota tracking,
 * detection toggles, proxy history scanning, and target management.
 */
public class ConfigurationTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final WordPressDataStore_littlespidy dataStore;
    private final WordPressPreferencesManager_littlespidy prefsManager;
    private final WordPressInspectorSuiteTab_littlespidy suiteTab;

    private JPasswordField apiKeyField;
    private JLabel apiKeyStatusLabel;
    private JLabel dailyCounterLabel;
    private JCheckBox liveScanCb;
    private JCheckBox cache24hCb;
    private JCheckBox smartPriorityCb;
    private JCheckBox wpOrgUpdatesCb;
    private JCheckBox hardeningCb;
    private JLabel historyScanStatusLabel;
    private JTextField newDomainField;

    public ConfigurationTab_littlespidy(
            MontoyaApi api,
            WordPressDataStore_littlespidy dataStore,
            WordPressPreferencesManager_littlespidy prefsManager,
            WordPressInspectorSuiteTab_littlespidy suiteTab
    ) {
        super(new BorderLayout());
        this.api = api;
        this.dataStore = dataStore;
        this.prefsManager = prefsManager;
        this.suiteTab = suiteTab;

        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBorder(new EmptyBorder(12, 16, 12, 16));

        contentPanel.add(buildApiKeySection());
        contentPanel.add(Box.createVerticalStrut(12));
        contentPanel.add(buildQuotaSection());
        contentPanel.add(Box.createVerticalStrut(12));
        contentPanel.add(buildOptionsSection());
        contentPanel.add(Box.createVerticalStrut(12));
        contentPanel.add(buildHistoryScanSection());
        contentPanel.add(Box.createVerticalStrut(12));
        contentPanel.add(buildAddTargetSection());
        contentPanel.add(Box.createVerticalGlue());

        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setBorder(null);
        add(scrollPane, BorderLayout.CENTER);

        loadInitialValues();
    }

    private JPanel buildApiKeySection() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createTitledBorder("WPScan API Credentials"));

        JPanel inner = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 8));
        inner.add(new JLabel("WPScan API Token:"));

        apiKeyField = new JPasswordField(30);
        inner.add(apiKeyField);

        JButton toggleShowBtn = new JButton("Show");
        toggleShowBtn.addActionListener(e -> {
            if (apiKeyField.getEchoChar() == 0) {
                apiKeyField.setEchoChar('\u2022');
                toggleShowBtn.setText("Show");
            } else {
                apiKeyField.setEchoChar((char) 0);
                toggleShowBtn.setText("Hide");
            }
        });
        inner.add(toggleShowBtn);

        JButton saveBtn = new JButton("Save API Key");
        saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD));
        saveBtn.addActionListener(e -> saveApiKey());
        inner.add(saveBtn);

        JButton testBtn = new JButton("Test & Verify Key");
        testBtn.addActionListener(e -> testApiKey());
        inner.add(testBtn);

        apiKeyStatusLabel = new JLabel("[Status: Ready]");
        inner.add(apiKeyStatusLabel);

        panel.add(inner, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildQuotaSection() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 8));
        panel.setBorder(BorderFactory.createTitledBorder("WPScan API Usage & Daily Quotas"));

        dailyCounterLabel = new JLabel("Daily API Calls Used: 0 / 50 (Estimated)");
        dailyCounterLabel.setFont(dailyCounterLabel.getFont().deriveFont(Font.BOLD));
        panel.add(dailyCounterLabel);

        JButton resetCounterBtn = new JButton("Reset Daily Counter");
        resetCounterBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(this, "Reset the daily WPScan API calls counter to 0?", "Confirm Reset", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                prefsManager.resetDailyCounter(dataStore.getConfig());
                dailyCounterLabel.setText("Daily API Calls Used: 0 / 50 (Estimated)");
            }
        });
        panel.add(resetCounterBtn);

        return panel;
    }

    private JPanel buildOptionsSection() {
        JPanel panel = new JPanel(new GridLayout(5, 1, 4, 4));
        panel.setBorder(BorderFactory.createTitledBorder("Inspection & Reconnaissance Options"));

        liveScanCb = new JCheckBox("Passive Live Traffic Detection: Inspect passing Burp Proxy responses in real-time");
        cache24hCb = new JCheckBox("24-Hour Cache for WPScan Results: Prevent redundant API requests for identical slugs");
        smartPriorityCb = new JCheckBox("Smart Plugin Prioritization: Scan 80+ curated high-risk plugins first");
        wpOrgUpdatesCb = new JCheckBox("WordPress.org Version Update Check: Compare detected plugins with latest WP.org releases (0 credits)");
        hardeningCb = new JCheckBox("Security Hardening Probes: Evaluate XML-RPC, REST API exposure, and hidden files");

        liveScanCb.addActionListener(e -> saveOptions());
        cache24hCb.addActionListener(e -> saveOptions());
        smartPriorityCb.addActionListener(e -> saveOptions());
        wpOrgUpdatesCb.addActionListener(e -> saveOptions());
        hardeningCb.addActionListener(e -> saveOptions());

        panel.add(liveScanCb);
        panel.add(cache24hCb);
        panel.add(smartPriorityCb);
        panel.add(wpOrgUpdatesCb);
        panel.add(hardeningCb);

        return panel;
    }

    private JPanel buildHistoryScanSection() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 8));
        panel.setBorder(BorderFactory.createTitledBorder("Historical Proxy Traffic Analysis"));

        JButton scanHistoryBtn = new JButton("Scan Burp HTTP Proxy History");
        scanHistoryBtn.setFont(scanHistoryBtn.getFont().deriveFont(Font.BOLD));
        scanHistoryBtn.addActionListener(e -> scanProxyHistory());
        panel.add(scanHistoryBtn);

        historyScanStatusLabel = new JLabel("Proxy history scan idle.");
        panel.add(historyScanStatusLabel);

        return panel;
    }

    private JPanel buildAddTargetSection() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 8));
        panel.setBorder(BorderFactory.createTitledBorder("Add Target Domain"));

        panel.add(new JLabel("Target URL / Host:"));
        newDomainField = new JTextField("https://", 26);
        panel.add(newDomainField);

        JButton addBtn = new JButton("Add Domain Tab");
        addBtn.setFont(addBtn.getFont().deriveFont(Font.BOLD));
        addBtn.addActionListener(e -> {
            String input = newDomainField.getText().trim();
            if (!input.isEmpty() && !input.equalsIgnoreCase("https://") && !input.equalsIgnoreCase("http://")) {
                WordPressTarget_littlespidy target = dataStore.getOrCreateTarget(input, input);
                suiteTab.openDomainTab(target);
                newDomainField.setText("https://");
            } else {
                JOptionPane.showMessageDialog(this, "Please enter a valid target URL or hostname.", "Notice", JOptionPane.WARNING_MESSAGE);
            }
        });
        panel.add(addBtn);

        return panel;
    }

    private void loadInitialValues() {
        ScanConfig_littlespidy config = dataStore.getConfig();
        apiKeyField.setText(config.getWpscanApiKey());
        dailyCounterLabel.setText("Daily API Calls Used: " + config.getDailyApiCounter() + " / 50 (Estimated)");
        liveScanCb.setSelected(config.isLiveScanEnabled());
        cache24hCb.setSelected(config.isCache24hEnabled());
        smartPriorityCb.setSelected(config.isSmartPluginPriority());
        wpOrgUpdatesCb.setSelected(config.isCheckWpOrgUpdates());
        hardeningCb.setSelected(config.isSecurityHardeningChecks());
    }

    private void saveApiKey() {
        String key = new String(apiKeyField.getPassword()).trim();
        dataStore.getConfig().setWpscanApiKey(key);
        prefsManager.savePreferences(dataStore.getConfig());
        apiKeyStatusLabel.setText("[+] Key Saved to Burp Preferences");
        apiKeyStatusLabel.setForeground(new Color(46, 125, 50));
    }

    private void testApiKey() {
        String key = new String(apiKeyField.getPassword()).trim();
        if (key.isEmpty()) {
            apiKeyStatusLabel.setText("[!] Please enter an API key first");
            apiKeyStatusLabel.setForeground(Color.RED);
            return;
        }

        apiKeyStatusLabel.setText("[*] Testing API key with wpscan.com...");
        apiKeyStatusLabel.setForeground(Color.BLUE);

        Thread worker = new Thread(() -> {
            WPScanApiClient_littlespidy client = new WPScanApiClient_littlespidy(dataStore);
            boolean valid = client.testApiKey(key);
            SwingUtilities.invokeLater(() -> {
                if (valid) {
                    apiKeyStatusLabel.setText("[+] Valid WPScan API Key (Active)");
                    apiKeyStatusLabel.setForeground(new Color(46, 125, 50));
                } else {
                    apiKeyStatusLabel.setText("[!] Verification Failed: Invalid Token or Network Error");
                    apiKeyStatusLabel.setForeground(Color.RED);
                }
            });
        });
        worker.setDaemon(true);
        worker.start();
    }

    private void saveOptions() {
        ScanConfig_littlespidy config = dataStore.getConfig();
        config.setLiveScanEnabled(liveScanCb.isSelected());
        config.setCache24hEnabled(cache24hCb.isSelected());
        config.setSmartPluginPriority(smartPriorityCb.isSelected());
        config.setCheckWpOrgUpdates(wpOrgUpdatesCb.isSelected());
        config.setSecurityHardeningChecks(hardeningCb.isSelected());
        prefsManager.savePreferences(config);
    }

    private void scanProxyHistory() {
        if (api == null || api.proxy() == null) {
            historyScanStatusLabel.setText("[!] Burp Proxy API not available.");
            return;
        }

        historyScanStatusLabel.setText("[*] Scanning proxy history for WordPress targets...");
        Thread worker = new Thread(() -> {
            int targetCount = 0;
            int pluginCount = 0;
            try {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                for (ProxyHttpRequestResponse item : history) {
                    if (!item.hasResponse()) continue;
                    String respBody = item.response().bodyToString();
                    List<String> headers = item.response().headers().stream().map(h -> h.name() + ": " + h.value()).toList();

                    if (WordPressDetectionEngine_littlespidy.isWordPressTraffic(respBody, headers)) {
                        String host = item.request().httpService().host();
                        String url = item.request().url();
                        WordPressTarget_littlespidy target = dataStore.getOrCreateTarget(url, host);
                        targetCount++;

                        // Extract version if missing
                        if (target.getDetectedVersion().equals("Unknown")) {
                            String v = WordPressDetectionEngine_littlespidy.extractVersion(respBody);
                            if (v != null) target.setDetectedVersion(v);
                        }

                        // Extract plugins
                        Set<String> plugins = WordPressDetectionEngine_littlespidy.extractPlugins(respBody);
                        for (String slug : plugins) {
                            PluginFinding_littlespidy p = new PluginFinding_littlespidy(slug);
                            p.setHighRisk(WordPressDetectionEngine_littlespidy.isHighRiskPlugin(slug));
                            p.setDetectionSource("Burp HTTP History");
                            target.addPlugin(p);
                            pluginCount++;
                        }

                        // Extract themes
                        Set<String> themes = WordPressDetectionEngine_littlespidy.extractThemes(respBody);
                        for (String slug : themes) {
                            ThemeFinding_littlespidy t = new ThemeFinding_littlespidy(slug);
                            t.setDetectionPath("HTTP History Response");
                            target.addTheme(t);
                        }
                    }
                }
            } catch (Exception ex) {
                targetCount = -1;
            }

            final int finalTargets = targetCount;
            final int finalPlugins = pluginCount;
            SwingUtilities.invokeLater(() -> {
                if (finalTargets >= 0) {
                    historyScanStatusLabel.setText("[+] Found " + finalTargets + " WordPress target(s) and " + finalPlugins + " plugin references in history.");
                } else {
                    historyScanStatusLabel.setText("[!] History scan encountered an issue.");
                }
            });
        });
        worker.setDaemon(true);
        worker.start();
    }
}
