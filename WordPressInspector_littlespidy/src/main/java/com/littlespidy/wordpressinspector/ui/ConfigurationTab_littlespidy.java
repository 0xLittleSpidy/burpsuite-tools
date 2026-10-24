// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.wordpressinspector.engine.WPScanApiClient_littlespidy;
import com.littlespidy.wordpressinspector.model.ScanConfig_littlespidy;
import com.littlespidy.wordpressinspector.model.WordPressDataStore_littlespidy;
import com.littlespidy.wordpressinspector.storage.WordPressPreferencesManager_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Dedicated permanent Configuration tab for WPScan API credentials, daily quota tracking,
 * and scanner optimization options.
 */
public class ConfigurationTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final WordPressDataStore_littlespidy dataStore;
    private final WordPressPreferencesManager_littlespidy prefsManager;
    private final WordPressInspectorSuiteTab_littlespidy suiteTab;

    private JPasswordField apiKeyField;
    private JLabel apiKeyStatusLabel;
    private JLabel dailyCounterLabel;
    private JCheckBox cache24hCb;
    private JCheckBox smartPriorityCb;
    private JCheckBox wpOrgUpdatesCb;
    private JCheckBox hardeningCb;

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
        JPanel panel = new JPanel(new GridLayout(4, 1, 6, 6));
        panel.setBorder(BorderFactory.createTitledBorder("Scanner Optimization Options"));

        cache24hCb = new JCheckBox("24-Hour Cache for WPScan Results: Prevent redundant API requests for identical slugs");
        smartPriorityCb = new JCheckBox("Smart Plugin Prioritization: Scan 80+ curated high-risk plugins first");
        wpOrgUpdatesCb = new JCheckBox("WordPress.org Version Update Check: Compare detected plugins with latest WP.org releases (0 credits)");
        hardeningCb = new JCheckBox("Security Hardening Probes: Evaluate XML-RPC, REST API exposure, and hidden files");

        cache24hCb.addActionListener(e -> saveOptions());
        smartPriorityCb.addActionListener(e -> saveOptions());
        wpOrgUpdatesCb.addActionListener(e -> saveOptions());
        hardeningCb.addActionListener(e -> saveOptions());

        panel.add(cache24hCb);
        panel.add(smartPriorityCb);
        panel.add(wpOrgUpdatesCb);
        panel.add(hardeningCb);

        return panel;
    }

    private void loadInitialValues() {
        ScanConfig_littlespidy config = dataStore.getConfig();
        apiKeyField.setText(config.getWpscanApiKey());
        dailyCounterLabel.setText("Daily API Calls Used: " + config.getDailyApiCounter() + " / 50 (Estimated)");
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
        config.setCache24hEnabled(cache24hCb.isSelected());
        config.setSmartPluginPriority(smartPriorityCb.isSelected());
        config.setCheckWpOrgUpdates(wpOrgUpdatesCb.isSelected());
        config.setSecurityHardeningChecks(hardeningCb.isSelected());
        prefsManager.savePreferences(config);
    }
}
