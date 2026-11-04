// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.endpointinspector.config.CommonConfig_littlespidy;
import com.littlespidy.endpointinspector.session.SessionData_littlespidy;
import com.littlespidy.endpointinspector.session.SessionData_littlespidy.CommonConfigData;
import com.littlespidy.endpointinspector.session.SessionData_littlespidy.DomainSessionState_littlespidy;
import com.littlespidy.endpointinspector.session.SessionManager_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class EndpointInspectorTab_littlespidy extends JPanel implements SessionManager_littlespidy.SessionPersistenceCallback {

    private final MontoyaApi api;
    private final CommonConfig_littlespidy commonConfig;
    private final SessionManager_littlespidy sessionManager;

    private final JTabbedPane rootTabbedPane = new JTabbedPane();
    private final ConfigurationTab_littlespidy configTab;
    private final List<DomainScanPanel_littlespidy> domainPanels = new ArrayList<>();
    private final AtomicInteger domainTabCounter = new AtomicInteger(1);

    private final JPanel plusTabPlaceholder = new JPanel();
    private boolean isAddingTabFromPlus = false;

    public EndpointInspectorTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        this.commonConfig = new CommonConfig_littlespidy();
        this.sessionManager = new SessionManager_littlespidy(api, this);

        this.configTab = new ConfigurationTab_littlespidy(commonConfig, sessionManager::markDirty);

        initUI();
    }

    private void initUI() {
        // Top Toolbar: Session Management Controls (without "+ New Domain Scan" button)
        JPanel topToolbar = sessionManager.createSessionToolbarComponent(this);
        add(topToolbar, BorderLayout.NORTH);

        // Root Tabbed Pane: First Tab is Configuration
        rootTabbedPane.addTab("Configuration", configTab);

        // Initial default domain tab
        addDomainTab("testphp.vulnweb.com");

        // Add "+" placeholder tab at the end
        rootTabbedPane.addTab("+", plusTabPlaceholder);
        int plusIdx = rootTabbedPane.indexOfComponent(plusTabPlaceholder);
        JLabel plusLabel = new JLabel("+");
        plusLabel.setFont(plusLabel.getFont().deriveFont(Font.BOLD, 13f));
        plusLabel.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4));
        plusLabel.setToolTipText("Add new target domain tab");
        rootTabbedPane.setTabComponentAt(plusIdx, plusLabel);

        rootTabbedPane.addChangeListener(e -> {
            if (isAddingTabFromPlus) return;
            int selected = rootTabbedPane.getSelectedIndex();
            int currentPlusIdx = rootTabbedPane.indexOfComponent(plusTabPlaceholder);
            if (selected != -1 && selected == currentPlusIdx) {
                isAddingTabFromPlus = true;
                SwingUtilities.invokeLater(() -> {
                    try {
                        addDomainTab("target.com");
                    } finally {
                        isAddingTabFromPlus = false;
                    }
                });
            }
        });

        add(rootTabbedPane, BorderLayout.CENTER);
    }

    public void initializeSessionStartup() {
        sessionManager.initializeOnStartup(this);
    }

    public synchronized DomainScanPanel_littlespidy addDomainTab(String domain) {
        if (domain == null || domain.isBlank()) domain = "target.com";
        String cleanDomain = domain.trim();

        // Check if tab already exists for this domain (unless it's default "target.com" when clicking "+")
        if (!cleanDomain.equalsIgnoreCase("target.com")) {
            for (int i = 0; i < domainPanels.size(); i++) {
                DomainScanPanel_littlespidy p = domainPanels.get(i);
                if (p.getTargetDomain().equalsIgnoreCase(cleanDomain)) {
                    int tabIdx = rootTabbedPane.indexOfComponent(p);
                    if (tabIdx != -1) {
                        rootTabbedPane.setSelectedIndex(tabIdx);
                        return p;
                    }
                }
            }
        }

        int tabId = domainTabCounter.getAndIncrement();
        String defaultTitle = "#" + tabId + " " + cleanDomain;

        DomainScanPanel_littlespidy panel = new DomainScanPanel_littlespidy(api, commonConfig, cleanDomain, sessionManager::markDirty);
        panel.setOpenDomainInNewTabConsumer(this::addDomainTab);

        domainPanels.add(panel);

        int plusIdx = rootTabbedPane.indexOfComponent(plusTabPlaceholder);
        int insertIdx;
        if (plusIdx != -1) {
            rootTabbedPane.insertTab(defaultTitle, null, panel, null, plusIdx);
            insertIdx = plusIdx;
        } else {
            rootTabbedPane.addTab(defaultTitle, panel);
            insertIdx = rootTabbedPane.indexOfComponent(panel);
        }

        EditableTabHeader_littlespidy tabHeader = new EditableTabHeader_littlespidy(rootTabbedPane, panel, defaultTitle);
        tabHeader.setCloseCallback(comp -> closeDomainTab((DomainScanPanel_littlespidy) comp));

        rootTabbedPane.setTabComponentAt(insertIdx, tabHeader);
        rootTabbedPane.setSelectedIndex(insertIdx);

        sessionManager.markDirty();
        return panel;
    }

    private synchronized void closeDomainTab(DomainScanPanel_littlespidy panel) {
        int res = JOptionPane.showConfirmDialog(this,
                "Close tab for " + panel.getTargetDomain() + " and abort any active scan?",
                "Confirm Close",
                JOptionPane.YES_NO_OPTION);
        if (res == JOptionPane.YES_OPTION) {
            panel.stopScan();
            domainPanels.remove(panel);
            int idx = rootTabbedPane.indexOfComponent(panel);
            if (idx != -1) {
                rootTabbedPane.removeTabAt(idx);
            }
            sessionManager.markDirty();
        }
    }

    @Override
    public synchronized SessionData_littlespidy exportCurrentSession() {
        SessionData_littlespidy data = new SessionData_littlespidy();

        CommonConfigData cData = new CommonConfigData();
        cData.userAgent = commonConfig.getUserAgent();
        cData.cdxUrlTemplate = commonConfig.getCdxUrlTemplate();
        cData.cdxRetries = commonConfig.getCdxRetries();
        cData.cdxRetryDelaySec = commonConfig.getCdxRetryDelaySec();
        cData.testBothHttpHttps = commonConfig.isTestBothHttpHttps();
        cData.honorBurpProxy = commonConfig.isHonorBurpProxy();
        cData.signatures = commonConfig.getSignatures();
        data.setCommonConfig(cData);

        List<DomainSessionState_littlespidy> dStates = new ArrayList<>();
        for (DomainScanPanel_littlespidy p : domainPanels) {
            dStates.add(p.exportState());
        }
        data.setDomains(dStates);
        return data;
    }

    @Override
    public synchronized void importSession(SessionData_littlespidy data) {
        if (data == null) return;

        // Restore common config
        if (data.getCommonConfig() != null) {
            CommonConfigData c = data.getCommonConfig();
            if (c.userAgent != null) commonConfig.setUserAgent(c.userAgent);
            if (c.cdxUrlTemplate != null) commonConfig.setCdxUrlTemplate(c.cdxUrlTemplate);
            commonConfig.setCdxRetries(c.cdxRetries);
            commonConfig.setCdxRetryDelaySec(c.cdxRetryDelaySec);
            commonConfig.setTestBothHttpHttps(c.testBothHttpHttps);
            commonConfig.setHonorBurpProxy(c.honorBurpProxy);
            if (c.signatures != null) commonConfig.setSignatures(c.signatures);
        }

        // Remove existing domain tabs
        resetDomainPanels();

        // Restore domain tabs
        if (data.getDomains() != null && !data.getDomains().isEmpty()) {
            for (DomainSessionState_littlespidy state : data.getDomains()) {
                DomainScanPanel_littlespidy p = addDomainTab(state.domain != null ? state.domain : "target.com");
                p.importState(state);
            }
        } else {
            addDomainTab("target.com");
        }
    }

    @Override
    public synchronized void resetSession() {
        resetDomainPanels();
        commonConfig.resetSignatures();
        addDomainTab("target.com");
    }

    private void resetDomainPanels() {
        for (DomainScanPanel_littlespidy p : domainPanels) {
            p.stopScan();
            int idx = rootTabbedPane.indexOfComponent(p);
            if (idx != -1) {
                rootTabbedPane.removeTabAt(idx);
            }
        }
        domainPanels.clear();
        domainTabCounter.set(1);
    }
}
