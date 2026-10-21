// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.littlespidy.sqlmapanalyzer.api.SqlmapApiClient;
import com.littlespidy.sqlmapanalyzer.api.SqlmapApiConfig;
import com.littlespidy.sqlmapanalyzer.api.SqlmapProcessManager;
import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
import com.littlespidy.sqlmapanalyzer.persistence.SQLMapPersistenceManager;
import com.littlespidy.sqlmapanalyzer.persistence.SessionStartupDialog_littlespidy;
import com.littlespidy.sqlmapanalyzer.runner.ScanTaskManager;
import com.littlespidy.sqlmapanalyzer.ui.SQLMapAnalyzerTab;
import com.littlespidy.sqlmapanalyzer.ui.runner.SqlmapRunnerRootPanel;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Main Montoya API Burp Suite extension entry point for SQLMap Output Analyzer and Scanner.
 * Plain ASCII text only.
 */
public class SQLMapAnalyzerExtension_littlespidy implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("ng-sqlmap littlespidy");

        // 1. Data Stores and Managers
        SqlmapDataStore dataStore = new SqlmapDataStore();
        SQLMapPersistenceManager persistenceManager = new SQLMapPersistenceManager(api);

        SqlmapApiConfig apiConfig = new SqlmapApiConfig();
        apiConfig.loadPreferences(api);
        SqlmapApiClient apiClient = new SqlmapApiClient(apiConfig);
        SqlmapProcessManager processManager = new SqlmapProcessManager();
        ScanTaskManager taskManager = new ScanTaskManager(apiClient);

        // 2. UI Components
        SqlmapRunnerRootPanel runnerRootPanel = new SqlmapRunnerRootPanel(api, apiClient, processManager, taskManager);
        SQLMapAnalyzerTab mainTab = new SQLMapAnalyzerTab(api, dataStore, persistenceManager, runnerRootPanel);

        persistenceManager.bindContext(mainTab, dataStore);

        // 3. Register Top-Level SuiteTab
        api.userInterface().registerSuiteTab("ng-sqlmap littlespidy", mainTab);

        // 4. Register Context Menu Provider: "Send to ng-sqlmap"
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                HttpRequest targetRequest = null;
                if (event.messageEditorRequestResponse().isPresent() &&
                        event.messageEditorRequestResponse().get().requestResponse() != null &&
                        event.messageEditorRequestResponse().get().requestResponse().request() != null) {
                    targetRequest = event.messageEditorRequestResponse().get().requestResponse().request();
                } else if (event.selectedRequestResponses() != null && !event.selectedRequestResponses().isEmpty()) {
                    targetRequest = event.selectedRequestResponses().get(0).request();
                }

                if (targetRequest != null) {
                    final HttpRequest resolvedReq = targetRequest;
                    JMenuItem sendItem = new JMenuItem("Send to ng-sqlmap");
                    sendItem.addActionListener(e -> {
                        runnerRootPanel.addOrFocusRequest(resolvedReq);
                        mainTab.switchToSqlmapTab();
                    });
                    return List.of(sendItem);
                }
                return Collections.emptyList();
            }
        });

        // 5. Register Clean Unload Handler
        api.extension().registerUnloadingHandler(() -> {
            runnerRootPanel.cleanup();
        });

        api.logging().logToOutput("SQLMap Output Analyzer and Scanner extension loaded successfully.");

        // 6. Interactive Session Startup Dialog
        SwingUtilities.invokeLater(() -> {
            SessionStartupDialog_littlespidy.StartupResult res = SessionStartupDialog_littlespidy.promptUser(api, mainTab);
            persistenceManager.handleStartupResult(res);
        });
    }
}
