// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
import com.littlespidy.sqlmapanalyzer.persistence.SQLMapPersistenceManager;
import com.littlespidy.sqlmapanalyzer.persistence.SessionStartupDialog_littlespidy;
import com.littlespidy.sqlmapanalyzer.ui.SQLMapAnalyzerTab;

import javax.swing.*;

/**
 * Main Montoya API Burp Suite extension entry point for SQLMap Output Analyzer.
 * Plain ASCII text only.
 */
public class SQLMapAnalyzerExtension_littlespidy implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("SQLMap Output Analyzer");

        SqlmapDataStore dataStore = new SqlmapDataStore();
        SQLMapPersistenceManager persistenceManager = new SQLMapPersistenceManager(api);
        SQLMapAnalyzerTab mainTab = new SQLMapAnalyzerTab(api, dataStore, persistenceManager);

        persistenceManager.bindContext(mainTab, dataStore);

        api.userInterface().registerSuiteTab("SQLMap Analyzer", mainTab);
        api.logging().logToOutput("SQLMap Output Analyzer extension loaded successfully.");

        // Interactive session startup dialog per Burp Suite Creator guidelines
        SwingUtilities.invokeLater(() -> {
            SessionStartupDialog_littlespidy.StartupResult res = SessionStartupDialog_littlespidy.promptUser(api, mainTab);
            persistenceManager.handleStartupResult(res);
        });
    }
}
