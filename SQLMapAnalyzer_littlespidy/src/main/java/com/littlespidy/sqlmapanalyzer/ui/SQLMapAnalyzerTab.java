// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
import com.littlespidy.sqlmapanalyzer.persistence.SQLMapPersistenceManager;
import com.littlespidy.sqlmapanalyzer.ui.analysis.AnalysisPanel;
import com.littlespidy.sqlmapanalyzer.ui.viewer.TableViewerPanel;

import javax.swing.*;
import java.awt.*;

/**
 * Main Suite Tab component for SQLMap Analyzer in Burp Suite.
 * Plain ASCII text only.
 */
public class SQLMapAnalyzerTab extends JPanel {

    private final MontoyaApi api;
    private final SqlmapDataStore dataStore;
    private final SQLMapPersistenceManager persistenceManager;

    private final SessionControlPanel sessionControlPanel;
    private final TopControlPanel topControlPanel;
    private final JTabbedPane mainTabbedPane;
    private final TableViewerPanel viewerPanel;
    private final AnalysisPanel analysisPanel;

    public SQLMapAnalyzerTab(MontoyaApi api, SqlmapDataStore dataStore, SQLMapPersistenceManager persistenceManager) {
        this.api = api;
        this.dataStore = dataStore;
        this.persistenceManager = persistenceManager;

        setLayout(new BorderLayout());

        // Header section: Session controls + Directory import controls
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));

        sessionControlPanel = new SessionControlPanel(persistenceManager);
        topControlPanel = new TopControlPanel(this, dataStore, persistenceManager);

        headerPanel.add(sessionControlPanel);
        headerPanel.add(topControlPanel);
        add(headerPanel, BorderLayout.NORTH);

        // Main Tabbed Pane: Tab 1 (Viewer) + Tab 2 (Analysis)
        mainTabbedPane = new JTabbedPane();

        viewerPanel = new TableViewerPanel(dataStore);
        analysisPanel = new AnalysisPanel(dataStore, this);

        mainTabbedPane.addTab("Database and Table Viewer", viewerPanel);
        mainTabbedPane.addTab("Analysis", analysisPanel);

        add(mainTabbedPane, BorderLayout.CENTER);
    }

    public void refreshFromDataStore() {
        topControlPanel.setDirectoryPath(dataStore.getSqlmapRootPath());
        viewerPanel.refreshDatabases();
        analysisPanel.refreshAll();
    }

    public void navigateToViewer(String dbName, String tableName) {
        mainTabbedPane.setSelectedIndex(0);
        viewerPanel.selectDatabaseAndTable(dbName, tableName);
    }

    public void selectDatabaseAndTable(String dbName, String tableName) {
        viewerPanel.selectDatabaseAndTable(dbName, tableName);
    }

    public String getSelectedDatabaseName() {
        return viewerPanel.getSelectedDatabaseName();
    }

    public String getSelectedTableName() {
        return viewerPanel.getSelectedTableName();
    }

    public void clearViews() {
        viewerPanel.clearTableView();
        analysisPanel.refreshAll();
        topControlPanel.resetStatus();
    }
}
