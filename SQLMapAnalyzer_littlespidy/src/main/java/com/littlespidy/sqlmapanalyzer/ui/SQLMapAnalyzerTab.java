// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
import com.littlespidy.sqlmapanalyzer.persistence.SQLMapPersistenceManager;
import com.littlespidy.sqlmapanalyzer.ui.analysis.AnalysisPanel;
import com.littlespidy.sqlmapanalyzer.ui.runner.SqlmapRunnerRootPanel;
import com.littlespidy.sqlmapanalyzer.ui.viewer.TableViewerPanel;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;
import java.awt.*;

/**
 * Main Suite Tab component for SQLMap Analyzer in Burp Suite.
 * Houses Tab 1: SQLMap (Scanner), Tab 2: Database and Table Viewer, Tab 3: Analysis.
 * Features a compact navigation strip with tabs on the far-left and SQLMap output controls on the far-right.
 * Plain ASCII text only.
 */
public class SQLMapAnalyzerTab extends JPanel {

    private static final String CARD_SQLMAP = "SQLMAP";
    private static final String CARD_VIEWER = "VIEWER";
    private static final String CARD_ANALYSIS = "ANALYSIS";

    private final MontoyaApi api;
    private final SqlmapDataStore dataStore;
    private final SQLMapPersistenceManager persistenceManager;

    private final SessionControlPanel sessionControlPanel;
    private final TopControlPanel topControlPanel;

    private final CardLayout cardLayout;
    private final JPanel cardsPanel;

    private final JToggleButton btnTabSqlmap;
    private final JToggleButton btnTabViewer;
    private final JToggleButton btnTabAnalysis;

    private final SqlmapRunnerRootPanel runnerRootPanel;
    private final TableViewerPanel viewerPanel;
    private final AnalysisPanel analysisPanel;

    public SQLMapAnalyzerTab(MontoyaApi api, SqlmapDataStore dataStore, SQLMapPersistenceManager persistenceManager, SqlmapRunnerRootPanel runnerRootPanel) {
        this.api = api;
        this.dataStore = dataStore;
        this.persistenceManager = persistenceManager;
        this.runnerRootPanel = runnerRootPanel;

        setLayout(new BorderLayout());

        // Header section: Row 1 = Session Controls; Row 2 = Combined Navigation & Output Bar
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));

        sessionControlPanel = new SessionControlPanel(persistenceManager);
        headerPanel.add(sessionControlPanel);

        // Row 2: Combined navigation bar (Tabs on left, SQLMap output on right)
        JPanel navBar = new JPanel(new BorderLayout());
        navBar.setBorder(new CompoundBorder(
                new MatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                new EmptyBorder(2, 6, 2, 6)
        ));

        // Far-left tabs
        JPanel tabsStrip = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        ButtonGroup tabGroup = new ButtonGroup();

        cardLayout = new CardLayout();
        cardsPanel = new JPanel(cardLayout);

        btnTabSqlmap = createTabButton("SQLMap", CARD_SQLMAP);
        btnTabViewer = createTabButton("Database and Table Viewer", CARD_VIEWER);
        btnTabAnalysis = createTabButton("Analysis", CARD_ANALYSIS);

        tabGroup.add(btnTabSqlmap);
        tabGroup.add(btnTabViewer);
        tabGroup.add(btnTabAnalysis);

        tabsStrip.add(btnTabSqlmap);
        tabsStrip.add(btnTabViewer);
        tabsStrip.add(btnTabAnalysis);
        navBar.add(tabsStrip, BorderLayout.WEST);

        // Far-right SQLMap output controls
        topControlPanel = new TopControlPanel(this, dataStore, persistenceManager);
        navBar.add(topControlPanel, BorderLayout.EAST);

        headerPanel.add(navBar);
        add(headerPanel, BorderLayout.NORTH);

        // Center: CardLayout views
        viewerPanel = new TableViewerPanel(dataStore);
        analysisPanel = new AnalysisPanel(dataStore, this);

        if (runnerRootPanel != null) {
            cardsPanel.add(runnerRootPanel, CARD_SQLMAP);
            btnTabSqlmap.setSelected(true);
            cardLayout.show(cardsPanel, CARD_SQLMAP);
        } else {
            btnTabSqlmap.setEnabled(false);
            btnTabViewer.setSelected(true);
            cardLayout.show(cardsPanel, CARD_VIEWER);
        }

        cardsPanel.add(viewerPanel, CARD_VIEWER);
        cardsPanel.add(analysisPanel, CARD_ANALYSIS);

        add(cardsPanel, BorderLayout.CENTER);
    }

    private JToggleButton createTabButton(String text, String cardName) {
        JToggleButton btn = new JToggleButton(text);
        btn.setFont(btn.getFont().deriveFont(Font.BOLD, 12));
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setMargin(new Insets(4, 12, 4, 12));
        btn.addActionListener(e -> cardLayout.show(cardsPanel, cardName));
        return btn;
    }

    public SqlmapRunnerRootPanel getRunnerRootPanel() {
        return runnerRootPanel;
    }

    public void switchToSqlmapTab() {
        btnTabSqlmap.setSelected(true);
        cardLayout.show(cardsPanel, CARD_SQLMAP);
    }

    public void refreshFromDataStore() {
        topControlPanel.setDirectoryPath(dataStore.getSqlmapRootPath());
        viewerPanel.refreshDatabases();
        analysisPanel.refreshAll();
    }

    public void navigateToViewer(String dbName, String tableName) {
        btnTabViewer.setSelected(true);
        cardLayout.show(cardsPanel, CARD_VIEWER);
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
        if (runnerRootPanel != null) {
            runnerRootPanel.clearAllTabs();
        }
    }
}
