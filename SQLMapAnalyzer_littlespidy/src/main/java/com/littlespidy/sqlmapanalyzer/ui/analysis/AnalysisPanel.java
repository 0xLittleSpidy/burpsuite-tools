// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.analysis;

import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
import com.littlespidy.sqlmapanalyzer.ui.SQLMapAnalyzerTab;

import javax.swing.*;
import java.awt.*;

/**
 * Tab 2: Analysis container hosting Table Gathering and Column Gathering.
 * Plain ASCII text only.
 */
public class AnalysisPanel extends JPanel {

    private final TableGatheringPanel tableGatheringPanel;
    private final ColumnGatheringPanel columnGatheringPanel;

    public AnalysisPanel(SqlmapDataStore dataStore, SQLMapAnalyzerTab mainTab) {
        setLayout(new BorderLayout());

        JTabbedPane analysisTabs = new JTabbedPane();

        tableGatheringPanel = new TableGatheringPanel(dataStore, mainTab);
        columnGatheringPanel = new ColumnGatheringPanel(dataStore, mainTab);

        analysisTabs.addTab("Table Gathering", tableGatheringPanel);
        analysisTabs.addTab("Column Gathering", columnGatheringPanel);

        add(analysisTabs, BorderLayout.CENTER);
    }

    public void refreshAll() {
        tableGatheringPanel.refreshData();
        columnGatheringPanel.refreshData();
    }
}
