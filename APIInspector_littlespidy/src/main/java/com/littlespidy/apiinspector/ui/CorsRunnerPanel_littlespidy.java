// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.apiinspector.model.CorsTestResult_littlespidy;
import com.littlespidy.apiinspector.model.CorsTestResult_littlespidy.CorsSeverity;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * Runner session panel for CORS testing.
 * Top: Results table with Classification filter and right-click marking.
 * Bottom: 50/50 parallel side-by-side Montoya Request and Response editors with equal size.
 */
public class CorsRunnerPanel_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final String runnerId;
    private final String runnerName;
    private final List<CorsTestResult_littlespidy> allResults = new ArrayList<>();
    private final List<CorsTestResult_littlespidy> displayedResults = new ArrayList<>();
    private final CorsResultsTableModel tableModel = new CorsResultsTableModel();
    private final JTable resultsTable = new JTable(tableModel);

    private ClassificationFilterDropDown_littlespidy classificationFilterDropDown;
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private JSplitPane parallelViewerSplitPane;

    private final JLabel statusSummaryLabel = new JLabel("Status: Ready | Total: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0");

    public CorsRunnerPanel_littlespidy(MontoyaApi api, String runnerId, String runnerName) {
        super(new BorderLayout(4, 4));
        this.api = api;
        this.runnerId = runnerId;
        this.runnerName = runnerName;

        setBorder(new EmptyBorder(6, 6, 6, 6));
        initComponents();
    }

    public String getRunnerId() {
        return runnerId;
    }

    public String getRunnerName() {
        return runnerName;
    }

    public List<CorsTestResult_littlespidy> getResults() {
        return new ArrayList<>(allResults);
    }

    public void addResult(CorsTestResult_littlespidy result) {
        SwingUtilities.invokeLater(() -> {
            allResults.add(result);
            applyClassificationFilter();
            updateSummary();
            if (displayedResults.size() == 1) {
                resultsTable.setRowSelectionInterval(0, 0);
            }
        });
    }

    public void setResults(List<CorsTestResult_littlespidy> newResults) {
        SwingUtilities.invokeLater(() -> {
            allResults.clear();
            if (newResults != null) {
                allResults.addAll(newResults);
            }
            applyClassificationFilter();
            updateSummary();
            if (!displayedResults.isEmpty()) {
                resultsTable.setRowSelectionInterval(0, 0);
            } else {
                clearEditors();
            }
        });
    }

    public void updateStatusText(String text) {
        SwingUtilities.invokeLater(() -> statusSummaryLabel.setText(text));
    }

    private void updateSummary() {
        int total = allResults.size();
        int high = 0;
        int med = 0;
        int low = 0;
        int info = 0;
        for (CorsTestResult_littlespidy r : allResults) {
            if (r.getSeverity() == CorsSeverity.HIGH) high++;
            else if (r.getSeverity() == CorsSeverity.MEDIUM) med++;
            else if (r.getSeverity() == CorsSeverity.LOW) low++;
            else info++;
        }
        statusSummaryLabel.setText(String.format("Status: Active | Total: %d | High: %d | Medium: %d | Low: %d | Info: %d",
                total, high, med, low, info));
    }

    private void applyClassificationFilter() {
        displayedResults.clear();
        for (CorsTestResult_littlespidy r : allResults) {
            if (classificationFilterDropDown == null || classificationFilterDropDown.matchesClassification(r.getClassification())) {
                displayedResults.add(r);
            }
        }
        tableModel.fireTableDataChanged();
    }

    public void setMarkOnSelectedRows(String classification) {
        int[] selectedRows = resultsTable.getSelectedRows();
        if (selectedRows.length == 0) return;

        for (int viewRow : selectedRows) {
            int modelRow = resultsTable.convertRowIndexToModel(viewRow);
            if (modelRow >= 0 && modelRow < displayedResults.size()) {
                displayedResults.get(modelRow).setClassification(classification);
            }
        }
        applyClassificationFilter();
    }

    private void initComponents() {
        // Top Toolbar
        JPanel topBar = new JPanel(new BorderLayout(6, 6));
        topBar.add(statusSummaryLabel, BorderLayout.WEST);

        JPanel filterAndActionBox = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        classificationFilterDropDown = new ClassificationFilterDropDown_littlespidy();
        classificationFilterDropDown.addFilterChangeListener(this::applyClassificationFilter);
        filterAndActionBox.add(classificationFilterDropDown);

        JButton exportCsvBtn = new JButton("Export CSV");
        exportCsvBtn.addActionListener(e -> exportToCsv());
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            allResults.clear();
            displayedResults.clear();
            tableModel.fireTableDataChanged();
            updateSummary();
            clearEditors();
        });
        filterAndActionBox.add(exportCsvBtn);
        filterAndActionBox.add(clearBtn);
        topBar.add(filterAndActionBox, BorderLayout.EAST);

        add(topBar, BorderLayout.NORTH);

        // Results Table setup
        resultsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        resultsTable.setFillsViewportHeight(true);
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = resultsTable.getSelectedRow();
                if (row >= 0 && row < displayedResults.size()) {
                    displayResultDetails(displayedResults.get(row));
                }
            }
        });

        // Context Menu for Classification Marking
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem tpItem = new JMenuItem("Mark as True Positive");
        tpItem.addActionListener(e -> setMarkOnSelectedRows("TRUE_POSITIVE"));
        JMenuItem fpItem = new JMenuItem("Mark as False Positive");
        fpItem.addActionListener(e -> setMarkOnSelectedRows("FALSE_POSITIVE"));
        JMenuItem unclassItem = new JMenuItem("Clear Classification");
        unclassItem.addActionListener(e -> setMarkOnSelectedRows(null));
        popupMenu.add(tpItem);
        popupMenu.add(fpItem);
        popupMenu.add(unclassItem);
        resultsTable.setComponentPopupMenu(popupMenu);

        resultsTable.setDefaultRenderer(Object.class, new CorsCellRenderer());

        JScrollPane tableScrollPane = new JScrollPane(resultsTable);
        tableScrollPane.setPreferredSize(new Dimension(800, 240));

        // Bottom Parallel Request & Response Editors (50/50 Split)
        if (api != null && api.userInterface() != null) {
            requestEditor = api.userInterface().createHttpRequestEditor();
            responseEditor = api.userInterface().createHttpResponseEditor();
        }

        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request Viewer (Tested Origin)"));
        if (requestEditor != null) {
            requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
        } else {
            requestPanel.add(new JScrollPane(new JTextArea("Montoya HttpRequestEditor placeholder")), BorderLayout.CENTER);
        }

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response Viewer (CORS Headers)"));
        if (responseEditor != null) {
            responsePanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);
        } else {
            responsePanel.add(new JScrollPane(new JTextArea("Montoya HttpResponseEditor placeholder")), BorderLayout.CENTER);
        }

        parallelViewerSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPanel, responsePanel);
        parallelViewerSplitPane.setResizeWeight(0.5d);
        parallelViewerSplitPane.setDividerSize(6);

        // Vertical Split between Table (Top) and Viewers (Bottom)
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, parallelViewerSplitPane);
        mainSplitPane.setResizeWeight(0.4d);
        mainSplitPane.setDividerSize(6);

        add(mainSplitPane, BorderLayout.CENTER);
    }

    private void displayResultDetails(CorsTestResult_littlespidy result) {
        if (result == null || result.getHttpRequestResponse() == null) {
            clearEditors();
            return;
        }

        HttpRequestResponse rr = result.getHttpRequestResponse();
        if (requestEditor != null && rr.request() != null) {
            requestEditor.setRequest(rr.request());
        }
        if (responseEditor != null && rr.hasResponse()) {
            responseEditor.setResponse(rr.response());
        }
    }

    private void clearEditors() {
        if (requestEditor != null) {
            requestEditor.setRequest(null);
        }
        if (responseEditor != null) {
            responseEditor.setResponse(null);
        }
    }

    private void exportToCsv() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(runnerName.replaceAll("[^a-zA-Z0-9_-]", "_") + "_cors_results.csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("ID,Method,Host,Path,TestedOrigin,Status,ACAO,ACAC,Severity,Classification,Description\n");
                for (CorsTestResult_littlespidy r : allResults) {
                    fw.write(String.format("\"%d\",\"%s\",\"%s\",\"%s\",\"%s\",\"%d\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                            r.getId(), r.getMethod(), r.getHost(), r.getPath(), r.getTestedOrigin(),
                            r.getStatusCode(), r.getReflectedAcao(), r.isAcacPresent(),
                            r.getSeverity().getLabel(),
                            r.getClassification() != null ? r.getClassification() : "Unclassified",
                            r.getDescription().replace("\"", "\"\"")));
                }
                JOptionPane.showMessageDialog(this, "Exported " + allResults.size() + " CORS records.", "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private class CorsResultsTableModel extends AbstractTableModel {
        private final String[] columns = {"ID", "Method", "Target Host", "Path", "Tested Origin", "Status", "ACAO", "ACAC", "Severity", "Classification", "Assessment"};

        @Override
        public int getRowCount() {
            return displayedResults.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= displayedResults.size()) return "";
            CorsTestResult_littlespidy r = displayedResults.get(rowIndex);
            switch (columnIndex) {
                case 0: return r.getId();
                case 1: return r.getMethod();
                case 2: return r.getHost();
                case 3: return r.getPath();
                case 4: return r.getTestedOrigin();
                case 5: return r.getStatusCode();
                case 6: return r.getReflectedAcao().isEmpty() ? "(None)" : r.getReflectedAcao();
                case 7: return r.isAcacPresent() ? "true" : "false";
                case 8: return r.getSeverity().getLabel();
                case 9:
                    String c = r.getClassification();
                    if ("TRUE_POSITIVE".equalsIgnoreCase(c)) return "True Positive";
                    if ("FALSE_POSITIVE".equalsIgnoreCase(c)) return "False Positive";
                    return "Unclassified";
                case 10: return r.getDescription();
                default: return "";
            }
        }
    }

    private static class CorsCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected && column == 8) {
                String val = String.valueOf(value);
                if ("High".equalsIgnoreCase(val)) {
                    c.setForeground(new Color(220, 50, 50));
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                } else if ("Medium".equalsIgnoreCase(val)) {
                    c.setForeground(new Color(230, 140, 20));
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                } else if ("Low".equalsIgnoreCase(val)) {
                    c.setForeground(new Color(60, 160, 220));
                } else {
                    c.setForeground(table.getForeground());
                }
            } else if (!isSelected && column == 9) {
                String val = String.valueOf(value);
                if ("True Positive".equalsIgnoreCase(val)) {
                    c.setForeground(new Color(220, 50, 50));
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                } else if ("False Positive".equalsIgnoreCase(val)) {
                    c.setForeground(new Color(130, 130, 130));
                } else {
                    c.setForeground(table.getForeground());
                }
            } else if (!isSelected) {
                c.setForeground(table.getForeground());
            }
            return c;
        }
    }
}
