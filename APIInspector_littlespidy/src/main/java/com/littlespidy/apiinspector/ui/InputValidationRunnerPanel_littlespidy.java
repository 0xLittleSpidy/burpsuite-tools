// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.apiinspector.model.InputValidationTestResult_littlespidy;
import com.littlespidy.apiinspector.model.InputValidationTestResult_littlespidy.ValidationSeverity;

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
 * Runner session panel for Input Validation testing and fuzzing.
 * Top: Results table.
 * Bottom: 50/50 parallel side-by-side Montoya Request and Response editors with equal size.
 */
public class InputValidationRunnerPanel_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final String runnerId;
    private final String runnerName;
    private final List<InputValidationTestResult_littlespidy> results = new ArrayList<>();
    private final FuzzResultsTableModel tableModel = new FuzzResultsTableModel();
    private final JTable resultsTable = new JTable(tableModel);

    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private JSplitPane parallelViewerSplitPane;

    private final JLabel statusSummaryLabel = new JLabel("Status: Ready | Total: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0");

    public InputValidationRunnerPanel_littlespidy(MontoyaApi api, String runnerId, String runnerName) {
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

    public List<InputValidationTestResult_littlespidy> getResults() {
        return new ArrayList<>(results);
    }

    public void addResult(InputValidationTestResult_littlespidy result) {
        SwingUtilities.invokeLater(() -> {
            results.add(result);
            tableModel.fireTableRowsInserted(results.size() - 1, results.size() - 1);
            updateSummary();
            if (results.size() == 1) {
                resultsTable.setRowSelectionInterval(0, 0);
            }
        });
    }

    public void setResults(List<InputValidationTestResult_littlespidy> newResults) {
        SwingUtilities.invokeLater(() -> {
            results.clear();
            if (newResults != null) {
                results.addAll(newResults);
            }
            tableModel.fireTableDataChanged();
            updateSummary();
            if (!results.isEmpty()) {
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
        int total = results.size();
        int high = 0;
        int med = 0;
        int low = 0;
        int info = 0;
        for (InputValidationTestResult_littlespidy r : results) {
            if (r.getSeverity() == ValidationSeverity.HIGH) high++;
            else if (r.getSeverity() == ValidationSeverity.MEDIUM) med++;
            else if (r.getSeverity() == ValidationSeverity.LOW) low++;
            else info++;
        }
        statusSummaryLabel.setText(String.format("Status: Active | Total: %d | High: %d | Medium: %d | Low: %d | Info: %d",
                total, high, med, low, info));
    }

    private void initComponents() {
        // Top Toolbar
        JPanel topBar = new JPanel(new BorderLayout(6, 6));
        topBar.add(statusSummaryLabel, BorderLayout.WEST);

        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        JButton exportCsvBtn = new JButton("Export CSV");
        exportCsvBtn.addActionListener(e -> exportToCsv());
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            results.clear();
            tableModel.fireTableDataChanged();
            updateSummary();
            clearEditors();
        });
        btnBar.add(exportCsvBtn);
        btnBar.add(clearBtn);
        topBar.add(btnBar, BorderLayout.EAST);

        add(topBar, BorderLayout.NORTH);

        // Results Table setup
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.setFillsViewportHeight(true);
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = resultsTable.getSelectedRow();
                if (row >= 0 && row < results.size()) {
                    displayResultDetails(results.get(row));
                }
            }
        });

        resultsTable.setDefaultRenderer(Object.class, new FuzzCellRenderer());

        JScrollPane tableScrollPane = new JScrollPane(resultsTable);
        tableScrollPane.setPreferredSize(new Dimension(800, 240));

        // Bottom Parallel Request & Response Editors (50/50 Split)
        if (api != null && api.userInterface() != null) {
            requestEditor = api.userInterface().createHttpRequestEditor();
            responseEditor = api.userInterface().createHttpResponseEditor();
        }

        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request Viewer (Injected Fuzz Payload)"));
        if (requestEditor != null) {
            requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
        } else {
            requestPanel.add(new JScrollPane(new JTextArea("Montoya HttpRequestEditor placeholder")), BorderLayout.CENTER);
        }

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response Viewer (Evidence & Differences)"));
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

    private void displayResultDetails(InputValidationTestResult_littlespidy result) {
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
        chooser.setSelectedFile(new File(runnerName.replaceAll("[^a-zA-Z0-9_-]", "_") + "_validation_results.csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("ID,Method,TargetURL,Parameter,Category,Payload,Status,Length,Severity,Indicator\n");
                for (InputValidationTestResult_littlespidy r : results) {
                    fw.write(String.format("\"%d\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%d\",\"%d\",\"%s\",\"%s\"\n",
                            r.getId(), r.getMethod(), r.getTargetUrl(), r.getParameterName(),
                            r.getCategory(), r.getPayload().replace("\"", "\"\""),
                            r.getStatusCode(), r.getResponseLength(),
                            r.getSeverity().getLabel(), r.getDetectionIndicator().replace("\"", "\"\"")));
                }
                JOptionPane.showMessageDialog(this, "Exported " + results.size() + " Input Validation records.", "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private class FuzzResultsTableModel extends AbstractTableModel {
        private final String[] columns = {"ID", "Method", "Target URL", "Parameter", "Category", "Payload", "Status", "Length", "Severity", "Detection Indicator"};

        @Override
        public int getRowCount() {
            return results.size();
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
            if (rowIndex < 0 || rowIndex >= results.size()) return "";
            InputValidationTestResult_littlespidy r = results.get(rowIndex);
            switch (columnIndex) {
                case 0: return r.getId();
                case 1: return r.getMethod();
                case 2: return r.getTargetUrl();
                case 3: return r.getParameterName();
                case 4: return r.getCategory();
                case 5: return r.getPayload();
                case 6: return r.getStatusCode();
                case 7: return r.getResponseLength();
                case 8: return r.getSeverity().getLabel();
                case 9: return r.getDetectionIndicator();
                default: return "";
            }
        }
    }

    private static class FuzzCellRenderer extends DefaultTableCellRenderer {
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
            } else if (!isSelected) {
                c.setForeground(table.getForeground());
            }
            return c;
        }
    }
}
