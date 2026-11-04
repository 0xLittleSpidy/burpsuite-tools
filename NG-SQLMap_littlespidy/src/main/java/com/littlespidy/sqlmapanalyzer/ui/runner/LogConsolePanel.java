// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.runner;

import com.littlespidy.sqlmapanalyzer.api.model.SqlmapFinding;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapLogEntry;
import com.littlespidy.sqlmapanalyzer.runner.ScanExecutionRecord;
import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

/**
 * Bottom console panel displaying streaming real-time logs and structured vulnerability findings.
 * Plain ASCII text only.
 */
public class LogConsolePanel extends JPanel {

    private final JLabel statusBadgeLabel;
    private final JComboBox<String> filterLevelCombo;
    private final JCheckBox autoScrollCheckBox;
    private final JButton btnClear;
    private final JButton btnCopy;

    private final JTabbedPane bottomTabbedPane;
    private final JTextArea logTextArea;
    private final JTable findingsTable;
    private final DefaultTableModel findingsModel;

    private final List<SqlmapLogEntry> allLogs = new ArrayList<>();

    public LogConsolePanel() {
        setLayout(new BorderLayout(0, 4));
        setBorder(new EmptyBorder(4, 6, 4, 6));

        // 1. Initialize text area and table models first
        logTextArea = new JTextArea();
        logTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logTextArea.setEditable(false);
        logTextArea.setLineWrap(false);

        String[] findingHeaders = {"Parameter", "DBMS", "Injection Type", "Payload", "Details"};
        findingsModel = new DefaultTableModel(findingHeaders, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        findingsTable = new JTable(findingsModel);
        findingsTable.setRowHeight(22);
        findingsTable.setFillsViewportHeight(true);

        // 2. Top bar
        JPanel topBar = new JPanel(new BorderLayout(10, 0));

        JPanel leftStatus = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        leftStatus.add(SwingUtils.createBoldLabel("Scan Status:"));

        statusBadgeLabel = new JLabel("IDLE");
        statusBadgeLabel.setFont(statusBadgeLabel.getFont().deriveFont(Font.BOLD, 12));
        statusBadgeLabel.setOpaque(true);
        statusBadgeLabel.setBackground(Color.LIGHT_GRAY);
        statusBadgeLabel.setBorder(new EmptyBorder(2, 6, 2, 6));
        leftStatus.add(statusBadgeLabel);

        topBar.add(leftStatus, BorderLayout.WEST);

        JPanel rightControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));

        rightControls.add(new JLabel("Log Level:"));
        filterLevelCombo = new JComboBox<>(new String[]{"ALL", "INFO", "WARNING", "ERROR", "CRITICAL"});
        filterLevelCombo.addActionListener(e -> renderLogs());
        rightControls.add(filterLevelCombo);

        autoScrollCheckBox = new JCheckBox("Auto-scroll", true);
        rightControls.add(autoScrollCheckBox);

        btnClear = SwingUtils.createStyledButton("Clear");
        btnClear.addActionListener(e -> {
            allLogs.clear();
            logTextArea.setText("");
            findingsModel.setRowCount(0);
        });
        rightControls.add(btnClear);

        btnCopy = SwingUtils.createStyledButton("Copy Logs");
        btnCopy.addActionListener(e -> copyLogsToClipboard());
        rightControls.add(btnCopy);

        topBar.add(rightControls, BorderLayout.EAST);
        add(topBar, BorderLayout.NORTH);

        // 3. Center: JTabbedPane (Live Logs + Identified Findings)
        bottomTabbedPane = new JTabbedPane();

        JScrollPane logScroll = new JScrollPane(logTextArea);
        bottomTabbedPane.addTab("Real-Time Logs", logScroll);

        JScrollPane findingsScroll = new JScrollPane(findingsTable);
        bottomTabbedPane.addTab("Vulnerability Findings", findingsScroll);

        add(bottomTabbedPane, BorderLayout.CENTER);
    }

    public void updateFromRecord(ScanExecutionRecord record) {
        if (record == null) {
            statusBadgeLabel.setText("IDLE");
            statusBadgeLabel.setBackground(Color.LIGHT_GRAY);
            allLogs.clear();
            logTextArea.setText("");
            findingsModel.setRowCount(0);
            return;
        }

        setStatusBadge(record.getStatus(), record.isVulnerable());

        allLogs.clear();
        allLogs.addAll(record.getLogs());
        renderLogs();

        updateFindings(record.getFindings());
    }

    public void appendLogs(List<SqlmapLogEntry> newEntries) {
        if (newEntries == null || newEntries.isEmpty()) return;
        allLogs.clear();
        allLogs.addAll(newEntries);
        renderLogs();
    }

    public void setStatusBadge(String status, boolean vulnerable) {
        if (vulnerable) {
            statusBadgeLabel.setText("VULNERABLE");
            statusBadgeLabel.setBackground(new Color(255, 100, 100));
            statusBadgeLabel.setForeground(Color.WHITE);
        } else if ("RUNNING".equalsIgnoreCase(status)) {
            statusBadgeLabel.setText("RUNNING");
            statusBadgeLabel.setBackground(new Color(100, 180, 255));
            statusBadgeLabel.setForeground(Color.BLACK);
        } else if ("CANCELLED".equalsIgnoreCase(status)) {
            statusBadgeLabel.setText("CANCELLED");
            statusBadgeLabel.setBackground(Color.ORANGE);
            statusBadgeLabel.setForeground(Color.BLACK);
        } else if ("ERROR".equalsIgnoreCase(status)) {
            statusBadgeLabel.setText("ERROR");
            statusBadgeLabel.setBackground(Color.RED);
            statusBadgeLabel.setForeground(Color.WHITE);
        } else if ("COMPLETED".equalsIgnoreCase(status)) {
            statusBadgeLabel.setText("COMPLETED (NOT VULNERABLE)");
            statusBadgeLabel.setBackground(new Color(120, 200, 120));
            statusBadgeLabel.setForeground(Color.BLACK);
        } else {
            statusBadgeLabel.setText(status.toUpperCase());
            statusBadgeLabel.setBackground(Color.LIGHT_GRAY);
            statusBadgeLabel.setForeground(Color.BLACK);
        }
    }

    public void updateFindings(List<SqlmapFinding> findings) {
        findingsModel.setRowCount(0);
        if (findings != null) {
            for (SqlmapFinding f : findings) {
                Vector<Object> row = new Vector<>();
                row.add(f.getParameter());
                row.add(f.getDbms());
                row.add(f.getInjectionType());
                row.add(f.getPayload());
                row.add(f.getDetails());
                findingsModel.addRow(row);
            }
            if (!findings.isEmpty()) {
                bottomTabbedPane.setTitleAt(1, "Vulnerability Findings (" + findings.size() + ")");
            } else {
                bottomTabbedPane.setTitleAt(1, "Vulnerability Findings");
            }
        }
    }

    private void renderLogs() {
        String filter = (String) filterLevelCombo.getSelectedItem();
        StringBuilder sb = new StringBuilder();

        for (SqlmapLogEntry entry : allLogs) {
            if ("ALL".equalsIgnoreCase(filter) || entry.getLevel().equalsIgnoreCase(filter)) {
                sb.append(entry.getFormatted()).append("\n");
            }
        }

        logTextArea.setText(sb.toString());

        if (autoScrollCheckBox.isSelected()) {
            logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
        }
    }

    private void copyLogsToClipboard() {
        String text = logTextArea.getText();
        if (text != null && !text.isBlank()) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
            JOptionPane.showMessageDialog(this, "Logs copied to clipboard.", "Logs Copied", JOptionPane.INFORMATION_MESSAGE);
        }
    }
}
