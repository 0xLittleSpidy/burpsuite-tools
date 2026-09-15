// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.ui;

import com.littlespidy.headerinspector.csp.evaluator.CspFinding;
import com.littlespidy.headerinspector.csp.evaluator.CspSeverity;
import com.littlespidy.headerinspector.csp.evaluator.GoogleCspEvaluator;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Dedicated Google CSP Evaluator panel embedded inside Burp Suite.
 * Audits policies against Google's official checks and provides master-detail inspection of findings.
 *
 * @author littlespidy
 */
public class GoogleCspEvaluatorPanel extends JPanel {

    private final JLabel statusBadge = new JLabel("NO POLICY LOADED");
    private final JTextField policyField = new JTextField();
    private final JButton copyPolicyBtn = new JButton("Copy CSP");
    private final JButton openScratchpadBtn = new JButton("Open in Scratchpad");
    private final JButton checkUpdatesBtn = new JButton("🌐 Check Engine Updates");

    private final FindingsTableModel tableModel = new FindingsTableModel();
    private final JTable findingsTable = new JTable(tableModel);

    private final JLabel detailSeverityLabel = new JLabel("Select a finding above to inspect details.");
    private final JTextArea detailDescArea = new JTextArea();
    private final JLabel detailDirectiveLabel = new JLabel("");
    private final JLabel detailValueLabel = new JLabel("");

    private String currentPolicy = "";
    private Runnable scratchpadLauncher;

    public GoogleCspEvaluatorPanel() {
        super(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        initComponents();
    }

    public void setScratchpadLauncher(Runnable launcher) {
        this.scratchpadLauncher = launcher;
    }

    private void initComponents() {
        // ── 1. Top Bar: Status Badge, Policy Preview, Actions ──
        JPanel topPanel = new JPanel(new BorderLayout(6, 6));

        JPanel badgeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        JLabel titleLabel = new JLabel("🔍 Google CSP Evaluator");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));

        statusBadge.setOpaque(true);
        statusBadge.setBackground(new Color(158, 158, 158));
        statusBadge.setForeground(Color.WHITE);
        statusBadge.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        statusBadge.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));

        badgeRow.add(titleLabel);
        badgeRow.add(statusBadge);

        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        copyPolicyBtn.addActionListener(e -> {
            if (!currentPolicy.isBlank()) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(currentPolicy), null);
                JOptionPane.showMessageDialog(this, "CSP header copied to clipboard.", "Copied", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        openScratchpadBtn.addActionListener(e -> {
            if (scratchpadLauncher != null) {
                scratchpadLauncher.run();
            }
        });
        actionRow.add(copyPolicyBtn);
        actionRow.add(openScratchpadBtn);

        checkUpdatesBtn.setToolTipText("Check https://github.com/google/csp-evaluator for new releases");
        checkUpdatesBtn.addActionListener(e -> com.littlespidy.headerinspector.csp.evaluator.GoogleCspUpdateChecker.checkForUpdatesAsync(this));
        actionRow.add(checkUpdatesBtn);

        JPanel headerRow = new JPanel(new BorderLayout());
        headerRow.add(badgeRow, BorderLayout.WEST);
        headerRow.add(actionRow, BorderLayout.EAST);

        policyField.setEditable(false);
        policyField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        policyField.setToolTipText("Raw Content-Security-Policy header value");

        topPanel.add(headerRow, BorderLayout.NORTH);
        topPanel.add(policyField, BorderLayout.SOUTH);
        add(topPanel, BorderLayout.NORTH);

        // ── 2. Center: Split Pane (Findings Table on top, Detail card on bottom) ──
        findingsTable.setRowSorter(new TableRowSorter<>(tableModel));
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setupTableRendering();

        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = findingsTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = findingsTable.convertRowIndexToModel(row);
                    CspFinding finding = tableModel.getFindingAt(modelRow);
                    showFindingDetails(finding);
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(findingsTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Google Security & Syntax Findings",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 12)
        ));

        // ── Detail Pane ──
        JPanel detailCard = new JPanel(new BorderLayout(6, 6));
        detailCard.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Finding Details & Remediation Guidance",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 12)
        ));

        JPanel detailHeader = new JPanel(new GridLayout(3, 1, 3, 3));
        detailHeader.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        detailSeverityLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        detailDirectiveLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        detailValueLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        detailHeader.add(detailSeverityLabel);
        detailHeader.add(detailDirectiveLabel);
        detailHeader.add(detailValueLabel);

        detailDescArea.setEditable(false);
        detailDescArea.setLineWrap(true);
        detailDescArea.setWrapStyleWord(true);
        detailDescArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        detailDescArea.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        detailCard.add(detailHeader, BorderLayout.NORTH);
        detailCard.add(new JScrollPane(detailDescArea), BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailCard);
        splitPane.setResizeWeight(0.55);
        add(splitPane, BorderLayout.CENTER);
    }

    public void setPolicy(String rawPolicy) {
        this.currentPolicy = (rawPolicy == null) ? "" : rawPolicy.trim();
        policyField.setText(currentPolicy.isEmpty() ? "(No CSP header)" : currentPolicy);

        if (currentPolicy.isEmpty() || currentPolicy.equalsIgnoreCase("(missing CSP)")) {
            statusBadge.setText("🔴 MISSING CSP");
            statusBadge.setBackground(CspSeverity.HIGH.getColor());
            tableModel.setFindings(List.of(new CspFinding(
                com.littlespidy.headerinspector.csp.evaluator.CspFindingType.MISSING_DIRECTIVES,
                "Content Security Policy is completely missing. Allows unrestricted script execution and Clickjacking.",
                CspSeverity.HIGH,
                "default-src",
                ""
            )));
            if (findingsTable.getRowCount() > 0) {
                findingsTable.setRowSelectionInterval(0, 0);
            }
            return;
        }

        List<CspFinding> findings = GoogleCspEvaluator.evaluate(currentPolicy);
        tableModel.setFindings(findings);

        CspSeverity highest = CspSeverity.getHighest(findings);
        if (highest == CspSeverity.NONE || findings.isEmpty()) {
            statusBadge.setText("🟢 STRONG / PASS");
            statusBadge.setBackground(CspSeverity.NONE.getColor());
        } else {
            statusBadge.setText(highest.getLabel() + " (" + findings.size() + " findings)");
            statusBadge.setBackground(highest.getColor());
        }

        if (findingsTable.getRowCount() > 0) {
            findingsTable.setRowSelectionInterval(0, 0);
        } else {
            detailSeverityLabel.setText("No violations detected by Google CSP Evaluator.");
            detailDirectiveLabel.setText("");
            detailValueLabel.setText("");
            detailDescArea.setText("This policy adheres to Google's baseline CSP rules.");
        }
    }

    public String getCurrentPolicy() {
        return currentPolicy;
    }

    private void showFindingDetails(CspFinding finding) {
        if (finding == null) return;
        detailSeverityLabel.setText(finding.severity().getLabel() + ": " + finding.getDisplayTitle());
        detailSeverityLabel.setForeground(finding.severity().getColor());

        detailDirectiveLabel.setText("Directive: " + (finding.directive().isEmpty() ? "(general)" : finding.directive()));
        detailValueLabel.setText("Offending Value: " + (finding.value().isEmpty() ? "(none)" : finding.value()));
        detailDescArea.setText(finding.description());
    }

    private void setupTableRendering() {
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(90);
        findingsTable.getColumnModel().getColumn(0).setMaxWidth(110);
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        findingsTable.getColumnModel().getColumn(1).setMaxWidth(160);
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(140);
        findingsTable.getColumnModel().getColumn(3).setPreferredWidth(450);

        findingsTable.getColumnModel().getColumn(0).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (value instanceof CspSeverity sev) {
                    setText(sev.getLabel());
                    setHorizontalAlignment(SwingConstants.CENTER);
                    if (!isSelected) {
                        setBackground(new Color(sev.getColor().getRed(), sev.getColor().getGreen(), sev.getColor().getBlue(), 35));
                        setForeground(sev.getColor().darker());
                        setFont(getFont().deriveFont(Font.BOLD));
                    }
                }
                return c;
            }
        });
    }

    // ── Table Model ──

    private static class FindingsTableModel extends AbstractTableModel {
        private static final String[] COLS = {"Severity", "Directive", "Value", "Description"};
        private final List<CspFinding> findings = new ArrayList<>();

        public void setFindings(List<CspFinding> newFindings) {
            findings.clear();
            if (newFindings != null) {
                findings.addAll(newFindings);
            }
            fireTableDataChanged();
        }

        public CspFinding getFindingAt(int row) {
            if (row >= 0 && row < findings.size()) {
                return findings.get(row);
            }
            return null;
        }

        @Override
        public int getRowCount() { return findings.size(); }

        @Override
        public int getColumnCount() { return COLS.length; }

        @Override
        public String getColumnName(int col) { return COLS[col]; }

        @Override
        public Class<?> getColumnClass(int col) {
            return (col == 0) ? CspSeverity.class : String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= findings.size()) return null;
            CspFinding f = findings.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> f.severity();
                case 1 -> f.directive().isEmpty() ? "(general)" : f.directive();
                case 2 -> f.value();
                case 3 -> f.description();
                default -> null;
            };
        }
    }
}
