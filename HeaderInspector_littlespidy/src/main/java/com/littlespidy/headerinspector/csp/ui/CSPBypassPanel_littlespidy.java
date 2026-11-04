// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.ui;

import com.littlespidy.headerinspector.csp.evaluator.CSPBypassEngine_littlespidy;
import com.littlespidy.headerinspector.csp.evaluator.CSPBypassEngine_littlespidy.BypassFinding_littlespidy;
import com.littlespidy.headerinspector.csp.evaluator.CSPBypassEngine_littlespidy.BypassEvaluationResult_littlespidy;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
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
 * Dedicated UI panel for evaluating and exploring CSP bypass techniques ported from renniepak/CSPBypass.
 * Displays matching JSONP, script gadget, and CDN execution vectors for active CSP policies.
 *
 * @author littlespidy
 */
public class CSPBypassPanel_littlespidy extends JPanel {

    private final JLabel statusBadge = new JLabel("NO POLICY LOADED");
    private final JTextField searchField = new JTextField(18);
    private final JButton evalBtn = new JButton("Evaluate Active CSP");
    private final JButton showAllBtn = new JButton("Show All Database (" + CSPBypassEngine_littlespidy.getDatabaseSize() + ")");
    private final JButton copyPayloadBtn = new JButton("Copy Exploit Payload");

    private final BypassTableModel tableModel = new BypassTableModel();
    private final JTable table = new JTable(tableModel);

    private final JLabel detailDomainLabel = new JLabel("Domain: -");
    private final JLabel detailDirectiveLabel = new JLabel("Directive: -");
    private final JLabel detailTokenLabel = new JLabel("Allowed By Token: -");
    private final JTextArea payloadArea = new JTextArea();

    private String activePolicy = "";
    private int matchCount = 0;

    public CSPBypassPanel_littlespidy() {
        super(new BorderLayout(6, 6));
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        initComponents();
        setupListeners();
    }

    private void initComponents() {
        // ── Top Toolbar ──
        JPanel topContainer = new JPanel(new BorderLayout(6, 4));

        JPanel titleRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        JLabel titleLabel = new JLabel("CSPBypass Techniques");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));

        statusBadge.setOpaque(true);
        statusBadge.setBackground(new Color(158, 158, 158));
        statusBadge.setForeground(Color.WHITE);
        statusBadge.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        statusBadge.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));

        titleRow.add(titleLabel);
        titleRow.add(statusBadge);

        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        actionRow.add(new JLabel("Search Bypasses:"));
        actionRow.add(searchField);
        actionRow.add(evalBtn);
        actionRow.add(showAllBtn);
        actionRow.add(copyPayloadBtn);

        topContainer.add(titleRow, BorderLayout.WEST);
        topContainer.add(actionRow, BorderLayout.EAST);

        // ── Main Content: Table & Details Split ──
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        TableRowSorter<BypassTableModel> sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        setupTableRendering();

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = table.getSelectedRow();
                if (row >= 0) {
                    int mr = table.convertRowIndexToModel(row);
                    BypassFinding_littlespidy finding = tableModel.getFindingAt(mr);
                    if (finding != null) {
                        displayFinding(finding);
                    }
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(800, 200));

        // ── Bottom Detail Panel ──
        JPanel detailPanel = new JPanel(new BorderLayout(4, 4));
        detailPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Bypass Payload and Exploit Details",
                TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 11)
        ));

        JPanel metaRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        metaRow.add(detailDomainLabel);
        metaRow.add(new JSeparator(SwingConstants.VERTICAL));
        metaRow.add(detailDirectiveLabel);
        metaRow.add(new JSeparator(SwingConstants.VERTICAL));
        metaRow.add(detailTokenLabel);

        payloadArea.setEditable(false);
        payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        payloadArea.setLineWrap(true);
        payloadArea.setWrapStyleWord(true);
        payloadArea.setRows(5);

        JScrollPane payloadScroll = new JScrollPane(payloadArea);

        detailPanel.add(metaRow, BorderLayout.NORTH);
        detailPanel.add(payloadScroll, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailPanel);
        splitPane.setResizeWeight(0.55);

        add(topContainer, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
    }

    private void setupListeners() {
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { doSearch(); }
            @Override public void removeUpdate(DocumentEvent e) { doSearch(); }
            @Override public void changedUpdate(DocumentEvent e) { doSearch(); }
        });

        evalBtn.addActionListener(e -> evaluatePolicy(activePolicy));

        showAllBtn.addActionListener(e -> {
            searchField.setText("");
            List<BypassFinding_littlespidy> all = CSPBypassEngine_littlespidy.searchDatabase("");
            tableModel.setFindings(all);
            statusBadge.setText("DATABASE (" + all.size() + " ENTRIES)");
            statusBadge.setBackground(new Color(66, 133, 244));
            if (!all.isEmpty()) table.setRowSelectionInterval(0, 0);
        });

        copyPayloadBtn.addActionListener(e -> {
            String code = payloadArea.getText();
            if (code != null && !code.isBlank()) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(code), null);
                JOptionPane.showMessageDialog(this, "Exploit payload copied to clipboard.", "Copied", JOptionPane.INFORMATION_MESSAGE);
            }
        });
    }

    private void setupTableRendering() {
        if (table.getColumnModel().getColumnCount() >= 5) {
            table.getColumnModel().getColumn(0).setMaxWidth(45);
            table.getColumnModel().getColumn(1).setPreferredWidth(180);
            table.getColumnModel().getColumn(2).setPreferredWidth(90);
            table.getColumnModel().getColumn(3).setPreferredWidth(140);
            table.getColumnModel().getColumn(4).setPreferredWidth(350);
        }

        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable t, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, value, isSelected, hasFocus, row, col);
                if (!isSelected) {
                    c.setForeground(Color.BLACK);
                    c.setBackground(row % 2 == 0 ? Color.WHITE : new Color(248, 249, 250));
                }
                return c;
            }
        });
    }

    public synchronized void evaluatePolicy(String policy) {
        this.activePolicy = (policy != null) ? policy : "";
        if (activePolicy.isBlank()) {
            tableModel.setFindings(List.of());
            matchCount = 0;
            statusBadge.setText("NO POLICY LOADED");
            statusBadge.setBackground(new Color(158, 158, 158));
            clearDetails();
            return;
        }

        BypassEvaluationResult_littlespidy result = CSPBypassEngine_littlespidy.evaluatePolicy(activePolicy);
        List<BypassFinding_littlespidy> findings = result.findings();
        this.matchCount = findings.size();

        tableModel.setFindings(findings);

        if (matchCount > 0) {
            statusBadge.setText(matchCount + " BYPASSES DETECTED");
            statusBadge.setBackground(new Color(217, 48, 37));
            table.setRowSelectionInterval(0, 0);
        } else {
            if (result.hasUnsafeInline()) {
                statusBadge.setText("UNSAFE-INLINE ALLOWED");
                statusBadge.setBackground(new Color(234, 134, 0));
            } else {
                statusBadge.setText("NO BYPASSES FOUND");
                statusBadge.setBackground(new Color(15, 157, 88));
            }
            clearDetails();
        }
    }

    private void doSearch() {
        String q = searchField.getText().trim();
        if (q.isEmpty()) {
            if (!activePolicy.isBlank()) {
                evaluatePolicy(activePolicy);
            } else {
                List<BypassFinding_littlespidy> all = CSPBypassEngine_littlespidy.searchDatabase("");
                tableModel.setFindings(all);
                statusBadge.setText("DATABASE (" + all.size() + " ENTRIES)");
                statusBadge.setBackground(new Color(66, 133, 244));
            }
            return;
        }

        List<BypassFinding_littlespidy> matches = CSPBypassEngine_littlespidy.searchDatabase(q);
        tableModel.setFindings(matches);
        statusBadge.setText(matches.size() + " SEARCH RESULTS");
        statusBadge.setBackground(new Color(66, 133, 244));
        if (!matches.isEmpty()) {
            table.setRowSelectionInterval(0, 0);
        } else {
            clearDetails();
        }
    }

    private void displayFinding(BypassFinding_littlespidy finding) {
        detailDomainLabel.setText("Domain: " + finding.domain());
        detailDirectiveLabel.setText("Directive: " + finding.directive());
        detailTokenLabel.setText("Allowed By Token: " + finding.sourceToken());
        payloadArea.setText(finding.code());
        payloadArea.setCaretPosition(0);
    }

    private void clearDetails() {
        detailDomainLabel.setText("Domain: -");
        detailDirectiveLabel.setText("Directive: -");
        detailTokenLabel.setText("Allowed By Token: -");
        payloadArea.setText("");
    }

    public int getMatchCount() {
        return matchCount;
    }

    private static class BypassTableModel extends AbstractTableModel {
        private final String[] columns = {"#", "Domain", "Directive", "Allowed Token", "Payload Preview"};
        private final List<BypassFinding_littlespidy> findings = new ArrayList<>();

        public void setFindings(List<BypassFinding_littlespidy> newFindings) {
            findings.clear();
            if (newFindings != null) findings.addAll(newFindings);
            fireTableDataChanged();
        }

        public BypassFinding_littlespidy getFindingAt(int row) {
            if (row >= 0 && row < findings.size()) return findings.get(row);
            return null;
        }

        @Override public int getRowCount() { return findings.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            BypassFinding_littlespidy f = findings.get(row);
            return switch (col) {
                case 0 -> row + 1;
                case 1 -> f.domain();
                case 2 -> f.directive();
                case 3 -> f.sourceToken();
                case 4 -> f.code();
                default -> "";
            };
        }
    }
}
