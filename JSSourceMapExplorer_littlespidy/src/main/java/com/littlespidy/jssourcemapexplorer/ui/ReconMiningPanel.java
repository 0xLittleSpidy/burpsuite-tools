// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import com.littlespidy.jssourcemapexplorer.model.DiscoveredEndpoint;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredSecret;
import com.littlespidy.jssourcemapexplorer.model.JsDataStore;
import com.littlespidy.jssourcemapexplorer.model.JsFileEntry;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * Dedicated top-level panel for exploring and exporting all discovered API endpoints,
 * routes, hardcoded secrets, tokens, and credentials extracted from both
 * raw JavaScript files and unpacked Source Maps with hover cloud tooltips and right-click context menu copying.
 *
 * @author littlespidy
 */
public class ReconMiningPanel extends JPanel {

    private final JsDataStore dataStore;

    private final EndpointsTableModel endpointsTableModel = new EndpointsTableModel();
    private final JTable endpointsTable = new JTable(endpointsTableModel);

    private final SecretsTableModel secretsTableModel = new SecretsTableModel();
    private final JTable secretsTable = new JTable(secretsTableModel);

    private final JComboBox<String> sourceTypeFilter = new JComboBox<>(new String[]{"All Sources", "JS Files Only", "SourceMap Files Only"});
    private final JTextField searchField = new JTextField(18);
    private final JLabel statsLabel = new JLabel("Endpoints: 0 | Secrets: 0");

    private final List<DiscoveredEndpoint> masterEndpoints = new ArrayList<>();
    private final List<DiscoveredSecret> masterSecrets = new ArrayList<>();

    public ReconMiningPanel(JsDataStore dataStore) {
        this.dataStore = dataStore;
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ── Top Filter Toolbar ──
        JPanel topToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JLabel filterLbl = new JLabel("Filter Source:");
        filterLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        topToolbar.add(filterLbl);
        topToolbar.add(sourceTypeFilter);

        sourceTypeFilter.addActionListener(e -> applyFilter());

        JLabel searchLbl = new JLabel(" Search: ");
        searchLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        topToolbar.add(searchLbl);
        topToolbar.add(searchField);

        JButton applyBtn = new JButton("Filter");
        applyBtn.addActionListener(e -> applyFilter());
        topToolbar.add(applyBtn);

        JButton resetBtn = new JButton("Reset");
        resetBtn.addActionListener(e -> {
            searchField.setText("");
            sourceTypeFilter.setSelectedIndex(0);
            applyFilter();
        });
        topToolbar.add(resetBtn);

        JButton refreshBtn = new JButton("Refresh Findings");
        refreshBtn.addActionListener(e -> refreshFromDataStore());
        topToolbar.add(refreshBtn);

        topToolbar.add(new JSeparator(SwingConstants.VERTICAL));
        topToolbar.add(statsLabel);

        add(topToolbar, BorderLayout.NORTH);

        // ── Center Tabbed Tables ──
        JTabbedPane tabs = new JTabbedPane();

        // ── Tab 1: API Endpoints & Routes ──
        JPanel endpointsPanel = new JPanel(new BorderLayout(5, 5));
        endpointsPanel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        JPanel epToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        JButton exportEpBtn = new JButton("Export Endpoints TSV");
        exportEpBtn.addActionListener(e -> exportTableToTsv(endpointsTable, "Endpoints"));
        epToolbar.add(exportEpBtn);

        endpointsTable.setRowSorter(new TableRowSorter<>(endpointsTableModel));
        setupTableRendering(endpointsTable);
        setupTableKeyboardCopy(endpointsTable);
        setupEndpointsContextMenu();

        endpointsPanel.add(epToolbar, BorderLayout.NORTH);
        endpointsPanel.add(new JScrollPane(endpointsTable), BorderLayout.CENTER);

        // ── Tab 2: Secrets & Tokens ──
        JPanel secretsPanel = new JPanel(new BorderLayout(5, 5));
        secretsPanel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        JPanel secToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        JButton exportSecBtn = new JButton("Export Secrets TSV");
        exportSecBtn.addActionListener(e -> exportTableToTsv(secretsTable, "Secrets"));
        secToolbar.add(exportSecBtn);

        secretsTable.setRowSorter(new TableRowSorter<>(secretsTableModel));
        setupTableRendering(secretsTable);
        setupTableKeyboardCopy(secretsTable);
        setupSecretsContextMenu();

        secretsPanel.add(secToolbar, BorderLayout.NORTH);
        secretsPanel.add(new JScrollPane(secretsTable), BorderLayout.CENTER);

        tabs.addTab("Discovered Endpoints & Routes", endpointsPanel);
        tabs.addTab("Discovered Secrets & Tokens", secretsPanel);

        add(tabs, BorderLayout.CENTER);
    }

    public synchronized void refreshFromDataStore() {
        masterEndpoints.clear();
        masterSecrets.clear();

        if (dataStore != null) {
            for (JsFileEntry entry : dataStore.getEntries()) {
                // 1. Add JS findings
                masterEndpoints.addAll(entry.getJsEndpoints());
                masterSecrets.addAll(entry.getJsSecrets());

                // 2. Add SourceMap findings
                if (entry.getUnpackedProject() != null) {
                    masterEndpoints.addAll(entry.getUnpackedProject().getAllEndpoints());
                    masterSecrets.addAll(entry.getUnpackedProject().getAllSecrets());
                }
            }
        }

        applyFilter();
    }

    private synchronized void applyFilter() {
        String filterType = (String) sourceTypeFilter.getSelectedItem();
        if (filterType == null) filterType = "All Sources";
        String query = searchField.getText().trim().toLowerCase();

        List<DiscoveredEndpoint> filteredEndpoints = new ArrayList<>();
        for (DiscoveredEndpoint ep : masterEndpoints) {
            if (filterType.equals("JS Files Only") && !"JS File".equalsIgnoreCase(ep.sourceType())) continue;
            if (filterType.equals("SourceMap Files Only") && !"SourceMap".equalsIgnoreCase(ep.sourceType())) continue;

            if (!query.isEmpty()) {
                boolean match = ep.endpoint().toLowerCase().contains(query)
                    || ep.sourceLocation().toLowerCase().contains(query)
                    || ep.contextSnippet().toLowerCase().contains(query);
                if (!match) continue;
            }
            filteredEndpoints.add(ep);
        }

        List<DiscoveredSecret> filteredSecrets = new ArrayList<>();
        for (DiscoveredSecret sec : masterSecrets) {
            if (filterType.equals("JS Files Only") && !"JS File".equalsIgnoreCase(sec.sourceType())) continue;
            if (filterType.equals("SourceMap Files Only") && !"SourceMap".equalsIgnoreCase(sec.sourceType())) continue;

            if (!query.isEmpty()) {
                boolean match = sec.secretValue().toLowerCase().contains(query)
                    || sec.category().toLowerCase().contains(query)
                    || sec.sourceLocation().toLowerCase().contains(query)
                    || sec.contextSnippet().toLowerCase().contains(query);
                if (!match) continue;
            }
            filteredSecrets.add(sec);
        }

        endpointsTableModel.updateData(filteredEndpoints);
        secretsTableModel.updateData(filteredSecrets);

        statsLabel.setText(String.format(
            "Endpoints: %d / %d | Secrets: %d / %d",
            filteredEndpoints.size(), masterEndpoints.size(),
            filteredSecrets.size(), masterSecrets.size()
        ));
    }

    private void setupTableRendering(JTable table) {
        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                JTable tbl, Object value, boolean isSelected, boolean hasFocus, int row, int column
            ) {
                Component c = super.getTableCellRendererComponent(tbl, value, isSelected, hasFocus, row, column);

                if (value != null && !value.toString().trim().isEmpty() && !value.toString().equals("-")) {
                    String valStr = value.toString();
                    ((JComponent) c).setToolTipText("<html><div style='max-width: 600px; padding: 4px; font-family: monospace; font-size: 11px; word-wrap: break-word;'>"
                        + escapeHtml(valStr) + "</div></html>");
                } else {
                    ((JComponent) c).setToolTipText(null);
                }

                if (!isSelected) {
                    if (row % 2 == 1) {
                        c.setBackground(new Color(250, 250, 252));
                    } else {
                        c.setBackground(tbl.getBackground());
                    }
                }
                return c;
            }
        });
    }

    private void setupEndpointsContextMenu() {
        endpointsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) { handlePopup(e); }
            @Override
            public void mouseReleased(MouseEvent e) { handlePopup(e); }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = endpointsTable.rowAtPoint(e.getPoint());
                    int col = endpointsTable.columnAtPoint(e.getPoint());
                    if (row >= 0) {
                        if (!endpointsTable.isRowSelected(row)) {
                            endpointsTable.setRowSelectionInterval(row, row);
                        }

                        int modelRow = endpointsTable.convertRowIndexToModel(row);
                        DiscoveredEndpoint ep = endpointsTableModel.getEndpointAt(modelRow);
                        if (ep == null) return;

                        Object cellVal = endpointsTable.getValueAt(row, col);
                        String cellStr = cellVal != null ? cellVal.toString() : "";

                        JPopupMenu menu = new JPopupMenu();

                        JMenuItem copyCellItem = new JMenuItem("Copy Cell Value (\"" + (cellStr.length() > 30 ? cellStr.substring(0, 27) + "..." : cellStr) + "\")");
                        copyCellItem.addActionListener(ev -> copyToClipboard(cellStr));
                        menu.add(copyCellItem);

                        JMenuItem copyEndpointItem = new JMenuItem("Copy Endpoint / Route");
                        copyEndpointItem.addActionListener(ev -> copyToClipboard(ep.endpoint()));
                        menu.add(copyEndpointItem);

                        JMenuItem copyLocationItem = new JMenuItem("Copy Location / Source File");
                        copyLocationItem.addActionListener(ev -> copyToClipboard(ep.sourceLocation()));
                        menu.add(copyLocationItem);

                        JMenuItem copySnippetItem = new JMenuItem("Copy Context Snippet");
                        copySnippetItem.addActionListener(ev -> copyToClipboard(ep.contextSnippet()));
                        menu.add(copySnippetItem);

                        JMenuItem copyRowsItem = new JMenuItem("Copy Selected Row(s) as TSV");
                        copyRowsItem.addActionListener(ev -> exportTableToTsv(endpointsTable, "Endpoints Selection"));
                        menu.add(copyRowsItem);

                        menu.show(endpointsTable, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private void setupSecretsContextMenu() {
        secretsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) { handlePopup(e); }
            @Override
            public void mouseReleased(MouseEvent e) { handlePopup(e); }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = secretsTable.rowAtPoint(e.getPoint());
                    int col = secretsTable.columnAtPoint(e.getPoint());
                    if (row >= 0) {
                        if (!secretsTable.isRowSelected(row)) {
                            secretsTable.setRowSelectionInterval(row, row);
                        }

                        int modelRow = secretsTable.convertRowIndexToModel(row);
                        DiscoveredSecret sec = secretsTableModel.getSecretAt(modelRow);
                        if (sec == null) return;

                        Object cellVal = secretsTable.getValueAt(row, col);
                        String cellStr = cellVal != null ? cellVal.toString() : "";

                        JPopupMenu menu = new JPopupMenu();

                        JMenuItem copyCellItem = new JMenuItem("Copy Cell Value (\"" + (cellStr.length() > 30 ? cellStr.substring(0, 27) + "..." : cellStr) + "\")");
                        copyCellItem.addActionListener(ev -> copyToClipboard(cellStr));
                        menu.add(copyCellItem);

                        JMenuItem copySecretItem = new JMenuItem("Copy Secret Value");
                        copySecretItem.addActionListener(ev -> copyToClipboard(sec.secretValue()));
                        menu.add(copySecretItem);

                        JMenuItem copyLocationItem = new JMenuItem("Copy Location / Source File");
                        copyLocationItem.addActionListener(ev -> copyToClipboard(sec.sourceLocation()));
                        menu.add(copyLocationItem);

                        JMenuItem copySnippetItem = new JMenuItem("Copy Context Snippet");
                        copySnippetItem.addActionListener(ev -> copyToClipboard(sec.contextSnippet()));
                        menu.add(copySnippetItem);

                        JMenuItem copyRowsItem = new JMenuItem("Copy Selected Row(s) as TSV");
                        copyRowsItem.addActionListener(ev -> exportTableToTsv(secretsTable, "Secrets Selection"));
                        menu.add(copyRowsItem);

                        menu.show(secretsTable, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private void setupTableKeyboardCopy(JTable table) {
        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_C, mask), "copy");
        table.getActionMap().put("copy", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportTableToTsv(table, "Table Selection");
            }
        });
    }

    private void exportTableToTsv(JTable table, String name) {
        int[] rows = table.getSelectedRows();
        boolean useAll = rows.length == 0;
        int rowCount = useAll ? table.getRowCount() : rows.length;

        if (rowCount == 0) {
            JOptionPane.showMessageDialog(this, "No data to export.", "Export TSV", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        StringBuilder sb = new StringBuilder();
        for (int col = 0; col < table.getColumnCount(); col++) {
            sb.append(table.getColumnName(col)).append(col == table.getColumnCount() - 1 ? "\n" : "\t");
        }

        for (int r = 0; r < (useAll ? table.getRowCount() : rows.length); r++) {
            int modelRow = useAll ? r : rows[r];
            for (int col = 0; col < table.getColumnCount(); col++) {
                Object val = table.getValueAt(modelRow, col);
                sb.append(val != null ? val.toString() : "").append(col == table.getColumnCount() - 1 ? "\n" : "\t");
            }
        }

        copyToClipboard(sb.toString());
        JOptionPane.showMessageDialog(this, "Copied " + rowCount + " rows to clipboard as TSV!", "Export Success", JOptionPane.INFORMATION_MESSAGE);
    }

    private static void copyToClipboard(String text) {
        if (text != null && !text.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        }
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }

    // ── Table Models ──
    private static class EndpointsTableModel extends AbstractTableModel {
        private static final String[] COLS = {"Source Type", "Location / File", "Method", "Endpoint / Route", "Line", "Context Snippet"};
        private final List<DiscoveredEndpoint> list = new ArrayList<>();

        public synchronized void updateData(List<DiscoveredEndpoint> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized DiscoveredEndpoint getEndpointAt(int row) {
            if (row >= 0 && row < list.size()) {
                return list.get(row);
            }
            return null;
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) { return c == 4 ? Integer.class : String.class; }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            DiscoveredEndpoint item = list.get(r);
            return switch (c) {
                case 0 -> item.sourceType();
                case 1 -> item.sourceLocation();
                case 2 -> item.methodGuess();
                case 3 -> item.endpoint();
                case 4 -> item.line();
                case 5 -> item.contextSnippet();
                default -> null;
            };
        }
    }

    private static class SecretsTableModel extends AbstractTableModel {
        private static final String[] COLS = {"Source Type", "Location / File", "Category", "Secret Value / Match", "Line", "Context Snippet"};
        private final List<DiscoveredSecret> list = new ArrayList<>();

        public synchronized void updateData(List<DiscoveredSecret> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized DiscoveredSecret getSecretAt(int row) {
            if (row >= 0 && row < list.size()) {
                return list.get(row);
            }
            return null;
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) { return c == 4 ? Integer.class : String.class; }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            DiscoveredSecret item = list.get(r);
            return switch (c) {
                case 0 -> item.sourceType();
                case 1 -> item.sourceLocation();
                case 2 -> item.category();
                case 3 -> item.secretValue();
                case 4 -> item.line();
                case 5 -> item.contextSnippet();
                default -> null;
            };
        }
    }
}
