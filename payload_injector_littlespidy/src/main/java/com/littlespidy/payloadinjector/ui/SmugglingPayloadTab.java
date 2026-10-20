// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.ui;

import com.littlespidy.payloadinjector.model.SmugglingPayloadEntry;
import com.littlespidy.payloadinjector.model.SmugglingPayloadStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Dedicated UI tab for HTTP Request Smuggling payloads.
 * Features a 3-column table (Name, Payload Value, Description) matching the other tabs,
 * an action toolbar, and a detail inspection pane for raw CRLF bytes and discrepancy headers.
 *
 * @author littlespidy
 */
public class SmugglingPayloadTab extends JPanel {

    private static final String COL_NAME = "Name";
    private static final String COL_VALUE = "Payload Value";
    private static final String COL_DESC = "Description";

    private final SmugglingPayloadStore store;
    private final SmugglingPayloadTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<SmugglingPayloadTableModel> sorter;
    private final JTextField searchField;
    private final JTextArea descArea;
    private final JTextArea headersArea;
    private final JTextArea bodyArea;
    private final JLabel statusLabel;

    public SmugglingPayloadTab(SmugglingPayloadStore store) {
        this.store = store;
        setLayout(new BorderLayout(5, 5));
        setBorder(new EmptyBorder(8, 8, 8, 8));

        // -- Top Section: Action Toolbar --
        JPanel topContainer = new JPanel(new BorderLayout(0, 4));

        JToolBar actionsBar = new JToolBar();
        actionsBar.setFloatable(false);
        actionsBar.setBorder(new EmptyBorder(2, 4, 2, 4));

        JButton addBtn = new JButton("Add Payload");
        addBtn.addActionListener(e -> openAddDialog());
        actionsBar.add(addBtn);

        actionsBar.addSeparator(new Dimension(6, 0));

        JButton editBtn = new JButton("Edit Selected");
        editBtn.addActionListener(e -> openEditDialog());
        actionsBar.add(editBtn);

        actionsBar.addSeparator(new Dimension(6, 0));

        JButton deleteBtn = new JButton("Delete Selected");
        deleteBtn.addActionListener(e -> deleteSelected());
        actionsBar.add(deleteBtn);

        actionsBar.addSeparator(new Dimension(10, 0));

        JButton reloadBtn = new JButton("Reload from JSON");
        reloadBtn.addActionListener(e -> reload());
        actionsBar.add(reloadBtn);

        actionsBar.addSeparator(new Dimension(10, 0));

        // -- Search Bar --
        actionsBar.add(new JLabel("Search: "));
        searchField = new JTextField(15);
        searchField.setToolTipText("Filter payloads across all columns");
        searchField.setMaximumSize(new Dimension(200, 26));
        actionsBar.add(searchField);

        actionsBar.addSeparator(new Dimension(4, 0));

        JButton clearBtn = new JButton("Clear");
        clearBtn.setToolTipText("Clear active search filter");
        clearBtn.addActionListener(e -> {
            searchField.setText("");
            searchField.requestFocusInWindow();
        });
        actionsBar.add(clearBtn);

        actionsBar.addSeparator(new Dimension(12, 0));

        statusLabel = new JLabel();
        statusLabel.setForeground(new Color(100, 100, 100));
        actionsBar.add(statusLabel);

        actionsBar.add(Box.createHorizontalGlue());
        actionsBar.add(new JLabel("<html><i>File: http_request_smuggling_payloads.json</i></html>  "));

        topContainer.add(actionsBar, BorderLayout.NORTH);
        add(topContainer, BorderLayout.NORTH);

        // -- Table (3 Columns matching other tabs) --
        tableModel = new SmugglingPayloadTableModel();
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setRowHeight(24);
        table.setFont(table.getFont().deriveFont(13f));
        table.getTableHeader().setFont(table.getFont().deriveFont(Font.BOLD, 13f));

        table.getColumnModel().getColumn(0).setPreferredWidth(200);
        table.getColumnModel().getColumn(1).setPreferredWidth(440);
        table.getColumnModel().getColumn(2).setPreferredWidth(300);

        sorter = new TableRowSorter<>(tableModel);
        sorter.setSortsOnUpdates(true);
        for (int i = 0; i < tableModel.getColumnCount(); i++) {
            sorter.setComparator(i, String.CASE_INSENSITIVE_ORDER);
        }
        table.setRowSorter(sorter);

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applySearchFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { applySearchFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applySearchFilter(); }
        });

        // Keyboard Delete shortcut
        table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "deleteSelectedSmuggling");
        table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE, 0), "deleteSelectedSmuggling");
        table.getActionMap().put("deleteSelectedSmuggling", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) {
                deleteSelected();
            }
        });

        // -- Detail Pane --
        JPanel detail = new JPanel(new GridBagLayout());
        detail.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Payload Discrepancy Detail"),
                BorderFactory.createEmptyBorder(4, 6, 6, 6)));

        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 12);

        descArea    = makeTextArea(2, mono, false);
        headersArea = makeTextArea(4, mono, true);
        bodyArea    = makeTextArea(4, mono, true);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(3, 4, 3, 4);

        addDetailRow(detail, gbc, 0, "Description:", new JScrollPane(descArea));
        addDetailRow(detail, gbc, 1, "Headers:",     new JScrollPane(headersArea));
        addDetailRow(detail, gbc, 2, "Body:",        new JScrollPane(bodyArea));

        table.getSelectionModel().addListSelectionListener(evt -> {
            if (!evt.getValueIsAdjusting() && table.getSelectedRow() >= 0) {
                int modelRow = table.convertRowIndexToModel(table.getSelectedRow());
                List<SmugglingPayloadEntry> entries = store.getEntries();
                if (modelRow >= 0 && modelRow < entries.size()) {
                    populateDetail(entries.get(modelRow));
                }
            }
        });

        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table),
                detail);
        split.setResizeWeight(0.55);
        split.setDividerSize(5);

        add(split, BorderLayout.CENTER);

        store.addChangeListener(() -> SwingUtilities.invokeLater(() -> {
            tableModel.fireTableDataChanged();
            applySearchFilter();
            updateStatusLabel();
            clearDetail();
        }));

        applySearchFilter();
        updateStatusLabel();
    }

    private void openAddDialog() {
        Window owner = SwingUtilities.getWindowAncestor(this);
        AddSmugglingPayloadDialog dialog = new AddSmugglingPayloadDialog(owner, store, null);
        dialog.setVisible(true);
        SmugglingPayloadEntry result = dialog.getResult();
        if (result != null) {
            store.addEntry(result);
            clearDetail();
        }
    }

    private void openEditDialog() {
        int viewRow = table.getSelectedRow();
        if (viewRow == -1) {
            JOptionPane.showMessageDialog(this, "Please select a payload to edit.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        table.editCellAt(viewRow, 1);
        if (table.getEditorComponent() != null) {
            table.getEditorComponent().requestFocusInWindow();
        }
    }

    private void deleteSelected() {
        int[] viewRows = table.getSelectedRows();
        if (viewRows.length == 0) {
            JOptionPane.showMessageDialog(this, "Please select at least one payload to delete.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String confirmMsg = (viewRows.length == 1)
                ? "Delete HTTP request smuggling payload \"" + store.getEntries().get(table.convertRowIndexToModel(viewRows[0])).getName() + "\"?"
                : "Delete " + viewRows.length + " selected HTTP request smuggling payloads?";

        int confirm = JOptionPane.showConfirmDialog(this,
                confirmMsg,
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            int[] modelRows = new int[viewRows.length];
            for (int i = 0; i < viewRows.length; i++) {
                modelRows[i] = table.convertRowIndexToModel(viewRows[i]);
            }
            store.removeEntries(modelRows);
            clearDetail();
        }
    }

    private void reload() {
        store.reload();
        applySearchFilter();
        clearDetail();
    }

    public void applySearchFilter() {
        if (sorter == null) return;
        String text = (searchField != null) ? searchField.getText().trim() : "";
        if (text.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(text), 0, 1));
        }
        updateStatusLabel();
    }

    public void updateStatusLabel() {
        if (statusLabel == null) return;
        int total = tableModel.getRowCount();
        int filtered = table.getRowCount();
        if (searchField != null && !searchField.getText().trim().isEmpty()) {
            statusLabel.setText("Showing " + filtered + " of " + total + " payloads");
        } else {
            statusLabel.setText(total + " payload" + (total == 1 ? "" : "s") + " loaded");
        }
    }

    public JTextField getSearchField() {
        return searchField;
    }

    public SmugglingPayloadTableModel getTableModel() {
        return tableModel;
    }

    public JTable getTable() {
        return table;
    }

    private void populateDetail(SmugglingPayloadEntry entry) {
        descArea.setText(entry.getDescription());
        descArea.setCaretPosition(0);

        StringBuilder h = new StringBuilder();
        entry.getHeaders().forEach((k, v) -> h.append(k).append(": ").append(v).append("\n"));
        headersArea.setText(h.toString().stripTrailing());
        headersArea.setCaretPosition(0);

        bodyArea.setText(entry.getBody());
        bodyArea.setCaretPosition(0);
    }

    private void clearDetail() {
        descArea.setText("");
        headersArea.setText("");
        bodyArea.setText("");
    }

    private static JTextArea makeTextArea(int rows, Font font, boolean monospaced) {
        JTextArea area = new JTextArea(rows, 60);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(!monospaced);
        if (monospaced) area.setFont(font);
        area.setBackground(UIManager.getColor("Panel.background"));
        return area;
    }

    private static void addDetailRow(JPanel panel, GridBagConstraints gbc, int row, String label, JComponent comp) {
        gbc.gridx = 0; gbc.gridy = row;
        gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        panel.add(new JLabel(label), gbc);

        gbc.gridx = 1; gbc.weightx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(comp, gbc);
    }

    public class SmugglingPayloadTableModel extends AbstractTableModel {
        private final String[] columns = {COL_NAME, COL_VALUE, COL_DESC};

        @Override public int getRowCount() { return store.getEntries().size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }
        @Override public Class<?> getColumnClass(int col) { return String.class; }
        @Override public boolean isCellEditable(int row, int col) { return true; }

        @Override
        public void setValueAt(Object aValue, int row, int col) {
            List<SmugglingPayloadEntry> entries = store.getEntries();
            if (row >= 0 && row < entries.size()) {
                SmugglingPayloadEntry e = entries.get(row);
                String val = (aValue != null) ? aValue.toString().trim() : "";
                String newName = (col == 0 && !val.isEmpty()) ? val : e.getName();
                String newBody = (col == 1) ? val : e.getBody();
                String newDesc = (col == 2) ? val : e.getDescription();

                SmugglingPayloadEntry updated = new SmugglingPayloadEntry(
                        newName, newDesc, e.getHeaders(), newBody, e.getSourceType(), e.getSourceFile()
                );
                store.updateEntry(row, updated);
                fireTableCellUpdated(row, col);

                if (table.getSelectedRow() != -1 && table.convertRowIndexToModel(table.getSelectedRow()) == row) {
                    populateDetail(updated);
                }
            }
        }

        @Override
        public Object getValueAt(int row, int col) {
            List<SmugglingPayloadEntry> entries = store.getEntries();
            if (row < 0 || row >= entries.size()) return null;
            SmugglingPayloadEntry e = entries.get(row);
            return switch (col) {
                case 0 -> e.getName();
                case 1 -> e.getBody();
                case 2 -> e.getDescription();
                default -> null;
            };
        }
    }
}
