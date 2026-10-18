// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.ui;

import com.littlespidy.payloadinjector.model.SmugglingPayloadEntry;
import com.littlespidy.payloadinjector.model.SmugglingPayloadStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

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
    private static final String COL_SOURCE_TYPE = "Source Type";
    private static final String COL_SOURCE_FILE = "Source File";

    private final SmugglingPayloadStore store;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final JTextArea descArea;
    private final JTextArea headersArea;
    private final JTextArea bodyArea;
    private final JLabel statusLabel;

    public SmugglingPayloadTab(SmugglingPayloadStore store) {
        this.store = store;
        setLayout(new BorderLayout(5, 5));
        setBorder(new EmptyBorder(8, 8, 8, 8));

        // ── Top Section: Action Toolbar ──
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

        actionsBar.addSeparator(new Dimension(12, 0));

        JButton reloadBtn = new JButton("Reload from JSON");
        reloadBtn.addActionListener(e -> reload());
        actionsBar.add(reloadBtn);

        actionsBar.addSeparator(new Dimension(12, 0));

        statusLabel = new JLabel();
        statusLabel.setForeground(new Color(100, 100, 100));
        actionsBar.add(statusLabel);

        actionsBar.add(Box.createHorizontalGlue());
        actionsBar.add(new JLabel("<html><i>File: http_request_smuggling_payloads.json</i></html>  "));

        topContainer.add(actionsBar, BorderLayout.NORTH);
        add(topContainer, BorderLayout.NORTH);

        // ── Table (5 Columns matching other tabs) ──
        tableModel = new DefaultTableModel(new String[]{COL_NAME, COL_VALUE, COL_DESC, COL_SOURCE_TYPE, COL_SOURCE_FILE}, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
            @Override public Class<?> getColumnClass(int col) { return String.class; }
        };

        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(24);
        table.setFont(table.getFont().deriveFont(13f));
        table.getTableHeader().setFont(table.getFont().deriveFont(Font.BOLD, 13f));

        table.getColumnModel().getColumn(0).setPreferredWidth(160);
        table.getColumnModel().getColumn(1).setPreferredWidth(320);
        table.getColumnModel().getColumn(2).setPreferredWidth(220);
        table.getColumnModel().getColumn(3).setPreferredWidth(100);
        table.getColumnModel().getColumn(4).setPreferredWidth(130);

        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
        sorter.setSortsOnUpdates(true);
        table.setRowSorter(sorter);

        // Double click to edit
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && table.getSelectedRow() != -1) {
                    openEditDialog();
                }
            }
        });

        // ── Detail Pane ──
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
            populateTable();
            clearDetail();
        }));

        populateTable();
    }

    private void openAddDialog() {
        Window owner = SwingUtilities.getWindowAncestor(this);
        AddSmugglingPayloadDialog dialog = new AddSmugglingPayloadDialog(owner, store, null);
        dialog.setVisible(true);
        SmugglingPayloadEntry result = dialog.getResult();
        if (result != null) {
            store.addEntry(result);
            populateTable();
            clearDetail();
        }
    }

    private void openEditDialog() {
        int viewRow = table.getSelectedRow();
        if (viewRow == -1) {
            JOptionPane.showMessageDialog(this, "Please select a payload to edit.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);
        SmugglingPayloadEntry existing = store.getEntries().get(modelRow);

        Window owner = SwingUtilities.getWindowAncestor(this);
        AddSmugglingPayloadDialog dialog = new AddSmugglingPayloadDialog(owner, store, existing);
        dialog.setVisible(true);

        SmugglingPayloadEntry result = dialog.getResult();
        if (result != null) {
            store.updateEntry(modelRow, result);
            populateTable();
            clearDetail();
        }
    }

    private void deleteSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a payload to delete.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);
        String name = (String) tableModel.getValueAt(modelRow, 0);

        int confirm = JOptionPane.showConfirmDialog(this,
                "Delete HTTP request smuggling payload \"" + name + "\"?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            store.removeEntry(modelRow);
            populateTable();
            clearDetail();
        }
    }

    private void reload() {
        store.reload();
        populateTable();
        clearDetail();
    }

    private void populateTable() {
        tableModel.setRowCount(0);
        for (SmugglingPayloadEntry e : store.getEntries()) {
            tableModel.addRow(new Object[]{e.getName(), e.getBody(), e.getDescription(), e.getSourceType(), e.getSourceFile()});
        }
        int count = store.getEntries().size();
        statusLabel.setText(count + " payload" + (count == 1 ? "" : "s") + " loaded");
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
}
