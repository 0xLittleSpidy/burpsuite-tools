// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.requestsmugglinginspector.ui;

import com.littlespidy.requestsmugglinginspector.model.PayloadEntry;
import com.littlespidy.requestsmugglinginspector.model.PayloadStore;
import com.littlespidy.requestsmugglinginspector.storage.SmugglingPersistentStorageManager_littlespidy;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Burp Suite tab that displays all HTTP request-smuggling payloads in a
 * 2-column table (Name | Payload Value) backed by {@link PayloadStore}
 * and integrated with persistent session management.
 * Plain ASCII text only.
 *
 * @author littlespidy
 */
public class PayloadsTab extends JPanel {

    private static final String COL_NAME  = "Name";
    private static final String COL_VALUE = "Payload Value";

    private final PayloadStore store;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final JTextArea descArea;
    private final JTextArea headersArea;
    private final JTextArea bodyArea;
    private final JLabel statusLabel;
    private final JPanel topContainer;
    private SmugglingPersistentStorageManager_littlespidy storageManager;

    public PayloadsTab(PayloadStore store) {
        this.store = store;
        setLayout(new BorderLayout(0, 0));

        topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));
        add(topContainer, BorderLayout.NORTH);

        // -- Toolbar -----------------------------------------------------------
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        JButton addBtn = new JButton("Add");
        addBtn.setToolTipText("Add a new payload (saved immediately).");
        addBtn.addActionListener(e -> openAddDialog());
        toolbar.add(addBtn);

        toolbar.addSeparator(new Dimension(6, 0));

        JButton deleteBtn = new JButton("Delete");
        deleteBtn.setToolTipText("Delete the selected payload (saved immediately).");
        deleteBtn.addActionListener(e -> deleteSelected());
        toolbar.add(deleteBtn);

        toolbar.addSeparator(new Dimension(12, 0));

        JButton reloadBtn = new JButton("Reload from JSON");
        reloadBtn.setToolTipText("Re-reads smuggling-payloads.json from disk - no Burp restart needed.");
        reloadBtn.addActionListener(e -> reload());
        toolbar.add(reloadBtn);

        toolbar.addSeparator(new Dimension(12, 0));

        statusLabel = new JLabel();
        statusLabel.setForeground(new Color(100, 100, 100));
        toolbar.add(statusLabel);

        toolbar.add(Box.createHorizontalGlue());
        toolbar.add(new JLabel("<html><i>Use Add button or edit smuggling-payloads.json directly.</i></html>  "));

        topContainer.add(toolbar);

        // -- Table -------------------------------------------------------------
        tableModel = new DefaultTableModel(new String[]{COL_NAME, COL_VALUE}, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };

        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(22);
        table.getTableHeader().setReorderingAllowed(false);

        table.getColumnModel().getColumn(0).setPreferredWidth(260);
        table.getColumnModel().getColumn(0).setMaxWidth(360);
        table.getColumnModel().getColumn(1).setPreferredWidth(600);

        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        // -- Detail pane -------------------------------------------------------
        JPanel detail = new JPanel(new GridBagLayout());
        detail.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 12);

        descArea    = makeTextArea(2, null, false);
        headersArea = makeTextArea(3, mono, true);
        bodyArea    = makeTextArea(4, mono, true);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 4, 2, 4);
        gbc.anchor = GridBagConstraints.NORTHWEST;

        addDetailRow(detail, gbc, 0, "Description:", new JScrollPane(descArea));
        addDetailRow(detail, gbc, 1, "Headers:",     new JScrollPane(headersArea));
        addDetailRow(detail, gbc, 2, "Body:",        new JScrollPane(bodyArea));

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = table.getSelectedRow();
                if (viewRow >= 0) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    List<PayloadEntry> entries = store.getEntries();
                    if (modelRow < entries.size()) {
                        populateDetail(entries.get(modelRow));
                    }
                } else {
                    clearDetail();
                }
            }
        });

        // -- Split pane --------------------------------------------------------
        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table),
                detail);
        split.setResizeWeight(0.60);
        split.setDividerSize(5);

        add(split, BorderLayout.CENTER);

        // Initial population
        populateTable();
    }

    public void setStorageManager(SmugglingPersistentStorageManager_littlespidy storageManager) {
        this.storageManager = storageManager;
        topContainer.add(storageManager.createSessionToolbar(), 0);
        revalidate();
        repaint();
    }

    public void refreshTable() {
        populateTable();
        clearDetail();
    }

    // -- Private helpers --------------------------------------------------------

    /** Opens the {@link AddPayloadDialog}; refreshes the table if the user saved. */
    private void openAddDialog() {
        Window owner = SwingUtilities.getWindowAncestor(this);
        AddPayloadDialog dialog = new AddPayloadDialog(owner, store);
        dialog.setVisible(true);
        if (dialog.isSaved()) {
            populateTable();
            clearDetail();
            if (storageManager != null) {
                storageManager.markDirty();
            }
        }
    }

    /**
     * Confirms and deletes the currently selected payload row, then persists
     * the change to the JSON file via {@link PayloadStore#removeEntry(int)}.
     */
    private void deleteSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this,
                    "Please select a payload row to delete.",
                    "No Selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        String name = (String) tableModel.getValueAt(modelRow, 0);

        int confirm = JOptionPane.showConfirmDialog(this,
                "Delete payload \"" + name + "\"?\nThis will update smuggling-payloads.json.",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            store.removeEntry(modelRow);
            populateTable();
            clearDetail();
            if (storageManager != null) {
                storageManager.markDirty();
            }
        }
    }

    private void reload() {
        store.reload();
        populateTable();
        clearDetail();
        if (storageManager != null) {
            storageManager.markDirty();
        }
    }

    private void populateTable() {
        tableModel.setRowCount(0);
        for (PayloadEntry e : store.getEntries()) {
            tableModel.addRow(new Object[]{e.getName(), e.getBody()});
        }
        int count = store.getEntries().size();
        statusLabel.setText(count + " payload" + (count == 1 ? "" : "s") + " loaded");
    }

    private void populateDetail(PayloadEntry entry) {
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

    /** Creates a read-only {@link JTextArea} with consistent styling. */
    private static JTextArea makeTextArea(int rows, Font font, boolean monospaced) {
        JTextArea area = new JTextArea(rows, 60);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(!monospaced);
        if (monospaced) area.setFont(font);
        area.setBackground(UIManager.getColor("Panel.background"));
        return area;
    }

    /** Adds a label + component pair as one row in the detail {@link GridBagLayout}. */
    private static void addDetailRow(JPanel panel, GridBagConstraints gbc,
                                     int row, String label, JComponent comp) {
        gbc.gridx = 0; gbc.gridy = row;
        gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        panel.add(new JLabel(label), gbc);

        gbc.gridx = 1; gbc.weightx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(comp, gbc);
    }
}
