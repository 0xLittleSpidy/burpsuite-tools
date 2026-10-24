// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.wayback.model.DiscoveredSubdomain_littlespidy;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class SubdomainsTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final List<DiscoveredSubdomain_littlespidy> subdomainList = new ArrayList<>();
    private final SubdomainTableModel tableModel = new SubdomainTableModel();
    private final JTable table = new JTable(tableModel);
    private final TableRowSorter<SubdomainTableModel> sorter = new TableRowSorter<>(tableModel);
    private Consumer<String> scanInNewTabCallback;

    public SubdomainsTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout(4, 4));
        this.api = api;
        initUI();
    }

    private void initUI() {
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);

        table.getColumnModel().getColumn(0).setPreferredWidth(45);
        table.getColumnModel().getColumn(1).setPreferredWidth(320);
        table.getColumnModel().getColumn(2).setPreferredWidth(160);
        table.getColumnModel().getColumn(3).setPreferredWidth(140);

        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        filterBar.add(new JLabel("Filter Subdomains:"));

        JTextField searchField = new JTextField(20);
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
            private void applyFilter() {
                String text = searchField.getText().trim();
                sorter.setRowFilter(text.isEmpty() ? null : RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(text)));
            }
        });
        filterBar.add(searchField);

        JButton addScopeBtn = new JButton("Add All to Burp Scope");
        addScopeBtn.addActionListener(e -> addAllToScope());
        filterBar.add(addScopeBtn);

        JButton exportBtn = new JButton("Export Subdomains");
        exportBtn.addActionListener(e -> exportSubdomains());
        filterBar.add(exportBtn);

        JLabel tipLabel = new JLabel("Tip: Right-click row to Scan in Dedicated Tab or Add to Scope");
        tipLabel.setFont(tipLabel.getFont().deriveFont(Font.ITALIC, 11f));
        tipLabel.setForeground(Color.GRAY);
        filterBar.add(tipLabel);

        add(filterBar, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) showContextMenu(e);
            }
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) showContextMenu(e);
            }
        });
    }

    private void showContextMenu(MouseEvent e) {
        int viewRow = table.rowAtPoint(e.getPoint());
        if (viewRow != -1) {
            table.setRowSelectionInterval(viewRow, viewRow);
            int modelRow = table.convertRowIndexToModel(viewRow);
            DiscoveredSubdomain_littlespidy sub = subdomainList.get(modelRow);

            JPopupMenu popup = new JPopupMenu();

            JMenuItem scanItem = new JMenuItem("Scan in Dedicated Tab");
            scanItem.addActionListener(ev -> {
                if (scanInNewTabCallback != null) {
                    scanInNewTabCallback.accept(sub.getSubdomain());
                }
            });
            popup.add(scanItem);

            popup.addSeparator();

            JMenuItem scopeItem = new JMenuItem("Add to Burp Scope");
            scopeItem.addActionListener(ev -> {
                if (api != null && api.scope() != null) {
                    try {
                        api.scope().includeInScope("https://" + sub.getSubdomain());
                        api.scope().includeInScope("http://" + sub.getSubdomain());
                        JOptionPane.showMessageDialog(this, "Added " + sub.getSubdomain() + " to Burp Scope.", "Scope Updated", JOptionPane.INFORMATION_MESSAGE);
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(this, "Error adding to scope: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                    }
                }
            });
            popup.add(scopeItem);

            JMenuItem copyItem = new JMenuItem("Copy Subdomain");
            copyItem.addActionListener(ev -> Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sub.getSubdomain()), null));
            popup.add(copyItem);

            popup.show(e.getComponent(), e.getX(), e.getY());
        }
    }

    public void setScanInNewTabCallback(Consumer<String> scanInNewTabCallback) {
        this.scanInNewTabCallback = scanInNewTabCallback;
    }

    public synchronized void setSubdomains(List<DiscoveredSubdomain_littlespidy> list) {
        subdomainList.clear();
        if (list != null) {
            subdomainList.addAll(list);
        }
        tableModel.fireTableDataChanged();
    }

    public synchronized void addSubdomain(DiscoveredSubdomain_littlespidy sub) {
        if (!subdomainList.contains(sub)) {
            subdomainList.add(sub);
            int idx = subdomainList.size() - 1;
            tableModel.fireTableRowsInserted(idx, idx);
        }
    }

    public synchronized void clear() {
        subdomainList.clear();
        tableModel.fireTableDataChanged();
    }

    public List<DiscoveredSubdomain_littlespidy> getSubdomains() {
        return new ArrayList<>(subdomainList);
    }

    private void addAllToScope() {
        if (api == null || api.scope() == null) {
            JOptionPane.showMessageDialog(this, "Burp Scope API not available.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int count = 0;
        for (DiscoveredSubdomain_littlespidy sub : subdomainList) {
            try {
                api.scope().includeInScope("https://" + sub.getSubdomain());
                api.scope().includeInScope("http://" + sub.getSubdomain());
                count++;
            } catch (Exception ignored) {
            }
        }
        JOptionPane.showMessageDialog(this, "Added " + count + " subdomains to Burp Target Scope.", "Scope Updated", JOptionPane.INFORMATION_MESSAGE);
    }

    private void exportSubdomains() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("wayback_subdomains.txt"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter writer = new PrintWriter(chooser.getSelectedFile())) {
                for (DiscoveredSubdomain_littlespidy s : subdomainList) {
                    writer.println(s.getSubdomain() + "\t" + s.getPathCount() + " paths\t" + s.getStatus());
                }
                JOptionPane.showMessageDialog(this, "Subdomains exported successfully.", "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error exporting subdomains: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private class SubdomainTableModel extends AbstractTableModel {
        private final String[] columns = {"#", "Discovered Subdomain", "Archived Paths Found", "Scan Status"};

        @Override
        public int getRowCount() {
            return subdomainList.size();
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
            DiscoveredSubdomain_littlespidy s = subdomainList.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> rowIndex + 1;
                case 1 -> s.getSubdomain();
                case 2 -> s.getPathCount() + " paths";
                case 3 -> s.getStatus();
                default -> "";
            };
        }
    }
}
