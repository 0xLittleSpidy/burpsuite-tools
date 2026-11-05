// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.ui;

import burp.ssrfmap.modules.SSRFPayloadItem_littlespidy;
import burp.ssrfmap.modules.SSRFPayloadManager_littlespidy;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;

public class PayloadViewerDialog_littlespidy extends JDialog {

    private static class PayloadTableModel extends AbstractTableModel {
        private final String[] columns = {"Category", "Module", "Scheme", "Title", "Payload Template", "Indicators", "Collaborator"};
        private final List<SSRFPayloadItem_littlespidy> items;

        PayloadTableModel(List<SSRFPayloadItem_littlespidy> items) {
            this.items = items;
        }

        @Override
        public int getRowCount() {
            return items.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int col) {
            return columns[col];
        }

        @Override
        public Object getValueAt(int row, int col) {
            if (row < 0 || row >= items.size()) return null;
            SSRFPayloadItem_littlespidy item = items.get(row);
            switch (col) {
                case 0: return item.getCategory().name();
                case 1: return item.getModuleName();
                case 2: return item.getScheme();
                case 3: return item.getTitle();
                case 4: return item.getPayloadTemplate();
                case 5: return String.join(", ", item.getExpectedIndicators());
                case 6: return item.isRequiresCollaborator() ? "Yes" : "No";
                default: return "";
            }
        }
    }

    public PayloadViewerDialog_littlespidy(Frame parent) {
        super(parent, "SSRFmap Payload Library [littlespidy]", true);
        setLayout(new BorderLayout(6, 6));
        setSize(920, 560);
        setLocationRelativeTo(parent);

        SSRFPayloadManager_littlespidy manager = SSRFPayloadManager_littlespidy.getInstance();
        List<SSRFPayloadItem_littlespidy> payloads = manager.getAllPayloads();

        // Top Filter Bar
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 6));
        filterPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 0, 4));

        filterPanel.add(new JLabel("Category:"));
        JComboBox<String> categoryCombo = new JComboBox<>(new String[]{"All", "PROTOCOL", "CLOUD", "SERVICE"});
        filterPanel.add(categoryCombo);

        filterPanel.add(new JLabel("Search:"));
        JTextField searchField = new JTextField(20);
        filterPanel.add(searchField);

        PayloadTableModel tableModel = new PayloadTableModel(payloads);
        JTable table = new JTable(tableModel);
        TableRowSorter<PayloadTableModel> sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        Runnable updateFilter = () -> {
            String selectedCat = (String) categoryCombo.getSelectedItem();
            String query = searchField.getText().trim();

            RowFilter<PayloadTableModel, Integer> catFilter = null;
            if (selectedCat != null && !selectedCat.equals("All")) {
                catFilter = RowFilter.regexFilter("^" + selectedCat + "$", 0);
            }

            RowFilter<PayloadTableModel, Integer> textFilter = null;
            if (!query.isEmpty()) {
                textFilter = RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(query));
            }

            if (catFilter != null && textFilter != null) {
                sorter.setRowFilter(RowFilter.andFilter(java.util.Arrays.asList(catFilter, textFilter)));
            } else if (catFilter != null) {
                sorter.setRowFilter(catFilter);
            } else if (textFilter != null) {
                sorter.setRowFilter(textFilter);
            } else {
                sorter.setRowFilter(null);
            }
        };

        categoryCombo.addActionListener(e -> updateFilter.run());
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { updateFilter.run(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { updateFilter.run(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { updateFilter.run(); }
        });

        add(filterPanel, BorderLayout.NORTH);

        // Center Tabs
        JTabbedPane tabbedPane = new JTabbedPane();

        JScrollPane tableScroll = new JScrollPane(table);
        tabbedPane.addTab("Structured Payloads (" + payloads.size() + ")", tableScroll);

        JTextArea rawJsonArea = new JTextArea(manager.getRawJson());
        rawJsonArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        rawJsonArea.setEditable(false);
        tabbedPane.addTab("Raw JSON Source", new JScrollPane(rawJsonArea));

        add(tabbedPane, BorderLayout.CENTER);

        // Bottom Controls
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 6));
        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dispose());
        bottomPanel.add(closeBtn);
        add(bottomPanel, BorderLayout.SOUTH);
    }
}
