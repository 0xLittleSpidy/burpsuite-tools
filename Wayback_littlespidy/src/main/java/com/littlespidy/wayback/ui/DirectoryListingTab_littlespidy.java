// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.wayback.model.DirectoryFinding_littlespidy;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class DirectoryListingTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final List<DirectoryFinding_littlespidy> findingsList = new ArrayList<>();
    private final FindingsTableModel tableModel = new FindingsTableModel();
    private final JTable table = new JTable(tableModel);
    private final TableRowSorter<FindingsTableModel> sorter = new TableRowSorter<>(tableModel);
    private final ParallelHttpInspector_littlespidy parallelInspector;

    public DirectoryListingTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout(4, 4));
        this.api = api;
        this.parallelInspector = new ParallelHttpInspector_littlespidy(api);
        initUI();
    }

    private void initUI() {
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);

        table.getColumnModel().getColumn(0).setPreferredWidth(40);
        table.getColumnModel().getColumn(1).setPreferredWidth(65);
        table.getColumnModel().getColumn(2).setPreferredWidth(180);
        table.getColumnModel().getColumn(3).setPreferredWidth(260);
        table.getColumnModel().getColumn(4).setPreferredWidth(75);
        table.getColumnModel().getColumn(5).setPreferredWidth(170);
        table.getColumnModel().getColumn(6).setPreferredWidth(85);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = table.getSelectedRow();
                if (viewRow != -1) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    DirectoryFinding_littlespidy finding = findingsList.get(modelRow);
                    parallelInspector.displayRequestResponse(
                            finding.getRequest(),
                            finding.getResponse(),
                            finding.getRawRequestBase64(),
                            finding.getRawResponseBase64()
                    );
                } else {
                    parallelInspector.clear();
                }
            }
        });

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

        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        filterBar.add(new JLabel("Filter Directory Listings:"));

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

        JLabel tipLabel = new JLabel("Tip: Right-click row for actions (Send to Repeater, Intruder, Open in Browser, Copy URL)");
        tipLabel.setFont(tipLabel.getFont().deriveFont(Font.ITALIC, 11f));
        tipLabel.setForeground(Color.GRAY);
        filterBar.add(tipLabel);

        JPanel topTablePanel = new JPanel(new BorderLayout());
        topTablePanel.add(filterBar, BorderLayout.NORTH);
        topTablePanel.add(new JScrollPane(table), BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topTablePanel, parallelInspector);
        splitPane.setResizeWeight(0.55);
        splitPane.setContinuousLayout(true);
        splitPane.setBorder(null);

        add(splitPane, BorderLayout.CENTER);
    }

    private void showContextMenu(MouseEvent e) {
        int viewRow = table.rowAtPoint(e.getPoint());
        if (viewRow != -1) {
            table.setRowSelectionInterval(viewRow, viewRow);
            int modelRow = table.convertRowIndexToModel(viewRow);
            DirectoryFinding_littlespidy finding = findingsList.get(modelRow);

            JPopupMenu popup = new JPopupMenu();

            JMenuItem repeaterItem = new JMenuItem("Send to Repeater");
            repeaterItem.addActionListener(ev -> {
                if (api != null && api.repeater() != null) {
                    HttpRequest req = finding.getRequest();
                    if (req == null && finding.getRawRequestBase64() != null) {
                        try {
                            byte[] bytes = java.util.Base64.getDecoder().decode(finding.getRawRequestBase64());
                            req = HttpRequest.httpRequest(burp.api.montoya.core.ByteArray.byteArray(bytes));
                        } catch (Exception ignored) {
                        }
                    }
                    if (req != null) {
                        api.repeater().sendToRepeater(req, finding.getHost() + finding.getPath());
                    } else {
                        boolean isSecure = "HTTPS".equalsIgnoreCase(finding.getProtocol());
                        HttpService s = HttpService.httpService(finding.getHost(), isSecure ? 443 : 80, isSecure);
                        HttpRequest newReq = HttpRequest.httpRequest(s, "GET " + finding.getPath() + " HTTP/1.1\r\nHost: " + finding.getHost() + "\r\n\r\n");
                        api.repeater().sendToRepeater(newReq, finding.getHost() + finding.getPath());
                    }
                }
            });
            popup.add(repeaterItem);

            JMenuItem intruderItem = new JMenuItem("Send to Intruder");
            intruderItem.addActionListener(ev -> {
                if (api != null && api.intruder() != null) {
                    HttpRequest req = finding.getRequest();
                    if (req == null) {
                        boolean isSecure = "HTTPS".equalsIgnoreCase(finding.getProtocol());
                        HttpService s = HttpService.httpService(finding.getHost(), isSecure ? 443 : 80, isSecure);
                        req = HttpRequest.httpRequest(s, "GET " + finding.getPath() + " HTTP/1.1\r\nHost: " + finding.getHost() + "\r\n\r\n");
                    }
                    api.intruder().sendToIntruder(req);
                }
            });
            popup.add(intruderItem);

            popup.addSeparator();

            JMenuItem copyUrlItem = new JMenuItem("Copy URL");
            copyUrlItem.addActionListener(ev -> Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(finding.getFullUrl()), null));
            popup.add(copyUrlItem);

            JMenuItem openBrowserItem = new JMenuItem("Open in Browser");
            openBrowserItem.addActionListener(ev -> {
                try {
                    Desktop.getDesktop().browse(URI.create(finding.getFullUrl()));
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Could not launch browser: " + ex.getMessage(), "Notice", JOptionPane.INFORMATION_MESSAGE);
                }
            });
            popup.add(openBrowserItem);

            popup.show(e.getComponent(), e.getX(), e.getY());
        }
    }

    public synchronized void setFindings(List<DirectoryFinding_littlespidy> list) {
        findingsList.clear();
        if (list != null) {
            findingsList.addAll(list);
        }
        tableModel.fireTableDataChanged();
        if (!findingsList.isEmpty()) {
            table.setRowSelectionInterval(0, 0);
        } else {
            parallelInspector.clear();
        }
    }

    public synchronized void addFinding(DirectoryFinding_littlespidy finding) {
        findingsList.add(finding);
        int idx = findingsList.size() - 1;
        tableModel.fireTableRowsInserted(idx, idx);
        if (findingsList.size() == 1) {
            table.setRowSelectionInterval(0, 0);
        }
    }

    public synchronized void clear() {
        findingsList.clear();
        tableModel.fireTableDataChanged();
        parallelInspector.clear();
    }

    public List<DirectoryFinding_littlespidy> getFindings() {
        return new ArrayList<>(findingsList);
    }

    private class FindingsTableModel extends AbstractTableModel {
        private final String[] columns = {"#", "Protocol", "Host", "Exposed Directory Path", "Status", "Matched Signature", "Length"};

        @Override
        public int getRowCount() {
            return findingsList.size();
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
            DirectoryFinding_littlespidy f = findingsList.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> f.getId();
                case 1 -> f.getProtocol();
                case 2 -> f.getHost();
                case 3 -> f.getPath();
                case 4 -> f.getStatusCode() + " OK";
                case 5 -> f.getMatchedSignature();
                case 6 -> f.getContentLength() + " B";
                default -> "";
            };
        }
    }
}
