// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.wayback.model.DiscoveredPath_littlespidy;

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

public class PathsTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final List<DiscoveredPath_littlespidy> pathList = new ArrayList<>();
    private final PathTableModel tableModel = new PathTableModel();
    private final JTable table = new JTable(tableModel);
    private final TableRowSorter<PathTableModel> sorter = new TableRowSorter<>(tableModel);
    private Consumer<DiscoveredPath_littlespidy> retestCallback;

    public PathsTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout(4, 4));
        this.api = api;
        initUI();
    }

    private void initUI() {
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);

        table.getColumnModel().getColumn(0).setPreferredWidth(45);
        table.getColumnModel().getColumn(1).setPreferredWidth(180);
        table.getColumnModel().getColumn(2).setPreferredWidth(320);
        table.getColumnModel().getColumn(3).setPreferredWidth(100);
        table.getColumnModel().getColumn(4).setPreferredWidth(120);

        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        filterBar.add(new JLabel("Filter Paths:"));

        JTextField searchField = new JTextField(20);
        searchField.putClientProperty("JTextField.placeholderText", "Search by host or path...");
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

        JButton exportBtn = new JButton("Export Paths");
        exportBtn.addActionListener(e -> exportPaths());
        filterBar.add(exportBtn);

        JButton siteMapBtn = new JButton("Send All to Site Map");
        siteMapBtn.addActionListener(e -> sendAllToSiteMap());
        filterBar.add(siteMapBtn);

        JLabel tipLabel = new JLabel("Tip: Right-click row for actions (Re-test, Send to Repeater, Copy)");
        tipLabel.setFont(tipLabel.getFont().deriveFont(Font.ITALIC, 11f));
        tipLabel.setForeground(Color.GRAY);
        filterBar.add(tipLabel);

        add(filterBar, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showContextMenu(e);
                }
            }
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showContextMenu(e);
                }
            }
        });
    }

    private void showContextMenu(MouseEvent e) {
        int viewRow = table.rowAtPoint(e.getPoint());
        if (viewRow != -1) {
            table.setRowSelectionInterval(viewRow, viewRow);
            int modelRow = table.convertRowIndexToModel(viewRow);
            DiscoveredPath_littlespidy item = pathList.get(modelRow);

            JPopupMenu popup = new JPopupMenu();

            JMenuItem retestItem = new JMenuItem("Re-test Path");
            retestItem.addActionListener(ev -> {
                if (retestCallback != null) {
                    retestCallback.accept(item);
                }
            });
            popup.add(retestItem);

            JMenuItem repeaterItem = new JMenuItem("Send to Repeater");
            repeaterItem.addActionListener(ev -> {
                if (api != null && api.repeater() != null) {
                    boolean isSecure = !"HTTP".equalsIgnoreCase(item.getLastTestedProtocol());
                    int port = isSecure ? 443 : 80;
                    HttpService service = HttpService.httpService(item.getHost(), port, isSecure);
                    HttpRequest req = HttpRequest.httpRequest(service, "GET " + item.getPath() + " HTTP/1.1\r\nHost: " + item.getHost() + "\r\n\r\n");
                    api.repeater().sendToRepeater(req, item.getHost() + item.getPath());
                }
            });
            popup.add(repeaterItem);

            JMenuItem siteMapItem = new JMenuItem("Add to Burp Site Map");
            siteMapItem.addActionListener(ev -> {
                if (api != null && api.siteMap() != null) {
                    boolean isSecure = !"HTTP".equalsIgnoreCase(item.getLastTestedProtocol());
                    int port = isSecure ? 443 : 80;
                    HttpService service = HttpService.httpService(item.getHost(), port, isSecure);
                    HttpRequest req = HttpRequest.httpRequest(service, "GET " + item.getPath() + " HTTP/1.1\r\nHost: " + item.getHost() + "\r\n\r\n");
                    api.siteMap().add(burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(req, null));
                }
            });
            popup.add(siteMapItem);

            popup.addSeparator();

            JMenuItem copyPathItem = new JMenuItem("Copy Path");
            copyPathItem.addActionListener(ev -> Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(item.getPath()), null));
            popup.add(copyPathItem);

            JMenuItem copyUrlItem = new JMenuItem("Copy Full URL");
            copyUrlItem.addActionListener(ev -> {
                String proto = "HTTP".equalsIgnoreCase(item.getLastTestedProtocol()) ? "http" : "https";
                String fullUrl = proto + "://" + item.getHost() + item.getPath();
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(fullUrl), null);
            });
            popup.add(copyUrlItem);

            popup.show(e.getComponent(), e.getX(), e.getY());
        }
    }

    public void setRetestCallback(Consumer<DiscoveredPath_littlespidy> retestCallback) {
        this.retestCallback = retestCallback;
    }

    public synchronized void setPaths(List<DiscoveredPath_littlespidy> paths) {
        pathList.clear();
        if (paths != null) {
            pathList.addAll(paths);
        }
        tableModel.fireTableDataChanged();
    }

    public synchronized void addPath(DiscoveredPath_littlespidy path) {
        if (!pathList.contains(path)) {
            pathList.add(path);
            int idx = pathList.size() - 1;
            tableModel.fireTableRowsInserted(idx, idx);
        }
    }

    public synchronized void updatePath(DiscoveredPath_littlespidy path) {
        int idx = pathList.indexOf(path);
        if (idx != -1) {
            tableModel.fireTableRowsUpdated(idx, idx);
        }
    }

    public synchronized void clear() {
        pathList.clear();
        tableModel.fireTableDataChanged();
    }

    public List<DiscoveredPath_littlespidy> getPaths() {
        return new ArrayList<>(pathList);
    }

    private void exportPaths() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("wayback_paths.txt"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter writer = new PrintWriter(chooser.getSelectedFile())) {
                for (DiscoveredPath_littlespidy p : pathList) {
                    writer.println(p.getHost() + "\t" + p.getPath() + "\t" + p.getStatus() + "\t" + p.getResult());
                }
                JOptionPane.showMessageDialog(this, "Paths exported successfully.", "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error exporting paths: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void sendAllToSiteMap() {
        if (api == null || api.siteMap() == null) {
            JOptionPane.showMessageDialog(this, "Burp Site Map API not available.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int count = 0;
        for (DiscoveredPath_littlespidy p : pathList) {
            try {
                boolean isSecure = !"HTTP".equalsIgnoreCase(p.getLastTestedProtocol());
                HttpService s = HttpService.httpService(p.getHost(), isSecure ? 443 : 80, isSecure);
                HttpRequest req = HttpRequest.httpRequest(s, "GET " + p.getPath() + " HTTP/1.1\r\nHost: " + p.getHost() + "\r\n\r\n");
                api.siteMap().add(burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(req, null));
                count++;
            } catch (Exception ignored) {
            }
        }
        JOptionPane.showMessageDialog(this, "Added " + count + " paths to Burp Site Map.", "Site Map", JOptionPane.INFORMATION_MESSAGE);
    }

    private class PathTableModel extends AbstractTableModel {
        private final String[] columns = {"#", "Target Host", "Archived Path Prefix", "Probe Status", "Directory Result"};

        @Override
        public int getRowCount() {
            return pathList.size();
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
            DiscoveredPath_littlespidy p = pathList.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> rowIndex + 1;
                case 1 -> p.getHost();
                case 2 -> p.getPath();
                case 3 -> p.getStatus();
                case 4 -> p.getResult();
                default -> "";
            };
        }
    }
}
