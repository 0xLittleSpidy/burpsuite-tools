// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.graphqlcop.model.HttpLogEntry_littlespidy;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

public class HttpHistorySubTab_littlespidy extends JPanel {
    private final MontoyaApi api;
    private final List<HttpLogEntry_littlespidy> allLogs = new ArrayList<>();
    private final DefaultTableModel tableModel;
    private final JTable historyTable;
    private final TableRowSorter<DefaultTableModel> rowSorter;
    private final MultiSelectProbeFilter_littlespidy probeFilter;

    private final HttpRequestEditor requestViewer;
    private final HttpResponseEditor responseViewer;

    public HttpHistorySubTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout(4, 4));
        this.api = api;

        // Toolbar
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        probeFilter = new MultiSelectProbeFilter_littlespidy(this::onFilterChanged);
        toolbar.add(probeFilter);

        JButton clearBtn = new JButton("Clear Traffic History");
        clearBtn.addActionListener(e -> clearHistory());
        toolbar.add(clearBtn);

        add(toolbar, BorderLayout.NORTH);

        // Table
        String[] columns = {"#", "Time", "Method", "URL", "Probe Type", "Status", "Length", "Duration (ms)"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };

        historyTable = new JTable(tableModel);
        historyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        rowSorter = new TableRowSorter<>(tableModel);
        historyTable.setRowSorter(rowSorter);

        historyTable.getColumnModel().getColumn(0).setPreferredWidth(45);
        historyTable.getColumnModel().getColumn(1).setPreferredWidth(70);
        historyTable.getColumnModel().getColumn(2).setPreferredWidth(60);
        historyTable.getColumnModel().getColumn(3).setPreferredWidth(260);
        historyTable.getColumnModel().getColumn(4).setPreferredWidth(160);
        historyTable.getColumnModel().getColumn(5).setPreferredWidth(60);
        historyTable.getColumnModel().getColumn(6).setPreferredWidth(70);
        historyTable.getColumnModel().getColumn(7).setPreferredWidth(85);

        JScrollPane tableScroll = new JScrollPane(historyTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Probe Traffic & Audit Requests"));

        // Editors
        requestViewer = api.userInterface().createHttpRequestEditor();
        responseViewer = api.userInterface().createHttpResponseEditor();

        JSplitPane httpSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                wrapInTitled(requestViewer.uiComponent(), "Request Inspector"),
                wrapInTitled(responseViewer.uiComponent(), "Response Inspector"));
        httpSplit.setResizeWeight(0.5);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, httpSplit);
        mainSplit.setResizeWeight(0.5);
        add(mainSplit, BorderLayout.CENTER);

        historyTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = historyTable.getSelectedRow();
                if (viewRow >= 0) {
                    int modelRow = historyTable.convertRowIndexToModel(viewRow);
                    if (modelRow >= 0 && modelRow < allLogs.size()) {
                        showLogDetails(allLogs.get(modelRow));
                    }
                }
            }
        });
    }

    private void onFilterChanged(Set<String> selectedProbeNames) {
        rowSorter.setRowFilter(new RowFilter<DefaultTableModel, Integer>() {
            @Override
            public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                String probe = entry.getStringValue(4);
                return probeFilter.isProbeSelected(probe);
            }
        });
    }

    private JComponent wrapInTitled(Component c, String title) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createTitledBorder(title));
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    public synchronized void addLog(HttpLogEntry_littlespidy entry) {
        allLogs.add(entry);
        tableModel.addRow(new Object[]{
                entry.getId(),
                entry.getTime(),
                entry.getMethod(),
                entry.getUrl(),
                entry.getProbeName(),
                entry.getStatusCode(),
                entry.getResponseLength(),
                entry.getDurationMs()
        });
    }

    public synchronized void clearHistory() {
        allLogs.clear();
        tableModel.setRowCount(0);
        requestViewer.setRequest(HttpRequest.httpRequest(""));
        responseViewer.setResponse(HttpResponse.httpResponse(""));
    }

    private void showLogDetails(HttpLogEntry_littlespidy entry) {
        try {
            if (entry.getRequestBase64() != null && !entry.getRequestBase64().isEmpty()) {
                byte[] reqBytes = Base64.getDecoder().decode(entry.getRequestBase64());
                requestViewer.setRequest(HttpRequest.httpRequest(new String(reqBytes)));
            } else {
                requestViewer.setRequest(HttpRequest.httpRequest(""));
            }

            if (entry.getResponseBase64() != null && !entry.getResponseBase64().isEmpty()) {
                byte[] respBytes = Base64.getDecoder().decode(entry.getResponseBase64());
                responseViewer.setResponse(HttpResponse.httpResponse(new String(respBytes)));
            } else {
                responseViewer.setResponse(HttpResponse.httpResponse(""));
            }
        } catch (Exception ignored) {}
    }

    public List<HttpLogEntry_littlespidy> getAllLogs() {
        return new ArrayList<>(allLogs);
    }
}
