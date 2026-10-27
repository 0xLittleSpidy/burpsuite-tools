// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.littlespidy.quickhelper.model.JsonTableData_littlespidy;
import com.littlespidy.quickhelper.service.ClipboardService_littlespidy;
import com.littlespidy.quickhelper.service.JsonTableService_littlespidy;
import com.littlespidy.quickhelper.ui.JsonTableModel_littlespidy;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * Custom Response Editor tab rendering JSON responses in a structured, interactive table view.
 */
public class JsonTableResponseEditorTab_littlespidy implements ExtensionProvidedHttpResponseEditor {

    private final MontoyaApi api;
    private final EditorCreationContext creationContext;
    private final ClipboardService_littlespidy clipboardService;
    private final JsonTableService_littlespidy jsonService;

    private final JPanel mainPanel;
    private final JTextField filterField;
    private final JButton btnCopyCell;
    private final JButton btnCopyRowJson;
    private final JButton btnCopyTableCsv;
    private final JLabel statusLabel;
    private final JLabel countLabel;

    private final JsonTableModel_littlespidy tableModel;
    private final JTable dataTable;
    private final TableRowSorter<JsonTableModel_littlespidy> tableSorter;

    private final JLabel inspectorTitle;
    private final JTextArea inspectorArea;

    private HttpResponse originalResponse;
    private JsonTableData_littlespidy currentTableData;
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");

    public JsonTableResponseEditorTab_littlespidy(MontoyaApi api,
                                                 EditorCreationContext creationContext,
                                                 ClipboardService_littlespidy clipboardService,
                                                 JsonTableService_littlespidy jsonService) {
        this.api = api;
        this.creationContext = creationContext;
        this.clipboardService = clipboardService;
        this.jsonService = jsonService;

        this.mainPanel = new JPanel(new BorderLayout(0, 6));
        this.mainPanel.setBorder(new EmptyBorder(6, 6, 6, 6));

        // Top Toolbar
        JPanel topContainer = new JPanel(new BorderLayout(0, 4));

        JPanel toolBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        JLabel filterLabel = new JLabel("Filter:");
        filterLabel.setFont(filterLabel.getFont().deriveFont(Font.BOLD));
        toolBar.add(filterLabel);

        filterField = new JTextField(18);
        filterField.setToolTipText("Type keywords or regex to filter rows in real-time");
        toolBar.add(filterField);

        btnCopyCell = new JButton("Copy Cell");
        btnCopyRowJson = new JButton("Copy Row JSON");
        btnCopyTableCsv = new JButton("Copy Table CSV");

        btnCopyCell.setEnabled(false);
        btnCopyRowJson.setEnabled(false);
        btnCopyTableCsv.setEnabled(false);

        toolBar.add(btnCopyCell);
        toolBar.add(btnCopyRowJson);
        toolBar.add(btnCopyTableCsv);

        // Status Strip
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                new EmptyBorder(4, 8, 4, 8)
        ));
        statusLabel = new JLabel("Ready - No JSON loaded");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 11f));

        countLabel = new JLabel("0 of 0 visible");
        countLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));

        statusPanel.add(statusLabel, BorderLayout.CENTER);
        statusPanel.add(countLabel, BorderLayout.EAST);

        topContainer.add(toolBar, BorderLayout.NORTH);
        topContainer.add(statusPanel, BorderLayout.SOUTH);
        mainPanel.add(topContainer, BorderLayout.NORTH);

        // Table
        tableModel = new JsonTableModel_littlespidy();
        dataTable = new JTable(tableModel);
        dataTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        dataTable.setCellSelectionEnabled(true);
        dataTable.setFillsViewportHeight(true);
        dataTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        tableSorter = new TableRowSorter<>(tableModel);
        dataTable.setRowSorter(tableSorter);

        JScrollPane tableScroll = new JScrollPane(dataTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("JSON Tabular View"));

        // Bottom Cell Inspector
        JPanel inspectorPanel = new JPanel(new BorderLayout(0, 4));
        inspectorPanel.setBorder(BorderFactory.createTitledBorder("Selected Cell Inspector"));

        JPanel inspectorHeader = new JPanel(new BorderLayout());
        inspectorTitle = new JLabel("Selected Cell: (None)");
        inspectorTitle.setFont(inspectorTitle.getFont().deriveFont(Font.BOLD, 11f));

        JButton btnCopyInspector = new JButton("Copy Value");
        btnCopyInspector.addActionListener(e -> copySelectedCellValue());

        inspectorHeader.add(inspectorTitle, BorderLayout.CENTER);
        inspectorHeader.add(btnCopyInspector, BorderLayout.EAST);

        inspectorArea = new JTextArea();
        inspectorArea.setEditable(false);
        inspectorArea.setLineWrap(true);
        inspectorArea.setWrapStyleWord(true);
        inspectorArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane inspectorScroll = new JScrollPane(inspectorArea);
        inspectorScroll.setPreferredSize(new Dimension(200, 85));

        inspectorPanel.add(inspectorHeader, BorderLayout.NORTH);
        inspectorPanel.add(inspectorScroll, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, inspectorPanel);
        splitPane.setResizeWeight(0.70);
        splitPane.setContinuousLayout(true);
        mainPanel.add(splitPane, BorderLayout.CENTER);

        initListeners();
    }

    private void initListeners() {
        // Live Filter Listener
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override
            public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override
            public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });

        // Button Actions
        btnCopyCell.addActionListener(e -> copySelectedCellValue());
        btnCopyRowJson.addActionListener(e -> copySelectedRowJson());
        btnCopyTableCsv.addActionListener(e -> copyTableCsv());

        // Cell & Row Selection Listener
        dataTable.getSelectionModel().addListSelectionListener(e -> updateInspectorFromSelection());
        dataTable.getColumnModel().getSelectionModel().addListSelectionListener(e -> updateInspectorFromSelection());

        // Right-Click Context Menu and Double-Click
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyCellItem = new JMenuItem("Copy Cell Value");
        copyCellItem.addActionListener(e -> copySelectedCellValue());
        popupMenu.add(copyCellItem);

        JMenuItem copyRowItem = new JMenuItem("Copy Row as JSON");
        copyRowItem.addActionListener(e -> copySelectedRowJson());
        popupMenu.add(copyRowItem);

        JMenuItem copyCsvItem = new JMenuItem("Copy Entire Table as CSV");
        copyCsvItem.addActionListener(e -> copyTableCsv());
        popupMenu.add(copyCsvItem);

        dataTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    copySelectedCellValue();
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                handlePopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopup(e);
            }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int r = dataTable.rowAtPoint(e.getPoint());
                    int c = dataTable.columnAtPoint(e.getPoint());
                    if (r >= 0 && c >= 0) {
                        dataTable.changeSelection(r, c, false, false);
                    }
                    if (dataTable.getSelectedRow() >= 0) {
                        popupMenu.show(dataTable, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private void applyFilter() {
        String text = filterField.getText().trim();
        if (text.isEmpty()) {
            tableSorter.setRowFilter(null);
        } else {
            try {
                tableSorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
            } catch (Exception ex) {
                tableSorter.setRowFilter(null);
            }
        }
        updateCountLabel();
    }

    private void updateCountLabel() {
        int visible = dataTable.getRowCount();
        int total = tableModel.getRowCount();
        countLabel.setText(visible + " of " + total + " visible");
    }

    private void updateInspectorFromSelection() {
        int viewRow = dataTable.getSelectedRow();
        int viewCol = dataTable.getSelectedColumn();
        if (viewRow >= 0 && viewCol >= 0) {
            int modelRow = dataTable.convertRowIndexToModel(viewRow);
            int modelCol = dataTable.convertColumnIndexToModel(viewCol);

            String colName = tableModel.getColumnName(modelCol);
            Object valObj = tableModel.getValueAt(modelRow, modelCol);
            String val = valObj != null ? valObj.toString() : "";

            inspectorTitle.setText("Selected Cell: (Row " + (modelRow + 1) + ", Column '" + colName + "')");
            inspectorArea.setText(val);
            inspectorArea.setCaretPosition(0);
        }
    }

    private void copySelectedCellValue() {
        int viewRow = dataTable.getSelectedRow();
        int viewCol = dataTable.getSelectedColumn();
        if (viewRow >= 0 && viewCol >= 0) {
            int modelRow = dataTable.convertRowIndexToModel(viewRow);
            int modelCol = dataTable.convertColumnIndexToModel(viewCol);

            Object valObj = tableModel.getValueAt(modelRow, modelCol);
            String val = valObj != null ? valObj.toString() : "";
            clipboardService.copyToClipboard(val);
            updateStatus("Copied cell value to clipboard (" + val.length() + " chars)");
        }
    }

    private void copySelectedRowJson() {
        int viewRow = dataTable.getSelectedRow();
        if (viewRow < 0) {
            return;
        }
        int modelRow = dataTable.convertRowIndexToModel(viewRow);

        if (currentTableData != null && currentTableData.isArray()
                && modelRow < currentTableData.getRawRowElements().size()) {
            JsonElement el = currentTableData.getRawRowElements().get(modelRow);
            String jsonStr = jsonService.formatPretty(el);
            clipboardService.copyToClipboard(jsonStr);
            updateStatus("Copied row JSON to clipboard (" + jsonStr.length() + " chars)");
        } else {
            // Build simple JsonObject from row key-values
            List<String> cols = tableModel.getColumnNames();
            List<String> rowVals = tableModel.getRowValues(modelRow);
            JsonObject obj = new JsonObject();
            for (int i = 0; i < cols.size() && i < rowVals.size(); i++) {
                obj.addProperty(cols.get(i), rowVals.get(i));
            }
            String jsonStr = jsonService.formatPretty(obj);
            clipboardService.copyToClipboard(jsonStr);
            updateStatus("Copied row JSON to clipboard (" + jsonStr.length() + " chars)");
        }
    }

    private void copyTableCsv() {
        if (currentTableData == null || tableModel.getRowCount() == 0) {
            return;
        }
        String csv = jsonService.toCsv(tableModel.getColumnNames(), tableModel.getAllRows());
        clipboardService.copyToClipboard(csv);
        updateStatus("Copied entire table as CSV to clipboard (" + csv.length() + " chars)");
    }

    private void updateStatus(String message) {
        String timestamp = timeFormat.format(new Date());
        statusLabel.setText("[OK] " + message + " at " + timestamp);
    }

    @Override
    public HttpResponse getResponse() {
        return originalResponse;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.response() == null) {
            this.originalResponse = null;
            this.currentTableData = null;
            Runnable clearUi = () -> {
                tableModel.clear();
                btnCopyCell.setEnabled(false);
                btnCopyRowJson.setEnabled(false);
                btnCopyTableCsv.setEnabled(false);
                inspectorTitle.setText("Selected Cell: (None)");
                inspectorArea.setText("");
                statusLabel.setText("No response loaded");
                countLabel.setText("0 of 0 visible");
            };
            if (SwingUtilities.isEventDispatchThread()) {
                clearUi.run();
            } else {
                SwingUtilities.invokeLater(clearUi);
            }
            return;
        }

        this.originalResponse = requestResponse.response();
        String body = "";
        try {
            body = this.originalResponse.bodyToString();
        } catch (Exception ignored) {}

        final JsonTableData_littlespidy tableData = jsonService.parseJsonToTable(body);
        this.currentTableData = tableData;

        Runnable updateUi = () -> {
            tableModel.setTableData(tableData.getColumnNames(), tableData.getRowValues());
            applyFilter();

            boolean hasData = tableData.getRowCount() > 0;
            btnCopyCell.setEnabled(hasData);
            btnCopyRowJson.setEnabled(hasData);
            btnCopyTableCsv.setEnabled(hasData);

            if (hasData) {
                statusLabel.setText("[OK] " + tableData.getTitle());
                dataTable.changeSelection(0, 0, false, false);
                updateInspectorFromSelection();
            } else {
                statusLabel.setText(tableData.getTitle());
                inspectorTitle.setText("Selected Cell: (None)");
                inspectorArea.setText("");
            }
            updateCountLabel();
        };

        if (SwingUtilities.isEventDispatchThread()) {
            updateUi.run();
        } else {
            SwingUtilities.invokeLater(updateUi);
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.response() == null) {
            return false;
        }
        HttpResponse resp = requestResponse.response();
        String contentType = null;
        try {
            List<HttpHeader> headers = resp.headers();
            if (headers != null) {
                for (HttpHeader h : headers) {
                    if (h.name() != null && h.name().equalsIgnoreCase("content-type")) {
                        contentType = h.value();
                        break;
                    }
                }
            }
        } catch (Exception ignored) {}

        String body = "";
        try {
            body = resp.bodyToString();
        } catch (Exception ignored) {}

        return jsonService.isJsonCandidate(body, contentType);
    }

    @Override
    public String caption() {
        return "JSON Table";
    }

    @Override
    public Component uiComponent() {
        return mainPanel;
    }

    @Override
    public Selection selectedData() {
        if (inspectorArea.getSelectedText() != null && !inspectorArea.getSelectedText().isEmpty()) {
            return Selection.selection(ByteArray.byteArray(inspectorArea.getSelectedText()));
        }
        return null;
    }

    @Override
    public boolean isModified() {
        return false;
    }
}
