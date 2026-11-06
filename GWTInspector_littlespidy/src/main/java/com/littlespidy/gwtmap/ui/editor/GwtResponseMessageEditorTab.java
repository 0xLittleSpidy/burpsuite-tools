// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.ui.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import com.littlespidy.gwtmap.model.GWTRpcResponse;
import com.littlespidy.gwtmap.parser.GWTRpcResponseDeserializer;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.List;

/**
 * Native Burp Suite HTTP Response Editor tab for GWT-RPC responses.
 * Parses //OK success values and //EX serialized exceptions into a human-readable,
 * structured layout while preserving access to the raw response.
 *
 * @author littlespidy
 */
public class GwtResponseMessageEditorTab implements ExtensionProvidedHttpResponseEditor {

    private final MontoyaApi api;
    private final EditorCreationContext creationContext;

    private final JPanel mainPanel;
    private final JPanel bannerPanel;
    private final JLabel statusLabel;
    private final JTextArea structuredArea = new JTextArea();
    private final JTextArea rawResponseArea = new JTextArea();
    private final JTable stringTableViewer;
    private final DefaultTableModel stringTableModel;

    private HttpRequestResponse currentRequestResponse;
    private HttpResponse currentResponse;
    private GWTRpcResponse currentParsedResponse;

    public GwtResponseMessageEditorTab(MontoyaApi api, EditorCreationContext creationContext) {
        this.api = api;
        this.creationContext = creationContext;

        this.mainPanel = new JPanel(new BorderLayout(4, 4));
        this.mainPanel.setBorder(new EmptyBorder(4, 4, 4, 4));

        // 1. Top Status Banner
        bannerPanel = new JPanel(new BorderLayout(6, 4));
        bannerPanel.setBorder(new CompoundBorder(
                new LineBorder(Color.GRAY, 1),
                new EmptyBorder(6, 8, 6, 8)
        ));

        statusLabel = new JLabel("GWT Response: Not analyzed");
        statusLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));

        JPanel btnGroup = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton copySummaryBtn = new JButton("Copy Structured View");
        copySummaryBtn.setToolTipText("Copy human-readable GWT breakdown to clipboard");
        copySummaryBtn.addActionListener(e -> {
            if (structuredArea.getText() != null && !structuredArea.getText().isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(structuredArea.getText()), null);
            }
        });
        btnGroup.add(copySummaryBtn);

        JButton copyRawBtn = new JButton("Copy Raw Body");
        copyRawBtn.setToolTipText("Copy original raw response body to clipboard");
        copyRawBtn.addActionListener(e -> {
            if (rawResponseArea.getText() != null && !rawResponseArea.getText().isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(rawResponseArea.getText()), null);
            }
        });
        btnGroup.add(copyRawBtn);

        bannerPanel.add(statusLabel, BorderLayout.CENTER);
        bannerPanel.add(btnGroup, BorderLayout.EAST);
        mainPanel.add(bannerPanel, BorderLayout.NORTH);

        // 2. Center Tabs
        JTabbedPane tabbedPane = new JTabbedPane();

        // Sub-Tab 1: Structured Human-Readable View
        structuredArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        structuredArea.setEditable(false);
        tabbedPane.addTab("Structured View", new JScrollPane(structuredArea));

        // Sub-Tab 2: String Table
        String[] cols = {"#", "Type / Category", "String Value"};
        stringTableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        stringTableViewer = new JTable(stringTableModel);
        stringTableViewer.setAutoCreateRowSorter(true);
        stringTableViewer.getColumnModel().getColumn(0).setPreferredWidth(50);
        stringTableViewer.getColumnModel().getColumn(1).setPreferredWidth(120);
        stringTableViewer.getColumnModel().getColumn(2).setPreferredWidth(550);
        tabbedPane.addTab("String Table", new JScrollPane(stringTableViewer));

        // Sub-Tab 3: Raw Response
        rawResponseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        rawResponseArea.setEditable(false);
        tabbedPane.addTab("Raw Response", new JScrollPane(rawResponseArea));

        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    @Override
    public HttpResponse getResponse() {
        return currentResponse;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.currentRequestResponse = requestResponse;
        if (requestResponse == null || requestResponse.response() == null) {
            clearViews();
            return;
        }

        this.currentResponse = requestResponse.response();
        String body = currentResponse.bodyToString();
        if (body == null) body = "";

        rawResponseArea.setText(body);
        rawResponseArea.setCaretPosition(0);

        try {
            currentParsedResponse = GWTRpcResponseDeserializer.deserialize(body);
            updateUI(currentParsedResponse);
        } catch (Throwable t) {
            statusLabel.setText("[!] GWT Response: Error parsing payload (" + t.getMessage() + ")");
            bannerPanel.setBackground(new Color(255, 243, 205));
            bannerPanel.setBorder(new LineBorder(new Color(255, 193, 7), 1));
            structuredArea.setText("Error parsing GWT response:\n" + t.getMessage() + "\n\nRaw body preserved in Raw Response tab.");
        }
    }

    private void updateUI(GWTRpcResponse resp) {
        if (resp == null) {
            clearViews();
            return;
        }

        structuredArea.setText(resp.getFormattedSummary());
        structuredArea.setCaretPosition(0);

        // Update String Table
        stringTableModel.setRowCount(0);
        List<String> strList = resp.getStringTable();
        for (int i = 0; i < strList.size(); i++) {
            String val = strList.get(i);
            String category = GWTRpcResponseDeserializer.isTypeSignature(val) ? "Type Signature" : "String Value";
            stringTableModel.addRow(new Object[]{i + 1, category, val});
        }

        // Update Banner Status & Colors
        if (resp.isSuccess()) {
            String retInfo = !resp.getReturnType().isEmpty() ? " [" + resp.getReturnType() + "]" : "";
            statusLabel.setText("[OK] GWT-RPC Return Value: Success" + retInfo);
            statusLabel.setForeground(new Color(25, 110, 25));
            bannerPanel.setBackground(new Color(235, 250, 235));
            bannerPanel.setBorder(new LineBorder(new Color(40, 167, 69), 1));
        } else if (resp.isException()) {
            String exInfo = !resp.getExceptionType().isEmpty() ? resp.getExceptionType() : "Server Exception";
            String msg = !resp.getExceptionMessage().isEmpty() ? " - " + resp.getExceptionMessage() : "";
            statusLabel.setText("[EX] GWT Exception: " + exInfo + msg);
            statusLabel.setForeground(new Color(160, 25, 25));
            bannerPanel.setBackground(new Color(255, 235, 235));
            bannerPanel.setBorder(new LineBorder(new Color(220, 53, 69), 1));
        } else {
            statusLabel.setText("[?] GWT Response: Unrecognized or non-standard payload format");
            statusLabel.setForeground(new Color(90, 90, 90));
            bannerPanel.setBackground(new Color(245, 245, 245));
            bannerPanel.setBorder(new LineBorder(Color.GRAY, 1));
        }
    }

    private void clearViews() {
        currentResponse = null;
        currentParsedResponse = null;
        statusLabel.setText("GWT Response: None");
        statusLabel.setForeground(Color.DARK_GRAY);
        bannerPanel.setBackground(UIManager.getColor("Panel.background"));
        bannerPanel.setBorder(new CompoundBorder(new LineBorder(Color.GRAY, 1), new EmptyBorder(6, 8, 6, 8)));
        structuredArea.setText("");
        rawResponseArea.setText("");
        stringTableModel.setRowCount(0);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.response() == null) {
            return false;
        }

        try {
            HttpResponse resp = requestResponse.response();
            String body = resp.bodyToString();
            if (body != null && !body.isBlank()) {
                String trimmed = body.trim();
                if (trimmed.startsWith("//OK") || trimmed.startsWith("//EX")
                        || trimmed.contains("//OK[") || trimmed.contains("//EX[")) {
                    return true;
                }
            }

            // Check response Content-Type header
            try {
                List<HttpHeader> headers = resp.headers();
                if (headers != null) {
                    for (HttpHeader h : headers) {
                        String val = h.value().toLowerCase();
                        if (val.contains("gwt-rpc") || val.contains("x-gwt")) {
                            return true;
                        }
                    }
                }
            } catch (Throwable ignored) {}

            // Check request
            if (requestResponse.request() != null) {
                String reqBody = requestResponse.request().bodyToString();
                if (reqBody != null && !reqBody.isBlank()) {
                    String trimmed = reqBody.trim();
                    if (trimmed.matches("^[0-9]+\\|[0-9]+\\|.*") || trimmed.contains("|0|") || trimmed.contains("|1|")) {
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {}

        return false;
    }

    @Override
    public String caption() {
        return "GWT Response";
    }

    @Override
    public Component uiComponent() {
        return mainPanel;
    }

    @Override
    public Selection selectedData() {
        if (structuredArea.getSelectedText() != null && !structuredArea.getSelectedText().isEmpty()) {
            return Selection.selection(ByteArray.byteArray(structuredArea.getSelectedText()));
        }
        if (rawResponseArea.getSelectedText() != null && !rawResponseArea.getSelectedText().isEmpty()) {
            return Selection.selection(ByteArray.byteArray(rawResponseArea.getSelectedText()));
        }
        return null;
    }

    @Override
    public boolean isModified() {
        return false;
    }
}
