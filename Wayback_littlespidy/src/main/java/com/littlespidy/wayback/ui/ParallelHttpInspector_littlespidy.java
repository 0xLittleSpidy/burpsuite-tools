// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import java.awt.*;
import java.util.Base64;

public class ParallelHttpInspector_littlespidy extends JPanel {

    private final MontoyaApi api;
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private JTextArea fallbackReqArea;
    private JTextArea fallbackRespArea;

    public ParallelHttpInspector_littlespidy(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        initUI();
    }

    private void initUI() {
        Component reqComponent;
        Component respComponent;

        if (api != null && api.userInterface() != null) {
            this.requestEditor = api.userInterface().createHttpRequestEditor();
            this.responseEditor = api.userInterface().createHttpResponseEditor();
            reqComponent = requestEditor.uiComponent();
            respComponent = responseEditor.uiComponent();
        } else {
            fallbackReqArea = new JTextArea();
            fallbackReqArea.setEditable(false);
            fallbackReqArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            reqComponent = new JScrollPane(fallbackReqArea);

            fallbackRespArea = new JTextArea();
            fallbackRespArea.setEditable(false);
            fallbackRespArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            respComponent = new JScrollPane(fallbackRespArea);
        }

        JPanel reqPanel = new JPanel(new BorderLayout());
        JLabel reqHeader = new JLabel("HTTP Request");
        reqHeader.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        reqHeader.setFont(reqHeader.getFont().deriveFont(Font.BOLD, 11f));
        reqPanel.add(reqHeader, BorderLayout.NORTH);
        reqPanel.add(reqComponent, BorderLayout.CENTER);

        JPanel respPanel = new JPanel(new BorderLayout());
        JLabel respHeader = new JLabel("HTTP Response");
        respHeader.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        respHeader.setFont(respHeader.getFont().deriveFont(Font.BOLD, 11f));
        respPanel.add(respHeader, BorderLayout.NORTH);
        respPanel.add(respComponent, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, respPanel);
        splitPane.setResizeWeight(0.5);
        splitPane.setContinuousLayout(true);
        splitPane.setBorder(null);

        add(splitPane, BorderLayout.CENTER);
        setPreferredSize(new Dimension(600, 240));
    }

    public void displayRequestResponse(HttpRequest request, HttpResponse response, String rawReqBase64, String rawRespBase64) {
        if (requestEditor != null && request != null) {
            requestEditor.setRequest(request);
        } else if (requestEditor != null && rawReqBase64 != null && !rawReqBase64.isBlank()) {
            try {
                byte[] bytes = Base64.getDecoder().decode(rawReqBase64);
                requestEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(bytes)));
            } catch (Exception ignored) {
            }
        } else if (fallbackReqArea != null) {
            if (rawReqBase64 != null && !rawReqBase64.isBlank()) {
                fallbackReqArea.setText(new String(Base64.getDecoder().decode(rawReqBase64)));
            } else if (request != null) {
                fallbackReqArea.setText(request.toString());
            } else {
                fallbackReqArea.setText("");
            }
            fallbackReqArea.setCaretPosition(0);
        }

        if (responseEditor != null && response != null) {
            responseEditor.setResponse(response);
        } else if (responseEditor != null && rawRespBase64 != null && !rawRespBase64.isBlank()) {
            try {
                byte[] bytes = Base64.getDecoder().decode(rawRespBase64);
                responseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(bytes)));
            } catch (Exception ignored) {
            }
        } else if (fallbackRespArea != null) {
            if (rawRespBase64 != null && !rawRespBase64.isBlank()) {
                fallbackRespArea.setText(new String(Base64.getDecoder().decode(rawRespBase64)));
            } else if (response != null) {
                fallbackRespArea.setText(response.toString());
            } else {
                fallbackRespArea.setText("");
            }
            fallbackRespArea.setCaretPosition(0);
        }
    }

    public void clear() {
        if (requestEditor != null) {
            requestEditor.setRequest(null);
        }
        if (responseEditor != null) {
            responseEditor.setResponse(null);
        }
        if (fallbackReqArea != null) {
            fallbackReqArea.setText("");
        }
        if (fallbackRespArea != null) {
            fallbackRespArea.setText("");
        }
    }
}
