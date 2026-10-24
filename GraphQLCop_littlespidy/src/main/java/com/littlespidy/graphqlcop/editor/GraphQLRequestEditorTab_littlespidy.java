// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.google.gson.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.nio.charset.StandardCharsets;

public class GraphQLRequestEditorTab_littlespidy implements ExtensionProvidedHttpRequestEditor {
    private final MontoyaApi api;
    private final EditorCreationContext creationContext;
    private final JPanel mainPanel;
    private final JTextArea queryTextArea;
    private final JTextArea variablesTextArea;
    private final JTextField operationNameField;

    private HttpRequest originalRequest;
    private boolean isModified = false;
    private boolean updatingInternally = false;
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public GraphQLRequestEditorTab_littlespidy(MontoyaApi api, EditorCreationContext creationContext) {
        this.api = api;
        this.creationContext = creationContext;

        mainPanel = new JPanel(new BorderLayout(4, 4));
        mainPanel.setBorder(new EmptyBorder(4, 4, 4, 4));

        // Top toolbar
        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        topBar.add(new JLabel("Operation Name:"));
        operationNameField = new JTextField(20);
        topBar.add(operationNameField);

        JButton formatBtn = new JButton("Format");
        topBar.add(formatBtn);

        mainPanel.add(topBar, BorderLayout.NORTH);

        // Split pane for Query and Variables
        queryTextArea = new JTextArea();
        queryTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane queryScroll = new JScrollPane(queryTextArea);
        queryScroll.setBorder(BorderFactory.createTitledBorder("GraphQL Query / Mutation"));

        variablesTextArea = new JTextArea();
        variablesTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane varScroll = new JScrollPane(variablesTextArea);
        varScroll.setBorder(BorderFactory.createTitledBorder("Query Variables (JSON)"));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, queryScroll, varScroll);
        splitPane.setResizeWeight(0.7);
        mainPanel.add(splitPane, BorderLayout.CENTER);

        DocumentListener docListener = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { onModified(); }
            @Override
            public void removeUpdate(DocumentEvent e) { onModified(); }
            @Override
            public void changedUpdate(DocumentEvent e) { onModified(); }
        };

        queryTextArea.getDocument().addDocumentListener(docListener);
        variablesTextArea.getDocument().addDocumentListener(docListener);
        operationNameField.getDocument().addDocumentListener(docListener);

        formatBtn.addActionListener(e -> formatContent());
    }

    private void onModified() {
        if (!updatingInternally) {
            isModified = true;
        }
    }

    private void formatContent() {
        try {
            String vars = variablesTextArea.getText().trim();
            if (!vars.isEmpty()) {
                JsonElement el = JsonParser.parseString(vars);
                variablesTextArea.setText(GSON.toJson(el));
            }
        } catch (Exception ignored) {}
    }

    @Override
    public HttpRequest getRequest() {
        if (!isModified || originalRequest == null) {
            return originalRequest;
        }

        JsonObject obj = new JsonObject();
        obj.addProperty("query", queryTextArea.getText());

        String opName = operationNameField.getText().trim();
        if (!opName.isEmpty()) {
            obj.addProperty("operationName", opName);
        }

        String varsText = variablesTextArea.getText().trim();
        if (!varsText.isEmpty()) {
            try {
                JsonElement varsEl = JsonParser.parseString(varsText);
                obj.add("variables", varsEl);
            } catch (Exception e) {
                obj.addProperty("variables", varsText);
            }
        }

        String newBodyStr = GSON.toJson(obj);
        return originalRequest.withBody(newBodyStr)
                .withHeader("Content-Type", "application/json")
                .withHeader("Content-Length", String.valueOf(newBodyStr.getBytes(StandardCharsets.UTF_8).length));
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            return;
        }

        this.originalRequest = requestResponse.request();
        this.isModified = false;
        this.updatingInternally = true;

        try {
            String body = originalRequest.bodyToString();
            if (body != null && body.trim().startsWith("{")) {
                JsonObject obj = JsonParser.parseString(body).getAsJsonObject();
                if (obj.has("query") && !obj.get("query").isJsonNull()) {
                    queryTextArea.setText(obj.get("query").getAsString());
                } else {
                    queryTextArea.setText("");
                }

                if (obj.has("operationName") && !obj.get("operationName").isJsonNull()) {
                    operationNameField.setText(obj.get("operationName").getAsString());
                } else {
                    operationNameField.setText("");
                }

                if (obj.has("variables") && !obj.get("variables").isJsonNull()) {
                    JsonElement vars = obj.get("variables");
                    if (vars.isJsonObject() || vars.isJsonArray()) {
                        variablesTextArea.setText(GSON.toJson(vars));
                    } else {
                        variablesTextArea.setText(vars.getAsString());
                    }
                } else {
                    variablesTextArea.setText("{}");
                }
            } else {
                queryTextArea.setText(body != null ? body : "");
                operationNameField.setText("");
                variablesTextArea.setText("{}");
            }
        } catch (Exception e) {
            queryTextArea.setText(originalRequest.bodyToString());
            operationNameField.setText("");
            variablesTextArea.setText("");
        } finally {
            this.updatingInternally = false;
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            return false;
        }
        HttpRequest req = requestResponse.request();
        String url = req.url().toLowerCase();
        String body = req.bodyToString();

        if (url.contains("graphql") || url.contains("/gql")) {
            return true;
        }
        if (body != null && (body.contains("\"query\"") || body.contains("\"mutation\"") || body.contains("\"__schema\""))) {
            return true;
        }
        return false;
    }

    @Override
    public String caption() {
        return "GraphQL";
    }

    @Override
    public Component uiComponent() {
        return mainPanel;
    }

    @Override
    public Selection selectedData() {
        if (queryTextArea.getSelectedText() != null) {
            return Selection.selection(queryTextArea.getSelectionStart(), queryTextArea.getSelectionEnd());
        }
        return null;
    }

    @Override
    public boolean isModified() {
        return isModified;
    }
}
