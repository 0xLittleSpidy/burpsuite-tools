// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.google.gson.*;
import com.littlespidy.graphqlcop.engine.HttpHelper_littlespidy;
import com.littlespidy.graphqlcop.voyager.LocalVoyagerServer_littlespidy;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import java.awt.*;
import java.util.function.Supplier;

public class QueryVoyagerSubTab_littlespidy extends JPanel {
    private final MontoyaApi api;
    private final LocalVoyagerServer_littlespidy voyagerServer;
    private final Supplier<String> targetUrlSupplier;
    private final Supplier<String> customHeadersSupplier;

    private final JTree operationsTree;
    private final DefaultTreeModel treeModel;
    private final DefaultMutableTreeNode rootNode;
    private final JTextArea queryTextArea;
    private final JTextArea variablesTextArea;
    private final HttpResponseEditor responseViewer;
    private String currentIntrospectionJson = "";

    public QueryVoyagerSubTab_littlespidy(MontoyaApi api, LocalVoyagerServer_littlespidy voyagerServer,
                                         Supplier<String> targetUrlSupplier, Supplier<String> customHeadersSupplier) {
        super(new BorderLayout(4, 4));
        this.api = api;
        this.voyagerServer = voyagerServer;
        this.targetUrlSupplier = targetUrlSupplier;
        this.customHeadersSupplier = customHeadersSupplier;

        // Top Controls
        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton runQueryBtn = new JButton("Run Query");
        JButton fetchIntrospectionBtn = new JButton("Fetch Full Schema Introspection");
        JButton openVoyagerBtn = new JButton("Open GraphQL Voyager in Browser");

        topBar.add(runQueryBtn);
        topBar.add(fetchIntrospectionBtn);
        topBar.add(openVoyagerBtn);
        add(topBar, BorderLayout.NORTH);

        // Operations Tree (Left)
        rootNode = new DefaultMutableTreeNode("Schema Operations");
        treeModel = new DefaultTreeModel(rootNode);
        operationsTree = new JTree(treeModel);
        operationsTree.setRootVisible(false);
        JScrollPane treeScroll = new JScrollPane(operationsTree);
        treeScroll.setPreferredSize(new Dimension(220, 0));
        treeScroll.setBorder(BorderFactory.createTitledBorder("Schema Operations"));

        // Query & Variables (Center)
        queryTextArea = new JTextArea("query {\n  __typename\n}\n");
        queryTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane queryScroll = new JScrollPane(queryTextArea);
        queryScroll.setBorder(BorderFactory.createTitledBorder("GraphQL Query / Mutation"));

        variablesTextArea = new JTextArea("{\n}\n");
        variablesTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane varScroll = new JScrollPane(variablesTextArea);
        varScroll.setPreferredSize(new Dimension(0, 100));
        varScroll.setBorder(BorderFactory.createTitledBorder("Variables (JSON)"));

        JPanel centerPanel = new JPanel(new BorderLayout(4, 4));
        centerPanel.add(queryScroll, BorderLayout.CENTER);
        centerPanel.add(varScroll, BorderLayout.SOUTH);

        // Response (Right)
        responseViewer = api.userInterface().createHttpResponseEditor();
        JPanel respPanel = new JPanel(new BorderLayout());
        respPanel.setBorder(BorderFactory.createTitledBorder("Execution Response"));
        respPanel.add(responseViewer.uiComponent(), BorderLayout.CENTER);

        JSplitPane editorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, centerPanel, respPanel);
        editorSplit.setResizeWeight(0.5);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScroll, editorSplit);
        mainSplit.setResizeWeight(0.2);
        add(mainSplit, BorderLayout.CENTER);

        // Listeners
        runQueryBtn.addActionListener(e -> executeCurrentQuery());
        fetchIntrospectionBtn.addActionListener(e -> fetchIntrospection());
        openVoyagerBtn.addActionListener(e -> {
            if (currentIntrospectionJson != null && !currentIntrospectionJson.isEmpty()) {
                voyagerServer.setSchemaJson(currentIntrospectionJson);
            }
            voyagerServer.openInBrowser();
        });

        operationsTree.addTreeSelectionListener(e -> {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) operationsTree.getLastSelectedPathComponent();
            if (node != null && node.isLeaf() && node.getUserObject() instanceof String) {
                String op = (String) node.getUserObject();
                queryTextArea.setText("query {\n  " + op + " {\n    __typename\n  }\n}\n");
            }
        });
    }

    private void executeCurrentQuery() {
        String targetUrl = targetUrlSupplier.get();
        String customHeaders = customHeadersSupplier.get();
        if (!HttpHelper_littlespidy.isValidUrl(targetUrl)) {
            JOptionPane.showMessageDialog(this, "Please enter a valid HTTP/HTTPS GraphQL target URL (e.g. https://example.com/graphql).", "Invalid Target URL", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JsonObject payload = new JsonObject();
        payload.addProperty("query", queryTextArea.getText());
        try {
            String vars = variablesTextArea.getText().trim();
            if (!vars.isEmpty()) {
                payload.add("variables", JsonParser.parseString(vars));
            }
        } catch (Exception ignored) {}

        new Thread(() -> {
            HttpRequestResponse pair = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders,
                    payload.toString(), "Query Executor", null);
            if (pair != null && pair.response() != null) {
                responseViewer.setResponse(pair.response());
            }
        }).start();
    }

    public void fetchIntrospection() {
        String targetUrl = targetUrlSupplier.get();
        String customHeaders = customHeadersSupplier.get();
        if (!HttpHelper_littlespidy.isValidUrl(targetUrl)) {
            JOptionPane.showMessageDialog(this, "Please enter a valid HTTP/HTTPS GraphQL target URL (e.g. https://example.com/graphql).", "Invalid Target URL", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String introspectionQuery = "{\"query\": \"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }\"}";

        new Thread(() -> {
            HttpRequestResponse pair = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders,
                    introspectionQuery, "Full Introspection Query", null);
            if (pair != null && pair.response() != null) {
                responseViewer.setResponse(pair.response());
                String body = HttpHelper_littlespidy.getResponseBody(pair);
                if (body.contains("__schema")) {
                    currentIntrospectionJson = body;
                    voyagerServer.setSchemaJson(body);
                    loadOperationsIntoTree(body);
                    JOptionPane.showMessageDialog(this, "Schema Introspection retrieved successfully!\nYou can now open GraphQL Voyager.", "Introspection Success", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        }).start();
    }

    public void loadOperationsIntoTree(String schemaJson) {
        currentIntrospectionJson = schemaJson;
        rootNode.removeAllChildren();
        DefaultMutableTreeNode queriesNode = new DefaultMutableTreeNode("Queries");
        DefaultMutableTreeNode mutationsNode = new DefaultMutableTreeNode("Mutations");
        DefaultMutableTreeNode subscriptionsNode = new DefaultMutableTreeNode("Subscriptions");

        try {
            JsonObject root = JsonParser.parseString(schemaJson).getAsJsonObject();
            JsonObject schemaObj = root.has("data") && root.getAsJsonObject("data").has("__schema")
                    ? root.getAsJsonObject("data").getAsJsonObject("__schema")
                    : (root.has("__schema") ? root.getAsJsonObject("__schema") : root);

            if (schemaObj.has("types")) {
                JsonArray types = schemaObj.getAsJsonArray("types");
                for (JsonElement tEl : types) {
                    JsonObject typeObj = tEl.getAsJsonObject();
                    String name = typeObj.has("name") && !typeObj.get("name").isJsonNull() ? typeObj.get("name").getAsString() : "";
                    if ("Query".equalsIgnoreCase(name) && typeObj.has("fields")) {
                        for (JsonElement f : typeObj.getAsJsonArray("fields")) {
                            queriesNode.add(new DefaultMutableTreeNode(f.getAsJsonObject().get("name").getAsString()));
                        }
                    } else if ("Mutation".equalsIgnoreCase(name) && typeObj.has("fields")) {
                        for (JsonElement f : typeObj.getAsJsonArray("fields")) {
                            mutationsNode.add(new DefaultMutableTreeNode(f.getAsJsonObject().get("name").getAsString()));
                        }
                    } else if ("Subscription".equalsIgnoreCase(name) && typeObj.has("fields")) {
                        for (JsonElement f : typeObj.getAsJsonArray("fields")) {
                            subscriptionsNode.add(new DefaultMutableTreeNode(f.getAsJsonObject().get("name").getAsString()));
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        rootNode.add(queriesNode);
        rootNode.add(mutationsNode);
        rootNode.add(subscriptionsNode);
        treeModel.reload();
        operationsTree.expandRow(0);
        operationsTree.expandRow(1);
    }

    public String getCurrentIntrospectionJson() {
        return currentIntrospectionJson;
    }
}
