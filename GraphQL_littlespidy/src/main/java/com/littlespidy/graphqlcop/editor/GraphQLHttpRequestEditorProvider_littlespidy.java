// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

public class GraphQLHttpRequestEditorProvider_littlespidy implements HttpRequestEditorProvider {
    private final MontoyaApi api;

    public GraphQLHttpRequestEditorProvider_littlespidy(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new GraphQLRequestEditorTab_littlespidy(api, creationContext);
    }
}
