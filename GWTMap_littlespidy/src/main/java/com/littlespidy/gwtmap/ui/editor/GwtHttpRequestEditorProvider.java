// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.ui.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import com.littlespidy.gwtmap.ui.GWTMapTab;

/**
 * Provider factory for GWT HTTP Request Editor tabs across Burp Suite.
 *
 * @author littlespidy
 */
public class GwtHttpRequestEditorProvider implements HttpRequestEditorProvider {

    private final MontoyaApi api;
    private final GWTMapTab mainTab;

    public GwtHttpRequestEditorProvider(MontoyaApi api, GWTMapTab mainTab) {
        this.api = api;
        this.mainTab = mainTab;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new GwtMessageEditorTab(api, mainTab, creationContext);
    }
}
