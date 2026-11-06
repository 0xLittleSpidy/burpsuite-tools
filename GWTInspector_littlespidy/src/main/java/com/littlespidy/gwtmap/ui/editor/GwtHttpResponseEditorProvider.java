// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.ui.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import com.littlespidy.gwtmap.ui.GWTMapTab;

/**
 * Provider factory for GWT HTTP Response Editor tabs across Burp Suite.
 *
 * @author littlespidy
 */
public class GwtHttpResponseEditorProvider implements HttpResponseEditorProvider {

    private final MontoyaApi api;
    private final GWTMapTab mainTab;

    public GwtHttpResponseEditorProvider(MontoyaApi api, GWTMapTab mainTab) {
        this.api = api;
        this.mainTab = mainTab;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new GwtResponseMessageEditorTab(api, creationContext);
    }
}
