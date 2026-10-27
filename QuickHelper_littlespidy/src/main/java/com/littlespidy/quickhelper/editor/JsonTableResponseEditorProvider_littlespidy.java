// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import com.littlespidy.quickhelper.service.ClipboardService_littlespidy;
import com.littlespidy.quickhelper.service.JsonTableService_littlespidy;

/**
 * Provider registering the 'JSON Table' Response Editor tab across Burp Suite tools.
 */
public class JsonTableResponseEditorProvider_littlespidy implements HttpResponseEditorProvider {

    private final MontoyaApi api;
    private final ClipboardService_littlespidy clipboardService;
    private final JsonTableService_littlespidy jsonService;

    public JsonTableResponseEditorProvider_littlespidy(MontoyaApi api,
                                                       ClipboardService_littlespidy clipboardService,
                                                       JsonTableService_littlespidy jsonService) {
        this.api = api;
        this.clipboardService = clipboardService;
        this.jsonService = jsonService;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new JsonTableResponseEditorTab_littlespidy(api, creationContext, clipboardService, jsonService);
    }
}
