// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import com.littlespidy.quickhelper.service.AuthTokenExtractorService_littlespidy;
import com.littlespidy.quickhelper.service.ClipboardService_littlespidy;

/**
 * Provider registering the 'Auth & Tokens' Request Editor tab across Burp Suite tools.
 */
public class AuthHttpRequestEditorProvider_littlespidy implements HttpRequestEditorProvider {

    private final MontoyaApi api;
    private final ClipboardService_littlespidy clipboardService;
    private final AuthTokenExtractorService_littlespidy extractorService;

    public AuthHttpRequestEditorProvider_littlespidy(MontoyaApi api,
                                                     ClipboardService_littlespidy clipboardService,
                                                     AuthTokenExtractorService_littlespidy extractorService) {
        this.api = api;
        this.clipboardService = clipboardService;
        this.extractorService = extractorService;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new AuthRequestEditorTab_littlespidy(api, creationContext, clipboardService, extractorService);
    }
}
