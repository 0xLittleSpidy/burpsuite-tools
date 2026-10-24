// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.graphqlcop.editor.GraphQLHttpRequestEditorProvider_littlespidy;
import com.littlespidy.graphqlcop.ui.ContextMenuProvider_littlespidy;
import com.littlespidy.graphqlcop.ui.GraphQLCopRootTab_littlespidy;

public class GraphQLCopExtension_littlespidy implements BurpExtension {
    private GraphQLCopRootTab_littlespidy rootTab;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("graphql");

        rootTab = new GraphQLCopRootTab_littlespidy(api);
        api.userInterface().registerSuiteTab("graphql", rootTab);

        api.userInterface().registerHttpRequestEditorProvider(new GraphQLHttpRequestEditorProvider_littlespidy(api));
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuProvider_littlespidy(rootTab));

        api.extension().registerUnloadingHandler(() -> {
            if (rootTab != null) {
                rootTab.cleanup();
            }
            api.logging().logToOutput("graphql extension unloaded successfully.");
        });

        api.logging().logToOutput("graphql extension initialized successfully (littlespidy).");
    }
}
