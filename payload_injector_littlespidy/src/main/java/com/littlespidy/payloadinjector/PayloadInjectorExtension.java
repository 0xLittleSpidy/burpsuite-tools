// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.payloadinjector.model.InjectionSettings;
import com.littlespidy.payloadinjector.model.ParamPayloadStore;
import com.littlespidy.payloadinjector.model.PayloadCategoryRegistry_littlespidy;
import com.littlespidy.payloadinjector.model.SmugglingPayloadStore;
import com.littlespidy.payloadinjector.ui.PayloadContextMenuProvider;
import com.littlespidy.payloadinjector.ui.PayloadInjectorTab;

import java.util.Map;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Main extension entry point for Payload Injector.
 * Initializes dedicated tabs for all JSON payload files (wrapping across multiple rows)
 * and provides full context menu integration for all categories.
 *
 * @author littlespidy
 */
public class PayloadInjectorExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Payload Injector (littlespidy)");

        // ── 1. Initialize Stores & Settings ──
        Map<String, ParamPayloadStore> paramStores = PayloadCategoryRegistry_littlespidy.createAllParamStores(api);
        SmugglingPayloadStore smugglingStore = new SmugglingPayloadStore(api);
        InjectionSettings settings = new InjectionSettings();

        // ── 2. Register Master Suite Tab ──
        PayloadInjectorTab masterTab = new PayloadInjectorTab(
                paramStores,
                smugglingStore,
                settings
        );
        api.userInterface().registerSuiteTab("Payload Injector", masterTab);

        // ── 3. Register Context Menu Provider ──
        api.userInterface().registerContextMenuItemsProvider(
                new PayloadContextMenuProvider(
                        api,
                        paramStores,
                        smugglingStore,
                        settings
                )
        );

        // ── 4. Register Unloading Handler ──
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("Payload Injector extension unloaded successfully.");
        });

        api.logging().logToOutput("Payload Injector (littlespidy) loaded successfully!");
    }
}
