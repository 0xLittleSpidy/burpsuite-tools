package com.littlespidy.parampayloadinjector;

import com.littlespidy.parampayloadinjector.engine.ReflectionDetector;
import com.littlespidy.parampayloadinjector.model.InjectionConfig;
import com.littlespidy.parampayloadinjector.ui.ContextMenuProvider;
import com.littlespidy.parampayloadinjector.ui.InjectorTab;
import com.littlespidy.parampayloadinjector.ui.ReflectionTableModel;
import com.littlespidy.parampayloadinjector.ui.TemplateTableModel;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Main extension entry point for Param Payload Injector.
 * Dynamically binds parameter names into security payloads (XSS, Angular CSTI, etc.)
 * for unambiguous reflection and vulnerability attribution across parameters.
 *
 * @author littlespidy
 */
public class ParamPayloadInjectorExtension implements BurpExtension {

    private MontoyaApi api;
    private InjectionConfig config;
    private ReflectionTableModel reflectionTableModel;
    private TemplateTableModel templateTableModel;
    private InjectorTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Param Payload Injector (littlespidy)");

        this.config = new InjectionConfig();
        this.reflectionTableModel = new ReflectionTableModel(api);
        this.templateTableModel = new TemplateTableModel(config);

        this.mainTab = new InjectorTab(api, config, reflectionTableModel, templateTableModel);

        // ── 1. Register Suite Tab ──
        api.userInterface().registerSuiteTab("Param Injector", mainTab);

        // ── 2. Register Context Menu Provider ──
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuProvider(api, config));

        // ── 3. Register HTTP Handler for Reflection Detection ──
        ReflectionDetector detector = new ReflectionDetector(api, config, finding -> {
            SwingUtilities.invokeLater(() -> {
                reflectionTableModel.addFinding(finding);
                mainTab.updateCountBadge();
            });
        });
        api.http().registerHttpHandler(detector);

        // ── 4. Register Unloading Handler ──
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("Param Payload Injector extension unloaded successfully.");
        });

        api.logging().logToOutput("Param Payload Injector (littlespidy) loaded successfully!");
    }
}
