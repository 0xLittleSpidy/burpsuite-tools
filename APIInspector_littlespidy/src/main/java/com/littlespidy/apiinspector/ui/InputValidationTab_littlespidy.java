// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.apiinspector.engine.InputValidationEngine_littlespidy;
import com.littlespidy.apiinspector.engine.InputValidationProgressListener_littlespidy;
import com.littlespidy.apiinspector.model.AuthProfile_littlespidy;
import com.littlespidy.apiinspector.model.EndpointSelectionItem_littlespidy;
import com.littlespidy.apiinspector.model.InputValidationPayloadItem_littlespidy;
import com.littlespidy.apiinspector.model.InputValidationTechnique_littlespidy;
import com.littlespidy.apiinspector.model.InputValidationTestResult_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Root Suite Tab for Input Validation Fuzzing and Testing.
 * Hosts closable Runner session tabs, each with a results table
 * and 50/50 parallel side-by-side Montoya Request and Response editors.
 */
public class InputValidationTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final InputValidationEngine_littlespidy fuzzEngine;
    private final JTabbedPane runnerTabbedPane = new JTabbedPane();
    private final List<InputValidationRunnerPanel_littlespidy> activeRunners = new ArrayList<>();
    private final AtomicInteger runnerCounter = new AtomicInteger(1);

    public InputValidationTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        this.fuzzEngine = new InputValidationEngine_littlespidy(api);

        initComponents();
    }

    private void initComponents() {
        // Initial default runner
        createNewRunner("Input Validation Runner 1");
        add(runnerTabbedPane, BorderLayout.CENTER);
    }

    public InputValidationRunnerPanel_littlespidy createNewRunner(String runnerName) {
        String id = "fuzz_runner_" + runnerCounter.getAndIncrement();
        String name = (runnerName != null && !runnerName.isBlank()) ? runnerName : "Input Validation Runner " + runnerCounter.get();

        InputValidationRunnerPanel_littlespidy panel = new InputValidationRunnerPanel_littlespidy(api, id, name);
        activeRunners.add(panel);

        int index = runnerTabbedPane.getTabCount();
        runnerTabbedPane.addTab(name, panel);
        setupTabHeader(runnerTabbedPane, panel, name);
        runnerTabbedPane.setSelectedComponent(panel);

        return panel;
    }

    private void setupTabHeader(JTabbedPane tabbedPane, InputValidationRunnerPanel_littlespidy panel, String title) {
        JPanel headerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        headerPanel.setOpaque(false);

        JLabel titleLabel = new JLabel(title);
        headerPanel.add(titleLabel);

        JButton closeBtn = new JButton("x");
        closeBtn.setMargin(new Insets(0, 2, 0, 2));
        closeBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        closeBtn.setFocusable(false);
        closeBtn.setBorderPainted(false);
        closeBtn.setContentAreaFilled(false);
        closeBtn.setToolTipText("Close Runner");

        closeBtn.addActionListener(e -> {
            if (runnerTabbedPane.getTabCount() > 1) {
                int idx = runnerTabbedPane.indexOfComponent(panel);
                if (idx != -1) {
                    runnerTabbedPane.remove(idx);
                    activeRunners.remove(panel);
                }
            } else {
                panel.setResults(new ArrayList<>());
            }
        });

        headerPanel.add(closeBtn);
        int idx = tabbedPane.indexOfComponent(panel);
        if (idx != -1) {
            tabbedPane.setTabComponentAt(idx, headerPanel);
        }
    }

    public void executeAttack(
            List<? extends EndpointSelectionItem_littlespidy> endpoints,
            String defaultBaseUrl,
            AuthProfile_littlespidy profile,
            String customAuthHeader,
            List<InputValidationPayloadItem_littlespidy> payloads,
            int threads,
            int delayMs,
            String runnerName) {

        InputValidationRunnerPanel_littlespidy runner = createNewRunner(runnerName);

        fuzzEngine.executeEndpointsFuzzAsync(
                endpoints,
                defaultBaseUrl,
                profile,
                customAuthHeader,
                payloads,
                threads,
                delayMs,
                new InputValidationProgressListener_littlespidy() {
                    @Override
                    public void onFuzzTestCompleted(InputValidationTestResult_littlespidy result) {
                        runner.addResult(result);
                    }

                    @Override
                    public void onStatusUpdate(String statusMessage, int current, int total) {
                        runner.updateStatusText("Status: " + statusMessage);
                    }

                    @Override
                    public void onAllTestsCompleted() {
                        runner.updateStatusText("Status: Completed all fuzzing tests");
                    }
                }
        );
    }

    public void executeAttack(
            List<? extends EndpointSelectionItem_littlespidy> endpoints,
            String defaultBaseUrl,
            List<InputValidationPayloadItem_littlespidy> payloads,
            int threads,
            int delayMs,
            String runnerName) {
        executeAttack(endpoints, defaultBaseUrl, null, null, payloads, threads, delayMs, runnerName);
    }

    public void executeAttackForPayloads(
            HttpRequest targetRequest,
            List<InputValidationPayloadItem_littlespidy> payloads,
            int threads,
            int delayMs,
            String runnerName) {

        InputValidationRunnerPanel_littlespidy runner = createNewRunner(runnerName);

        fuzzEngine.executeIndividualPayloadsAsync(
                targetRequest,
                payloads,
                threads,
                delayMs,
                new InputValidationProgressListener_littlespidy() {
                    @Override
                    public void onFuzzTestCompleted(InputValidationTestResult_littlespidy result) {
                        runner.addResult(result);
                    }

                    @Override
                    public void onStatusUpdate(String statusMessage, int current, int total) {
                        runner.updateStatusText("Status: " + statusMessage);
                    }

                    @Override
                    public void onAllTestsCompleted() {
                        runner.updateStatusText("Status: Completed all fuzzing tests");
                    }
                }
        );
    }

    public void executeAttack(
            HttpRequest targetRequest,
            List<InputValidationTechnique_littlespidy> techniques,
            int threads,
            int delayMs,
            String runnerName) {

        InputValidationRunnerPanel_littlespidy runner = createNewRunner(runnerName);

        fuzzEngine.executeTestsAsync(
                targetRequest,
                techniques,
                threads,
                delayMs,
                new InputValidationProgressListener_littlespidy() {
                    @Override
                    public void onFuzzTestCompleted(InputValidationTestResult_littlespidy result) {
                        runner.addResult(result);
                    }

                    @Override
                    public void onStatusUpdate(String statusMessage, int current, int total) {
                        runner.updateStatusText("Status: " + statusMessage);
                    }

                    @Override
                    public void onAllTestsCompleted() {
                        runner.updateStatusText("Status: Completed all fuzzing tests");
                    }
                }
        );
    }

    public void sendToInputValidation(HttpRequest request, HttpResponse response) {
        if (request == null) return;
        String path = request.path() != null ? request.path() : "/";
        String runnerName = "Fuzz - " + path;
        InputValidationRunnerPanel_littlespidy runner = createNewRunner(runnerName);

        // Run default categories against this request
        List<InputValidationTechnique_littlespidy> techs = InputValidationTechnique_littlespidy.getDefaultTechniques();

        fuzzEngine.executeTestsAsync(
                request,
                techs,
                4,
                50,
                new InputValidationProgressListener_littlespidy() {
                    @Override
                    public void onFuzzTestCompleted(InputValidationTestResult_littlespidy result) {
                        runner.addResult(result);
                    }

                    @Override
                    public void onStatusUpdate(String statusMessage, int current, int total) {
                        runner.updateStatusText("Status: " + statusMessage);
                    }

                    @Override
                    public void onAllTestsCompleted() {
                        runner.updateStatusText("Status: Completed all fuzzing tests");
                    }
                }
        );
    }

    public List<InputValidationRunnerPanel_littlespidy> getActiveRunners() {
        return new ArrayList<>(activeRunners);
    }

    public void clearAllRunners() {
        runnerTabbedPane.removeAll();
        activeRunners.clear();
        runnerCounter.set(1);
        createNewRunner("Input Validation Runner 1");
    }

    public InputValidationRunnerPanel_littlespidy restoreRunner(String id, String name, List<InputValidationTestResult_littlespidy> results) {
        InputValidationRunnerPanel_littlespidy runner = createNewRunner(name);
        runner.setResults(results);
        return runner;
    }
}
