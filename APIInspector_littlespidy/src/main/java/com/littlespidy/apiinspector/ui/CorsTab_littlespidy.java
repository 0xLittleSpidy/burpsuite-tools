// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.apiinspector.engine.CorsEngine_littlespidy;
import com.littlespidy.apiinspector.engine.CorsProgressListener_littlespidy;
import com.littlespidy.apiinspector.model.CorsTechnique_littlespidy;
import com.littlespidy.apiinspector.model.CorsTestResult_littlespidy;
import com.littlespidy.apiinspector.model.EndpointSelectionItem_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Root Suite Tab for CORS Analysis and Testing.
 * Hosts closable CORS runner session tabs, each with a results table
 * and 50/50 parallel side-by-side Montoya Request and Response editors.
 */
public class CorsTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final CorsEngine_littlespidy corsEngine;
    private final JTabbedPane runnerTabbedPane = new JTabbedPane();
    private final List<CorsRunnerPanel_littlespidy> activeRunners = new ArrayList<>();
    private final AtomicInteger runnerCounter = new AtomicInteger(1);

    public CorsTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        this.corsEngine = new CorsEngine_littlespidy(api);

        initComponents();
    }

    private void initComponents() {
        // Initial default runner
        createNewRunner("CORS Runner 1");
        add(runnerTabbedPane, BorderLayout.CENTER);
    }

    public CorsRunnerPanel_littlespidy createNewRunner(String runnerName) {
        String id = "cors_runner_" + runnerCounter.getAndIncrement();
        String name = (runnerName != null && !runnerName.isBlank()) ? runnerName : "CORS Runner " + runnerCounter.get();

        CorsRunnerPanel_littlespidy panel = new CorsRunnerPanel_littlespidy(api, id, name);
        activeRunners.add(panel);

        int index = runnerTabbedPane.getTabCount();
        runnerTabbedPane.addTab(name, panel);
        setupTabHeader(runnerTabbedPane, panel, name);
        runnerTabbedPane.setSelectedComponent(panel);

        return panel;
    }

    private void setupTabHeader(JTabbedPane tabbedPane, CorsRunnerPanel_littlespidy panel, String title) {
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
            String targetBaseUrl,
            String attackerDomain,
            List<CorsTechnique_littlespidy> techniques,
            int threads,
            int delayMs,
            String runnerName) {

        CorsRunnerPanel_littlespidy runner = createNewRunner(runnerName);

        corsEngine.executeEndpointsTestsAsync(
                endpoints,
                targetBaseUrl,
                attackerDomain,
                techniques,
                threads,
                delayMs,
                new CorsProgressListener_littlespidy() {
                    @Override
                    public void onCorsTestCompleted(CorsTestResult_littlespidy result) {
                        runner.addResult(result);
                    }

                    @Override
                    public void onStatusUpdate(String statusMessage, int current, int total) {
                        runner.updateStatusText("Status: " + statusMessage);
                    }

                    @Override
                    public void onAllTestsCompleted() {
                        runner.updateStatusText("Status: Completed all CORS tests");
                    }
                }
        );
    }

    public void executeAttack(
            HttpRequest targetRequest,
            String targetBaseUrl,
            String attackerDomain,
            List<CorsTechnique_littlespidy> techniques,
            int threads,
            int delayMs,
            String runnerName) {

        CorsRunnerPanel_littlespidy runner = createNewRunner(runnerName);

        corsEngine.executeTestsAsync(
                targetRequest,
                targetBaseUrl,
                attackerDomain,
                techniques,
                threads,
                delayMs,
                new CorsProgressListener_littlespidy() {
                    @Override
                    public void onCorsTestCompleted(CorsTestResult_littlespidy result) {
                        runner.addResult(result);
                    }

                    @Override
                    public void onStatusUpdate(String statusMessage, int current, int total) {
                        runner.updateStatusText("Status: " + statusMessage);
                    }

                    @Override
                    public void onAllTestsCompleted() {
                        runner.updateStatusText("Status: Completed all CORS tests");
                    }
                }
        );
    }

    public void sendToCors(HttpRequest request, HttpResponse response) {
        if (request == null) return;
        String host = request.httpService() != null ? request.httpService().host() : "target";
        String runnerName = "CORS - " + host;
        CorsRunnerPanel_littlespidy runner = createNewRunner(runnerName);

        // Run default 29 techniques against this request
        List<CorsTechnique_littlespidy> techs = CorsTechnique_littlespidy.getDefaultTechniques();
        String targetUrl = request.url();
        String attacker = "evil.com";

        corsEngine.executeTestsAsync(
                request,
                targetUrl,
                attacker,
                techs,
                4,
                50,
                new CorsProgressListener_littlespidy() {
                    @Override
                    public void onCorsTestCompleted(CorsTestResult_littlespidy result) {
                        runner.addResult(result);
                    }

                    @Override
                    public void onStatusUpdate(String statusMessage, int current, int total) {
                        runner.updateStatusText("Status: " + statusMessage);
                    }

                    @Override
                    public void onAllTestsCompleted() {
                        runner.updateStatusText("Status: Completed all CORS tests");
                    }
                }
        );
    }

    public List<CorsRunnerPanel_littlespidy> getActiveRunners() {
        return new ArrayList<>(activeRunners);
    }

    public void clearAllRunners() {
        runnerTabbedPane.removeAll();
        activeRunners.clear();
        runnerCounter.set(1);
        createNewRunner("CORS Runner 1");
    }

    public CorsRunnerPanel_littlespidy restoreRunner(String id, String name, List<CorsTestResult_littlespidy> results) {
        CorsRunnerPanel_littlespidy runner = createNewRunner(name);
        runner.setResults(results);
        return runner;
    }
}
