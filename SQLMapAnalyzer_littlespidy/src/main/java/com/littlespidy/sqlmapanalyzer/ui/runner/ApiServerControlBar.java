// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.runner;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.sqlmapanalyzer.api.SqlmapApiClient;
import com.littlespidy.sqlmapanalyzer.api.SqlmapApiConfig;
import com.littlespidy.sqlmapanalyzer.api.SqlmapProcessManager;
import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Control bar for configuring, testing, and managing the SQLMap REST API server.
 * Plain ASCII text only.
 */
public class ApiServerControlBar extends JPanel {

    private final MontoyaApi api;
    private final SqlmapApiClient apiClient;
    private final SqlmapProcessManager processManager;
    private final SqlmapApiConfig config;

    private final JTextField hostField;
    private final JTextField portField;
    private final JButton btnTest;
    private final JButton btnStartLocal;
    private final JButton btnStopLocal;
    private final JButton btnSettings;
    private final JLabel statusLabel;

    public ApiServerControlBar(MontoyaApi api, SqlmapApiClient apiClient, SqlmapProcessManager processManager) {
        this.api = api;
        this.apiClient = apiClient;
        this.processManager = processManager;
        this.config = apiClient.getConfig();
        if (api != null) {
            config.loadPreferences(api);
        }

        setLayout(new BorderLayout(10, 0));
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                new EmptyBorder(6, 10, 6, 10)
        ));

        // Left controls
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));

        leftPanel.add(SwingUtils.createBoldLabel("API Host:"));
        hostField = new JTextField(config.getHost(), 10);
        leftPanel.add(hostField);

        leftPanel.add(SwingUtils.createBoldLabel("Port:"));
        portField = new JTextField(String.valueOf(config.getPort()), 5);
        leftPanel.add(portField);

        btnTest = SwingUtils.createStyledButton("Test Connection");
        btnTest.addActionListener(e -> testApiConnection());
        leftPanel.add(btnTest);

        btnStartLocal = SwingUtils.createStyledButton("Start Local API");
        btnStartLocal.addActionListener(e -> startLocalApi());
        leftPanel.add(btnStartLocal);

        btnStopLocal = SwingUtils.createStyledButton("Stop Local API");
        btnStopLocal.setEnabled(false);
        btnStopLocal.addActionListener(e -> stopLocalApi());
        leftPanel.add(btnStopLocal);

        btnSettings = SwingUtils.createStyledButton("API Settings...");
        btnSettings.addActionListener(e -> openSettingsDialog());
        leftPanel.add(btnSettings);

        add(leftPanel, BorderLayout.WEST);

        // Right status indicator
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        statusLabel = new JLabel("API Status: UNCHECKED");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 11));
        rightPanel.add(statusLabel);
        add(rightPanel, BorderLayout.EAST);
    }

    private void syncFieldsToConfig() {
        config.setHost(hostField.getText().trim());
        try {
            config.setPort(Integer.parseInt(portField.getText().trim()));
        } catch (Exception ignored) {}
        if (api != null) {
            config.savePreferences(api);
        }
    }

    public void testApiConnection() {
        syncFieldsToConfig();
        statusLabel.setText("API Status: Testing connection...");
        btnTest.setEnabled(false);

        SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
            @Override
            protected Boolean doInBackground() {
                return apiClient.testConnection();
            }

            @Override
            protected void done() {
                btnTest.setEnabled(true);
                try {
                    boolean ok = get();
                    if (ok) {
                        statusLabel.setText("API Status: CONNECTED (" + config.getBaseUrl() + ")");
                        statusLabel.setForeground(new Color(0, 130, 0));
                    } else {
                        statusLabel.setText("API Status: DISCONNECTED (Unreachable at " + config.getBaseUrl() + ")");
                        statusLabel.setForeground(Color.RED);
                    }
                } catch (Exception e) {
                    statusLabel.setText("API Status: ERROR (" + e.getMessage() + ")");
                    statusLabel.setForeground(Color.RED);
                }
            }
        };
        worker.execute();
    }

    private void startLocalApi() {
        syncFieldsToConfig();
        btnStartLocal.setEnabled(false);
        statusLabel.setText("API Status: Spawning local server...");

        SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
            @Override
            protected Boolean doInBackground() {
                return processManager.startServer(config, msg -> {
                    if (api != null && api.logging() != null) {
                        api.logging().logToOutput(msg);
                    }
                });
            }

            @Override
            protected void done() {
                try {
                    boolean started = get();
                    if (started && processManager.isServerRunning()) {
                        statusLabel.setText("API Status: LOCAL SERVER RUNNING (PID active on " + config.getBaseUrl() + ")");
                        statusLabel.setForeground(new Color(0, 130, 0));
                        btnStopLocal.setEnabled(true);
                        testApiConnection();
                    } else {
                        statusLabel.setText("API Status: FAILED TO START LOCAL SERVER");
                        statusLabel.setForeground(Color.RED);
                        btnStartLocal.setEnabled(true);
                    }
                } catch (Exception e) {
                    statusLabel.setText("API Status: ERROR starting process: " + e.getMessage());
                    statusLabel.setForeground(Color.RED);
                    btnStartLocal.setEnabled(true);
                }
            }
        };
        worker.execute();
    }

    private void stopLocalApi() {
        processManager.stopServer();
        btnStopLocal.setEnabled(false);
        btnStartLocal.setEnabled(true);
        statusLabel.setText("API Status: LOCAL SERVER STOPPED");
        statusLabel.setForeground(Color.DARK_GRAY);
    }

    private void openSettingsDialog() {
        Window owner = SwingUtilities.getWindowAncestor(this);
        JDialog dialog = new JDialog(owner, "SQLMap API Server Settings", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(520, 240);
        dialog.setLocationRelativeTo(owner);

        JPanel form = new JPanel(new GridLayout(4, 2, 8, 8));
        form.setBorder(new EmptyBorder(15, 15, 15, 15));

        JTextField txtPython = new JTextField(config.getPythonPath());
        JTextField txtScript = new JTextField(config.getApiScriptPath());

        form.add(new JLabel("Python Binary (python / python3):"));
        form.add(txtPython);
        form.add(new JLabel("sqlmapapi.py Script Path:"));
        form.add(txtScript);
        form.add(new JLabel("Default Host:"));
        form.add(new JLabel(config.getHost()));
        form.add(new JLabel("Default Port:"));
        form.add(new JLabel(String.valueOf(config.getPort())));

        dialog.add(form, BorderLayout.CENTER);

        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 8));
        JButton btnSave = SwingUtils.createStyledButton("Save");
        btnSave.addActionListener(e -> {
            config.setPythonPath(txtPython.getText().trim());
            config.setApiScriptPath(txtScript.getText().trim());
            if (api != null) {
                config.savePreferences(api);
            }
            dialog.dispose();
        });
        JButton btnCancel = SwingUtils.createStyledButton("Cancel");
        btnCancel.addActionListener(e -> dialog.dispose());

        btnBar.add(btnSave);
        btnBar.add(btnCancel);
        dialog.add(btnBar, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }
}
