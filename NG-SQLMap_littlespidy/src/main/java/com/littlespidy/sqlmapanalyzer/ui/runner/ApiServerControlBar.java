// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.runner;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.sqlmapanalyzer.api.SqlmapApiClient;
import com.littlespidy.sqlmapanalyzer.api.SqlmapApiConfig;
import com.littlespidy.sqlmapanalyzer.api.SqlmapProcessManager;
import com.littlespidy.sqlmapanalyzer.util.OSUtils;
import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;

/**
 * Control bar for configuring, testing, and managing the SQLMap REST API server.
 * Plain ASCII text only.
 */
public class ApiServerControlBar extends JPanel {

    private final MontoyaApi api;
    private final SqlmapApiClient apiClient;
    private final SqlmapProcessManager processManager;
    private final SqlmapApiConfig config;

    private final JLabel targetEndpointLabel;
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
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));

        targetEndpointLabel = new JLabel("Target: " + config.getBaseUrl());
        targetEndpointLabel.setFont(targetEndpointLabel.getFont().deriveFont(Font.BOLD, 12));
        targetEndpointLabel.setForeground(new Color(40, 40, 40));
        leftPanel.add(targetEndpointLabel);

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

    private void updateTargetLabel() {
        targetEndpointLabel.setText("Target: " + config.getBaseUrl());
    }

    public void testApiConnection() {
        statusLabel.setText("API Status: Testing connection...");
        btnTest.setEnabled(false);

        SwingWorker<String, Void> worker = new SwingWorker<>() {
            @Override
            protected String doInBackground() {
                return apiClient.testConnectionDetails();
            }

            @Override
            protected void done() {
                btnTest.setEnabled(true);
                try {
                    String result = get();
                    if ("OK".equals(result)) {
                        statusLabel.setText("API Status: CONNECTED (" + config.getBaseUrl() + ")");
                        statusLabel.setForeground(new Color(0, 130, 0));
                    } else if (result != null && result.startsWith("401")) {
                        statusLabel.setText("API Status: " + result);
                        statusLabel.setForeground(Color.RED);
                    } else {
                        statusLabel.setText("API Status: DISCONNECTED (" + (result != null ? result : "Unreachable") + ")");
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
                        statusLabel.setText("API Status: LOCAL SERVER RUNNING (" + config.getBaseUrl() + ")");
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
        JDialog dialog = new JDialog(owner, "SQLMap API Settings", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(620, 360);
        dialog.setLocationRelativeTo(owner);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(new EmptyBorder(10, 12, 10, 12));

        // 1. Connection Panel (Host and Port)
        JPanel connPanel = new JPanel(new GridBagLayout());
        connPanel.setBorder(BorderFactory.createTitledBorder("API Server Connection"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0; gbc.gridy = 0;
        connPanel.add(new JLabel("API Host:"), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        JTextField txtHost = new JTextField(config.getHost(), 14);
        connPanel.add(txtHost, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0;
        connPanel.add(new JLabel("API Port:"), gbc);
        gbc.gridx = 3; gbc.gridy = 0; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.5;
        JTextField txtPort = new JTextField(String.valueOf(config.getPort()), 6);
        connPanel.add(txtPort, gbc);

        mainPanel.add(connPanel);
        mainPanel.add(Box.createVerticalStrut(6));

        // 2. Authentication Panel (Username and Password)
        JPanel authPanel = new JPanel(new GridBagLayout());
        authPanel.setBorder(BorderFactory.createTitledBorder("REST API Authentication (Mandatory in modern SQLMap)"));

        gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0; gbc.gridy = 0;
        authPanel.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        JTextField txtUser = new JTextField(config.getUsername(), 14);
        authPanel.add(txtUser, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0;
        authPanel.add(new JLabel("Password:"), gbc);
        gbc.gridx = 3; gbc.gridy = 0; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        JTextField txtPass = new JTextField(config.getPassword(), 14);
        authPanel.add(txtPass, gbc);

        mainPanel.add(authPanel);
        mainPanel.add(Box.createVerticalStrut(6));

        // 3. Local Server Process Settings Panel
        JPanel execPanel = new JPanel(new GridBagLayout());
        execPanel.setBorder(BorderFactory.createTitledBorder("Local Server Execution"));

        gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.anchor = GridBagConstraints.WEST;

        // Python Binary row
        gbc.gridx = 0; gbc.gridy = 0;
        execPanel.add(new JLabel("Python Binary:"), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        JTextField txtPython = new JTextField(config.getPythonPath());
        execPanel.add(txtPython, gbc);
        gbc.gridx = 2; gbc.gridy = 0; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0;
        JButton btnBrowsePython = SwingUtils.createStyledButton("Browse...");
        btnBrowsePython.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Select Python Executable");
            chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            if (chooser.showOpenDialog(dialog) == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
                txtPython.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });
        execPanel.add(btnBrowsePython, gbc);

        // sqlmapapi.py Script Path row
        gbc.gridx = 0; gbc.gridy = 1;
        execPanel.add(new JLabel("sqlmapapi.py Path:"), gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        JTextField txtScript = new JTextField(config.getApiScriptPath());
        execPanel.add(txtScript, gbc);

        JPanel scriptBtnBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        JButton btnBrowseScript = SwingUtils.createStyledButton("Browse...");
        btnBrowseScript.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Select sqlmapapi.py");
            chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            chooser.setFileFilter(new FileNameExtensionFilter("Python Scripts (*.py)", "py"));
            if (chooser.showOpenDialog(dialog) == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
                txtScript.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });
        scriptBtnBox.add(btnBrowseScript);

        JButton btnAutoDetect = SwingUtils.createStyledButton("Auto-Detect");
        btnAutoDetect.addActionListener(e -> {
            String detected = OSUtils.findSqlmapApiPath();
            if (detected != null && !detected.isBlank()) {
                txtScript.setText(detected);
                if (txtPython.getText().trim().isBlank()) {
                    txtPython.setText(OSUtils.getDefaultPythonBinary());
                }
                JOptionPane.showMessageDialog(dialog, "Discovered sqlmapapi.py at:\n" + detected, "Auto-Detect Success", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(dialog, "Could not automatically locate sqlmapapi.py.\nPlease browse or enter the path manually (e.g. site-packages\\sqlmap\\sqlmapapi.py).", "Auto-Detect", JOptionPane.WARNING_MESSAGE);
            }
        });
        scriptBtnBox.add(btnAutoDetect);

        gbc.gridx = 2; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0;
        execPanel.add(scriptBtnBox, gbc);

        mainPanel.add(execPanel);

        dialog.add(mainPanel, BorderLayout.CENTER);

        // Bottom action buttons
        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        JButton btnSave = SwingUtils.createStyledButton("Save");
        btnSave.setFont(btnSave.getFont().deriveFont(Font.BOLD));
        btnSave.addActionListener(e -> {
            int portNum;
            try {
                portNum = Integer.parseInt(txtPort.getText().trim());
                if (portNum <= 0 || portNum > 65535) throw new NumberFormatException();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(dialog, "Invalid port number. Please enter a value between 1 and 65535.", "Validation Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            config.setHost(txtHost.getText().trim());
            config.setPort(portNum);
            config.setUsername(txtUser.getText().trim());
            config.setPassword(txtPass.getText().trim());
            config.setPythonPath(txtPython.getText().trim());
            config.setApiScriptPath(txtScript.getText().trim());

            if (api != null) {
                config.savePreferences(api);
            }
            updateTargetLabel();
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
