// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.ui;

import com.littlespidy.wayback.config.CommonConfig_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

public class ConfigurationTab_littlespidy extends JPanel {

    private final CommonConfig_littlespidy config;
    private final Runnable onConfigSaved;

    private final DefaultListModel<String> signatureListModel = new DefaultListModel<>();
    private final JList<String> signatureList = new JList<>(signatureListModel);

    private final JTextField userAgentField = new JTextField();
    private final JTextField cdxTemplateField = new JTextField();
    private final JSpinner retriesSpinner = new JSpinner(new SpinnerNumberModel(3, 1, 10, 1));
    private final JSpinner backoffSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 60, 1));
    private final JCheckBox testBothProtocolsChk = new JCheckBox("Test both HTTP and HTTPS protocols for each path");
    private final JCheckBox honorProxyChk = new JCheckBox("Honor Burp Suite upstream proxies and SOCKS settings");

    public ConfigurationTab_littlespidy(CommonConfig_littlespidy config, Runnable onConfigSaved) {
        super(new BorderLayout(8, 8));
        this.config = config != null ? config : new CommonConfig_littlespidy();
        this.onConfigSaved = onConfigSaved;
        initUI();
        loadFromConfig();
    }

    private void initUI() {
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel gridPanel = new JPanel(new GridLayout(1, 2, 12, 12));

        // Left Card: Signatures
        JPanel sigCard = new JPanel(new BorderLayout(6, 6));
        sigCard.setBorder(BorderFactory.createTitledBorder("Directory Listing Detection Signatures (Common)"));

        JLabel sigHelp = new JLabel("<html>Responses containing any of these substrings when returning HTTP 200<br>will be flagged as open directory listings across all scans.</html>");
        sigHelp.setFont(sigHelp.getFont().deriveFont(11f));
        sigHelp.setForeground(Color.GRAY);
        sigCard.add(sigHelp, BorderLayout.NORTH);

        signatureList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        signatureList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        sigCard.add(new JScrollPane(signatureList), BorderLayout.CENTER);

        JPanel sigControls = new JPanel(new BorderLayout(4, 4));
        JPanel inputRow = new JPanel(new BorderLayout(4, 4));
        JTextField newSigInput = new JTextField();
        newSigInput.putClientProperty("JTextField.placeholderText", "New signature pattern");
        JButton addSigBtn = new JButton("Add");
        addSigBtn.addActionListener(e -> {
            String val = newSigInput.getText().trim();
            if (!val.isEmpty() && !signatureListModel.contains(val)) {
                signatureListModel.addElement(val);
                newSigInput.setText("");
            }
        });
        inputRow.add(newSigInput, BorderLayout.CENTER);
        inputRow.add(addSigBtn, BorderLayout.EAST);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        JButton removeSigBtn = new JButton("Remove Selected");
        removeSigBtn.addActionListener(e -> {
            int idx = signatureList.getSelectedIndex();
            if (idx != -1) {
                signatureListModel.remove(idx);
            }
        });

        JButton resetSigBtn = new JButton("Reset Defaults");
        resetSigBtn.addActionListener(e -> {
            signatureListModel.clear();
            for (String s : CommonConfig_littlespidy.DEFAULT_SIGNATURES) {
                signatureListModel.addElement(s);
            }
        });

        btnRow.add(removeSigBtn);
        btnRow.add(resetSigBtn);

        sigControls.add(inputRow, BorderLayout.NORTH);
        sigControls.add(btnRow, BorderLayout.SOUTH);
        sigCard.add(sigControls, BorderLayout.SOUTH);

        // Right Card: CDX and HTTP Settings
        JPanel netCard = new JPanel();
        netCard.setLayout(new BoxLayout(netCard, BoxLayout.Y_AXIS));
        netCard.setBorder(BorderFactory.createTitledBorder("Wayback CDX & HTTP Settings (Common)"));

        netCard.add(new JLabel("Wayback Machine CDX API URL Template:"));
        netCard.add(Box.createVerticalStrut(2));
        cdxTemplateField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        netCard.add(cdxTemplateField);
        netCard.add(Box.createVerticalStrut(10));

        netCard.add(new JLabel("Standard Browser User-Agent:"));
        netCard.add(Box.createVerticalStrut(2));
        userAgentField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        netCard.add(userAgentField);
        JLabel uaNote = new JLabel("Standard realistic browser User-Agent header (no custom tool signature).");
        uaNote.setFont(uaNote.getFont().deriveFont(10.5f));
        uaNote.setForeground(Color.GRAY);
        netCard.add(uaNote);
        netCard.add(Box.createVerticalStrut(10));

        JPanel retryRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        retryRow.add(new JLabel("CDX Retries:"));
        retryRow.add(retriesSpinner);
        retryRow.add(new JLabel("Retry Backoff (s):"));
        retryRow.add(backoffSpinner);
        retryRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        netCard.add(retryRow);
        netCard.add(Box.createVerticalStrut(10));

        netCard.add(testBothProtocolsChk);
        netCard.add(Box.createVerticalStrut(4));
        netCard.add(honorProxyChk);
        netCard.add(Box.createVerticalGlue());

        JButton saveBtn = new JButton("Save Configuration");
        saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD, 12f));
        saveBtn.addActionListener(e -> saveToConfig());
        JPanel savePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        savePanel.add(saveBtn);
        netCard.add(savePanel);

        gridPanel.add(sigCard);
        gridPanel.add(netCard);

        add(gridPanel, BorderLayout.CENTER);
    }

    private void loadFromConfig() {
        signatureListModel.clear();
        for (String s : config.getSignatures()) {
            signatureListModel.addElement(s);
        }
        userAgentField.setText(config.getUserAgent());
        cdxTemplateField.setText(config.getCdxUrlTemplate());
        retriesSpinner.setValue(config.getCdxRetries());
        backoffSpinner.setValue(config.getCdxRetryDelaySec());
        testBothProtocolsChk.setSelected(config.isTestBothHttpHttps());
        honorProxyChk.setSelected(config.isHonorBurpProxy());
    }

    private void saveToConfig() {
        java.util.List<String> sigs = new ArrayList<>();
        for (int i = 0; i < signatureListModel.size(); i++) {
            sigs.add(signatureListModel.get(i));
        }
        config.setSignatures(sigs);
        config.setUserAgent(userAgentField.getText().trim());
        config.setCdxUrlTemplate(cdxTemplateField.getText().trim());
        config.setCdxRetries((Integer) retriesSpinner.getValue());
        config.setCdxRetryDelaySec((Integer) backoffSpinner.getValue());
        config.setTestBothHttpHttps(testBothProtocolsChk.isSelected());
        config.setHonorBurpProxy(honorProxyChk.isSelected());

        if (onConfigSaved != null) {
            onConfigSaved.run();
        }
        JOptionPane.showMessageDialog(this, "Configuration updated successfully.", "Saved", JOptionPane.INFORMATION_MESSAGE);
    }
}
