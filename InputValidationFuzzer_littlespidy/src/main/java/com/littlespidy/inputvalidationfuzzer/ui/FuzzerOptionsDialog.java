package com.littlespidy.inputvalidationfuzzer.ui;

import com.littlespidy.inputvalidationfuzzer.model.FuzzPayload;
import com.littlespidy.inputvalidationfuzzer.model.FuzzerConfig;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Options and settings dialog allowing customization of fuzz payloads,
 * error detection signatures, parameter scoping, concurrency, and anomaly thresholds.
 *
 * @author littlespidy
 */
public class FuzzerOptionsDialog extends JDialog {
    private final FuzzerConfig config;

    public FuzzerOptionsDialog(Frame owner, FuzzerConfig config) {
        super(owner, "Input Validation Fuzzer Options", true);
        this.config = config;

        setLayout(new BorderLayout(10, 10));
        setSize(700, 550);
        setLocationRelativeTo(owner);

        JTabbedPane tabbedPane = new JTabbedPane();

        // ── Tab 1: Scope & Execution ──
        JPanel generalPanel = new JPanel();
        generalPanel.setLayout(new BoxLayout(generalPanel, BoxLayout.Y_AXIS));
        generalPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel scopeGroup = new JPanel(new GridLayout(0, 2, 8, 8));
        scopeGroup.setBorder(new TitledBorder("Parameter Scope"));
        JCheckBox urlCb = new JCheckBox("URL Query Parameters", config.isFuzzUrlParams());
        JCheckBox bodyCb = new JCheckBox("Body Parameters (Form/URL-encoded)", config.isFuzzBodyParams());
        JCheckBox cookieCb = new JCheckBox("Cookie Parameters", config.isFuzzCookieParams());
        JCheckBox jsonCb = new JCheckBox("JSON Parameters", config.isFuzzJsonParams());
        JCheckBox xmlCb = new JCheckBox("XML Parameters & Attributes", config.isFuzzXmlParams());
        JCheckBox multiCb = new JCheckBox("Multipart Attributes", config.isFuzzMultipartParams());

        scopeGroup.add(urlCb);
        scopeGroup.add(bodyCb);
        scopeGroup.add(cookieCb);
        scopeGroup.add(jsonCb);
        scopeGroup.add(xmlCb);
        scopeGroup.add(multiCb);
        generalPanel.add(scopeGroup);
        generalPanel.add(Box.createVerticalStrut(10));

        JPanel perfGroup = new JPanel(new GridLayout(0, 2, 8, 8));
        perfGroup.setBorder(new TitledBorder("Performance & Detection"));
        JSpinner threadsSpinner = new JSpinner(new SpinnerNumberModel(config.getMaxConcurrentThreads(), 1, 50, 1));
        JSpinner delaySpinner = new JSpinner(new SpinnerNumberModel(config.getDelayBetweenRequestsMs(), 0, 10000, 50));
        JSpinner sizeDiffSpinner = new JSpinner(new SpinnerNumberModel(config.getSizeDiffPercent(), 100, 2000, 50));

        perfGroup.add(new JLabel("Max Concurrent Threads:"));
        perfGroup.add(threadsSpinner);
        perfGroup.add(new JLabel("Delay Between Requests (ms):"));
        perfGroup.add(delaySpinner);
        perfGroup.add(new JLabel("Size Anomaly Threshold (%):"));
        perfGroup.add(sizeDiffSpinner);
        generalPanel.add(perfGroup);

        tabbedPane.addTab("General & Scope", generalPanel);

        // ── Tab 2: Payloads ──
        JPanel payloadPanel = new JPanel(new BorderLayout(5, 5));
        payloadPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        DefaultTableModel payloadTableModel = new DefaultTableModel(new String[]{"Name", "Value", "Detail"}, 0);
        for (FuzzPayload p : config.getPayloads()) {
            payloadTableModel.addRow(new Object[]{p.name(), p.value(), p.detail()});
        }
        JTable payloadTable = new JTable(payloadTableModel);
        payloadPanel.add(new JScrollPane(payloadTable), BorderLayout.CENTER);

        JPanel payloadButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addPayloadBtn = new JButton("Add Payload");
        addPayloadBtn.addActionListener(e -> payloadTableModel.addRow(new Object[]{"Custom Payload", "fuzz_val", "Custom test"}));
        JButton removePayloadBtn = new JButton("Remove Selected");
        removePayloadBtn.addActionListener(e -> {
            int row = payloadTable.getSelectedRow();
            if (row >= 0) payloadTableModel.removeRow(row);
        });
        payloadButtons.add(addPayloadBtn);
        payloadButtons.add(removePayloadBtn);
        payloadPanel.add(payloadButtons, BorderLayout.SOUTH);

        tabbedPane.addTab("Fuzz Payloads", payloadPanel);

        // ── Tab 3: Error Signatures ──
        JPanel sigPanel = new JPanel(new BorderLayout(5, 5));
        sigPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JTextArea sigTextArea = new JTextArea(String.join("\n", config.getErrorSignatures()));
        sigPanel.add(new JLabel("Enter error signatures to detect in response bodies (one per line):"), BorderLayout.NORTH);
        sigPanel.add(new JScrollPane(sigTextArea), BorderLayout.CENTER);

        tabbedPane.addTab("Error Signatures", sigPanel);

        add(tabbedPane, BorderLayout.CENTER);

        // ── Bottom Action Buttons ──
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveBtn = new JButton("Save & Apply");
        saveBtn.addActionListener(e -> {
            config.setFuzzUrlParams(urlCb.isSelected());
            config.setFuzzBodyParams(bodyCb.isSelected());
            config.setFuzzCookieParams(cookieCb.isSelected());
            config.setFuzzJsonParams(jsonCb.isSelected());
            config.setFuzzXmlParams(xmlCb.isSelected());
            config.setFuzzMultipartParams(multiCb.isSelected());

            config.setMaxConcurrentThreads((Integer) threadsSpinner.getValue());
            config.setDelayBetweenRequestsMs((Integer) delaySpinner.getValue());
            config.setSizeDiffPercent((Integer) sizeDiffSpinner.getValue());

            List<FuzzPayload> newPayloads = new ArrayList<>();
            for (int r = 0; r < payloadTableModel.getRowCount(); r++) {
                String name = String.valueOf(payloadTableModel.getValueAt(r, 0));
                String val = String.valueOf(payloadTableModel.getValueAt(r, 1));
                String det = String.valueOf(payloadTableModel.getValueAt(r, 2));
                newPayloads.add(new FuzzPayload(name, val, det));
            }
            config.setPayloads(newPayloads);

            List<String> newSigs = new ArrayList<>();
            for (String line : sigTextArea.getText().split("\n")) {
                if (!line.trim().isEmpty()) {
                    newSigs.add(line.trim());
                }
            }
            config.setErrorSignatures(newSigs);

            dispose();
        });

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        actionPanel.add(saveBtn);
        actionPanel.add(cancelBtn);
        add(actionPanel, BorderLayout.SOUTH);
    }
}
