// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.inputvalidation;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;

import com.protect7.authanalyzer.entities.CustomHttpRequestResponse_littlespidy;
import com.protect7.authanalyzer.entities.CustomHttpService_littlespidy;
import com.protect7.authanalyzer.gui.main.MainPanel;
import com.protect7.authanalyzer.inputvalidation.InputValidationTestResult_littlespidy;

/**
 * Suite tab for uploading and reviewing previously exported Input Validation fuzzing datasets.
 */
public class InputValidationImportPanel_littlespidy extends InputValidationHistoryPanel_littlespidy {

    private static final long serialVersionUID = 1L;

    public InputValidationImportPanel_littlespidy(MainPanel mainPanel) {
        super(mainPanel);
    }

    @Override
    protected void initActionsPanel() {
        JButton uploadButton = new JButton("Upload Input Validation Data");
        uploadButton.addActionListener(e -> uploadDataPressed());
        clearTableButton.addActionListener(e -> clearTable());

        topActionsPanel.add(uploadButton);
        topActionsPanel.add(clearTableButton);
    }

    private void uploadDataPressed() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Upload Input Validation Data (CSV)");
        chooser.setFileFilter(new FileNameExtensionFilter("CSV Data (*.csv)", "csv"));
        int res = chooser.showOpenDialog(this);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            loadDataFile(chooser.getSelectedFile());
        }
    }

    public void loadDataFile(File file) {
        try {
            List<InputValidationTestResult_littlespidy> imported = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
                String line;
                boolean first = true;
                while ((line = reader.readLine()) != null) {
                    if (first) {
                        first = false;
                        if (line.toLowerCase().contains("id") && line.toLowerCase().contains("parameter")) {
                            continue;
                        }
                    }
                    String[] parts = line.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
                    if (parts.length >= 13) {
                        int id = Integer.parseInt(parts[0].trim().replace("\"", ""));
                        String category = parts[1].trim().replace("\"", "");
                        String method = parts[2].trim().replace("\"", "");
                        String host = parts[3].trim().replace("\"", "");
                        String path = parts[4].trim().replace("\"", "");
                        String parameter = parts[5].trim().replace("\"", "");
                        String type = parts[6].trim().replace("\"", "");
                        String payload = parts[7].trim().replace("\"", "");
                        int baseStatus = Integer.parseInt(parts[8].trim().replace("\"", ""));
                        int status = Integer.parseInt(parts[9].trim().replace("\"", ""));
                        int baseLen = Integer.parseInt(parts[10].trim().replace("\"", ""));
                        int length = Integer.parseInt(parts[11].trim().replace("\"", ""));
                        int diffPercent = Integer.parseInt(parts[12].trim().replace("\"", ""));
                        String anomaly = parts.length > 13 ? parts[13].trim().replace("\"", "") : "Clean";
                        String evidence = parts.length > 14 ? parts[14].trim().replace("\"", "") : "";

                        CustomHttpService_littlespidy svc = new CustomHttpService_littlespidy(host, 443, "https");
                        byte[] req = (method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n[" + parameter + "=" + payload + "]").getBytes(StandardCharsets.UTF_8);
                        byte[] resp = ("HTTP/1.1 " + status + " Response\r\nContent-Length: " + length + "\r\n\r\n" + evidence).getBytes(StandardCharsets.UTF_8);
                        CustomHttpRequestResponse_littlespidy msg = new CustomHttpRequestResponse_littlespidy(req, resp, svc);

                        imported.add(new InputValidationTestResult_littlespidy(
                                id, category, method, host, path, parameter, type,
                                payload, payload, baseStatus, status, baseLen, length,
                                diffPercent, anomaly, evidence, msg, msg
                        ));
                    }
                }
            }

            if (!imported.isEmpty()) {
                tableModel.addResults(imported);
                List<String> hosts = new ArrayList<>();
                for (InputValidationTestResult_littlespidy r : imported) {
                    hosts.add(r.getHost());
                }
                domainFilterDropDown.updateDomains(hosts);
                JOptionPane.showMessageDialog(this, "Loaded " + imported.size() + " test results successfully.", "Import Complete", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "No valid records found in the selected file.", "Import Notice", JOptionPane.WARNING_MESSAGE);
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error importing file: " + ex.getMessage(), "Import Failed", JOptionPane.ERROR_MESSAGE);
        }
    }
}
