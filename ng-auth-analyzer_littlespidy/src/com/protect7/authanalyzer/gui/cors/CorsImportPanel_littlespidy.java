// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.cors;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import com.protect7.authanalyzer.cors.CorsTestResult_littlespidy;
import com.protect7.authanalyzer.cors.CorsTestResult_littlespidy.CorsSeverity;
import com.protect7.authanalyzer.entities.CustomHttpRequestResponse_littlespidy;
import com.protect7.authanalyzer.entities.CustomHttpService_littlespidy;
import com.protect7.authanalyzer.gui.main.MainPanel;

public class CorsImportPanel_littlespidy extends CorsHistoryPanel_littlespidy {

	private static final long serialVersionUID = 1L;

	public CorsImportPanel_littlespidy(MainPanel mainPanel) {
		super(mainPanel);
		optionsRow.setVisible(false);
	}

	@Override
	protected void initActionsPanel() {
		JButton uploadButton = new JButton("Upload CORS Data");
		uploadButton.addActionListener(e -> uploadDataPressed());
		clearTableButton.addActionListener(e -> clearTable());

		topActionsPanel.add(uploadButton);
		topActionsPanel.add(clearTableButton);
	}

	private void uploadDataPressed() {
		JFileChooser chooser = new JFileChooser();
		chooser.setDialogTitle("Upload CORS Test Data (CSV/XML)");
		chooser.setFileFilter(new FileNameExtensionFilter("Data Files (*.csv, *.xml)", "csv", "xml"));
		int res = chooser.showOpenDialog(this);
		if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
			loadDataFile(chooser.getSelectedFile());
		}
	}

	public void loadDataFile(File file) {
		try {
			List<CorsTestResult_littlespidy> imported = new ArrayList<CorsTestResult_littlespidy>();
			Set<String> domains = new HashSet<String>();

			try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
				String line;
				boolean first = true;
				while ((line = reader.readLine()) != null) {
					if (first) {
						first = false;
						if (line.toLowerCase().contains("id,method")) {
							continue;
						}
					}
					String[] parts = line.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
					if (parts.length >= 10) {
						int id = Integer.parseInt(parts[0].trim().replace("\"", ""));
						String method = parts[1].trim().replace("\"", "");
						String host = parts[2].trim().replace("\"", "");
						String path = parts[3].trim().replace("\"", "");
						String testVector = parts[4].trim().replace("\"", "");
						String testedOrigin = parts[5].trim().replace("\"", "");
						String reflectedAcao = parts[6].trim().replace("\"", "");
						boolean acac = Boolean.parseBoolean(parts[7].trim().replace("\"", ""));
						int status = Integer.parseInt(parts[8].trim().replace("\"", ""));
						int length = Integer.parseInt(parts[9].trim().replace("\"", ""));
						CorsSeverity severity = CorsSeverity.SECURE;
						if (parts.length > 10) {
							try {
								severity = CorsSeverity.valueOf(parts[10].trim().replace("\"", ""));
							} catch (Exception ignored) {}
						}
						CustomHttpService_littlespidy svc = new CustomHttpService_littlespidy(host, 443, "https");
						CustomHttpRequestResponse_littlespidy msg = new CustomHttpRequestResponse_littlespidy(
								(method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\nOrigin: " + testedOrigin + "\r\n\r\n").getBytes(StandardCharsets.UTF_8),
								("HTTP/1.1 " + status + " OK\r\nAccess-Control-Allow-Origin: " + reflectedAcao + "\r\n\r\n").getBytes(StandardCharsets.UTF_8),
								svc);
						CorsTestResult_littlespidy r = new CorsTestResult_littlespidy(id, method, host, path, testedOrigin,
								testVector, reflectedAcao, acac, status, length, severity, msg);
						imported.add(r);
						domains.add(host);
					}
				}
			}

			tableModel.addResults(imported);
			domainFilterDropDown.updateDomains(domains);

			JOptionPane.showMessageDialog(this, "Successfully imported " + imported.size() + " CORS records.",
					"Import Successful", JOptionPane.INFORMATION_MESSAGE);

			SwingUtilities.invokeLater(() -> {
				if (table.getRowCount() > 0) {
					try {
						table.setRowSelectionInterval(0, 0);
					} catch (Exception ignored) {}
				}
			});
		} catch (Exception ex) {
			JOptionPane.showMessageDialog(this, "Failed to load CORS data: " + ex.getMessage(),
					"Import Error", JOptionPane.ERROR_MESSAGE);
		}
	}
}
