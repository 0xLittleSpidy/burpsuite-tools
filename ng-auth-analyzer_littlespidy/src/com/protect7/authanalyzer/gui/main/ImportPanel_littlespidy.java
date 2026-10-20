// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.main;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.util.ImportRequestTableModel_littlespidy;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.util.XMLImportHelper_littlespidy;

public class ImportPanel_littlespidy extends CenterPanel {

	private static final long serialVersionUID = 1L;
	private ImportRequestTableModel_littlespidy importTableModel;
	private final ArrayList<Session> importedSessions = new ArrayList<Session>();
	private final JButton uploadButton;

	public ImportPanel_littlespidy(MainPanel mainPanel) {
		super(mainPanel);
		getPendingRequestsLabel().setVisible(false);

		uploadButton = new JButton("Upload XML Data");
		uploadButton.setToolTipText("Upload previously exported XML data");
		uploadButton.addActionListener(e -> uploadXMLPressed());

		topActionsPanel.removeAll();
		topActionsPanel.add(uploadButton);
		topActionsPanel.add(clearTableButton);
	}

	@Override
	protected RequestTableModel createTableModel() {
		if (importTableModel == null) {
			importTableModel = new ImportRequestTableModel_littlespidy();
		}
		return importTableModel;
	}

	@Override
	protected boolean isLiveHistory() {
		return false;
	}

	@Override
	public List<Session> getSessions() {
		return importedSessions;
	}

	@Override
	public ArrayList<Session> getSessionsForExport() {
		return importedSessions;
	}

	public ArrayList<Session> getImportedSessions() {
		return importedSessions;
	}

	public ImportRequestTableModel_littlespidy getImportTableModel() {
		if (importTableModel == null) {
			importTableModel = new ImportRequestTableModel_littlespidy();
		}
		return importTableModel;
	}

	public void uploadXMLPressed() {
		JFileChooser chooser = new JFileChooser();
		chooser.setDialogTitle("Upload Auth Analyzer XML Data");
		chooser.setFileFilter(new FileNameExtensionFilter("XML Files (*.xml)", "xml"));
		int res = chooser.showOpenDialog(this);
		if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
			File file = chooser.getSelectedFile();
			loadXMLFile(file);
		}
	}

	public void loadXMLFile(File file) {
		try {
			XMLImportHelper_littlespidy.ParseResult result = XMLImportHelper_littlespidy.parseXML(file);
			setImportedData(result.originals, result.sessions);
			JOptionPane.showMessageDialog(this,
					"Successfully imported " + result.originals.size() + " requests across " + result.sessions.size() + " session(s) from:\n" + file.getName(),
					"Import Successful",
					JOptionPane.INFORMATION_MESSAGE);
			if (getMainPanel() != null && getMainPanel().getPersistenceManager() != null) {
				getMainPanel().getPersistenceManager().triggerAutoSave();
			}
		} catch (Exception ex) {
			JOptionPane.showMessageDialog(this,
					"Failed to import XML: " + ex.getMessage(),
					"Import Error",
					JOptionPane.ERROR_MESSAGE);
		}
	}

	public void setImportedData(List<OriginalRequestResponse> originals, List<Session> sessions) {
		importedSessions.clear();
		if (sessions != null) {
			importedSessions.addAll(sessions);
		}
		importTableModel.setImportedData(originals, importedSessions);
		updateColumnWidths();

		SwingUtilities.invokeLater(() -> {
			if (table.getRowCount() > 0) {
				try {
					table.setRowSelectionInterval(0, 0);
				} catch (Exception ignored) {}
			}
		});
	}

	@Override
	public void clearTable() {
		if (importTableModel != null) {
			importTableModel.clear();
		}
		importedSessions.clear();
		domainFilterDropDown.clear();
		columnsContainer.removeAll();
		columnsContainer.revalidate();
		columnsContainer.repaint();
		if (getMainPanel() != null && getMainPanel().getPersistenceManager() != null) {
			getMainPanel().getPersistenceManager().triggerAutoSave();
		}
	}

	public JButton getUploadButton() {
		return uploadButton;
	}
}
