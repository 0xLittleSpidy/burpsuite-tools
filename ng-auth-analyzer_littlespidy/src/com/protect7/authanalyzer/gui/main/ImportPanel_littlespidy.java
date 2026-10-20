// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.main;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.util.ImportRequestTableModel_littlespidy;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.util.XMLImportHelper_littlespidy;

public class ImportPanel_littlespidy extends CenterPanel {

	private static final long serialVersionUID = 1L;
	private final ImportRequestTableModel_littlespidy importTableModel = new ImportRequestTableModel_littlespidy();
	private final ArrayList<Session> importedSessions = new ArrayList<Session>();
	private final JButton uploadButton;
	private int importSelectedId = -1;

	public ImportPanel_littlespidy(MainPanel mainPanel) {
		super(mainPanel);
		getPendingRequestsLabel().setVisible(false);

		uploadButton = new JButton("Upload XML Data");
		uploadButton.setToolTipText("Upload previously exported XML data");
		uploadButton.addActionListener(e -> uploadXMLPressed());

		tableConfigPanel.add(uploadButton, 0);
	}

	@Override
	protected RequestTableModel createTableModel() {
		return importTableModel;
	}

	@Override
	protected boolean isLiveHistory() {
		return false;
	}

	@Override
	public ArrayList<Session> getSessionsForExport() {
		return importedSessions;
	}

	public ArrayList<Session> getImportedSessions() {
		return importedSessions;
	}

	public ImportRequestTableModel_littlespidy getImportTableModel() {
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
		
		ArrayList<String> sessionNames = new ArrayList<String>();
		for (Session s : importedSessions) {
			sessionNames.add(s.getName());
		}
		tabbedPanel1.initWithSessions(sessionNames);
		tabbedPanel2.initWithSessions(sessionNames);
		importSelectedId = -1;
		updateColumnWidths();

		if (importTableModel.getRowCount() > 0) {
			table.setRowSelectionInterval(0, 0);
		}
	}

	@Override
	public void clearTable() {
		importTableModel.clear();
		importedSessions.clear();
		tabbedPanel1.initWithSessions(Collections.emptyList());
		tabbedPanel2.initWithSessions(Collections.emptyList());
		importSelectedId = -1;
		if (getMainPanel() != null && getMainPanel().getPersistenceManager() != null) {
			getMainPanel().getPersistenceManager().triggerAutoSave();
		}
	}

	@Override
	protected void changeRequestResponseView(boolean force) {
		if (table.getSelectedRow() != -1) {
			int modelRowIndex = table.convertRowIndexToModel(table.getSelectedRow());
			OriginalRequestResponse originalRequestResponse = importTableModel.getOriginalRequestResponse(modelRowIndex);
			if (force || (originalRequestResponse != null && importSelectedId != originalRequestResponse.getId())) {
				importSelectedId = originalRequestResponse.getId();
				boolean compareViewVisible = tabbedPanel2.isVisible();
				if (originalRequestResponse.getRequestResponse() != null) {
					IMessageEditorController controllerOriginal = new CustomIMessageEditorController(
							originalRequestResponse.getRequestResponse().getHttpService(),
							originalRequestResponse.getRequestResponse().getRequest(),
							originalRequestResponse.getRequestResponse().getResponse());
					IMessageEditor reqEd1 = BurpExtender.callbacks.createMessageEditor(controllerOriginal, false);
					reqEd1.setMessage(originalRequestResponse.getRequestResponse().getRequest(), true);
					tabbedPanel1.setRequestMessage(tabbedPanel1.TITLE_ORIGINAL, reqEd1.getComponent(), reqEd1);

					if (compareViewVisible) {
						IMessageEditor reqEd2 = BurpExtender.callbacks.createMessageEditor(controllerOriginal, false);
						reqEd2.setMessage(originalRequestResponse.getRequestResponse().getRequest(), true);
						tabbedPanel2.setRequestMessage(tabbedPanel1.TITLE_ORIGINAL, reqEd2.getComponent(), reqEd2);
					}

					if (originalRequestResponse.getRequestResponse().getResponse() != null) {
						IMessageEditor respEd1 = BurpExtender.callbacks.createMessageEditor(controllerOriginal, false);
						respEd1.setMessage(originalRequestResponse.getRequestResponse().getResponse(), false);
						tabbedPanel1.setResponseMessage(tabbedPanel1.TITLE_ORIGINAL, respEd1.getComponent(), respEd1);
						if (compareViewVisible) {
							IMessageEditor respEd2 = BurpExtender.callbacks.createMessageEditor(controllerOriginal, false);
							respEd2.setMessage(originalRequestResponse.getRequestResponse().getResponse(), false);
							tabbedPanel2.setResponseMessage(tabbedPanel1.TITLE_ORIGINAL, respEd2.getComponent(), respEd2);
						}
					} else {
						tabbedPanel1.setResponseMessage(tabbedPanel1.TITLE_ORIGINAL, getMessageViewLabel(originalRequestResponse.getInfoText()), null);
						if (compareViewVisible) {
							tabbedPanel2.setResponseMessage(tabbedPanel1.TITLE_ORIGINAL, getMessageViewLabel(originalRequestResponse.getInfoText()), null);
						}
					}
				}

				for (Session session : importedSessions) {
					AnalyzerRequestResponse analyzerRequestResponse = session.getRequestResponseMap().get(originalRequestResponse.getId());
					if (analyzerRequestResponse != null && analyzerRequestResponse.getRequestResponse() != null) {
						IHttpRequestResponse sessionRequestResponse = analyzerRequestResponse.getRequestResponse();
						IMessageEditorController controller = new CustomIMessageEditorController(
								sessionRequestResponse.getHttpService(), sessionRequestResponse.getRequest(),
								sessionRequestResponse.getResponse());

						IMessageEditor reqEd = BurpExtender.callbacks.createMessageEditor(controller, false);
						reqEd.setMessage(sessionRequestResponse.getRequest(), true);
						tabbedPanel1.setRequestMessage(session.getName(), reqEd.getComponent(), reqEd);
						if (compareViewVisible) {
							IMessageEditor reqEd2 = BurpExtender.callbacks.createMessageEditor(controller, false);
							reqEd2.setMessage(sessionRequestResponse.getRequest(), true);
							tabbedPanel2.setRequestMessage(session.getName(), reqEd2.getComponent(), reqEd2);
						}

						IMessageEditor respEd = BurpExtender.callbacks.createMessageEditor(controller, false);
						respEd.setMessage(sessionRequestResponse.getResponse(), false);
						tabbedPanel1.setResponseMessage(session.getName(), respEd.getComponent(), respEd);
						if (compareViewVisible) {
							IMessageEditor respEd2 = BurpExtender.callbacks.createMessageEditor(controller, false);
							respEd2.setMessage(sessionRequestResponse.getResponse(), false);
							tabbedPanel2.setResponseMessage(session.getName(), respEd2.getComponent(), respEd2);
						}
					} else {
						String info = analyzerRequestResponse != null ? analyzerRequestResponse.getInfoText() : "No data";
						tabbedPanel1.setRequestMessage(session.getName(), getMessageViewLabel(info), null);
						tabbedPanel1.setResponseMessage(session.getName(), getMessageViewLabel(info), null);
						if (compareViewVisible) {
							tabbedPanel2.setRequestMessage(session.getName(), getMessageViewLabel(info), null);
							tabbedPanel2.setResponseMessage(session.getName(), getMessageViewLabel(info), null);
						}
					}
				}
				tabbedPanel1.setViewMode(getActiveViewMode());
				if (compareViewVisible) {
					tabbedPanel2.setViewMode(getActiveViewMode());
				}
				updateDiffPane();
				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						messageViewPanel.revalidate();
					}
				});
			}
		}
	}
}
