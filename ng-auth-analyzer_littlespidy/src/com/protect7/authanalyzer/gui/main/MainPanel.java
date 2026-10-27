// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.main;

import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.border.EmptyBorder;
import burp.BurpExtender;
import com.protect7.authanalyzer.controller.ContextMenuController;
import com.protect7.authanalyzer.gui.convert.ConvertPostToGetPanel_littlespidy;
import com.protect7.authanalyzer.gui.cors.CorsHistoryPanel_littlespidy;
import com.protect7.authanalyzer.gui.cors.CorsImportPanel_littlespidy;
import com.protect7.authanalyzer.persistence.PersistenceManager_littlespidy;

public class MainPanel extends JPanel {

	private static final long serialVersionUID = -8438576029794021570L;
	private final ConfigurationPanel configurationPanel;
	private final HistoryPanel_littlespidy historyPanel;
	private final ImportPanel_littlespidy importPanel;
	private final CorsHistoryPanel_littlespidy corsHistoryPanel;
	private final CorsImportPanel_littlespidy corsImportPanel;
	private final ConvertPostToGetPanel_littlespidy convertPanel;
	private final JTabbedPane rootTabbedPane;
	private final PersistenceManager_littlespidy persistenceManager;

	public MainPanel() {
		setLayout(new BorderLayout(5, 5));
		setBorder(new EmptyBorder(5, 5, 5, 5));

		persistenceManager = new PersistenceManager_littlespidy(BurpExtender.api, BurpExtender.callbacks);
		persistenceManager.setMainPanel(this);

		configurationPanel = new ConfigurationPanel(this);
		historyPanel = new HistoryPanel_littlespidy(this);
		importPanel = new ImportPanel_littlespidy(this);
		corsHistoryPanel = new CorsHistoryPanel_littlespidy(this);
		corsImportPanel = new CorsImportPanel_littlespidy(this);
		convertPanel = new ConvertPostToGetPanel_littlespidy(this);

		rootTabbedPane = new JTabbedPane();
		JScrollPane scrollPane = new JScrollPane(configurationPanel);
		scrollPane.getVerticalScrollBar().setUnitIncrement(20);

		rootTabbedPane.addTab("Configuration", scrollPane);
		rootTabbedPane.addTab("Auth History", historyPanel);
		rootTabbedPane.addTab("Auth Import", importPanel);
		rootTabbedPane.addTab("CORS History", corsHistoryPanel);
		rootTabbedPane.addTab("CORS Import", corsImportPanel);
		rootTabbedPane.addTab("Convert POST to GET", convertPanel);

		add(persistenceManager.createToolbar(), BorderLayout.NORTH);
		add(rootTabbedPane, BorderLayout.CENTER);

		if (BurpExtender.callbacks != null) {
			BurpExtender.callbacks.registerContextMenuFactory(new ContextMenuController(configurationPanel));
		}
		configurationPanel.loadAutoStoredData();
	}

	public void updateDividerLocation() {
		// Preserved for compatibility with ConfigurationPanel
		if (historyPanel != null) {
			historyPanel.revalidate();
		}
	}

	public CenterPanel getCenterPanel() {
		return historyPanel;
	}

	public HistoryPanel_littlespidy getHistoryPanel() {
		return historyPanel;
	}

	public ImportPanel_littlespidy getImportPanel() {
		return importPanel;
	}

	public CorsHistoryPanel_littlespidy getCorsHistoryPanel() {
		return corsHistoryPanel;
	}

	public CorsImportPanel_littlespidy getCorsImportPanel() {
		return corsImportPanel;
	}

	public ConvertPostToGetPanel_littlespidy getConvertPanel() {
		return convertPanel;
	}

	public ConfigurationPanel getConfigurationPanel() {
		return configurationPanel;
	}

	public PersistenceManager_littlespidy getPersistenceManager() {
		return persistenceManager;
	}

	public JTabbedPane getRootTabbedPane() {
		return rootTabbedPane;
	}
}
