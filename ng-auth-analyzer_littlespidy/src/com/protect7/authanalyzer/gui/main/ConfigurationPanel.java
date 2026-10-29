// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.main;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.lang.reflect.Type;
import java.net.URL;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToggleButton;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import com.protect7.authanalyzer.entities.AutoExtractLocation;
import com.protect7.authanalyzer.entities.FromToExtractLocation;
import com.protect7.authanalyzer.entities.MatchAndReplace;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.entities.TokenBuilder;
import com.protect7.authanalyzer.entities.TokenLocation;
import com.protect7.authanalyzer.filter.CompleteUrlFilter_littlespidy;
import com.protect7.authanalyzer.filter.ExactPathFilter_littlespidy;
import com.protect7.authanalyzer.filter.FileTypeFilter;
import com.protect7.authanalyzer.filter.InScopeFilter;
import com.protect7.authanalyzer.filter.MethodFilter;
import com.protect7.authanalyzer.filter.OnlyProxyFilter;
import com.protect7.authanalyzer.filter.PathFilter;
import com.protect7.authanalyzer.filter.QueryFilter;
import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.filter.StatusCodeFilter;
import com.protect7.authanalyzer.gui.cors.CorsTechniquesDialog_littlespidy;
import com.protect7.authanalyzer.gui.inputvalidation.InputValidationPayloadsDialog_littlespidy;
import com.protect7.authanalyzer.inputvalidation.InputValidationConfig_littlespidy;
import com.protect7.authanalyzer.gui.dialog.SettingsDialog;
import com.protect7.authanalyzer.gui.entity.SessionPanel;
import com.protect7.authanalyzer.gui.entity.TokenPanel;
import com.protect7.authanalyzer.gui.listener.CloneSessionListener;
import com.protect7.authanalyzer.gui.listener.DeleteSessionListener;
import com.protect7.authanalyzer.gui.listener.NewSessionListener;
import com.protect7.authanalyzer.gui.listener.RenameSessionListener;
import com.protect7.authanalyzer.gui.util.HintCheckBox;
import com.protect7.authanalyzer.gui.util.SessionTabbedPane;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.DataStorageProvider;
import com.protect7.authanalyzer.util.GenericHelper;
import burp.BurpExtender;

public class ConfigurationPanel extends JPanel {

	private static final long serialVersionUID = -4278008236240529083L;
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final String ANALYZER_STOPPED_TEXT = "<html><span style='color:red; font-weight: bold'>[Stopped]</span> Analyzer Stopped</html>";
	private final String ANALYZER_STARTED_TEXT = "<html><span style='color:green; font-weight: bold'>[Running]</span> Analyzer Running</html>";
	private final String DROP_REQUEST_TEXT = "Drop Original Requests";
	private final String STOP_DROP_REQUEST_TEXT = "Stop Drop Requests";
	private final JButton startStopButton = new JButton();
	private final JToggleButton dropOriginalButton = new JToggleButton(DROP_REQUEST_TEXT);

	// Three Analyzer toggles
	private final HintCheckBox testAuthAnalyzer = new HintCheckBox("Auth Analyzer", true,
			"Analyzes authentication and authorization bypasses across defined session profiles.");
	private final HintCheckBox testCors = new HintCheckBox("CORS", true,
			"Analyzes Cross-Origin Resource Sharing (CORS) misconfigurations using PortSwigger techniques.");
	private final JButton corsTechniquesButton = new JButton("CORS Techniques");
	private String corsAttackerUrl = "evil.com";
	private final Set<String> corsEnabledTechniqueIds = new HashSet<String>();

	private final HintCheckBox testConvertPostToGet = new HintCheckBox("Convert POST to GET", true,
			"Automatically converts intercepted POST requests to GET and evaluates responses for authorization/CSRF bypasses.");

	private final HintCheckBox testInputValidation = new HintCheckBox("Input Validation", true,
			"Automatically fuzzes parameters using Big List of Naughty Strings to detect boundary flaws, SQL errors, XSS reflection, and status shifts.");
	private final JButton inputValidationPayloadsButton = new JButton("Input Validation Payloads");
	private final InputValidationConfig_littlespidy inputValidationConfig = new InputValidationConfig_littlespidy();

	private final JButton exportSetupButton = new JButton("Export Setup");
	private final JButton importSetupButton = new JButton("Import Setup");

	private final JPanel filterPanel;
	private final LinkedHashMap<String, SessionPanel> sessionPanelMap = new LinkedHashMap<>();
	private final SessionTabbedPane sessionTabbedPane = new SessionTabbedPane();
	boolean sessionListChanged = true;
	private final MainPanel mainPanel;

	// Enhanced Path Filters
	private ExactPathFilter_littlespidy exactPathFilter;
	private PathFilter pathFilter;
	private CompleteUrlFilter_littlespidy completeUrlFilter;

	private static class FilterItemView {
		final DefaultListModel<String> listModel;
		final JLabel countLabel;
		FilterItemView(DefaultListModel<String> listModel, JLabel countLabel) {
			this.listModel = listModel;
			this.countLabel = countLabel;
		}
	}
	private final Map<RequestFilter, FilterItemView> filterViewMap = new HashMap<RequestFilter, FilterItemView>();

	public ConfigurationPanel(MainPanel mainPanel) {
		this.mainPanel = mainPanel;

		sessionTabbedPane.addNewSessionListener(new NewSessionListener() {
			@Override
			public void newSession() {
				String sessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Enter Name of Session");
				if (sessionName != null && isSessionNameValid(sessionName)) {
					createSession(sessionName);
				}
			}
		});

		sessionTabbedPane.addCloneSessionListener(new CloneSessionListener() {
			@Override
			public void cloneSession() {
				String newSessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Enter Name of New Session");
				if (newSessionName != null && isSessionNameValid(newSessionName)) {
					int currentIndex = sessionTabbedPane.getSelectedIndex();
					String currentSessionName = sessionTabbedPane.getTitleAt(currentIndex);
					doCloneSession(newSessionName, sessionPanelMap.get(currentSessionName));
				}
			}
		});

		sessionTabbedPane.addRenameSessionListener(new RenameSessionListener() {
			@Override
			public void renameSession(String currentName) {
				String sessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Rename Current Session:", currentName);
				if (sessionName != null && isSessionNameValid(sessionName)) {
					if (doModify()) {
						sessionTabbedPane.setTitleAt(getTabbedPaneIndexForTitle(currentName), sessionName);
						sessionPanelMap.put(sessionName, sessionPanelMap.get(currentName));
						sessionPanelMap.remove(currentName);
						sessionPanelMap.get(sessionName).setSessionName(sessionName);
					}
				}
			}
		});

		sessionTabbedPane.addDeleteSessionListener(new DeleteSessionListener() {
			@Override
			public void deleteSession(String title) {
				if (doModify()) {
					sessionPanelMap.remove(title);
					sessionTabbedPane.remove(getTabbedPaneIndexForTitle(title));
					sessionTabbedPane.setSelectedIndex(0);
				}
			}
		});

		sessionTabbedPane.addTabOrderChangedListener(this::onSessionTabOrderChanged);

		// Redesigned Filters Panel (Full-Width Bottom Panel)
		filterPanel = new JPanel();
		filterPanel.setLayout(new GridLayout(3, 3, 10, 8));

		HintCheckBox onlyInScopeButton = new HintCheckBox("Only In Scope");
		onlyInScopeButton.setSelected(true);
		addFilter(new InScopeFilter(filterPanel.getComponentCount(), "Only In Scope requests are analyzed"), onlyInScopeButton);
		JPanel inScopeCard = new JPanel(new BorderLayout(4, 2));
		inScopeCard.setBorder(BorderFactory.createEmptyBorder(2, 2, 4, 2));
		inScopeCard.add(onlyInScopeButton, BorderLayout.NORTH);
		JLabel inScopeDesc = new JLabel("<html><span style='color:gray; font-size:10px;'>Analyze only traffic within target scope.</span></html>");
		inScopeCard.add(inScopeDesc, BorderLayout.CENTER);
		filterPanel.add(inScopeCard);

		HintCheckBox onlyProxyButton = new HintCheckBox("Only Proxy Traffic");
		onlyProxyButton.setSelected(true);
		addFilter(new OnlyProxyFilter(filterPanel.getComponentCount(), "Analyze only proxy traffic. Unselect to analyze repeater and proxy traffic"), onlyProxyButton);
		JPanel proxyCard = new JPanel(new BorderLayout(4, 2));
		proxyCard.setBorder(BorderFactory.createEmptyBorder(2, 2, 4, 2));
		proxyCard.add(onlyProxyButton, BorderLayout.NORTH);
		JLabel proxyDesc = new JLabel("<html><span style='color:gray; font-size:10px;'>Analyze only traffic passing through Burp Proxy.</span></html>");
		proxyCard.add(proxyDesc, BorderLayout.CENTER);
		filterPanel.add(proxyCard);

		HintCheckBox fileTypeFilterButton = new HintCheckBox("Exclude Filetypes");
		fileTypeFilterButton.setSelected(true);
		FileTypeFilter fileTypeFilter = new FileTypeFilter(filterPanel.getComponentCount(), "Excludes every specified filetype");
		filterPanel.add(createConfigurableFilterRow(fileTypeFilter, fileTypeFilterButton, "Enter filetypes to filter (comma separated)", "jpg, png, js, css, woff, ico"));

		HintCheckBox methodFilterButton = new HintCheckBox("Exclude HTTP Methods");
		methodFilterButton.setSelected(true);
		MethodFilter methodFilter = new MethodFilter(filterPanel.getComponentCount(), "Excludes every specified http method");
		filterPanel.add(createConfigurableFilterRow(methodFilter, methodFilterButton, "Enter HTTP methods to filter (comma separated)", "OPTIONS, TRACE"));

		HintCheckBox statusCodeFilterButton = new HintCheckBox("Exclude Status Codes");
		statusCodeFilterButton.setSelected(true);
		StatusCodeFilter statusCodeFilter = new StatusCodeFilter(filterPanel.getComponentCount(), "Excludes every specified status code");
		filterPanel.add(createConfigurableFilterRow(statusCodeFilter, statusCodeFilterButton, "Enter status codes to filter (comma separated)", "204, 304"));

		HintCheckBox exactPathFilterButton = new HintCheckBox("Exclude Exact Path");
		exactPathFilterButton.setSelected(false);
		exactPathFilter = new ExactPathFilter_littlespidy(filterPanel.getComponentCount(), "Excludes exact path matches");
		filterPanel.add(createConfigurableFilterRow(exactPathFilter, exactPathFilterButton, "Enter exact paths to exclude (comma separated)", "/api/v1/logout, /healthz"));

		HintCheckBox pathFilterButton = new HintCheckBox("Exclude Partial Path");
		pathFilterButton.setSelected(false);
		pathFilter = new PathFilter(filterPanel.getComponentCount(), "Excludes every path that contains one of the specified string literals");
		filterPanel.add(createConfigurableFilterRow(pathFilter, pathFilterButton, "Enter partial path string literals (comma separated)", "/static/, /assets/, log"));

		HintCheckBox completeUrlFilterButton = new HintCheckBox("Exclude Complete URL");
		completeUrlFilterButton.setSelected(false);
		completeUrlFilter = new CompleteUrlFilter_littlespidy(filterPanel.getComponentCount(), "Excludes complete URL matches");
		filterPanel.add(createConfigurableFilterRow(completeUrlFilter, completeUrlFilterButton, "Enter complete URLs to exclude (comma separated)", "https://example.com/api/v1/ping"));

		HintCheckBox queryFilterButton = new HintCheckBox("Exclude Queries / Params");
		queryFilterButton.setSelected(false);
		QueryFilter queryFilter = new QueryFilter(filterPanel.getComponentCount(), "Excludes every GET query that contains one of the specified string literals");
		filterPanel.add(createConfigurableFilterRow(queryFilter, queryFilterButton, "Enter string literals for queries to be excluded (comma separated)", "utm_source, cachebust"));

		startStopButton.putClientProperty("html.disable", null);
		startStopButton.setText(ANALYZER_STOPPED_TEXT);
		startStopButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					startStopButtonPressed();
				} catch (Exception ex) {
					ex.printStackTrace(new PrintWriter(BurpExtender.callbacks.getStdout()));
				}
			}
		});

		dropOriginalButton.addActionListener(e -> dropOriginalButtonPressed());
		dropOriginalButton.setEnabled(false);

		corsTechniquesButton.addActionListener(e -> {
			CorsTechniquesDialog_littlespidy dlg = new CorsTechniquesDialog_littlespidy(this, corsAttackerUrl, corsEnabledTechniqueIds);
			dlg.setVisible(true);
			corsAttackerUrl = dlg.getAttackerUrl();
			corsEnabledTechniqueIds.clear();
			corsEnabledTechniqueIds.addAll(dlg.getEnabledTechniqueIds());
		});

		inputValidationPayloadsButton.addActionListener(e -> {
			InputValidationPayloadsDialog_littlespidy dlg = new InputValidationPayloadsDialog_littlespidy(this, inputValidationConfig);
			dlg.setVisible(true);
		});

		exportSetupButton.addActionListener(e -> saveSetup());
		importSetupButton.addActionListener(e -> loadSetup());

		JButton settingsButton = new JButton("Settings");
		settingsButton.addActionListener(e -> new SettingsDialog(this));

		setLayout(new GridBagLayout());
		JPanel startStopButtonPanel = new JPanel();
		startStopButtonPanel.setLayout(new GridBagLayout());
		GridBagConstraints c1 = new GridBagConstraints();
		c1.fill = GridBagConstraints.BOTH;
		c1.gridx = 0;
		c1.insets = new Insets(6, 0, 0, 0);
		c1.gridy = 1;
		c1.gridwidth = 2;
		startStopButtonPanel.add(startStopButton, c1);
		c1.gridy = 2;
		c1.gridx = 0;
		c1.gridwidth = 2;
		startStopButtonPanel.add(dropOriginalButton, c1);

		// Analyzer Section
		c1.gridy = 3;
		startStopButtonPanel.add(testAuthAnalyzer, c1);

		c1.gridy = 4;
		JPanel corsRow = new JPanel(new BorderLayout(4, 0));
		corsRow.add(testCors, BorderLayout.WEST);
		corsRow.add(corsTechniquesButton, BorderLayout.EAST);
		startStopButtonPanel.add(corsRow, c1);

		c1.gridy = 5;
		startStopButtonPanel.add(testConvertPostToGet, c1);

		c1.gridy = 6;
		JPanel ivRow = new JPanel(new BorderLayout(4, 0));
		ivRow.add(testInputValidation, BorderLayout.WEST);
		ivRow.add(inputValidationPayloadsButton, BorderLayout.EAST);
		startStopButtonPanel.add(ivRow, c1);

		// Setup Export / Import
		c1.gridy = 7;
		JPanel setupButtonsPanel = new JPanel(new GridLayout(1, 2, 4, 0));
		setupButtonsPanel.add(exportSetupButton);
		setupButtonsPanel.add(importSetupButton);
		startStopButtonPanel.add(setupButtonsPanel, c1);

		c1.gridy = 8;
		startStopButtonPanel.add(settingsButton, c1);

		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.anchor = GridBagConstraints.NORTHWEST;
		c.fill = GridBagConstraints.NONE;
		c.weightx = 0.0;
		c.weighty = 0.0;
		c.insets = new Insets(10, 15, 10, 10);
		add(startStopButtonPanel, c);

		c.gridx = 1;
		c.gridy = 0;
		c.anchor = GridBagConstraints.NORTHWEST;
		c.fill = GridBagConstraints.BOTH;
		c.weightx = 1.0;
		c.weighty = 0.55;
		c.insets = new Insets(5, 10, 10, 15);
		sessionTabbedPane.setBorder(new CompoundBorder(BorderFactory.createTitledBorder("Sessions (Drag tabs to reorder columns)"), new EmptyBorder(3, 3, 3, 3)));
		add(sessionTabbedPane, c);

		c.gridx = 0;
		c.gridy = 1;
		c.gridwidth = 2;
		c.anchor = GridBagConstraints.NORTHWEST;
		c.fill = GridBagConstraints.BOTH;
		c.weightx = 1.0;
		c.weighty = 0.45;
		c.insets = new Insets(5, 15, 15, 15);
		JScrollPane filterScrollPane = new JScrollPane(filterPanel,
				JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
				JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		filterScrollPane.setBorder(new CompoundBorder(BorderFactory.createTitledBorder("Filters"), new EmptyBorder(3, 3, 3, 3)));
		add(filterScrollPane, c);
	}

	private void addFilter(RequestFilter filter, HintCheckBox onOffButton) {
		config.addRequestFilter(filter);
		filter.registerOnOffButton(onOffButton);
	}

	private JPanel createConfigurableFilterRow(RequestFilter filter, HintCheckBox onOffButton, String inputDialogTitle, String defaultExample) {
		JPanel row = new JPanel(new BorderLayout(4, 2));
		row.setBorder(BorderFactory.createEmptyBorder(2, 2, 4, 2));

		JPanel top = new JPanel(new BorderLayout(4, 0));
		top.add(onOffButton, BorderLayout.WEST);

		JPanel rightActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
		JLabel countLabel = new JLabel("(" + filter.getFilterStringLiterals().length + " items)");
		countLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
		countLabel.setForeground(Color.GRAY);

		JButton toggleBtn = new JButton("Collapse");
		toggleBtn.setMargin(new Insets(1, 6, 1, 6));

		JButton editBtn = new JButton("Edit");
		editBtn.setMargin(new Insets(1, 6, 1, 6));

		rightActions.add(countLabel);
		rightActions.add(toggleBtn);
		rightActions.add(editBtn);
		top.add(rightActions, BorderLayout.EAST);

		DefaultListModel<String> listModel = new DefaultListModel<String>();
		for (String item : filter.getFilterStringLiterals()) {
			listModel.addElement(item);
		}
		JList<String> valueList = new JList<String>(listModel);
		valueList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
		valueList.setVisibleRowCount(4);

		JScrollPane scrollPane = new JScrollPane(valueList,
				JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
				JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		scrollPane.setPreferredSize(new Dimension(180, 75));
		scrollPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, 85));
		scrollPane.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY));

		toggleBtn.addActionListener(e -> {
			boolean isVis = scrollPane.isVisible();
			scrollPane.setVisible(!isVis);
			toggleBtn.setText(isVis ? "Expand" : "Collapse");
			row.revalidate();
			row.repaint();
		});

		filterViewMap.put(filter, new FilterItemView(listModel, countLabel));

		editBtn.addActionListener(e -> {
			String current = GenericHelper.getArrayAsString(filter.getFilterStringLiterals());
			String[] inputArray = getInputArray(onOffButton, inputDialogTitle + "\r\neg: " + defaultExample, current);
			if (inputArray != null) {
				filter.setFilterStringLiterals(inputArray);
				listModel.clear();
				for (String s : filter.getFilterStringLiterals()) {
					listModel.addElement(s);
				}
				countLabel.setText("(" + filter.getFilterStringLiterals().length + " items)");
				if (mainPanel != null && mainPanel.getCenterPanel() != null && mainPanel.getCenterPanel().getTableModel() != null) {
					mainPanel.getCenterPanel().getTableModel().fireTableDataChanged();
				}
			}
		});

		row.add(top, BorderLayout.NORTH);
		row.add(scrollPane, BorderLayout.CENTER);

		config.addRequestFilter(filter);
		filter.registerOnOffButton(onOffButton);
		return row;
	}

	private void onSessionTabOrderChanged() {
		LinkedHashMap<String, SessionPanel> reorderedMap = new LinkedHashMap<String, SessionPanel>();
		for (int i = 0; i < sessionTabbedPane.getTabCount() - 1; i++) {
			String title = sessionTabbedPane.getTitleAt(i);
			SessionPanel sp = sessionPanelMap.get(title);
			if (sp != null) {
				reorderedMap.put(title, sp);
			}
		}
		sessionPanelMap.clear();
		sessionPanelMap.putAll(reorderedMap);
		sessionListChanged = true;
		createSessionObjects(false);
		if (mainPanel != null && mainPanel.getCenterPanel() != null) {
			mainPanel.getCenterPanel().initCenterPanel();
		}
	}

	public boolean isPathOrUrlFiltered(String host, String path) {
		if (path == null) return false;
		String pLower = path.trim().toLowerCase();
		String fullUrl = (host != null ? host.toLowerCase() : "") + pLower;

		if (exactPathFilter != null && exactPathFilter.isSelected()) {
			for (String lit : exactPathFilter.getFilterStringLiterals()) {
				if (!lit.trim().isEmpty() && pLower.equals(lit.trim().toLowerCase())) {
					return true;
				}
			}
		}
		if (pathFilter != null && pathFilter.isSelected()) {
			for (String lit : pathFilter.getFilterStringLiterals()) {
				if (!lit.trim().isEmpty() && pLower.contains(lit.trim().toLowerCase())) {
					return true;
				}
			}
		}
		if (completeUrlFilter != null && completeUrlFilter.isSelected()) {
			for (String lit : completeUrlFilter.getFilterStringLiterals()) {
				String l = lit.trim().toLowerCase();
				if (!l.isEmpty() && (fullUrl.contains(l) || ("https://" + fullUrl).startsWith(l) || ("http://" + fullUrl).startsWith(l))) {
					return true;
				}
			}
		}
		return false;
	}

	public void loadAutoStoredData() {
		try {
			String storedData = DataStorageProvider.loadSetup();
			if (storedData != null) {
				loadSetup(storedData);
				mainPanel.updateDividerLocation();
			}
		} catch (Exception e) {
			BurpExtender.callbacks.printOutput("Can not restore saved Data. Error Message: " + e.getMessage());
		}
		if (sessionTabbedPane.getTabCount() == 1) {
			createSession("user1");
		}
		sessionTabbedPane.setSelectedIndex(0);
	}

	public void saveSetup() {
		JFileChooser chooser = new JFileChooser();
		chooser.setSelectedFile(new File("Auth_Analyzer_Setup.json"));
		int status = chooser.showSaveDialog(this);
		if (status == JFileChooser.APPROVE_OPTION) {
			File file = chooser.getSelectedFile();
			if (!file.getName().endsWith(".json")) {
				String newFileName;
				if (file.getName().lastIndexOf(".") != -1) {
					int index = file.getAbsolutePath().lastIndexOf(".");
					newFileName = file.getAbsolutePath().substring(0, index);
				} else {
					newFileName = file.getAbsolutePath();
				}
				newFileName = newFileName + ".json";
				file = new File(newFileName);
			}
			try {
				FileWriter writer = new FileWriter(file);
				createSessionObjects(false);
				writer.write(DataStorageProvider.getSetupAsJsonString());
				writer.close();
				JOptionPane.showMessageDialog(this, "Successfully saved to\n" + file.getAbsolutePath());
			} catch (Exception e) {
				BurpExtender.callbacks.printError("Error. Can not write setup to JSON file. " + e.getMessage());
				JOptionPane.showMessageDialog(this, "Error.\nCan not write setup to JSON file.");
			}
		}
	}

	public void loadSetup() {
		if (doModify()) {
			JFileChooser chooser = new JFileChooser();
			int status = chooser.showOpenDialog(this);
			if (status == JFileChooser.APPROVE_OPTION) {
				File selectedFile = chooser.getSelectedFile();
				if (selectedFile != null) {
					Scanner scanner;
					String jsonString = "";
					try {
						scanner = new Scanner(selectedFile);
						while (scanner.hasNextLine()) {
							jsonString += scanner.nextLine();
						}
						scanner.close();
						sessionTabbedPane.removeAll();
						loadSetup(jsonString);
						mainPanel.updateDividerLocation();
						JOptionPane.showMessageDialog(this, "Setup successfully loaded");
					} catch (Exception e) {
						BurpExtender.callbacks.printError("Error. Can not load setup from JSON file. " + e.getMessage());
						JOptionPane.showMessageDialog(this, "Error.\nCan not load setup from JSON file.");
					}
				}
			}
		}
	}

	private void dropOriginalButtonPressed() {
		if (CurrentConfig.getCurrentConfig().isDropOriginal()) {
			setDropOriginalRequest(false);
		} else {
			setDropOriginalRequest(true);
		}
	}

	private void setDropOriginalRequest(boolean dropRequests) {
		if (dropRequests) {
			dropOriginalButton.setText(STOP_DROP_REQUEST_TEXT);
			dropOriginalButton.setSelected(true);
			CurrentConfig.getCurrentConfig().setDropOriginal(true);
		} else {
			dropOriginalButton.setText(DROP_REQUEST_TEXT);
			dropOriginalButton.setSelected(false);
			CurrentConfig.getCurrentConfig().setDropOriginal(false);
		}
	}

	private boolean isSessionNameValid(String name) {
		if (name.equals("")) {
			JOptionPane.showMessageDialog(sessionTabbedPane, "Session name can not be empty");
			return false;
		}
		if (sessionPanelMap.containsKey(name)) {
			JOptionPane.showMessageDialog(sessionTabbedPane, "Session name already exists");
			return false;
		}
		return true;
	}

	public SessionPanel createSession(String sessionName) {
		SessionPanel sessionPanel = new SessionPanel(sessionName, mainPanel);
		sessionPanelMap.put(sessionName, sessionPanel);
		sessionTabbedPane.addTab(sessionName, sessionPanel);
		setSelectedSession(sessionName);
		sessionListChanged = true;
		return sessionPanel;
	}

	public SessionPanel createSession(String sessionName, String headerToReplace) {
		if (!sessionPanelMap.containsKey(sessionName)) {
			SessionPanel sessionPanel = createSession(sessionName);
			if (sessionPanel != null) {
				sessionPanel.setHeadersToReplaceText(headerToReplace);
				return sessionPanel;
			}
		}
		return null;
	}

	private void doCloneSession(String newSessionName, SessionPanel sessionToClone) {
		SessionPanel sessionPanel = new SessionPanel(newSessionName, mainPanel);
		sessionPanel.setHeadersToReplaceText(sessionToClone.getHeadersToReplaceText());
		sessionPanel.setRemoveHeaders(sessionToClone.isRemoveHeaders());
		sessionPanel.setHeadersToRemoveText(sessionToClone.getHeadersToRemoveText());
		sessionPanel.setFilterRequestsWithSameHeader(sessionToClone.isFilterRequestsWithSameHeader());
		sessionPanel.setRestrictToScope(sessionToClone.isRestrictToScope());
		sessionPanel.setRestrictToScopeText(sessionToClone.getRestrictToScopeText());

		ArrayList<MatchAndReplace> matchAndReplaceList = new ArrayList<MatchAndReplace>();
		for (MatchAndReplace matchAndReplace : sessionToClone.getMatchAndReplaceList()) {
			matchAndReplaceList.add(new MatchAndReplace(matchAndReplace.getMatch(), matchAndReplace.getReplace()));
		}
		sessionPanel.setMatchAndReplaceList(matchAndReplaceList);

		for (TokenPanel tokenPanelToClone : sessionToClone.getTokenPanelList()) {
			TokenPanel newTokenPanel = sessionPanel.addToken(tokenPanelToClone.getTokenName());
			newTokenPanel.setTokenLocationSet(tokenPanelToClone.getTokenLocationSet());
			newTokenPanel.setAutoExtractLocationSet(tokenPanelToClone.getAutoExtractLocationSet());
			newTokenPanel.setFromToExtractLocationSet(tokenPanelToClone.getFromToExtractLocationSet());
			newTokenPanel.setIsRemoveToken(tokenPanelToClone.isRemoveToken());
			newTokenPanel.setAddTokenIfNotExists(tokenPanelToClone.isAddTokenIfNotExists());
			newTokenPanel.setCaseSensitiveTokenName(tokenPanelToClone.isCaseSensitiveTokenName());
			if (tokenPanelToClone.isAutoExtract()) {
				newTokenPanel.setAutoExtractFieldName(tokenPanelToClone.getAutoExtractFieldName());
			}
			if (tokenPanelToClone.isStaticValue()) {
				newTokenPanel.setStaticTokenValue(tokenPanelToClone.getStaticTokenValue());
			}
			if (tokenPanelToClone.isFromToString()) {
				newTokenPanel.setFromToString(tokenPanelToClone.getGrepFromString(), tokenPanelToClone.getGrepToString());
			}
			if (tokenPanelToClone.isPromptForInput()) {
				newTokenPanel.setPromptForInput();
			}
			newTokenPanel.setAliases(tokenPanelToClone.getAliases());
			newTokenPanel.setUrlEncoded(tokenPanelToClone.isUrlEncoded());
		}
		sessionPanelMap.put(newSessionName, sessionPanel);
		sessionTabbedPane.addTab(newSessionName, sessionPanel);
		setSelectedSession(newSessionName);
		sessionListChanged = true;
	}

	public SessionPanel getSessionPanelByName(String name) {
		return sessionPanelMap.get(name);
	}

	public void setSelectedSession(String sessionName) {
		sessionTabbedPane.setSelectedIndex(getTabbedPaneIndexForTitle(sessionName));
	}

	public int getTabbedPaneIndexForTitle(String title) {
		for (int i = 0; i < sessionTabbedPane.getTabCount(); i++) {
			if (sessionTabbedPane.getTitleAt(i).equals(title)) {
				return i;
			}
		}
		return -1;
	}

	public ArrayList<String> getSessionNames() {
		ArrayList<String> sessionNames = new ArrayList<String>();
		for (int i = 0; i < sessionTabbedPane.getTabCount() - 1; i++) {
			sessionNames.add(sessionTabbedPane.getTitleAt(i));
		}
		return sessionNames;
	}

	public void startStopButtonPressed() {
		if (sessionPanelMap.size() == 0) {
			JOptionPane.showMessageDialog(this, "No Session Created");
		} else {
			if (config.isRunning()) {
				for (String session : sessionPanelMap.keySet()) {
					sessionPanelMap.get(session).setStopped();
				}
				sessionTabbedPane.setModifEnabled(true);
				dropOriginalButton.setEnabled(false);
				setDropOriginalRequest(false);
				config.setRunning(false);
				startStopButton.setText(ANALYZER_STOPPED_TEXT);
			} else {
				boolean success = true;
				for (String session : sessionPanelMap.keySet()) {
					SessionPanel sessionPanel = sessionPanelMap.get(session);
					if (!sessionPanel.tokensValid() || !sessionPanel.isHeaderValid() || !sessionPanel.isScopeValid()) {
						success = false;
						setSelectedSession(session);
						break;
					}
				}
				if (success) {
					createSessionObjects(true);
					try {
						DataStorageProvider.saveSetup();
					} catch (Exception e) {
						BurpExtender.callbacks.printOutput("Can not store setup. Error Message: " + e.getMessage());
					}

					for (RequestFilter filter : config.getRequestFilterList()) {
						filter.resetFilteredAmount();
					}

					if (sessionListChanged) {
						mainPanel.getCenterPanel().initCenterPanel();
					}
					sessionTabbedPane.setModifEnabled(false);
					dropOriginalButton.setEnabled(true);
					config.setRunning(true);
					startStopButton.setText(ANALYZER_STARTED_TEXT);
					sessionListChanged = false;
				}
			}
			mainPanel.updateDividerLocation();
		}
	}

	public void createSessionObjects(boolean setRunning) {
		if (sessionPanelMap.size() != config.getSessions().size()) {
			sessionListChanged = true;
		}
		for (String session : sessionPanelMap.keySet()) {
			if (config.getSessionByName(session) == null) {
				sessionListChanged = true;
				break;
			}
		}
		if (sessionListChanged) {
			config.clearSessionList();
		}
		for (int i = 0; i < sessionTabbedPane.getTabCount() - 1; i++) {
			String session = sessionTabbedPane.getTitleAt(i);
			SessionPanel sessionPanel = sessionPanelMap.get(session);
			if (sessionPanel == null) continue;
			ArrayList<Token> tokenList = new ArrayList<Token>();
			for (TokenPanel tokenPanel : sessionPanel.getTokenPanelList()) {
				Token token = new TokenBuilder()
						.setName(tokenPanel.getTokenName())
						.setTokenLocationSet(tokenPanel.getTokenLocationSet())
						.setAutoExtractLocationSet(tokenPanel.getAutoExtractLocationSet())
						.setFromToExtractLocationSet(tokenPanel.getFromToExtractLocationSet())
						.setValue(tokenPanel.getStaticTokenValue())
						.setExtractName(tokenPanel.getAutoExtractFieldName())
						.setGrepFromString(tokenPanel.getGrepFromString())
						.setGrepToString(tokenPanel.getGrepToString())
						.setIsRemove(tokenPanel.isRemoveToken())
						.setIsAutoExtract(tokenPanel.isAutoExtract())
						.setIsStaticValue(tokenPanel.isStaticValue())
						.setIsFromToString(tokenPanel.isFromToString())
						.setIsPromptForInput(tokenPanel.isPromptForInput())
						.setIsCaseSensitiveTokenName(tokenPanel.isCaseSensitiveTokenName())
						.setIsAddIfNotExists(tokenPanel.isAddTokenIfNotExists())
						.setIsUrlEncoded(tokenPanel.isUrlEncoded())
						.setAliases(tokenPanel.getAliases())
						.build();
				tokenList.add(token);
			}
			Session newSession = null;
			if (sessionListChanged) {
				newSession = new Session(session, sessionPanel.getHeadersToReplaceText(), sessionPanel.isRemoveHeaders(),
						sessionPanel.getHeadersToRemoveText(), sessionPanel.isFilterRequestsWithSameHeader(), sessionPanel.isRestrictToScope(),
						sessionPanel.getScopeUrl(), false, tokenList, sessionPanel.getMatchAndReplaceList(), sessionPanel.getStatusPanel());
				newSession.setAttackerUrl(corsAttackerUrl);
				config.addSession(newSession);
			} else {
				newSession = config.getSessionByName(session);
				newSession.setHeadersToReplace(sessionPanel.getHeadersToReplaceText());
				newSession.setRemoveHeaders(sessionPanel.isRemoveHeaders());
				newSession.setHeadersToRemove(sessionPanel.getHeadersToRemoveText());
				newSession.setFilterRequestsWithSameHeader(sessionPanel.isFilterRequestsWithSameHeader());
				newSession.setRestrictToScope(sessionPanel.isRestrictToScope());
				newSession.setScopeUrl(sessionPanel.getScopeUrl());
				newSession.setTestCors(false);
				newSession.setAttackerUrl(corsAttackerUrl);
				newSession.setMatchAndReplaceList(sessionPanel.getMatchAndReplaceList());
				newSession.setTokens(tokenList);
			}
			if (setRunning) {
				sessionPanel.setRunning();
				sessionPanel.getStatusPanel().init(newSession);
			}
		}
	}

	public void loadSetup(String jsonString) {
		sessionPanelMap.clear();
		sessionTabbedPane.removeAll();
		JsonObject rootObject = JsonParser.parseString(jsonString).getAsJsonObject();
		if (rootObject.get("testAuthAnalyzer") != null) {
			testAuthAnalyzer.setSelected(rootObject.get("testAuthAnalyzer").getAsBoolean());
		} else {
			testAuthAnalyzer.setSelected(true);
		}
		if (rootObject.get("testCors") != null) {
			testCors.setSelected(rootObject.get("testCors").getAsBoolean());
		} else {
			testCors.setSelected(true);
		}
		if (rootObject.get("testConvertPostToGet") != null) {
			testConvertPostToGet.setSelected(rootObject.get("testConvertPostToGet").getAsBoolean());
		} else {
			testConvertPostToGet.setSelected(true);
		}
		if (rootObject.get("testInputValidation") != null) {
			testInputValidation.setSelected(rootObject.get("testInputValidation").getAsBoolean());
		} else {
			testInputValidation.setSelected(true);
		}
		if (rootObject.get("corsAttackerUrl") != null) {
			corsAttackerUrl = rootObject.get("corsAttackerUrl").getAsString();
		}
		if (rootObject.get("corsTechniques") != null) {
			corsEnabledTechniqueIds.clear();
			for (JsonElement el : rootObject.get("corsTechniques").getAsJsonArray()) {
				corsEnabledTechniqueIds.add(el.getAsString());
			}
		}

		// Load Sessions
		JsonArray storedSessionsArray = rootObject.get("sessions").getAsJsonArray();
		for (JsonElement sessionEl : storedSessionsArray) {
			JsonObject sessionObject = sessionEl.getAsJsonObject();
			String sessionName = sessionObject.get("name").getAsString();
			SessionPanel sessionPanel = new SessionPanel(sessionName, mainPanel);
			sessionPanel.setHeadersToReplaceText(sessionObject.get("headersToReplace").getAsString());
			sessionPanel.setFilterRequestsWithSameHeader(sessionObject.get("filterRequestsWithSameHeader").getAsBoolean());
			if (sessionObject.get("removeHeaders") != null) {
				sessionPanel.setRemoveHeaders(sessionObject.get("removeHeaders").getAsBoolean());
			}
			if (sessionObject.get("headersToRemove") != null) {
				sessionPanel.setHeadersToRemoveText(sessionObject.get("headersToRemove").getAsString());
			}
			if (sessionObject.get("restrictToScope") != null) {
				sessionPanel.setRestrictToScope(sessionObject.get("restrictToScope").getAsBoolean());
			}
			if (sessionObject.get("scopeUrl") != null) {
				sessionPanel.setRestrictToScopeText(sessionObject.get("scopeUrl").getAsString());
			}
			if (sessionObject.get("matchAndReplaceList") != null) {
				JsonArray matchAndReplaceArray = sessionObject.get("matchAndReplaceList").getAsJsonArray();
				ArrayList<MatchAndReplace> matchAndReplaceList = new ArrayList<MatchAndReplace>();
				for (JsonElement matchAndReplaceElement : matchAndReplaceArray) {
					JsonObject matchAndReplaceObject = matchAndReplaceElement.getAsJsonObject();
					if (matchAndReplaceObject.get("match") != null && matchAndReplaceObject.get("replace") != null) {
						matchAndReplaceList.add(new MatchAndReplace(matchAndReplaceObject.get("match").getAsString(),
								matchAndReplaceObject.get("replace").getAsString()));
					}
				}
				sessionPanel.setMatchAndReplaceList(matchAndReplaceList);
			}
			JsonArray tokenArray = sessionObject.get("tokens").getAsJsonArray();
			for (JsonElement tokenElement : tokenArray) {
				JsonObject tokenObject = tokenElement.getAsJsonObject();
				TokenPanel tokenPanel = sessionPanel.addToken(tokenObject.get("name").getAsString());
				if (tokenObject.get("tokenLocation") != null) {
					Type tokenLocationType = new TypeToken<EnumSet<TokenLocation>>() {}.getType();
					tokenPanel.setTokenLocationSet(new Gson().fromJson(tokenObject.get("tokenLocation"), tokenLocationType));
				}
				if (tokenObject.get("autoExtractLocation") != null) {
					Type autoExtractLocationType = new TypeToken<EnumSet<AutoExtractLocation>>() {}.getType();
					tokenPanel.setAutoExtractLocationSet(new Gson().fromJson(tokenObject.get("autoExtractLocation"), autoExtractLocationType));
				}
				if (tokenObject.get("fromToExtractLocation") != null) {
					Type fromToExtractLocationType = new TypeToken<EnumSet<FromToExtractLocation>>() {}.getType();
					tokenPanel.setFromToExtractLocationSet(new Gson().fromJson(tokenObject.get("fromToExtractLocation"), fromToExtractLocationType));
				}
				if (tokenObject.get("remove") != null) {
					tokenPanel.setIsRemoveToken(tokenObject.get("remove").getAsBoolean());
				}
				if (tokenObject.get("caseSensitiveTokenName") != null) {
					tokenPanel.setCaseSensitiveTokenName(tokenObject.get("caseSensitiveTokenName").getAsBoolean());
				}
				if (tokenObject.get("addTokenIfNotExists") != null) {
					tokenPanel.setAddTokenIfNotExists(tokenObject.get("addTokenIfNotExists").getAsBoolean());
				}
				if (tokenObject.get("urlEncoded") != null) {
					tokenPanel.setUrlEncoded(tokenObject.get("urlEncoded").getAsBoolean());
				}
				if (tokenObject.get("aliases") != null) {
					tokenPanel.setAliases(tokenObject.get("aliases").getAsString());
				}
				if (tokenObject.get("autoExtract") != null && tokenObject.get("autoExtract").getAsBoolean()) {
					if (tokenObject.get("extractName") != null) {
						tokenPanel.setAutoExtractFieldName(tokenObject.get("extractName").getAsString());
					}
				}
				if (tokenObject.get("staticValue") != null && tokenObject.get("staticValue").getAsBoolean()) {
					if (tokenObject.get("value") != null) {
						tokenPanel.setStaticTokenValue(tokenObject.get("value").getAsString());
					}
				}
				if (tokenObject.get("fromToString") != null && tokenObject.get("fromToString").getAsBoolean()) {
					String grepFrom = tokenObject.get("grepFromString") != null ? tokenObject.get("grepFromString").getAsString() : "";
					String grepTo = tokenObject.get("grepToString") != null ? tokenObject.get("grepToString").getAsString() : "";
					tokenPanel.setFromToString(grepFrom, grepTo);
				}
				if (tokenObject.get("promptForInput") != null && tokenObject.get("promptForInput").getAsBoolean()) {
					tokenPanel.setPromptForInput();
				}
			}
			sessionPanelMap.put(sessionName, sessionPanel);
			sessionTabbedPane.addTab(sessionName, sessionPanel);
		}

		// Load Filters
		JsonArray storedFilterArray = rootObject.get("filters").getAsJsonArray();
		for (JsonElement filterEl : storedFilterArray) {
			JsonObject filterObject = filterEl.getAsJsonObject();
			int idx = filterObject.get("filterIndex").getAsInt();
			if (idx < config.getRequestFilterList().size()) {
				RequestFilter requestFilter = config.getRequestFilterAt(idx);
				requestFilter.setIsSelected(filterObject.get("isSelected").getAsBoolean());
				if (filterObject.get("stringLiterals") != null) {
					JsonArray tokenArray = filterObject.get("stringLiterals").getAsJsonArray();
					String[] stringLiterals = new String[tokenArray.size()];
					for (int i = 0; i < tokenArray.size(); i++) {
						stringLiterals[i] = tokenArray.get(i).getAsString();
					}
					requestFilter.setFilterStringLiterals(stringLiterals);
				}
			}
		}
		updateFilterValueLabels();
		createSessionObjects(false);
	}

	public void updateFilterValueLabels() {
		for (Map.Entry<RequestFilter, FilterItemView> entry : filterViewMap.entrySet()) {
			entry.getValue().listModel.clear();
			String[] lits = entry.getKey().getFilterStringLiterals();
			if (lits != null) {
				for (String s : lits) {
					entry.getValue().listModel.addElement(s);
				}
				entry.getValue().countLabel.setText("(" + lits.length + " items)");
			} else {
				entry.getValue().countLabel.setText("(0 items)");
			}
		}
	}

	private String[] getInputArray(Component parentFrame, String message, String value) {
		String userInput = JOptionPane.showInputDialog(parentFrame, message, value);
		if (userInput == null) {
			return null;
		}
		String[] userInputParts = userInput.split(",");
		String[] inputs = new String[userInputParts.length];
		for (int i = 0; i < inputs.length; i++) {
			inputs[i] = userInputParts[i].trim();
		}
		return inputs;
	}

	public String getCorsAttackerUrl() {
		return (corsAttackerUrl != null && !corsAttackerUrl.trim().isEmpty()) ? corsAttackerUrl.trim() : "evil.com";
	}

	public void setCorsAttackerUrl(String url) {
		this.corsAttackerUrl = url;
	}

	public Set<String> getCorsEnabledTechniqueIds() {
		return new HashSet<String>(corsEnabledTechniqueIds);
	}

	public String getAttackerUrl() {
		return getCorsAttackerUrl();
	}

	public boolean isAuthAnalyzerActive() {
		return CurrentConfig.getCurrentConfig().isRunning() && testAuthAnalyzer.isSelected();
	}

	public boolean isCorsTestingActive() {
		return CurrentConfig.getCurrentConfig().isRunning() && testCors.isSelected();
	}

	public boolean isCorsTestingSelected() {
		return testCors.isSelected();
	}

	public boolean isConvertPostToGetActive() {
		return CurrentConfig.getCurrentConfig().isRunning() && testConvertPostToGet.isSelected();
	}

	public void setConvertPostToGetActive(boolean active) {
		testConvertPostToGet.setSelected(active);
	}

	public boolean isTestConvertPostToGetSelected() {
		return testConvertPostToGet.isSelected();
	}

	public boolean isInputValidationRunning() {
		return CurrentConfig.getCurrentConfig().isRunning() && testInputValidation.isSelected();
	}

	public boolean isInputValidationEnabled() {
		return testInputValidation.isSelected();
	}

	public void setInputValidationEnabled(boolean enabled) {
		testInputValidation.setSelected(enabled);
	}

	public InputValidationConfig_littlespidy getInputValidationConfig() {
		return inputValidationConfig;
	}

	public boolean doModify() {
		if (!sessionTabbedPane.canModify()) {
			JOptionPane.showMessageDialog(this, "Can not modify session setup while Analyzer is running");
			return false;
		}
		return true;
	}
}
