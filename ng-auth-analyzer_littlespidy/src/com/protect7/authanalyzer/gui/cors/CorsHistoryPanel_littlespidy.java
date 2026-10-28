// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.cors;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableRowSorter;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import com.protect7.authanalyzer.cors.CorsEngine_littlespidy;
import com.protect7.authanalyzer.cors.CorsTableModel_littlespidy;
import com.protect7.authanalyzer.cors.CorsTestResult_littlespidy;
import com.protect7.authanalyzer.gui.main.MainPanel;
import com.protect7.authanalyzer.gui.util.DomainFilterDropDown_littlespidy;
import com.protect7.authanalyzer.gui.util.MethodFilterDropDown_littlespidy;
import com.protect7.authanalyzer.gui.util.PlaceholderTextField;

public class CorsHistoryPanel_littlespidy extends JPanel {

	private static final long serialVersionUID = 1L;
	protected final MainPanel mainPanel;
	protected final CorsTableModel_littlespidy tableModel = new CorsTableModel_littlespidy();
	protected final JTable table = new JTable(tableModel);
	protected TableRowSorter<CorsTableModel_littlespidy> sorter;

	protected final MethodFilterDropDown_littlespidy methodFilterDropDown = new MethodFilterDropDown_littlespidy();
	protected final DomainFilterDropDown_littlespidy domainFilterDropDown = new DomainFilterDropDown_littlespidy();
	protected final PlaceholderTextField filterText = new PlaceholderTextField(16);
	protected final JButton searchButton = new JButton("Search");

	protected final JButton testSelectedButton = new JButton("Test Selected");
	protected final JButton clearTableButton = new JButton("Clear Table");
	protected final JButton exportDataButton = new JButton("Export Table Data");
	protected final JPanel topActionsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));

	private final JSplitPane viewerSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
	private IMessageEditor requestEditor;
	private IMessageEditor responseEditor;
	private final JLabel viewerInfoLabel = new JLabel("Select a CORS test result above to view details");

	private int nextResultId = 1;

	public CorsHistoryPanel_littlespidy(MainPanel mainPanel) {
		this.mainPanel = mainPanel;
		setLayout(new BorderLayout());
		initUI();
	}

	protected void initUI() {
		JPanel topPanel = new JPanel();
		topPanel.setLayout(new BorderLayout(5, 4));
		topPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

		// Filter and actions row
		JPanel controlsRow = new JPanel(new BorderLayout(8, 2));
		JPanel leftFilters = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
		leftFilters.add(methodFilterDropDown);
		leftFilters.add(domainFilterDropDown);
		controlsRow.add(leftFilters, BorderLayout.WEST);

		JPanel centerSearch = new JPanel(new FlowLayout(FlowLayout.CENTER, 6, 0));
		filterText.setPlaceholder("Search Pattern...");
		centerSearch.add(filterText);
		searchButton.addActionListener(e -> tableModel.fireTableDataChanged());
		centerSearch.add(searchButton);
		controlsRow.add(centerSearch, BorderLayout.CENTER);

		initActionsPanel();
		controlsRow.add(topActionsPanel, BorderLayout.EAST);
		topPanel.add(controlsRow, BorderLayout.CENTER);

		add(topPanel, BorderLayout.NORTH);

		// Table setup
		table.setDefaultRenderer(String.class, new CorsTableModel_littlespidy.CorsCellRenderer());
		table.setDefaultRenderer(Integer.class, new CorsTableModel_littlespidy.CorsCellRenderer());
		table.setDefaultRenderer(Boolean.class, new CorsTableModel_littlespidy.CorsCellRenderer());
		table.setDefaultRenderer(CorsTestResult_littlespidy.CorsSeverity.class, new CorsTableModel_littlespidy.CorsCellRenderer());

		sorter = new TableRowSorter<CorsTableModel_littlespidy>(tableModel);
		sorter.setMaxSortKeys(1);
		sorter.setSortKeys(Collections.singletonList(new RowSorter.SortKey(0, SortOrder.DESCENDING)));

		methodFilterDropDown.addFilterChangeListener(() -> tableModel.fireTableDataChanged());
		domainFilterDropDown.addFilterChangeListener(() -> tableModel.fireTableDataChanged());

		sorter.setRowFilter(new RowFilter<CorsTableModel_littlespidy, Integer>() {
			@Override
			public boolean include(Entry<? extends CorsTableModel_littlespidy, ? extends Integer> entry) {
				String method = entry.getStringValue(1);
				if (!methodFilterDropDown.isMethodSelected(method)) {
					return false;
				}
				String host = entry.getStringValue(2);
				if (!domainFilterDropDown.isDomainSelected(host)) {
					return false;
				}
				String query = filterText.getText();
				if (query != null && !query.trim().isEmpty()) {
					String q = query.trim().toLowerCase(Locale.ROOT);
					boolean matches = entry.getStringValue(1).toLowerCase(Locale.ROOT).contains(q) ||
							entry.getStringValue(2).toLowerCase(Locale.ROOT).contains(q) ||
							entry.getStringValue(3).toLowerCase(Locale.ROOT).contains(q) ||
							entry.getStringValue(4).toLowerCase(Locale.ROOT).contains(q) ||
							entry.getStringValue(5).toLowerCase(Locale.ROOT).contains(q) ||
							entry.getStringValue(6).toLowerCase(Locale.ROOT).contains(q);
					if (!matches) {
						return false;
					}
				}
				return true;
			}
		});
		table.setRowSorter(sorter);

		JPanel tableContainer = new JPanel(new BorderLayout());
		tableContainer.setBorder(BorderFactory.createLineBorder(Color.GRAY));
		tableContainer.add(new JScrollPane(table), BorderLayout.CENTER);

		// Bottom viewer setup: standard Burp Suite Request / Response JTabbedPane
		JPanel messageViewPanel = new JPanel(new BorderLayout());
		messageViewPanel.setBorder(BorderFactory.createLineBorder(Color.GRAY));

		viewerInfoLabel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
		messageViewPanel.add(viewerInfoLabel, BorderLayout.NORTH);

		initMessageEditors();
		messageViewPanel.add(viewerSplitPane, BorderLayout.CENTER);

		JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableContainer, messageViewPanel);
		splitPane.setDividerSize(6);
		splitPane.setResizeWeight(0.5d);
		add(splitPane, BorderLayout.CENTER);

		table.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				displaySelectedResult();
			}
		});
	}

	protected void initActionsPanel() {
		testSelectedButton.addActionListener(e -> testSelectedRow());
		clearTableButton.addActionListener(e -> clearTable());
		exportDataButton.addActionListener(e -> exportData());

		topActionsPanel.add(testSelectedButton);
		topActionsPanel.add(clearTableButton);
		topActionsPanel.add(exportDataButton);
	}

	private void initMessageEditors() {
		JPanel requestPanel = new JPanel(new BorderLayout());
		JLabel reqLabel = new JLabel("Request");
		reqLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
		requestPanel.add(reqLabel, BorderLayout.NORTH);

		JPanel responsePanel = new JPanel(new BorderLayout());
		JLabel respLabel = new JLabel("Response");
		respLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
		responsePanel.add(respLabel, BorderLayout.NORTH);

		if (BurpExtender.callbacks != null) {
			IMessageEditorController controller = new IMessageEditorController() {
				@Override
				public IHttpService getHttpService() {
					CorsTestResult_littlespidy res = getSelectedResult();
					return (res != null && res.getRequestResponse() != null) ? res.getRequestResponse().getHttpService() : null;
				}
				@Override
				public byte[] getRequest() {
					CorsTestResult_littlespidy res = getSelectedResult();
					return (res != null && res.getRequestResponse() != null) ? res.getRequestResponse().getRequest() : null;
				}
				@Override
				public byte[] getResponse() {
					CorsTestResult_littlespidy res = getSelectedResult();
					return (res != null && res.getRequestResponse() != null) ? res.getRequestResponse().getResponse() : null;
				}
			};
			requestEditor = BurpExtender.callbacks.createMessageEditor(controller, false);
			responseEditor = BurpExtender.callbacks.createMessageEditor(controller, false);
			requestPanel.add(requestEditor.getComponent(), BorderLayout.CENTER);
			responsePanel.add(responseEditor.getComponent(), BorderLayout.CENTER);
		} else {
			requestPanel.add(new JLabel("Request Viewer", JLabel.CENTER), BorderLayout.CENTER);
			responsePanel.add(new JLabel("Response Viewer", JLabel.CENTER), BorderLayout.CENTER);
		}

		viewerSplitPane.setLeftComponent(requestPanel);
		viewerSplitPane.setRightComponent(responsePanel);
		viewerSplitPane.setResizeWeight(0.5d);
		viewerSplitPane.setDividerLocation(0.5d);
	}

	private CorsTestResult_littlespidy getSelectedResult() {
		int viewRow = table.getSelectedRow();
		if (viewRow != -1) {
			int modelRow = table.convertRowIndexToModel(viewRow);
			return tableModel.getResult(modelRow);
		}
		return null;
	}

	private void displaySelectedResult() {
		CorsTestResult_littlespidy res = getSelectedResult();
		if (res != null) {
			viewerInfoLabel.setText("ID " + res.getId() + " - " + res.getMethod() + " " + res.getHost() + res.getPath() +
					" | Vector: " + res.getTestTypeDescription() + " | Severity: " + res.getSeverity().getName());
			if (requestEditor != null && res.getRequestResponse() != null) {
				requestEditor.setMessage(res.getRequestResponse().getRequest(), true);
				responseEditor.setMessage(res.getRequestResponse().getResponse() != null ?
						res.getRequestResponse().getResponse() : new byte[0], false);
			}
		} else {
			viewerInfoLabel.setText("Select a CORS test result above to view details");
			if (requestEditor != null) {
				requestEditor.setMessage(new byte[0], true);
				responseEditor.setMessage(new byte[0], false);
			}
		}
	}

	public void testSelectedRow() {
		CorsTestResult_littlespidy res = getSelectedResult();
		if (res != null && res.getRequestResponse() != null) {
			analyzeRequestAsync(res.getRequestResponse());
		} else {
			JOptionPane.showMessageDialog(this, "Please select a row with request data to test CORS.",
					"No Row Selected", JOptionPane.WARNING_MESSAGE);
		}
	}

	public void analyzeRequestAsync(IHttpRequestResponse messageInfo) {
		if (messageInfo == null) return;
		new Thread(() -> {
			String attacker = getAttackerUrl();
			Set<String> enabledIds = getEnabledTechniqueIds();
			List<CorsTestResult_littlespidy> testResults = CorsEngine_littlespidy.executeCorsTests(
					messageInfo, attacker, enabledIds, BurpExtender.callbacks, nextResultId);
			nextResultId += testResults.size();

			Set<String> domains = new HashSet<String>();
			for (CorsTestResult_littlespidy r : testResults) {
				domains.add(r.getHost());
			}

			SwingUtilities.invokeLater(() -> {
				tableModel.addResults(testResults);
				domainFilterDropDown.updateDomains(domains);
			});
		}).start();
	}

	public void clearTable() {
		tableModel.clear();
		domainFilterDropDown.clear();
		viewerInfoLabel.setText("Select a CORS test result above to view details");
		if (requestEditor != null) {
			requestEditor.setMessage(new byte[0], true);
			responseEditor.setMessage(new byte[0], false);
		}
	}

	public void exportData() {
		JFileChooser chooser = new JFileChooser();
		chooser.setDialogTitle("Export CORS Results (CSV)");
		chooser.setFileFilter(new FileNameExtensionFilter("CSV Files (*.csv)", "csv"));
		if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
			File f = chooser.getSelectedFile();
			if (!f.getName().toLowerCase(Locale.ROOT).endsWith(".csv")) {
				f = new File(f.getAbsolutePath() + ".csv");
			}
			try (PrintWriter pw = new PrintWriter(f, StandardCharsets.UTF_8)) {
				pw.println("ID,Method,Host,Path,TestVector,TestedOrigin,ReflectedACAO,ACAC,StatusCode,Length,Severity");
				for (CorsTestResult_littlespidy r : tableModel.getAllResults()) {
					pw.printf("%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%b,%d,%d,\"%s\"%n",
							r.getId(), r.getMethod(), r.getHost(), r.getPath(),
							r.getTestTypeDescription(), r.getTestedOrigin(),
							r.getReflectedAcao(), r.isAcacPresent(),
							r.getStatusCode(), r.getLength(), r.getSeverity().getName());
				}
				JOptionPane.showMessageDialog(this, "Exported " + tableModel.getRowCount() + " rows to " + f.getName(),
						"Export Successful", JOptionPane.INFORMATION_MESSAGE);
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(),
						"Export Error", JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	public String getAttackerUrl() {
		if (mainPanel != null && mainPanel.getConfigurationPanel() != null) {
			return mainPanel.getConfigurationPanel().getCorsAttackerUrl();
		}
		return "evil.com";
	}

	public Set<String> getEnabledTechniqueIds() {
		if (mainPanel != null && mainPanel.getConfigurationPanel() != null) {
			return mainPanel.getConfigurationPanel().getCorsEnabledTechniqueIds();
		}
		return null;
	}

	public JSplitPane getViewerSplitPane() {
		return viewerSplitPane;
	}

	public IMessageEditor getRequestEditor() {
		return requestEditor;
	}

	public IMessageEditor getResponseEditor() {
		return responseEditor;
	}

	public CorsTableModel_littlespidy getTableModel() {
		return tableModel;
	}

	public JTable getTable() {
		return table;
	}

	public DomainFilterDropDown_littlespidy getDomainFilterDropDown() {
		return domainFilterDropDown;
	}

	public MethodFilterDropDown_littlespidy getMethodFilterDropDown() {
		return methodFilterDropDown;
	}
}
