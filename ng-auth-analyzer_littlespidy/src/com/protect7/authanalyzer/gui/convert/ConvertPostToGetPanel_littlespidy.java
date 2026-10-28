// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.convert;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JToggleButton;
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
import burp.IRequestInfo;
import com.protect7.authanalyzer.convert.ConversionResult_littlespidy;
import com.protect7.authanalyzer.convert.ConversionTableModel_littlespidy;
import com.protect7.authanalyzer.convert.ConvertEngine_littlespidy;
import com.protect7.authanalyzer.gui.main.MainPanel;
import com.protect7.authanalyzer.gui.util.DomainFilterDropDown_littlespidy;
import com.protect7.authanalyzer.gui.util.PlaceholderTextField;
import com.protect7.authanalyzer.util.ConvertXMLHelper_littlespidy;

public class ConvertPostToGetPanel_littlespidy extends JPanel {

	private static final long serialVersionUID = 1L;
	private final MainPanel mainPanel;

	// Conversions Table & Models
	private final ConversionTableModel_littlespidy conversionTableModel = new ConversionTableModel_littlespidy();
	private final JTable conversionTable = new JTable(conversionTableModel);
	private TableRowSorter<ConversionTableModel_littlespidy> conversionSorter;
	private final DomainFilterDropDown_littlespidy domainFilterDropDown = new DomainFilterDropDown_littlespidy();
	private final PlaceholderTextField liveSearchText = new PlaceholderTextField(16);
	private final JButton liveSearchButton = new JButton("Search");
	private final JButton liveClearButton = new JButton("Clear Results");
	private final JButton liveExportButton = new JButton("Export TSV");
	private final JButton liveExportXmlButton = new JButton("Export XML");

	private final JLabel liveViewerInfoLabel = new JLabel("Select a conversion result above to view details");
	private final JToggleButton requestToggleButton = new JToggleButton("Request", true);
	private final JToggleButton responseToggleButton = new JToggleButton("Response", false);

	private IMessageEditor origPostRequestEditor;
	private IMessageEditor origPostResponseEditor;
	private IMessageEditor convGetRequestEditor;
	private IMessageEditor convGetResponseEditor;

	private CardLayout origCardLayout = new CardLayout();
	private JPanel origCardPanel = new JPanel(origCardLayout);
	private CardLayout convCardLayout = new CardLayout();
	private JPanel convCardPanel = new JPanel(convCardLayout);

	private int nextResultId = 1;

	public ConvertPostToGetPanel_littlespidy(MainPanel mainPanel) {
		this.mainPanel = mainPanel;
		setLayout(new BorderLayout());
		initUI();
	}

	private void initUI() {
		// Top Toolbar
		JPanel topToolbar = new JPanel(new BorderLayout(6, 4));
		topToolbar.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

		JPanel leftFilters = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
		leftFilters.add(domainFilterDropDown);

		liveSearchText.setPlaceholder("Search URL, Signal, Path...");
		liveSearchButton.addActionListener(e -> conversionTableModel.fireTableDataChanged());
		leftFilters.add(liveSearchText);
		leftFilters.add(liveSearchButton);
		topToolbar.add(leftFilters, BorderLayout.WEST);

		JPanel rightActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
		liveClearButton.addActionListener(e -> clearLiveConversions());
		liveExportButton.addActionListener(e -> exportLiveConversions());
		liveExportXmlButton.addActionListener(e -> exportXmlConversions());
		rightActions.add(liveClearButton);
		rightActions.add(liveExportButton);
		rightActions.add(liveExportXmlButton);
		topToolbar.add(rightActions, BorderLayout.EAST);

		add(topToolbar, BorderLayout.NORTH);

		// Conversions Table
		conversionTable.setDefaultRenderer(String.class, new ConversionTableModel_littlespidy.ConversionCellRenderer());
		conversionTable.setDefaultRenderer(Integer.class, new ConversionTableModel_littlespidy.ConversionCellRenderer());

		conversionSorter = new TableRowSorter<ConversionTableModel_littlespidy>(conversionTableModel);
		conversionSorter.setMaxSortKeys(1);
		conversionSorter.setSortKeys(Collections.singletonList(new RowSorter.SortKey(0, SortOrder.DESCENDING)));

		domainFilterDropDown.addFilterChangeListener(() -> conversionTableModel.fireTableDataChanged());

		conversionSorter.setRowFilter(new RowFilter<ConversionTableModel_littlespidy, Integer>() {
			@Override
			public boolean include(Entry<? extends ConversionTableModel_littlespidy, ? extends Integer> entry) {
				String host = entry.getStringValue(2);
				if (!domainFilterDropDown.isDomainSelected(host)) {
					return false;
				}
				String query = liveSearchText.getText();
				if (query != null && !query.trim().isEmpty()) {
					String q = query.trim().toLowerCase(Locale.ROOT);
					boolean matches = entry.getStringValue(2).toLowerCase(Locale.ROOT).contains(q) ||
							entry.getStringValue(3).toLowerCase(Locale.ROOT).contains(q) ||
							entry.getStringValue(8).toLowerCase(Locale.ROOT).contains(q);
					if (!matches) {
						return false;
					}
				}
				return true;
			}
		});
		conversionTable.setRowSorter(conversionSorter);

		JPanel tableContainer = new JPanel(new BorderLayout());
		tableContainer.setBorder(BorderFactory.createLineBorder(Color.GRAY));
		tableContainer.add(new JScrollPane(conversionTable), BorderLayout.CENTER);

		// Bottom Side-by-Side HTTP Message Viewers
		JPanel viewerContainer = new JPanel(new BorderLayout());
		viewerContainer.setBorder(BorderFactory.createLineBorder(Color.GRAY));

		JPanel headerPanel = new JPanel(new BorderLayout(5, 2));
		headerPanel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
		headerPanel.add(liveViewerInfoLabel, BorderLayout.WEST);

		JPanel rightSwitchPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
		JLabel switchLabel = new JLabel("View:");
		ButtonGroup viewGroup = new ButtonGroup();
		viewGroup.add(requestToggleButton);
		viewGroup.add(responseToggleButton);
		requestToggleButton.addActionListener(e -> setViewMode(0));
		responseToggleButton.addActionListener(e -> setViewMode(1));
		rightSwitchPanel.add(switchLabel);
		rightSwitchPanel.add(requestToggleButton);
		rightSwitchPanel.add(responseToggleButton);
		headerPanel.add(rightSwitchPanel, BorderLayout.EAST);

		viewerContainer.add(headerPanel, BorderLayout.NORTH);

		initLiveMessageEditors();

		JPanel columnsContainer = new JPanel(new GridLayout(1, 2, 8, 0));

		JPanel origPostColumn = new JPanel(new BorderLayout());
		origPostColumn.setBorder(BorderFactory.createLineBorder(Color.GRAY));
		JLabel origTitle = new JLabel("Original POST", JLabel.LEFT);
		origTitle.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
		origPostColumn.add(origTitle, BorderLayout.NORTH);
		origPostColumn.add(origCardPanel, BorderLayout.CENTER);

		JPanel convGetColumn = new JPanel(new BorderLayout());
		convGetColumn.setBorder(BorderFactory.createLineBorder(Color.GRAY));
		JLabel convTitle = new JLabel("Converted GET", JLabel.LEFT);
		convTitle.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
		convGetColumn.add(convTitle, BorderLayout.NORTH);
		convGetColumn.add(convCardPanel, BorderLayout.CENTER);

		columnsContainer.add(origPostColumn);
		columnsContainer.add(convGetColumn);
		viewerContainer.add(columnsContainer, BorderLayout.CENTER);

		JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableContainer, viewerContainer);
		splitPane.setDividerSize(6);
		splitPane.setResizeWeight(0.5d);
		add(splitPane, BorderLayout.CENTER);

		conversionTable.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				displaySelectedLiveConversion();
			}
		});
	}

	private void initLiveMessageEditors() {
		if (BurpExtender.callbacks != null) {
			IMessageEditorController origController = new IMessageEditorController() {
				@Override
				public IHttpService getHttpService() {
					ConversionResult_littlespidy r = getSelectedConversionResult();
					return (r != null && r.getOriginalRequestResponse() != null) ? r.getOriginalRequestResponse().getHttpService() : null;
				}
				@Override
				public byte[] getRequest() {
					ConversionResult_littlespidy r = getSelectedConversionResult();
					return (r != null && r.getOriginalRequestResponse() != null) ? r.getOriginalRequestResponse().getRequest() : null;
				}
				@Override
				public byte[] getResponse() {
					ConversionResult_littlespidy r = getSelectedConversionResult();
					return (r != null && r.getOriginalRequestResponse() != null) ? r.getOriginalRequestResponse().getResponse() : null;
				}
			};

			IMessageEditorController convController = new IMessageEditorController() {
				@Override
				public IHttpService getHttpService() {
					ConversionResult_littlespidy r = getSelectedConversionResult();
					return (r != null && r.getConvertedRequestResponse() != null) ? r.getConvertedRequestResponse().getHttpService() : null;
				}
				@Override
				public byte[] getRequest() {
					ConversionResult_littlespidy r = getSelectedConversionResult();
					return (r != null && r.getConvertedRequestResponse() != null) ? r.getConvertedRequestResponse().getRequest() : null;
				}
				@Override
				public byte[] getResponse() {
					ConversionResult_littlespidy r = getSelectedConversionResult();
					return (r != null && r.getConvertedRequestResponse() != null) ? r.getConvertedRequestResponse().getResponse() : null;
				}
			};

			origPostRequestEditor = BurpExtender.callbacks.createMessageEditor(origController, false);
			origPostResponseEditor = BurpExtender.callbacks.createMessageEditor(origController, false);
			convGetRequestEditor = BurpExtender.callbacks.createMessageEditor(convController, false);
			convGetResponseEditor = BurpExtender.callbacks.createMessageEditor(convController, false);

			origCardPanel.add(origPostRequestEditor.getComponent(), "REQ");
			origCardPanel.add(origPostResponseEditor.getComponent(), "RESP");
			convCardPanel.add(convGetRequestEditor.getComponent(), "REQ");
			convCardPanel.add(convGetResponseEditor.getComponent(), "RESP");
		} else {
			origCardPanel.add(new JLabel("Original POST Request", JLabel.CENTER), "REQ");
			origCardPanel.add(new JLabel("Original POST Response", JLabel.CENTER), "RESP");
			convCardPanel.add(new JLabel("Converted GET Request", JLabel.CENTER), "REQ");
			convCardPanel.add(new JLabel("Converted GET Response", JLabel.CENTER), "RESP");
		}
		setViewMode(0);
	}

	public void setViewMode(int mode) {
		if (mode == 0) {
			requestToggleButton.setSelected(true);
			origCardLayout.show(origCardPanel, "REQ");
			convCardLayout.show(convCardPanel, "REQ");
		} else {
			responseToggleButton.setSelected(true);
			origCardLayout.show(origCardPanel, "RESP");
			convCardLayout.show(convCardPanel, "RESP");
		}
	}

	private ConversionResult_littlespidy getSelectedConversionResult() {
		int viewRow = conversionTable.getSelectedRow();
		if (viewRow != -1) {
			int modelRow = conversionTable.convertRowIndexToModel(viewRow);
			return conversionTableModel.getResult(modelRow);
		}
		return null;
	}

	private void displaySelectedLiveConversion() {
		ConversionResult_littlespidy res = getSelectedConversionResult();
		if (res != null) {
			liveViewerInfoLabel.setText("ID " + res.getId() + " - " + res.getMethod() + " " + res.getHost() + res.getPath() +
					" | POST Status: " + res.getPostStatus() + " -> GET Status: " + res.getGetStatus() +
					" | Signal: " + res.getSignal());

			if (origPostRequestEditor != null && res.getOriginalRequestResponse() != null) {
				origPostRequestEditor.setMessage(res.getOriginalRequestResponse().getRequest(), true);
				origPostResponseEditor.setMessage(res.getOriginalRequestResponse().getResponse() != null ?
						res.getOriginalRequestResponse().getResponse() : new byte[0], false);
			}
			if (convGetRequestEditor != null && res.getConvertedRequestResponse() != null) {
				convGetRequestEditor.setMessage(res.getConvertedRequestResponse().getRequest(), true);
				convGetResponseEditor.setMessage(res.getConvertedRequestResponse().getResponse() != null ?
						res.getConvertedRequestResponse().getResponse() : new byte[0], false);
			}
		} else {
			liveViewerInfoLabel.setText("Select a conversion result above to view details");
			if (origPostRequestEditor != null) {
				origPostRequestEditor.setMessage(new byte[0], true);
				origPostResponseEditor.setMessage(new byte[0], false);
			}
			if (convGetRequestEditor != null) {
				convGetRequestEditor.setMessage(new byte[0], true);
				convGetResponseEditor.setMessage(new byte[0], false);
			}
		}
	}

	public void analyzePostRequestAsync(IHttpRequestResponse messageInfo) {
		if (messageInfo == null) return;
		new Thread(() -> {
			IRequestInfo analyzed = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
			if (analyzed == null || !"POST".equalsIgnoreCase(analyzed.getMethod())) {
				return;
			}
			ConversionResult_littlespidy result = ConvertEngine_littlespidy.convertAndTest(
					messageInfo, BurpExtender.callbacks, nextResultId++);
			if (result != null) {
				SwingUtilities.invokeLater(() -> {
					conversionTableModel.addResult(result);
					domainFilterDropDown.updateDomains(Collections.singleton(result.getHost()));
				});
			}
		}).start();
	}

	public void clearLiveConversions() {
		conversionTableModel.clear();
		domainFilterDropDown.clear();
		liveViewerInfoLabel.setText("Select a conversion result above to view details");
		if (origPostRequestEditor != null) {
			origPostRequestEditor.setMessage(new byte[0], true);
			origPostResponseEditor.setMessage(new byte[0], false);
		}
		if (convGetRequestEditor != null) {
			convGetRequestEditor.setMessage(new byte[0], true);
			convGetResponseEditor.setMessage(new byte[0], false);
		}
	}

	public void exportLiveConversions() {
		JFileChooser chooser = new JFileChooser();
		chooser.setDialogTitle("Export Conversions (TSV)");
		chooser.setFileFilter(new FileNameExtensionFilter("TSV Files (*.tsv)", "tsv"));
		if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
			File f = chooser.getSelectedFile();
			if (!f.getName().toLowerCase(Locale.ROOT).endsWith(".tsv")) {
				f = new File(f.getAbsolutePath() + ".tsv");
			}
			try (PrintWriter pw = new PrintWriter(f, StandardCharsets.UTF_8)) {
				pw.println("ID\tMethod\tHost\tPath\tPOST Status\tGET Status\tPOST Len\tGET Len\tSignal");
				for (ConversionResult_littlespidy r : conversionTableModel.getAllResults()) {
					pw.println(r.getId() + "\t" + r.getMethod() + "\t" + r.getHost() + "\t" + r.getPath() + "\t" +
							r.getPostStatus() + "\t" + r.getGetStatus() + "\t" + r.getPostLength() + "\t" +
							r.getGetLength() + "\t" + r.getSignal());
				}
				JOptionPane.showMessageDialog(this, "Exported " + conversionTableModel.getRowCount() + " rows to " + f.getName(),
						"Export Successful", JOptionPane.INFORMATION_MESSAGE);
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(),
						"Export Error", JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	public void exportXmlConversions() {
		JFileChooser chooser = new JFileChooser();
		chooser.setDialogTitle("Export Conversions (XML)");
		chooser.setFileFilter(new FileNameExtensionFilter("XML Files (*.xml)", "xml"));
		if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
			File f = chooser.getSelectedFile();
			if (!f.getName().toLowerCase(Locale.ROOT).endsWith(".xml")) {
				f = new File(f.getAbsolutePath() + ".xml");
			}
			boolean ok = ConvertXMLHelper_littlespidy.exportToXML(f, conversionTableModel.getAllResults());
			if (ok) {
				JOptionPane.showMessageDialog(this, "Exported " + conversionTableModel.getRowCount() + " rows to " + f.getName(),
						"Export Successful", JOptionPane.INFORMATION_MESSAGE);
			} else {
				JOptionPane.showMessageDialog(this, "Failed to export XML data.",
						"Export Error", JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	public ConversionTableModel_littlespidy getConversionTableModel() {
		return conversionTableModel;
	}

	public JTable getConversionTable() {
		return conversionTable;
	}

	public DomainFilterDropDown_littlespidy getDomainFilterDropDown() {
		return domainFilterDropDown;
	}
}
