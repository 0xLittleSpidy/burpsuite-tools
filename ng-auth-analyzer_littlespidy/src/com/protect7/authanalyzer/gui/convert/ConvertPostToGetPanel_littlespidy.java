// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.convert;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
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
import burp.IRequestInfo;
import com.protect7.authanalyzer.convert.ConversionResult_littlespidy;
import com.protect7.authanalyzer.convert.ConversionTableModel_littlespidy;
import com.protect7.authanalyzer.convert.ConvertEngine_littlespidy;
import com.protect7.authanalyzer.convert.PostCandidate_littlespidy;
import com.protect7.authanalyzer.convert.PostCandidatesTableModel_littlespidy;
import com.protect7.authanalyzer.gui.main.MainPanel;
import com.protect7.authanalyzer.gui.util.DomainFilterDropDown_littlespidy;
import com.protect7.authanalyzer.gui.util.MethodFilterDropDown_littlespidy;
import com.protect7.authanalyzer.gui.util.PlaceholderTextField;

/**
 * Master UI panel for Convert POST to GET containing Live Conversions and POST Traffic Discovery sub-tabs.
 *
 * @author littlespidy
 */
public class ConvertPostToGetPanel_littlespidy extends JPanel {

	private static final long serialVersionUID = 1L;
	private final MainPanel mainPanel;
	private final JTabbedPane subTabbedPane = new JTabbedPane();

	// Live Conversions Sub-Tab
	private final ConversionTableModel_littlespidy conversionTableModel = new ConversionTableModel_littlespidy();
	private final JTable conversionTable = new JTable(conversionTableModel);
	private TableRowSorter<ConversionTableModel_littlespidy> conversionSorter;
	private final DomainFilterDropDown_littlespidy domainFilterDropDown = new DomainFilterDropDown_littlespidy();
	private final PlaceholderTextField liveSearchText = new PlaceholderTextField(16);
	private final JButton liveSearchButton = new JButton("Search");
	private final JButton liveClearButton = new JButton("Clear Results");
	private final JButton liveExportButton = new JButton("Export TSV");
	private final JTabbedPane liveViewerTabbedPane = new JTabbedPane();
	private final JLabel liveViewerInfoLabel = new JLabel("Select a conversion result above to view details");
	private IMessageEditor origPostRequestEditor;
	private IMessageEditor origPostResponseEditor;
	private IMessageEditor convGetRequestEditor;
	private IMessageEditor convGetResponseEditor;

	// POST Traffic Discovery Sub-Tab
	private final PostCandidatesTableModel_littlespidy discoveryTableModel = new PostCandidatesTableModel_littlespidy();
	private final JTable discoveryTable = new JTable(discoveryTableModel);
	private TableRowSorter<PostCandidatesTableModel_littlespidy> discoverySorter;
	private final JButton loadProxyHistoryButton = new JButton("Load from Proxy History");
	private final JButton convertSelectedButton = new JButton("Convert Selected (Attack)");
	private final JButton selectAllButton = new JButton("Select All");
	private final JButton deselectAllButton = new JButton("Deselect All");
	private final JButton clearDiscoveryButton = new JButton("Clear Discovery");
	private final JTabbedPane discoveryViewerTabbedPane = new JTabbedPane();
	private final JLabel discoveryViewerInfoLabel = new JLabel("Select a discovered candidate above to view request/response");
	private IMessageEditor discoveryRequestEditor;
	private IMessageEditor discoveryResponseEditor;

	private int nextResultId = 1;
	private int nextCandidateId = 1;
	private boolean allSelectedToggle = true;

	public ConvertPostToGetPanel_littlespidy(MainPanel mainPanel) {
		this.mainPanel = mainPanel;
		setLayout(new BorderLayout());

		JPanel livePanel = createLiveConversionsPanel();
		JPanel discoveryPanel = createDiscoveryPanel();

		subTabbedPane.addTab("Live Conversions", livePanel);
		subTabbedPane.addTab("POST Traffic Discovery", discoveryPanel);

		add(subTabbedPane, BorderLayout.CENTER);
	}

	private JPanel createLiveConversionsPanel() {
		JPanel panel = new JPanel(new BorderLayout());

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
		rightActions.add(liveClearButton);
		rightActions.add(liveExportButton);
		topToolbar.add(rightActions, BorderLayout.EAST);

		panel.add(topToolbar, BorderLayout.NORTH);

		// Table
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
							entry.getStringValue(8).toLowerCase(Locale.ROOT).contains(q) ||
							entry.getStringValue(9).toLowerCase(Locale.ROOT).contains(q) ||
							entry.getStringValue(10).toLowerCase(Locale.ROOT).contains(q);
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

		// Bottom Viewers
		JPanel viewerContainer = new JPanel(new BorderLayout());
		viewerContainer.setBorder(BorderFactory.createLineBorder(Color.GRAY));
		liveViewerInfoLabel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
		viewerContainer.add(liveViewerInfoLabel, BorderLayout.NORTH);

		initLiveMessageEditors();
		viewerContainer.add(liveViewerTabbedPane, BorderLayout.CENTER);

		JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableContainer, viewerContainer);
		splitPane.setDividerSize(6);
		splitPane.setResizeWeight(0.5d);
		panel.add(splitPane, BorderLayout.CENTER);

		conversionTable.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				displaySelectedLiveConversion();
			}
		});

		return panel;
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

			liveViewerTabbedPane.addTab("Converted GET Request", convGetRequestEditor.getComponent());
			liveViewerTabbedPane.addTab("Converted GET Response", convGetResponseEditor.getComponent());
			liveViewerTabbedPane.addTab("Original POST Request", origPostRequestEditor.getComponent());
			liveViewerTabbedPane.addTab("Original POST Response", origPostResponseEditor.getComponent());
		} else {
			liveViewerTabbedPane.addTab("Converted GET Request", new JLabel("Converted GET Request", JLabel.CENTER));
			liveViewerTabbedPane.addTab("Converted GET Response", new JLabel("Converted GET Response", JLabel.CENTER));
			liveViewerTabbedPane.addTab("Original POST Request", new JLabel("Original POST Request", JLabel.CENTER));
			liveViewerTabbedPane.addTab("Original POST Response", new JLabel("Original POST Response", JLabel.CENTER));
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
					" | Signal: " + res.getSignal() + " (" + res.getSeverity() + ")");

			// Auto switch to Converted GET Response tab on High / Medium bypass findings
			if ("High".equalsIgnoreCase(res.getSeverity()) || "Medium".equalsIgnoreCase(res.getSeverity())) {
				liveViewerTabbedPane.setSelectedIndex(1);
			} else {
				liveViewerTabbedPane.setSelectedIndex(0);
			}

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

	private JPanel createDiscoveryPanel() {
		JPanel panel = new JPanel(new BorderLayout());

		// Top Toolbar
		JPanel topToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
		loadProxyHistoryButton.addActionListener(e -> loadFromProxyHistory());
		convertSelectedButton.addActionListener(e -> convertSelectedCandidates());
		selectAllButton.addActionListener(e -> {
			discoveryTableModel.selectAll(allSelectedToggle);
			allSelectedToggle = !allSelectedToggle;
			selectAllButton.setText(allSelectedToggle ? "Select All" : "Deselect All");
		});
		clearDiscoveryButton.addActionListener(e -> clearDiscovery());

		topToolbar.add(loadProxyHistoryButton);
		topToolbar.add(convertSelectedButton);
		topToolbar.add(selectAllButton);
		topToolbar.add(clearDiscoveryButton);

		panel.add(topToolbar, BorderLayout.NORTH);

		// Discovery Table
		discoveryTable.getColumnModel().getColumn(0).setMaxWidth(50);
		discoveryTable.getColumnModel().getColumn(1).setMaxWidth(50);
		discoveryTable.getColumnModel().getColumn(2).setMaxWidth(60);

		discoverySorter = new TableRowSorter<PostCandidatesTableModel_littlespidy>(discoveryTableModel);
		discoveryTable.setRowSorter(discoverySorter);

		JPanel tableContainer = new JPanel(new BorderLayout());
		tableContainer.setBorder(BorderFactory.createLineBorder(Color.GRAY));
		tableContainer.add(new JScrollPane(discoveryTable), BorderLayout.CENTER);

		// Bottom Viewers
		JPanel viewerContainer = new JPanel(new BorderLayout());
		viewerContainer.setBorder(BorderFactory.createLineBorder(Color.GRAY));
		discoveryViewerInfoLabel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
		viewerContainer.add(discoveryViewerInfoLabel, BorderLayout.NORTH);

		initDiscoveryMessageEditors();
		viewerContainer.add(discoveryViewerTabbedPane, BorderLayout.CENTER);

		JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableContainer, viewerContainer);
		splitPane.setDividerSize(6);
		splitPane.setResizeWeight(0.5d);
		panel.add(splitPane, BorderLayout.CENTER);

		discoveryTable.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				displaySelectedDiscoveryCandidate();
			}
		});

		return panel;
	}

	private void initDiscoveryMessageEditors() {
		if (BurpExtender.callbacks != null) {
			IMessageEditorController controller = new IMessageEditorController() {
				@Override
				public IHttpService getHttpService() {
					PostCandidate_littlespidy c = getSelectedCandidate();
					return (c != null && c.getRequestResponse() != null) ? c.getRequestResponse().getHttpService() : null;
				}
				@Override
				public byte[] getRequest() {
					PostCandidate_littlespidy c = getSelectedCandidate();
					return (c != null && c.getRequestResponse() != null) ? c.getRequestResponse().getRequest() : null;
				}
				@Override
				public byte[] getResponse() {
					PostCandidate_littlespidy c = getSelectedCandidate();
					return (c != null && c.getRequestResponse() != null) ? c.getRequestResponse().getResponse() : null;
				}
			};

			discoveryRequestEditor = BurpExtender.callbacks.createMessageEditor(controller, false);
			discoveryResponseEditor = BurpExtender.callbacks.createMessageEditor(controller, false);

			discoveryViewerTabbedPane.addTab("Request", discoveryRequestEditor.getComponent());
			discoveryViewerTabbedPane.addTab("Response", discoveryResponseEditor.getComponent());
		} else {
			discoveryViewerTabbedPane.addTab("Request", new JLabel("Request Viewer", JLabel.CENTER));
			discoveryViewerTabbedPane.addTab("Response", new JLabel("Response Viewer", JLabel.CENTER));
		}
	}

	private PostCandidate_littlespidy getSelectedCandidate() {
		int viewRow = discoveryTable.getSelectedRow();
		if (viewRow != -1) {
			int modelRow = discoveryTable.convertRowIndexToModel(viewRow);
			return discoveryTableModel.getCandidate(modelRow);
		}
		return null;
	}

	private void displaySelectedDiscoveryCandidate() {
		PostCandidate_littlespidy c = getSelectedCandidate();
		if (c != null) {
			discoveryViewerInfoLabel.setText("Candidate #" + c.getId() + " - " + c.getMethod() + " " + c.getHost() + c.getPath() +
					" | Params: " + c.getParameterCount() + " (" + String.join(", ", c.getParameterNames()) + ")");
			if (discoveryRequestEditor != null && c.getRequestResponse() != null) {
				discoveryRequestEditor.setMessage(c.getRequestResponse().getRequest(), true);
				discoveryResponseEditor.setMessage(c.getRequestResponse().getResponse() != null ?
						c.getRequestResponse().getResponse() : new byte[0], false);
			}
		} else {
			discoveryViewerInfoLabel.setText("Select a discovered candidate above to view request/response");
			if (discoveryRequestEditor != null) {
				discoveryRequestEditor.setMessage(new byte[0], true);
				discoveryResponseEditor.setMessage(new byte[0], false);
			}
		}
	}

	public void analyzePostRequestAsync(IHttpRequestResponse messageInfo) {
		if (messageInfo == null || BurpExtender.callbacks == null) return;

		new Thread(() -> {
			int resId = nextResultId++;
			ConversionResult_littlespidy result = ConvertEngine_littlespidy.convertAndTest(
					messageInfo, BurpExtender.callbacks, resId);

			if (result != null) {
				Set<String> domains = new HashSet<String>();
				domains.add(result.getHost());

				int candId = nextCandidateId++;
				PostCandidate_littlespidy candidate = ConvertEngine_littlespidy.createCandidate(
						messageInfo, BurpExtender.callbacks, candId);

				SwingUtilities.invokeLater(() -> {
					conversionTableModel.addResult(result);
					domainFilterDropDown.updateDomains(domains);
					if (candidate != null) {
						discoveryTableModel.addCandidate(candidate);
					}
				});
			}
		}).start();
	}

	public void loadFromProxyHistory() {
		if (BurpExtender.callbacks == null) {
			JOptionPane.showMessageDialog(this, "Burp callbacks not available.", "Information", JOptionPane.INFORMATION_MESSAGE);
			return;
		}

		new Thread(() -> {
			IHttpRequestResponse[] history = BurpExtender.callbacks.getProxyHistory();
			if (history == null || history.length == 0) {
				SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this, "No requests found in Proxy History.",
						"Proxy History Empty", JOptionPane.INFORMATION_MESSAGE));
				return;
			}

			List<PostCandidate_littlespidy> newCandidates = new ArrayList<PostCandidate_littlespidy>();
			Set<String> seenEndpoints = new HashSet<String>();

			for (IHttpRequestResponse item : history) {
				if (item == null || item.getRequest() == null) continue;
				IRequestInfo reqInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(item);
				if ("POST".equalsIgnoreCase(reqInfo.getMethod())) {
					String key = (reqInfo.getUrl() != null) ? reqInfo.getUrl().toString() : "";
					if (!key.isEmpty() && seenEndpoints.add(key)) {
						PostCandidate_littlespidy cand = ConvertEngine_littlespidy.createCandidate(
								item, BurpExtender.callbacks, nextCandidateId++);
						if (cand != null) {
							newCandidates.add(cand);
						}
					}
				}
			}

			SwingUtilities.invokeLater(() -> {
				discoveryTableModel.addCandidates(newCandidates);
				JOptionPane.showMessageDialog(this, "Discovered and loaded " + newCandidates.size() + " unique POST endpoint(s) from Proxy History.",
						"Load Complete", JOptionPane.INFORMATION_MESSAGE);
			});
		}).start();
	}

	public void convertSelectedCandidates() {
		List<PostCandidate_littlespidy> selected = discoveryTableModel.getSelectedCandidates();
		if (selected == null || selected.isEmpty()) {
			JOptionPane.showMessageDialog(this, "Please select at least one POST candidate checkbox to test.",
					"No Targets Selected", JOptionPane.WARNING_MESSAGE);
			return;
		}

		new Thread(() -> {
			for (PostCandidate_littlespidy cand : selected) {
				if (cand.getRequestResponse() != null) {
					int resId = nextResultId++;
					ConversionResult_littlespidy result = ConvertEngine_littlespidy.convertAndTest(
							cand.getRequestResponse(), BurpExtender.callbacks, resId);
					if (result != null) {
						SwingUtilities.invokeLater(() -> {
							conversionTableModel.addResult(result);
							domainFilterDropDown.updateDomains(Collections.singleton(result.getHost()));
						});
					}
				}
			}
			SwingUtilities.invokeLater(() -> {
				subTabbedPane.setSelectedIndex(0); // Switch to Live Conversions to see results
				JOptionPane.showMessageDialog(this, "Converted and tested " + selected.size() + " candidate(s). Switched to Live Conversions.",
						"Conversion Finished", JOptionPane.INFORMATION_MESSAGE);
			});
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

	public void clearDiscovery() {
		discoveryTableModel.clear();
		discoveryViewerInfoLabel.setText("Select a discovered candidate above to view request/response");
		if (discoveryRequestEditor != null) {
			discoveryRequestEditor.setMessage(new byte[0], true);
			discoveryResponseEditor.setMessage(new byte[0], false);
		}
	}

	public void exportLiveConversions() {
		JFileChooser chooser = new JFileChooser();
		chooser.setDialogTitle("Export POST to GET Results (TSV)");
		chooser.setFileFilter(new FileNameExtensionFilter("TSV Files (*.tsv)", "tsv"));
		if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
			File f = chooser.getSelectedFile();
			if (!f.getName().toLowerCase(Locale.ROOT).endsWith(".tsv")) {
				f = new File(f.getAbsolutePath() + ".tsv");
			}
			try (PrintWriter pw = new PrintWriter(f, StandardCharsets.UTF_8)) {
				pw.println("ID\tMethod\tHost\tPath\tPOST_Status\tGET_Status\tPOST_Length\tGET_Length\tContent_Type\tSignal\tSeverity");
				for (ConversionResult_littlespidy r : conversionTableModel.getAllResults()) {
					pw.printf("%d\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s%n",
							r.getId(), r.getMethod(), r.getHost(), r.getPath(),
							r.getPostStatus(), r.getGetStatus(),
							r.getPostLength(), r.getGetLength(),
							r.getContentType(), r.getSignal(), r.getSeverity());
				}
				JOptionPane.showMessageDialog(this, "Exported " + conversionTableModel.getRowCount() + " rows to " + f.getName(),
						"Export Successful", JOptionPane.INFORMATION_MESSAGE);
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(),
						"Export Error", JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	public ConversionTableModel_littlespidy getConversionTableModel() {
		return conversionTableModel;
	}

	public PostCandidatesTableModel_littlespidy getDiscoveryTableModel() {
		return discoveryTableModel;
	}

	public JTable getConversionTable() {
		return conversionTable;
	}

	public JTable getDiscoveryTable() {
		return discoveryTable;
	}

	public JTabbedPane getSubTabbedPane() {
		return subTabbedPane;
	}
}
