// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.main;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JToggleButton;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.RowSorterEvent;
import javax.swing.event.RowSorterListener;
import javax.swing.table.TableCellRenderer;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.dialog.DataExportDialog;
import com.protect7.authanalyzer.gui.util.BypassCellRenderer;
import com.protect7.authanalyzer.gui.util.CustomRowSorter;
import com.protect7.authanalyzer.gui.util.MethodFilterDropDown_littlespidy;
import com.protect7.authanalyzer.gui.util.PlaceholderTextField;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.gui.util.RequestTableModel.Column;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.GenericHelper;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;

public class CenterPanel extends JPanel {

	private static final long serialVersionUID = 8472627619821851125L;
	private final MainPanel mainPanel;
	private final String TABLE_SETTINGS = "TABLE_SETTINGS";
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final ImageIcon loaderImageIcon = new ImageIcon(this.getClass().getClassLoader().getResource("loader.gif"));
	protected final JTable table;
	protected final JPanel tablePanel = new JPanel(new BorderLayout());
	protected final ListSelectionModel selectionModel;
	protected final HashSet<Column> columnSet = new HashSet<Column>();
	protected RequestTableModel tableModel;
	protected final JPanel messageViewPanel;
	protected CustomRowSorter sorter;
	protected final MethodFilterDropDown_littlespidy methodFilterDropDown = new MethodFilterDropDown_littlespidy();
	protected final JPanel topActionsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
	protected final JButton clearTableButton;
	protected final JButton exportDataButton;
	private final JToggleButton requestToggleButton = new JToggleButton("Request");
	private final JToggleButton responseToggleButton = new JToggleButton("Response");
	private int activeViewMode = 0;
	private final JCheckBox showOnlyMarked = new JCheckBox("Marked", false);
	private final JCheckBox showDuplicates = new JCheckBox("Duplicates", true);
	private final JCheckBox showBypassed = new JCheckBox("Status " + BypassConstants.SAME.getName(), true);
	private final JCheckBox showPotentialBypassed = new JCheckBox("Status " + BypassConstants.SIMILAR.getName(), true);
	private final JCheckBox showNotBypassed = new JCheckBox("Status " + BypassConstants.DIFFERENT.getName(), true);
	private final JCheckBox showNA = new JCheckBox("Status " + BypassConstants.NA.getName(), true);
	private final PlaceholderTextField filterText;
	private final JPanel topPanel = new JPanel(new BorderLayout());
	private final JLabel tableFilterInfoLabel = new JLabel("", SwingConstants.CENTER);
	private final JLabel pendingRequestsLabel = new JLabel("", SwingConstants.CENTER);
	private final JCheckBox searchInPath = new JCheckBox("Search in Path", true);
	private final JCheckBox searchInRequest = new JCheckBox("Search in Request", false);
	private final JCheckBox searchInResponse = new JCheckBox("Search in Response", false);
	private final JCheckBox negativeSearch = new JCheckBox("Negative Search", false);
	private final JButton searchButton = new JButton("Search");
	private int selectedId = -1;

	protected final JPanel columnsContainer;
	protected final JScrollPane columnsScrollPane;
	private final List<SessionColumnView> columnViews = new ArrayList<SessionColumnView>();
	private final JSplitPane splitPane;

	public CenterPanel(MainPanel mainPanel) {
		this.mainPanel = mainPanel;
		setLayout(new BorderLayout());
		table = new JTable();
		tablePanel.setBorder(BorderFactory.createLineBorder(Color.gray));

		clearTableButton = new JButton("Clear Table");
		clearTableButton.addActionListener(e -> clearTablePressed());

		exportDataButton = new JButton("Export Table Data");
		exportDataButton.addActionListener(e -> { 
			exportDataButton.setIcon(loaderImageIcon);
			new Thread(new Runnable() {
				@Override
				public void run() {
					new DataExportDialog(CenterPanel.this);
					exportDataButton.setIcon(null);
				}
			}).start();			
		});

		topActionsPanel.add(clearTableButton);
		topActionsPanel.add(exportDataButton);

		JPanel tableControlPanel = new JPanel(new BorderLayout(10, 4));
		tableControlPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
		tableControlPanel.add(methodFilterDropDown, BorderLayout.WEST);

		filterText = new PlaceholderTextField(20);
		filterText.setPlaceholder("Enter Search Pattern...");
		searchButton.addActionListener(e -> tableModel.fireTableDataChanged());

		JButton filterButton = new JButton();
		filterButton.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("filter.png")));
		filterButton.addActionListener(e -> showTableFilterDialog(tableControlPanel));

		JButton settingsButton = new JButton();
		settingsButton.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("settings.png")));
		settingsButton.addActionListener(e -> showTableSettingsDialog(tableControlPanel));

		JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 6, 0));
		searchPanel.add(filterText);
		searchPanel.add(searchButton);
		searchPanel.add(filterButton);
		searchPanel.add(settingsButton);
		tableControlPanel.add(searchPanel, BorderLayout.CENTER);

		tableControlPanel.add(topActionsPanel, BorderLayout.EAST);
		topPanel.add(tableControlPanel, BorderLayout.NORTH);

		tableFilterInfoLabel.putClientProperty("html.disable", null);
		topPanel.add(tableFilterInfoLabel, BorderLayout.CENTER);
		pendingRequestsLabel.setForeground(new Color(240, 110, 0));
		pendingRequestsLabel.setVisible(false);
		topPanel.add(pendingRequestsLabel, BorderLayout.SOUTH);
		
		tablePanel.add(new JScrollPane(topPanel, JScrollPane.VERTICAL_SCROLLBAR_NEVER, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED), BorderLayout.NORTH);
	
		loadTableSettings();
		initTableWithModel();		
		table.setDefaultRenderer(Integer.class, new BypassCellRenderer());
		table.setDefaultRenderer(String.class, new BypassCellRenderer());
		table.setDefaultRenderer(BypassConstants.class, new BypassCellRenderer());	
		tablePanel.add(new JScrollPane(table), BorderLayout.CENTER);

		// Multi-Column Compare Viewer
		JPanel messageViewHeaderPanel = new JPanel(new BorderLayout());
		JLabel compareTitleLabel = new JLabel("Compare View (Side-by-Side User Columns)");
		compareTitleLabel.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0));

		JPanel rightSwitchPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 4));
		JLabel switchLabel = new JLabel("View:");
		ButtonGroup viewGroup = new ButtonGroup();
		viewGroup.add(requestToggleButton);
		viewGroup.add(responseToggleButton);
		requestToggleButton.setSelected(true);
		requestToggleButton.addActionListener(e -> setViewMode(0));
		responseToggleButton.addActionListener(e -> setViewMode(1));
		rightSwitchPanel.add(switchLabel);
		rightSwitchPanel.add(requestToggleButton);
		rightSwitchPanel.add(responseToggleButton);

		messageViewHeaderPanel.add(compareTitleLabel, BorderLayout.WEST);
		messageViewHeaderPanel.add(rightSwitchPanel, BorderLayout.EAST);

		columnsContainer = new JPanel(new GridLayout(1, 0, 8, 0)) {
			private static final long serialVersionUID = 1L;
			@Override
			public Dimension getPreferredSize() {
				int colCount = Math.max(1, getComponentCount());
				int minWidth = colCount * 360;
				int viewWidth = columnsScrollPane != null && columnsScrollPane.getViewport() != null ?
						columnsScrollPane.getViewport().getWidth() : 0;
				int w = Math.max(minWidth, viewWidth);
				int h = columnsScrollPane != null && columnsScrollPane.getViewport() != null ?
						Math.max(200, columnsScrollPane.getViewport().getHeight()) : 200;
				return new Dimension(w, h);
			}
		};

		columnsScrollPane = new JScrollPane(columnsContainer, JScrollPane.VERTICAL_SCROLLBAR_NEVER, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		columnsScrollPane.getHorizontalScrollBar().setUnitIncrement(16);

		messageViewPanel = new JPanel(new BorderLayout());
		messageViewPanel.setBorder(BorderFactory.createLineBorder(Color.GRAY));
		messageViewPanel.add(messageViewHeaderPanel, BorderLayout.NORTH);
		messageViewPanel.add(columnsScrollPane, BorderLayout.CENTER);

		splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePanel, messageViewPanel);
		splitPane.setDividerSize(6);
		splitPane.setResizeWeight(0.5d);
		add(splitPane, BorderLayout.CENTER);

		selectionModel = table.getSelectionModel();
		selectionModel.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) { 
				changeRequestResponseView(false);
			}
		});
		setupTableContextMenu();
	}

	private void loadTableSettings() {
		String savedSettings = null;
		if (BurpExtender.callbacks != null) {
			savedSettings = BurpExtender.callbacks.loadExtensionSetting(TABLE_SETTINGS);
		}
		if (savedSettings != null) {
			String[] split = savedSettings.split(",");
			for (String columnAsString : split) {
				for (Column column : Column.values()) {
					if (columnAsString.equals(column.toString())) {
						columnSet.add(column);
					}
				}
			}
		} else {
			for (Column column : Column.getDefaultSet()) {
				columnSet.add(column);
			}
		}
	}

	public void setViewMode(int mode) {
		this.activeViewMode = mode;
		if (mode == 0) {
			requestToggleButton.setSelected(true);
		} else {
			responseToggleButton.setSelected(true);
		}
		for (SessionColumnView view : columnViews) {
			view.setViewMode(mode);
		}
		if (columnsContainer != null) {
			columnsContainer.revalidate();
			columnsContainer.repaint();
		}
	}

	public void notifyViewModeChanged(int mode) {
		setViewMode(mode);
	}

	public int getActiveViewMode() {
		return activeViewMode;
	}

	public List<Session> getSessions() {
		return CurrentConfig.getCurrentConfig().getSessions();
	}

	public ArrayList<Session> getSessionsForExport() {
		return new ArrayList<Session>(getSessions());
	}

	private void setupTableContextMenu() {
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent event) {
				if (event.getButton() == MouseEvent.BUTTON3) {
					int[] rows = table.getSelectedRows();
					ArrayList<OriginalRequestResponse> requestResponseList = new ArrayList<OriginalRequestResponse>();
					for (int row : rows) {
						int modelRow = table.convertRowIndexToModel(row);
						requestResponseList.add(tableModel.getOriginalRequestResponse(modelRow));
					}
					if (requestResponseList.size() > 0) {
						JPopupMenu contextMenu = new JPopupMenu();
						JMenuItem markRowItem = new JMenuItem("Mark Row");
						markRowItem.addActionListener(e -> {
							for (OriginalRequestResponse requestResponse : requestResponseList) {
								requestResponse.setMarked(true);
							}
							tableModel.fireTableDataChanged();
						});
						JMenuItem unmarkRowItem = new JMenuItem("Unmark Row");
						unmarkRowItem.addActionListener(e -> {
							for (OriginalRequestResponse requestResponse : requestResponseList) {
								requestResponse.setMarked(false);
							}
							tableModel.fireTableDataChanged();
						});
						JMenuItem repeatRequestItem = new JMenuItem("Repeat Request");
						repeatRequestItem.addActionListener(e -> {
							Collections.sort(requestResponseList);
							IHttpRequestResponse[] messages = new IHttpRequestResponse[requestResponseList.size()];
							for (int i=0; i<requestResponseList.size(); i++) {
								messages[i] = requestResponseList.get(i).getRequestResponse();
							}
							if (mainPanel != null && mainPanel.getConfigurationPanel() != null) {
								GenericHelper.repeatRequests(messages, mainPanel.getConfigurationPanel());
							}
						});
						JMenuItem deleteRowItem = new JMenuItem("Delete Row");
						deleteRowItem.addActionListener(e -> {
							for (OriginalRequestResponse requestResponse : requestResponseList) {
								tableModel.deleteRequestResponse(requestResponse);
							}
						});
						JMenuItem commentItem = new JMenuItem("Comment");
						commentItem.addActionListener(e -> {
							if (requestResponseList.size() > 0) {
								JTextArea commentTextArea = new JTextArea(requestResponseList.get(0).getComment(), 2,
										8);
								JOptionPane.showMessageDialog(commentItem, new JScrollPane(commentTextArea), "Comment",
										JOptionPane.INFORMATION_MESSAGE);
								for (OriginalRequestResponse requestResponse : requestResponseList) {
									requestResponse.setComment(commentTextArea.getText());
								}
							}
						});
						if (rows.length == 1) {
							if (requestResponseList.get(0).isMarked()) {
								contextMenu.add(unmarkRowItem);
							} else {
								contextMenu.add(markRowItem);
							}
						} else {
							contextMenu.add(markRowItem);
							contextMenu.add(unmarkRowItem);
						}
						contextMenu.add(repeatRequestItem);
						contextMenu.add(deleteRowItem);
						contextMenu.add(commentItem);
						contextMenu.show(event.getComponent(), event.getX(), event.getY());
					}
				}
			}
		});
	}

	public void initCenterPanel() {
		initTableWithModel();
		selectedId = -1;
		columnsContainer.removeAll();
		columnViews.clear();
		columnsContainer.revalidate();
		columnsContainer.repaint();
	}

	public void clearTable() {
		tableModel.clearRequestMap();
		selectedId = -1;
		columnsContainer.removeAll();
		columnViews.clear();
		columnsContainer.revalidate();
		columnsContainer.repaint();
	}

	private void clearTablePressed() {
		int result = JOptionPane.showConfirmDialog(this, "Are you sure you want to clear table?", "Warning", JOptionPane.YES_NO_OPTION);
		if(result == JOptionPane.YES_OPTION) {
			clearTable();
		}
	}

	protected void initTableWithModel() {
		tableModel = createTableModel();
		if (tableModel == null) {
			tableModel = new RequestTableModel();
		}
		table.setModel(tableModel);
		if (isLiveHistory()) {
			config.setTableModel(tableModel);
		}
		sorter = new CustomRowSorter(this, tableModel, showOnlyMarked, showDuplicates, showBypassed, 
				showPotentialBypassed, showNotBypassed, showNA, filterText, searchInPath, searchInRequest, searchInResponse, negativeSearch,
				methodFilterDropDown);
		sorter.addRowSorterListener(new RowSorterListener() {
			@Override
			public void sorterChanged(RowSorterEvent e) {
				updateTableFilterInfo();
			}
		});
        table.setRowSorter(sorter);

		TableCellRenderer defaultHeaderRenderer = table.getTableHeader().getDefaultRenderer();
		table.getTableHeader().setDefaultRenderer(new TableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
				Component c = defaultHeaderRenderer.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
				if (value != null) {
					String valStr = value.toString();
					if (valStr.endsWith("Status Code") || valStr.equals("Original Status Code")) {
						c.setBackground(new Color(64, 150, 255, 60));
					} else if (valStr.endsWith("Length") || valStr.equals("Original Length")) {
						c.setBackground(new Color(46, 204, 113, 60));
					} else if (valStr.endsWith("Diff") || valStr.equals("Original Diff")) {
						c.setBackground(new Color(243, 156, 18, 60));
					}
				}
				return c;
			}
		});

        updateColumnWidths();
	}

	protected RequestTableModel createTableModel() {
		return new RequestTableModel();
	}

	protected boolean isLiveHistory() {
		return true;
	}

	public void updateTableFilterInfo() {
		int totalRows = tableModel.getRowCount();
		int shownRows = table.getRowCount();
		tableFilterInfoLabel.setText("Showing " + shownRows + " of " + totalRows + " Requests");
	}

	public void toggleSearchButtonText() {
		if(filterText.getText() != null && !filterText.getText().equals("")) {
			searchButton.setIcon(loaderImageIcon);
		}
		else {
			searchButton.setIcon(null);
		}
	}

	public void setAmountOfPendingRequests(int amountOfPendingRequests) {
		updateAmountOfPendingRequests(amountOfPendingRequests);
	}

	public void updateAmountOfPendingRequests(int amountOfPendingRequests) {
		if(amountOfPendingRequests == 0) {
			pendingRequestsLabel.setVisible(false);
		}
		else {
			pendingRequestsLabel.setVisible(true);
			pendingRequestsLabel.setText("Pending Requests Queue: " + amountOfPendingRequests);
		}
		tablePanel.revalidate();
	}

	public ArrayList<OriginalRequestResponse> getFilteredRequestResponseList() {
		ArrayList<OriginalRequestResponse> list = new ArrayList<OriginalRequestResponse>();
		for (int row = 0; row < table.getRowCount(); row++) {
			OriginalRequestResponse requestResponse = tableModel
					.getOriginalRequestResponse(table.convertRowIndexToModel(row));
			list.add(requestResponse);
		}
		return list;
	}

	public void updateDiffPane() {
		// Diff pane replaced by side-by-side columns
	}

	public void updateOtherTabbedPane(int tabbedPaneId, int index) {
		// Replaced by side-by-side columns
	} 

	protected void changeRequestResponseView(boolean force) {
		if (table.getSelectedRow() != -1) {
			int modelRowIndex = -1;
			try {
				modelRowIndex = table.convertRowIndexToModel(table.getSelectedRow());
			} catch (Exception ex) {
				return;
			}
			OriginalRequestResponse originalRequestResponse = tableModel.getOriginalRequestResponse(modelRowIndex);
			if (force || (originalRequestResponse != null && selectedId != originalRequestResponse.getId())) {
				if (originalRequestResponse == null) {
					return;
				}
				selectedId = originalRequestResponse.getId();
				columnsContainer.removeAll();
				columnViews.clear();

				// 1. Column for Original
				Component reqOrigComp = null;
				Component respOrigComp = null;
				if (originalRequestResponse.getRequestResponse() != null) {
					IMessageEditorController controllerOriginal = new CustomIMessageEditorController(
							originalRequestResponse.getRequestResponse().getHttpService(),
							originalRequestResponse.getRequestResponse().getRequest(),
							originalRequestResponse.getRequestResponse().getResponse());
					if (BurpExtender.callbacks != null) {
						IMessageEditor reqEd = BurpExtender.callbacks.createMessageEditor(controllerOriginal, false);
						reqEd.setMessage(originalRequestResponse.getRequestResponse().getRequest(), true);
						reqOrigComp = reqEd.getComponent();

						if (originalRequestResponse.getRequestResponse().getResponse() != null) {
							IMessageEditor respEd = BurpExtender.callbacks.createMessageEditor(controllerOriginal, false);
							respEd.setMessage(originalRequestResponse.getRequestResponse().getResponse(), false);
							respOrigComp = respEd.getComponent();
						}
					}
				}
				String origInfo = originalRequestResponse.getStatusCode() + " | " + originalRequestResponse.getResponseContentLength() + " B";
				SessionColumnView origCol = new SessionColumnView("Original", origInfo, new Color(225, 238, 255), reqOrigComp, respOrigComp);
				columnViews.add(origCol);
				columnsContainer.add(origCol.panel);

				// 2. Columns for each user session
				for (Session session : getSessions()) {
					AnalyzerRequestResponse arr = session.getRequestResponseMap().get(originalRequestResponse.getId());
					Component reqComp = null;
					Component respComp = null;
					String info = "No Data";
					Color colHeaderBg = null;
					if (arr != null && arr.getRequestResponse() != null) {
						IHttpRequestResponse srr = arr.getRequestResponse();
						IMessageEditorController controller = new CustomIMessageEditorController(
								srr.getHttpService(), srr.getRequest(), srr.getResponse());
						if (BurpExtender.callbacks != null) {
							IMessageEditor reqEd = BurpExtender.callbacks.createMessageEditor(controller, false);
							reqEd.setMessage(srr.getRequest(), true);
							reqComp = reqEd.getComponent();

							if (srr.getResponse() != null) {
								IMessageEditor respEd = BurpExtender.callbacks.createMessageEditor(controller, false);
								respEd.setMessage(srr.getResponse(), false);
								respComp = respEd.getComponent();
							}
						}
						int diff = originalRequestResponse.getResponseContentLength() - arr.getResponseContentLength();
						info = arr.getStatus().getName() + " | " + arr.getStatusCode() + " | " + arr.getResponseContentLength() + " B | Diff: " + diff;
						if (arr.getStatus() == BypassConstants.SAME) {
							colHeaderBg = new Color(255, 120, 120, 90);
						} else if (arr.getStatus() == BypassConstants.SIMILAR) {
							colHeaderBg = new Color(255, 190, 70, 90);
						} else if (arr.getStatus() == BypassConstants.DIFFERENT) {
							colHeaderBg = new Color(90, 225, 110, 90);
						}
					} else if (arr != null) {
						info = arr.getInfoText();
					}
					SessionColumnView sessionCol = new SessionColumnView(session.getName(), info, colHeaderBg, reqComp, respComp);
					columnViews.add(sessionCol);
					columnsContainer.add(sessionCol.panel);
				}

				// Apply active view mode to all columns
				for (SessionColumnView view : columnViews) {
					view.setViewMode(activeViewMode);
				}
				columnsContainer.revalidate();
				columnsContainer.repaint();
			}
		}
	}

	protected void updateColumnWidths() {		
		for (Column column : Column.values()) {
			if (!columnSet.contains(column)) {
				for(int i=0; i<table.getColumnModel().getColumnCount(); i++) {
					String columnName = table.getColumnModel().getColumn(i).getHeaderValue().toString();
					if(columnName.endsWith(column.toString())) {
						table.getColumnModel().getColumn(i).setMinWidth(0);
						table.getColumnModel().getColumn(i).setMaxWidth(0);
					}
				}
			} else {
				if (column == Column.ID) {
					table.getColumnModel().getColumn(getColumnIdByName(Column.ID)).setMaxWidth(40);
					table.getColumnModel().getColumn(getColumnIdByName(Column.ID)).setPreferredWidth(40);
				} else if (column == Column.Host) {
					table.getColumnModel().getColumn(getColumnIdByName(Column.Host)).setMaxWidth(10000);
					table.getColumnModel().getColumn(getColumnIdByName(Column.Host)).setPreferredWidth(200);
				} else if (column == Column.Path) {
					table.getColumnModel().getColumn(getColumnIdByName(Column.Path)).setMaxWidth(10000);
					table.getColumnModel().getColumn(getColumnIdByName(Column.Path)).setPreferredWidth(400);
				} else {
					for(int i=0; i<table.getColumnModel().getColumnCount(); i++) {
						String currentColumnName = table.getColumnModel().getColumn(i).getHeaderValue().toString();
						if(currentColumnName.endsWith(column.toString())) {
							table.getColumnModel().getColumn(i).setMaxWidth(10000);
							table.getColumnModel().getColumn(i).setPreferredWidth(80);
						}
					}
				}
			}
		}
	}

	private int getColumnIdByName(Column column) {
		for(int i=0; i<table.getColumnModel().getColumnCount(); i++) {
			if(table.getColumnModel().getColumn(i).getHeaderValue().toString().equals(column.toString())) {
				return i;
			}
		}
		return -1;
	}

	private void showTableFilterDialog(Component parent) {
		JPanel inputPanel = new JPanel();
		inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.Y_AXIS));
		inputPanel.add(showOnlyMarked);
		inputPanel.add(showDuplicates);
		inputPanel.add(showBypassed);
		inputPanel.add(showPotentialBypassed);
		inputPanel.add(showNotBypassed);
		inputPanel.add(showNA);
		JOptionPane.showConfirmDialog(parent, inputPanel, "Filter Table", JOptionPane.CLOSED_OPTION);
	}

	private void showTableSettingsDialog(Component parent) {
		JPanel inputPanel = new JPanel();
		inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.Y_AXIS));
		for (Column column : Column.values()) {
			JCheckBox columnCheckBox = new JCheckBox(column.toString(), columnSet.contains(column));
			columnCheckBox.addActionListener(e -> {
				if (columnCheckBox.isSelected()) {
					columnSet.add(column);
				} else {
					columnSet.remove(column);
				}
				updateColumnWidths();
			});
			inputPanel.add(columnCheckBox);
		}
		JOptionPane.showConfirmDialog(parent, inputPanel, "Show / Hide Columns", JOptionPane.CLOSED_OPTION);
		String saveString = columnSet.toString().replaceAll(" ", "").replace("[", "").replace("]", "");
		if (BurpExtender.callbacks != null) {
			BurpExtender.callbacks.saveExtensionSetting(TABLE_SETTINGS, saveString);
		}
	}

	public JTable getTable() {
		return table;
	}

	public RequestTableModel getTableModel() {
		return tableModel;
	}

	public JPanel getTablePanel() {
		return tablePanel;
	}

	public JPanel getMessageViewPanel() {
		return messageViewPanel;
	}

	public JSplitPane getSplitPane() {
		return splitPane;
	}

	public JButton getClearTableButton() {
		return clearTableButton;
	}

	public JButton getExportDataButton() {
		return exportDataButton;
	}

	public MethodFilterDropDown_littlespidy getMethodFilterDropDown() {
		return methodFilterDropDown;
	}

	public JLabel getPendingRequestsLabel() {
		return pendingRequestsLabel;
	}

	public MainPanel getMainPanel() {
		return mainPanel;
	}

	public static class CustomIMessageEditorController implements IMessageEditorController {

		private final IHttpService httpService;
		private final byte[] request;
		private final byte[] response;

		public CustomIMessageEditorController(IHttpService httpService, byte[] request, byte[] response) {
			this.httpService = httpService;
			this.request = request;
			this.response = response;
		}

		@Override
		public IHttpService getHttpService() {
			return httpService;
		}

		@Override
		public byte[] getRequest() {
			return request;
		}

		@Override
		public byte[] getResponse() {
			return response;
		}
	}

	public static class SessionColumnView {
		final JPanel panel = new JPanel(new BorderLayout());
		final CardLayout cardLayout = new CardLayout();
		final JPanel cardPanel = new JPanel(cardLayout);

		public SessionColumnView(String title, String info, Color headerBg, Component reqComp, Component respComp) {
			JPanel header = new JPanel(new BorderLayout(5, 2));
			header.setBorder(BorderFactory.createCompoundBorder(
					BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
					BorderFactory.createEmptyBorder(4, 6, 4, 6)));
			if (headerBg != null) {
				header.setBackground(headerBg);
			}
			JLabel titleLabel = new JLabel(title);
			JLabel infoLabel = new JLabel(info);
			header.add(titleLabel, BorderLayout.WEST);
			header.add(infoLabel, BorderLayout.EAST);

			cardPanel.add(reqComp != null ? reqComp : new JLabel("No Request Available", JLabel.CENTER), "REQ");
			cardPanel.add(respComp != null ? respComp : new JLabel("No Response Available", JLabel.CENTER), "RESP");

			panel.setBorder(BorderFactory.createLineBorder(Color.GRAY));
			panel.add(header, BorderLayout.NORTH);
			panel.add(cardPanel, BorderLayout.CENTER);
		}

		public void setViewMode(int mode) {
			if (mode == 0) {
				cardLayout.show(cardPanel, "REQ");
			} else {
				cardLayout.show(cardPanel, "RESP");
			}
		}
	}
}
