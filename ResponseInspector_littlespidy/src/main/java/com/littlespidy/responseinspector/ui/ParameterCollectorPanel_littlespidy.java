// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.responseinspector.engine.ParameterScanner_littlespidy;
import com.littlespidy.responseinspector.engine.ResponseScanEngine;
import com.littlespidy.responseinspector.model.ParameterEntry_littlespidy;
import com.littlespidy.responseinspector.model.ParameterOccurrence_littlespidy;
import com.littlespidy.responseinspector.model.ParameterSource_littlespidy;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * UI Panel for the Parameter Collector tab.
 * Displays deduplicated parameters with occurrence navigation controls.
 */
public class ParameterCollectorPanel_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final ResponseScanEngine scanEngine;
    private final Runnable refreshBadgeCallback;

    private final ParameterScanner_littlespidy parameterScanner = new ParameterScanner_littlespidy();
    private final Map<String, ParameterEntry_littlespidy> parameterMap = new ConcurrentHashMap<>();

    private final ParameterTableModel_littlespidy tableModel = new ParameterTableModel_littlespidy();
    private final JTable table;
    private final TableRowSorter<ParameterTableModel_littlespidy> sorter;

    private final HttpRequestEditor reqEditor;
    private final HttpResponseEditor respEditor;
    private final JPanel occurrenceNumbersPanel;
    private final JLabel occurrenceInfoLabel;

    private final JButton runBtn;
    private final JButton clearBtn;
    private final JTextField searchField;
    private final JComboBox<String> sourceFilterCombo;
    private final JComboBox<String> formatFilterCombo;
    private final JLabel statsLabel;
    private final JLabel liveStatusLabel;
    private final JProgressBar progressBar;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private ParameterEntry_littlespidy selectedEntry = null;
    private int currentOccurrenceIndex = 0;

    public ParameterCollectorPanel_littlespidy(MontoyaApi api, ResponseScanEngine scanEngine, Runnable refreshBadgeCallback) {
        this.api = api;
        this.scanEngine = scanEngine;
        this.refreshBadgeCallback = refreshBadgeCallback;

        setLayout(new BorderLayout());

        // ─── Top Toolbar ──────────────────────────────────────────────────────────
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        toolbar.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));

        runBtn = new JButton("Run");
        runBtn.setFont(runBtn.getFont().deriveFont(Font.BOLD));
        runBtn.setToolTipText("Run parameter collection analysis on all loaded traffic");
        runBtn.addActionListener(e -> runAnalysis());
        toolbar.add(runBtn);

        clearBtn = new JButton("Clear");
        clearBtn.setToolTipText("Clear all collected parameters");
        clearBtn.addActionListener(e -> clearFindings());
        toolbar.add(clearBtn);

        toolbar.add(new JSeparator(SwingConstants.VERTICAL));

        toolbar.add(new JLabel("Search:"));
        searchField = new JTextField(12);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { applyFilters(); }
            @Override
            public void removeUpdate(DocumentEvent e) { applyFilters(); }
            @Override
            public void changedUpdate(DocumentEvent e) { applyFilters(); }
        });
        toolbar.add(searchField);

        toolbar.add(new JLabel("Source:"));
        sourceFilterCombo = new JComboBox<>(new String[]{"All", "Request Body", "Response Body", "Both"});
        sourceFilterCombo.addActionListener(e -> applyFilters());
        toolbar.add(sourceFilterCombo);

        toolbar.add(new JLabel("Format:"));
        formatFilterCombo = new JComboBox<>(new String[]{"All", "JSON", "Form", "Multipart", "HTML", "XML"});
        formatFilterCombo.addActionListener(e -> applyFilters());
        toolbar.add(formatFilterCombo);

        statsLabel = new JLabel("Parameters: 0");
        statsLabel.setFont(statsLabel.getFont().deriveFont(Font.BOLD));
        toolbar.add(statsLabel);

        liveStatusLabel = new JLabel("");
        liveStatusLabel.setForeground(new Color(60, 110, 180));
        toolbar.add(liveStatusLabel);

        progressBar = new JProgressBar();
        progressBar.setPreferredSize(new Dimension(100, 16));
        progressBar.setVisible(false);
        toolbar.add(progressBar);

        add(toolbar, BorderLayout.NORTH);

        // ─── Center: Master Table ──────────────────────────────────────────────────
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        // Column widths
        table.getColumnModel().getColumn(0).setPreferredWidth(45);
        table.getColumnModel().getColumn(0).setMaxWidth(60);
        table.getColumnModel().getColumn(1).setPreferredWidth(180);
        table.getColumnModel().getColumn(2).setPreferredWidth(100);
        table.getColumnModel().getColumn(3).setPreferredWidth(90);
        table.getColumnModel().getColumn(4).setPreferredWidth(80);
        table.getColumnModel().getColumn(5).setPreferredWidth(320);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onTableRowSelected();
            }
        });

        // Context Menu
        setupTableContextMenu();

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(600, 260));

        // ─── Detail: Request & Response Pane + Occurrence Switcher ────────────────
        if (api != null && api.userInterface() != null) {
            reqEditor = api.userInterface().createHttpRequestEditor();
            respEditor = api.userInterface().createHttpResponseEditor();
        } else {
            reqEditor = null;
            respEditor = null;
        }

        JSplitPane editorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        editorSplit.setResizeWeight(0.5);

        JPanel reqPanel = new JPanel(new BorderLayout());
        reqPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        if (reqEditor != null) {
            reqPanel.add(reqEditor.uiComponent(), BorderLayout.CENTER);
        }

        JPanel respPanel = new JPanel(new BorderLayout());
        respPanel.setBorder(BorderFactory.createTitledBorder("Response"));
        if (respEditor != null) {
            respPanel.add(respEditor.uiComponent(), BorderLayout.CENTER);
        }

        editorSplit.setLeftComponent(reqPanel);
        editorSplit.setRightComponent(respPanel);

        // Right side occurrence navigation panel
        JPanel occurrenceSidePanel = new JPanel(new BorderLayout(4, 4));
        occurrenceSidePanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Occurrences"),
                BorderFactory.createEmptyBorder(4, 4, 4, 4)
        ));
        occurrenceSidePanel.setPreferredSize(new Dimension(170, 200));

        occurrenceInfoLabel = new JLabel("No parameter selected");
        occurrenceInfoLabel.setFont(occurrenceInfoLabel.getFont().deriveFont(Font.PLAIN, 11f));
        occurrenceSidePanel.add(occurrenceInfoLabel, BorderLayout.NORTH);

        occurrenceNumbersPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        JScrollPane numbersScroll = new JScrollPane(occurrenceNumbersPanel);
        numbersScroll.setBorder(BorderFactory.createEmptyBorder());
        occurrenceSidePanel.add(numbersScroll, BorderLayout.CENTER);

        JPanel detailContainer = new JPanel(new BorderLayout());
        detailContainer.add(editorSplit, BorderLayout.CENTER);
        detailContainer.add(occurrenceSidePanel, BorderLayout.EAST);

        // Root Split: Master Table on Top, Detail on Bottom
        JSplitPane rootSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailContainer);
        rootSplit.setResizeWeight(0.45);
        add(rootSplit, BorderLayout.CENTER);
    }

    private void onTableRowSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            selectedEntry = null;
            clearDetailViews();
            return;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);
        selectedEntry = tableModel.getEntryAt(modelRow);
        if (selectedEntry == null || selectedEntry.getOccurrences().isEmpty()) {
            clearDetailViews();
            return;
        }

        currentOccurrenceIndex = 0;
        updateOccurrenceButtons();
        displayOccurrence(0);
    }

    private void updateOccurrenceButtons() {
        occurrenceNumbersPanel.removeAll();
        if (selectedEntry == null) {
            occurrenceInfoLabel.setText("No selection");
            occurrenceNumbersPanel.revalidate();
            occurrenceNumbersPanel.repaint();
            return;
        }

        List<ParameterOccurrence_littlespidy> list = selectedEntry.getOccurrences();
        int total = list.size();
        occurrenceInfoLabel.setText("Total occurrences: " + total);

        for (int i = 0; i < total; i++) {
            final int index = i;
            JButton btn = new JButton(String.valueOf(i + 1));
            btn.setMargin(new Insets(2, 6, 2, 6));
            btn.setFont(btn.getFont().deriveFont(index == currentOccurrenceIndex ? Font.BOLD : Font.PLAIN, 11f));
            if (index == currentOccurrenceIndex) {
                btn.setBackground(new Color(215, 230, 250));
            }

            btn.addActionListener(e -> {
                currentOccurrenceIndex = index;
                displayOccurrence(index);
                updateOccurrenceButtonsHighlight();
            });

            occurrenceNumbersPanel.add(btn);
        }

        occurrenceNumbersPanel.revalidate();
        occurrenceNumbersPanel.repaint();
    }

    private void updateOccurrenceButtonsHighlight() {
        Component[] components = occurrenceNumbersPanel.getComponents();
        for (int i = 0; i < components.length; i++) {
            if (components[i] instanceof JButton btn) {
                boolean active = (i == currentOccurrenceIndex);
                btn.setFont(btn.getFont().deriveFont(active ? Font.BOLD : Font.PLAIN, 11f));
                if (active) {
                    btn.setBackground(new Color(215, 230, 250));
                } else {
                    btn.setBackground(null);
                }
            }
        }
    }

    private void displayOccurrence(int index) {
        if (selectedEntry == null || index < 0 || index >= selectedEntry.getOccurrences().size()) {
            clearDetailViews();
            return;
        }

        ParameterOccurrence_littlespidy occ = selectedEntry.getOccurrences().get(index);
        HttpRequestResponse hrr = occ.getHttpRequestResponse();
        if (hrr != null) {
            if (reqEditor != null && hrr.request() != null) {
                reqEditor.setRequest(hrr.request());
            }
            if (respEditor != null && hrr.response() != null) {
                respEditor.setResponse(hrr.response());
            }
        }

        String info = String.format("<html><b>#%d of %d</b><br>Source: %s<br>Format: %s<br>Method: %s<br>Status: %d<br>URL: %s</html>",
                index + 1,
                selectedEntry.getOccurrences().size(),
                occ.getSource().getDisplayName(),
                occ.getFormat(),
                occ.getMethod(),
                occ.getStatusCode(),
                occ.getUrl()
        );
        occurrenceInfoLabel.setText(info);
    }

    private void clearDetailViews() {
        if (reqEditor != null) {
            reqEditor.setRequest(null);
        }
        if (respEditor != null) {
            respEditor.setResponse(null);
        }
        occurrenceNumbersPanel.removeAll();
        occurrenceInfoLabel.setText("No selection");
        occurrenceNumbersPanel.revalidate();
        occurrenceNumbersPanel.repaint();
    }

    public void runAnalysis() {
        List<HttpRequestResponse> traffic = scanEngine.getLoadedTraffic();
        if (traffic.isEmpty()) {
            JOptionPane.showMessageDialog(
                    this,
                    "No HTTP traffic has been loaded into Response Inspector yet.\n"
                            + "Please click 'Load Proxy' or 'Load from Repeater' in the top-right toolbar first.",
                    "No Traffic Loaded",
                    JOptionPane.INFORMATION_MESSAGE
            );
            return;
        }

        runBtn.setEnabled(false);
        clearBtn.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(false);
        progressBar.setValue(0);
        progressBar.setMaximum(traffic.size());
        liveStatusLabel.setText("Collecting parameters from " + traffic.size() + " items...");

        parameterMap.clear();

        executor.submit(() -> {
            int processed = 0;
            for (HttpRequestResponse item : traffic) {
                try {
                    parameterScanner.scanItem(item, parameterMap);
                } catch (Exception ex) {
                    if (api != null && api.logging() != null) {
                        api.logging().logToError("Error collecting parameters: " + ex.getMessage());
                    }
                }
                processed++;
                if (processed % 25 == 0 || processed == traffic.size()) {
                    final int current = processed;
                    SwingUtilities.invokeLater(() -> {
                        progressBar.setValue(current);
                        liveStatusLabel.setText("Processed " + current + " / " + traffic.size() + " items...");
                    });
                }
            }

            SwingUtilities.invokeLater(() -> {
                progressBar.setVisible(false);
                runBtn.setEnabled(true);
                clearBtn.setEnabled(true);
                liveStatusLabel.setText("Complete: " + parameterMap.size() + " unique parameters");
                applyFilters();
                if (refreshBadgeCallback != null) {
                    refreshBadgeCallback.run();
                }
            });
        });
    }

    public void clearFindings() {
        parameterMap.clear();
        tableModel.clear();
        clearDetailViews();
        statsLabel.setText("Parameters: 0");
        liveStatusLabel.setText("");
        if (refreshBadgeCallback != null) {
            refreshBadgeCallback.run();
        }
    }

    public int getParameterCount() {
        return parameterMap.size();
    }

    private void applyFilters() {
        String query = searchField.getText().trim().toLowerCase();
        String sourceFilter = (String) sourceFilterCombo.getSelectedItem();
        String formatFilter = (String) formatFilterCombo.getSelectedItem();

        List<ParameterEntry_littlespidy> filtered = parameterMap.values().stream()
                .filter(entry -> {
                    // Search text filter
                    if (!query.isEmpty()) {
                        boolean matchName = entry.getName().toLowerCase().contains(query);
                        boolean matchValues = entry.getSampleValuesDisplay().toLowerCase().contains(query);
                        if (!matchName && !matchValues) {
                            return false;
                        }
                    }

                    // Source filter
                    if (sourceFilter != null && !sourceFilter.equals("All")) {
                        if (!entry.getSourceDisplay().equalsIgnoreCase(sourceFilter)) {
                            return false;
                        }
                    }

                    // Format filter
                    if (formatFilter != null && !formatFilter.equals("All")) {
                        if (!entry.getFormatDisplay().toLowerCase().contains(formatFilter.toLowerCase())) {
                            return false;
                        }
                    }

                    return true;
                })
                .sorted(Comparator.comparingInt(ParameterEntry_littlespidy::getOccurrenceCount).reversed())
                .collect(Collectors.toList());

        tableModel.setEntries(filtered);
        statsLabel.setText("Parameters: " + filtered.size() + " of " + parameterMap.size());
    }

    private void setupTableContextMenu() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem copyNameItem = new JMenuItem("Copy Parameter Name");
        copyNameItem.addActionListener(e -> {
            int viewRow = table.getSelectedRow();
            if (viewRow >= 0) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                ParameterEntry_littlespidy entry = tableModel.getEntryAt(modelRow);
                if (entry != null) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(entry.getName()), null);
                }
            }
        });
        menu.add(copyNameItem);

        JMenuItem copyValuesItem = new JMenuItem("Copy Sample Values");
        copyValuesItem.addActionListener(e -> {
            int viewRow = table.getSelectedRow();
            if (viewRow >= 0) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                ParameterEntry_littlespidy entry = tableModel.getEntryAt(modelRow);
                if (entry != null) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(entry.getSampleValuesDisplay()), null);
                }
            }
        });
        menu.add(copyValuesItem);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showMenu(e);
                }
            }
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showMenu(e);
                }
            }
            private void showMenu(MouseEvent e) {
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0 && !table.isRowSelected(row)) {
                    table.setRowSelectionInterval(row, row);
                }
                if (table.getSelectedRow() >= 0) {
                    menu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }
}
