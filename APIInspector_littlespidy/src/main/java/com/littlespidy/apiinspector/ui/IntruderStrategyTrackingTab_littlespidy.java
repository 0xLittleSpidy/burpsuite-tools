// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import com.littlespidy.apiinspector.model.IntruderStrategyEntry_littlespidy.GeneratedVariationItem;
import com.littlespidy.apiinspector.model.IntruderStrategyEntry_littlespidy.ReferenceRequestEntry;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Dedicated tracking tab for an Intruder Strategy (API Documentation or API Endpoint Discovery).
 * Displays ingested reference requests, their generated path/auth variations,
 * dispatch statuses, and provides Montoya request inspection and resend controls.
 */
public class IntruderStrategyTrackingTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final String strategyTitle;
    private final List<ReferenceRequestEntry> entries = new ArrayList<>();

    private ReferenceTableModel referenceTableModel;
    private JTable referenceTable;
    private TableRowSorter<ReferenceTableModel> referenceSorter;

    private VariationTableModel variationTableModel;
    private JTable variationTable;
    private TableRowSorter<VariationTableModel> variationSorter;

    private HttpRequestEditor requestEditor;
    private JLabel statsLabel;

    private Runnable onStateChangedCallback;
    private java.util.function.Consumer<com.littlespidy.apiinspector.model.HiddenEndpoint_littlespidy> onSaveToHiddenStorageCallback;

    public IntruderStrategyTrackingTab_littlespidy(MontoyaApi api, String strategyTitle) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.strategyTitle = strategyTitle;

        setBorder(new EmptyBorder(8, 8, 8, 8));
        initComponents();
    }

    private void initComponents() {
        // --- 1. Top Action & Stats Bar ---
        JPanel topBar = new JPanel(new BorderLayout(8, 4));
        topBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                new EmptyBorder(4, 6, 8, 6)
        ));

        JPanel leftTitleBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JLabel titleLabel = new JLabel("Strategy: " + strategyTitle);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));
        leftTitleBox.add(titleLabel);

        statsLabel = new JLabel("Reference Requests: 0 | Total Variations Sent: 0");
        statsLabel.setFont(statsLabel.getFont().deriveFont(Font.PLAIN, 12f));
        statsLabel.setForeground(Color.DARK_GRAY);
        leftTitleBox.add(statsLabel);

        topBar.add(leftTitleBox, BorderLayout.WEST);

        JPanel rightControlsBox = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton resendSelectedBtn = new JButton("Resend Selected to Intruder");
        resendSelectedBtn.setToolTipText("Resend selected variation to Intruder");
        resendSelectedBtn.addActionListener(e -> resendSelectedToIntruder());
        rightControlsBox.add(resendSelectedBtn);

        JButton resendAllBtn = new JButton("Resend All to Intruder");
        resendAllBtn.setToolTipText("Resend all variations for the active reference request to Intruder");
        resendAllBtn.addActionListener(e -> resendAllToIntruder());
        rightControlsBox.add(resendAllBtn);

        JButton clearBtn = new JButton("Clear History");
        clearBtn.setToolTipText("Clear all tracked requests and variations for this strategy");
        clearBtn.addActionListener(e -> clearHistory());
        rightControlsBox.add(clearBtn);

        topBar.add(rightControlsBox, BorderLayout.EAST);
        add(topBar, BorderLayout.NORTH);

        // --- 2. Center: Split Pane (Master: Reference Requests, Detail: Variations) ---
        referenceTableModel = new ReferenceTableModel();
        referenceTable = new JTable(referenceTableModel);
        referenceSorter = new TableRowSorter<>(referenceTableModel);
        referenceSorter.setSortsOnUpdates(true);
        referenceTable.setRowSorter(referenceSorter);
        referenceTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        referenceTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onReferenceSelected();
            }
        });

        JScrollPane refScrollPane = new JScrollPane(referenceTable);
        refScrollPane.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Ingested Reference Requests (Original Reference Endpoints)",
                TitledBorder.LEFT, TitledBorder.TOP
        ));
        refScrollPane.setPreferredSize(new Dimension(800, 160));

        variationTableModel = new VariationTableModel();
        variationTable = new JTable(variationTableModel);
        variationSorter = new TableRowSorter<>(variationTableModel);
        variationSorter.setSortsOnUpdates(true);
        variationTable.setRowSorter(variationSorter);
        variationTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        variationTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onVariationSelected();
            }
        });

        setupVariationContextMenu();

        JScrollPane varScrollPane = new JScrollPane(variationTable);
        varScrollPane.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Generated Intruder Variations (Authenticated and Unauthenticated)",
                TitledBorder.LEFT, TitledBorder.TOP
        ));
        varScrollPane.setPreferredSize(new Dimension(800, 200));

        JSplitPane tablesSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, refScrollPane, varScrollPane);
        tablesSplit.setResizeWeight(0.4);
        tablesSplit.setDividerLocation(180);

        // --- 3. Bottom: Montoya Request Viewer ---
        JPanel bottomViewerPanel = new JPanel(new BorderLayout());
        bottomViewerPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Generated Request Preview (Montoya Viewer)",
                TitledBorder.LEFT, TitledBorder.TOP
        ));

        Component editorComp;
        if (api != null && api.userInterface() != null) {
            requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
            editorComp = requestEditor.uiComponent();
        } else {
            editorComp = new JScrollPane(new JTextArea("Burp UI not connected (standalone / test mode)."));
        }
        bottomViewerPanel.add(editorComp, BorderLayout.CENTER);
        bottomViewerPanel.setPreferredSize(new Dimension(800, 220));

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablesSplit, bottomViewerPanel);
        mainSplit.setResizeWeight(0.65);
        mainSplit.setDividerLocation(380);

        add(mainSplit, BorderLayout.CENTER);
    }

    public synchronized void addReferenceEntry(ReferenceRequestEntry entry) {
        entries.add(entry);
        referenceTableModel.fireTableRowsInserted(entries.size() - 1, entries.size() - 1);
        updateStats();

        // Automatically select newest entry
        int lastRow = referenceTable.getRowCount() - 1;
        if (lastRow >= 0) {
            referenceTable.setRowSelectionInterval(lastRow, lastRow);
        }

        if (onStateChangedCallback != null) {
            onStateChangedCallback.run();
        }
    }

    public synchronized void restoreEntries(List<ReferenceRequestEntry> restored) {
        entries.clear();
        if (restored != null) {
            entries.addAll(restored);
        }
        referenceTableModel.fireTableDataChanged();
        updateStats();

        if (!entries.isEmpty()) {
            referenceTable.setRowSelectionInterval(0, 0);
        }
    }

    public synchronized List<ReferenceRequestEntry> getAllEntries() {
        return new ArrayList<>(entries);
    }

    public void setOnStateChangedCallback(Runnable callback) {
        this.onStateChangedCallback = callback;
    }

    private void onReferenceSelected() {
        int viewRow = referenceTable.getSelectedRow();
        if (viewRow == -1) {
            variationTableModel.setVariations(null);
            if (requestEditor != null) requestEditor.setRequest(null);
            return;
        }

        int modelRow = referenceTable.convertRowIndexToModel(viewRow);
        if (modelRow >= 0 && modelRow < entries.size()) {
            ReferenceRequestEntry entry = entries.get(modelRow);
            variationTableModel.setVariations(entry.getVariations());
            if (!entry.getVariations().isEmpty()) {
                variationTable.setRowSelectionInterval(0, 0);
            } else if (requestEditor != null && entry.getReferenceRequest() != null) {
                requestEditor.setRequest(entry.getReferenceRequest());
            }
        }
    }

    private void onVariationSelected() {
        int viewRow = variationTable.getSelectedRow();
        if (viewRow == -1) return;

        int modelRow = variationTable.convertRowIndexToModel(viewRow);
        GeneratedVariationItem item = variationTableModel.getItemAt(modelRow);
        if (item != null && requestEditor != null && item.getGeneratedRequest() != null) {
            requestEditor.setRequest(item.getGeneratedRequest());
        }
    }

    private void resendSelectedToIntruder() {
        int viewRow = variationTable.getSelectedRow();
        if (viewRow == -1) {
            JOptionPane.showMessageDialog(this, "Please select a variation to send to Intruder.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = variationTable.convertRowIndexToModel(viewRow);
        GeneratedVariationItem item = variationTableModel.getItemAt(modelRow);
        if (item != null && item.getGeneratedRequest() != null && api != null && api.intruder() != null) {
            api.intruder().sendToIntruder(item.getGeneratedRequest());
            JOptionPane.showMessageDialog(this, "Resent variation #" + item.getVariationIndex() + " to Intruder.", "Success", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void resendAllToIntruder() {
        int viewRow = referenceTable.getSelectedRow();
        if (viewRow == -1) {
            JOptionPane.showMessageDialog(this, "Please select a reference request first.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = referenceTable.convertRowIndexToModel(viewRow);
        if (modelRow >= 0 && modelRow < entries.size()) {
            ReferenceRequestEntry entry = entries.get(modelRow);
            if (api != null && api.intruder() != null) {
                for (GeneratedVariationItem item : entry.getVariations()) {
                    if (item.getGeneratedRequest() != null) {
                        api.intruder().sendToIntruder(item.getGeneratedRequest());
                    }
                }
                JOptionPane.showMessageDialog(this, "Resent all " + entry.getVariations().size() + " variations to Intruder.", "Success", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    private void clearHistory() {
        int opt = JOptionPane.showConfirmDialog(this, "Clear all tracked history for " + strategyTitle + "?", "Confirm Clear", JOptionPane.YES_NO_OPTION);
        if (opt == JOptionPane.YES_OPTION) {
            entries.clear();
            referenceTableModel.fireTableDataChanged();
            variationTableModel.setVariations(null);
            if (requestEditor != null) requestEditor.setRequest(null);
            updateStats();

            if (onStateChangedCallback != null) {
                onStateChangedCallback.run();
            }
        }
    }

    private void exportCsv() {
        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No tracked data to export.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        String safeName = strategyTitle.toLowerCase().replaceAll("[^a-z0-9]+", "_");
        fileChooser.setSelectedFile(new File(safeName + "_tracking.csv"));
        int ret = fileChooser.showSaveDialog(this);
        if (ret == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (FileWriter writer = new FileWriter(file)) {
                writer.write("Ref ID,Timestamp,Method,Original Path,Host,Var Index,Path Variation,Auth Mode,Intruder Status,Full URL\n");
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

                for (ReferenceRequestEntry ref : entries) {
                    String timeStr = sdf.format(new Date(ref.getTimestamp()));
                    for (GeneratedVariationItem var : ref.getVariations()) {
                        writer.write(String.format("%d,\"%s\",\"%s\",\"%s\",\"%s\",%d,\"%s\",\"%s\",\"%s\",\"%s\"\n",
                                ref.getId(),
                                timeStr,
                                ref.getMethod(),
                                ref.getOriginalPath(),
                                ref.getHost(),
                                var.getVariationIndex(),
                                var.getPathVariation(),
                                var.isAuthenticated() ? "Authenticated" : "Unauthenticated",
                                var.getIntruderStatus(),
                                var.getFullUrl()
                        ));
                    }
                }
                JOptionPane.showMessageDialog(this, "Exported successfully to " + file.getName(), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void updateStats() {
        int totalVars = 0;
        for (ReferenceRequestEntry r : entries) {
            totalVars += r.getVariations().size();
        }
        statsLabel.setText("Reference Requests: " + entries.size() + " | Total Variations Sent: " + totalVars);
    }

    private void setupVariationContextMenu() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem resend = new JMenuItem("Send to Intruder");
        resend.addActionListener(e -> resendSelectedToIntruder());
        menu.add(resend);

        JMenuItem repeater = new JMenuItem("Send to Repeater");
        repeater.addActionListener(e -> {
            int viewRow = variationTable.getSelectedRow();
            if (viewRow != -1 && api != null && api.repeater() != null) {
                int modelRow = variationTable.convertRowIndexToModel(viewRow);
                GeneratedVariationItem item = variationTableModel.getItemAt(modelRow);
                if (item != null && item.getGeneratedRequest() != null) {
                    api.repeater().sendToRepeater(item.getGeneratedRequest(), "Var #" + item.getVariationIndex() + " " + item.getPathVariation());
                }
            }
        });
        menu.add(repeater);

        JMenuItem saveToStorage = new JMenuItem("Save to Hidden API Storage");
        saveToStorage.addActionListener(e -> {
            int viewRow = variationTable.getSelectedRow();
            if (viewRow != -1 && onSaveToHiddenStorageCallback != null) {
                int modelRow = variationTable.convertRowIndexToModel(viewRow);
                GeneratedVariationItem item = variationTableModel.getItemAt(modelRow);
                if (item != null && item.getGeneratedRequest() != null) {
                    HttpRequest req = item.getGeneratedRequest();
                    String method = req.method() != null ? req.method() : "GET";
                    String url = item.getFullUrl() != null ? item.getFullUrl() : req.url();
                    com.littlespidy.apiinspector.model.HiddenEndpoint_littlespidy ep =
                            new com.littlespidy.apiinspector.model.HiddenEndpoint_littlespidy(
                                    "Endpoint Discovery",
                                    method,
                                    url,
                                    item.getPathVariation(),
                                    0,
                                    "Discovered variation #" + item.getVariationIndex() + " from " + strategyTitle,
                                    req,
                                    null
                            );
                    onSaveToHiddenStorageCallback.accept(ep);
                }
            }
        });
        menu.add(saveToStorage);

        menu.addSeparator();

        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> {
            int viewRow = variationTable.getSelectedRow();
            if (viewRow != -1) {
                int modelRow = variationTable.convertRowIndexToModel(viewRow);
                GeneratedVariationItem item = variationTableModel.getItemAt(modelRow);
                if (item != null && item.getFullUrl() != null) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(item.getFullUrl()), null);
                }
            }
        });
        menu.add(copyUrl);

        JMenuItem copyReq = new JMenuItem("Copy Request");
        copyReq.addActionListener(e -> {
            int viewRow = variationTable.getSelectedRow();
            if (viewRow != -1) {
                int modelRow = variationTable.convertRowIndexToModel(viewRow);
                GeneratedVariationItem item = variationTableModel.getItemAt(modelRow);
                if (item != null && item.getGeneratedRequest() != null) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(item.getGeneratedRequest().toString()), null);
                }
            }
        });
        menu.add(copyReq);

        variationTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) { handlePopup(e); }
            @Override
            public void mouseReleased(MouseEvent e) { handlePopup(e); }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int r = variationTable.rowAtPoint(e.getPoint());
                    if (r >= 0 && r < variationTable.getRowCount()) {
                        variationTable.setRowSelectionInterval(r, r);
                    }
                    menu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }

    public void setOnSaveToHiddenStorageCallback(java.util.function.Consumer<com.littlespidy.apiinspector.model.HiddenEndpoint_littlespidy> callback) {
        this.onSaveToHiddenStorageCallback = callback;
    }

    // --- Table Models ---

    private class ReferenceTableModel extends AbstractTableModel {
        private final String[] COLUMNS = {"#", "Time", "Method", "Host", "Original Path", "Variations Sent"};
        private final Class<?>[] CLASSES = {Integer.class, String.class, String.class, String.class, String.class, Integer.class};
        private final SimpleDateFormat timeFmt = new SimpleDateFormat("HH:mm:ss");

        @Override
        public int getRowCount() { return entries.size(); }
        @Override
        public int getColumnCount() { return COLUMNS.length; }
        @Override
        public String getColumnName(int col) { return COLUMNS[col]; }
        @Override
        public Class<?> getColumnClass(int col) { return CLASSES[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            if (row < 0 || row >= entries.size()) return null;
            ReferenceRequestEntry r = entries.get(row);
            return switch (col) {
                case 0 -> r.getId();
                case 1 -> timeFmt.format(new Date(r.getTimestamp()));
                case 2 -> r.getMethod();
                case 3 -> r.getHost();
                case 4 -> r.getOriginalPath();
                case 5 -> r.getVariations().size();
                default -> null;
            };
        }
    }

    private static class VariationTableModel extends AbstractTableModel {
        private final String[] COLUMNS = {"Var #", "Path Variation", "Auth Mode", "Intruder Status", "Full URL"};
        private final Class<?>[] CLASSES = {Integer.class, String.class, String.class, String.class, String.class};
        private final List<GeneratedVariationItem> currentList = new ArrayList<>();

        public void setVariations(List<GeneratedVariationItem> items) {
            currentList.clear();
            if (items != null) {
                currentList.addAll(items);
            }
            fireTableDataChanged();
        }

        public GeneratedVariationItem getItemAt(int row) {
            if (row >= 0 && row < currentList.size()) return currentList.get(row);
            return null;
        }

        @Override
        public int getRowCount() { return currentList.size(); }
        @Override
        public int getColumnCount() { return COLUMNS.length; }
        @Override
        public String getColumnName(int col) { return COLUMNS[col]; }
        @Override
        public Class<?> getColumnClass(int col) { return CLASSES[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            if (row < 0 || row >= currentList.size()) return null;
            GeneratedVariationItem item = currentList.get(row);
            return switch (col) {
                case 0 -> item.getVariationIndex();
                case 1 -> item.getPathVariation();
                case 2 -> item.isAuthenticated() ? "Authenticated" : "Unauthenticated";
                case 3 -> item.getIntruderStatus();
                case 4 -> item.getFullUrl();
                default -> null;
            };
        }
    }
}
