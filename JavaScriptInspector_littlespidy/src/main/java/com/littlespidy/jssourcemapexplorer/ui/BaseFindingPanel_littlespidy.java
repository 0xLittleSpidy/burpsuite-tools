// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.jssourcemapexplorer.engine.SecretAndEndpointMiner;
import com.littlespidy.jssourcemapexplorer.engine.SourceMapProber;
import com.littlespidy.jssourcemapexplorer.engine.SourceMapUnpacker;
import com.littlespidy.jssourcemapexplorer.model.JsDataStore;
import com.littlespidy.jssourcemapexplorer.model.JsFileEntry;
import com.littlespidy.jssourcemapexplorer.model.PassiveMapStatus;
import com.littlespidy.jssourcemapexplorer.model.UnpackedProject;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Base panel for individual finding tabs (Paths, Secrets, Comments, Security Bypasses,
 * Cloud URLs, Dependencies) featuring:
 * 1. Dedicated Run button that fetches/unpacks source maps and executes mining.
 * 2. Parallel Request and Response editors with equal 50/50 sizing.
 * 3. Multi-select Classification filter (True Positive, False Positive, Not Classified).
 * 4. Custom table renderer highlighting TP in light green and FP in light red.
 * 5. Right-click context menu for marking classification.
 *
 * @author littlespidy
 */
public abstract class BaseFindingPanel_littlespidy extends JPanel {

    protected final MontoyaApi api;
    protected final JsDataStore dataStore;
    protected final SourceMapProber prober;
    private final String categoryTitle;

    // HTTP Editors
    protected final HttpRequestEditor requestEditor;
    protected final HttpResponseEditor responseEditor;

    // Toolbar Controls
    protected final JButton runBtn;
    protected final AtomicBoolean isMining = new AtomicBoolean(false);
    protected MultiSelectFilterButton classificationFilterBtn;
    protected final JTextField searchField = new JTextField(12);
    protected final JLabel statsLabel = new JLabel("Findings: 0");
    protected final JTable table;

    private Runnable onMiningFinished;
    private Runnable autoSaveCallback;

    public BaseFindingPanel_littlespidy(MontoyaApi api, JsDataStore dataStore, String categoryTitle, TableModel tableModel) {
        this.api = api;
        this.dataStore = dataStore;
        this.prober = new SourceMapProber(api);
        this.categoryTitle = categoryTitle;

        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();

        this.runBtn = new JButton("Run " + categoryTitle);
        this.runBtn.setToolTipText("Run " + categoryTitle + " analysis on all JavaScript assets, unpacking source maps if detected");
        this.runBtn.addActionListener(e -> runMining());

        this.table = new JTable(tableModel);
        setupTable();

        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        buildUi();
    }

    public void setOnMiningFinished(Runnable callback) {
        this.onMiningFinished = callback;
    }

    public void setAutoSaveCallback(Runnable callback) {
        this.autoSaveCallback = callback;
    }

    private void buildUi() {
        // ── Top Toolbar ──
        JPanel topToolbar = new JPanel(new BorderLayout(6, 4));
        JPanel leftToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        leftToolbar.add(runBtn);
        leftToolbar.add(new JSeparator(SwingConstants.VERTICAL));

        // Add category-specific filters
        addCategoryFiltersToToolbar(leftToolbar);

        // Classification Filter
        classificationFilterBtn = new MultiSelectFilterButton(
            "Classification",
            List.of("All Classifications", "True Positive", "False Positive", "Not Classified"),
            sel -> applyFilter()
        );
        classificationFilterBtn.setToolTipText("Filter by triage classification (True Positive, False Positive, Not Classified)");
        leftToolbar.add(classificationFilterBtn);

        leftToolbar.add(new JSeparator(SwingConstants.VERTICAL));

        JLabel searchLbl = new JLabel("Search:");
        searchLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        leftToolbar.add(searchLbl);
        searchField.setToolTipText("Search findings");
        searchField.addActionListener(e -> applyFilter());
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            private final javax.swing.Timer timer = new javax.swing.Timer(300, ev -> applyFilter());
            { timer.setRepeats(false); }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { timer.restart(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { timer.restart(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { timer.restart(); }
        });
        leftToolbar.add(searchField);

        JButton filterBtn = new JButton("Filter");
        filterBtn.addActionListener(e -> applyFilter());
        leftToolbar.add(filterBtn);

        JButton resetBtn = new JButton("Reset");
        resetBtn.addActionListener(e -> {
            if (classificationFilterBtn != null) classificationFilterBtn.clearSelection();
            searchField.setText("");
            resetCategoryFilters();
            applyFilter();
        });
        leftToolbar.add(resetBtn);

        JButton exportBtn = new JButton("Export TSV");
        exportBtn.addActionListener(e -> exportTsv(table));
        leftToolbar.add(exportBtn);

        JPanel rightToolbar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        rightToolbar.add(statsLabel);

        topToolbar.add(leftToolbar, BorderLayout.WEST);
        topToolbar.add(rightToolbar, BorderLayout.EAST);

        // ── Findings Table Section (Top) ──
        JPanel tablePanel = new JPanel(new BorderLayout(4, 4));
        tablePanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), categoryTitle + " Findings",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 12)
        ));
        tablePanel.add(new JScrollPane(table), BorderLayout.CENTER);

        // ── Parallel Request & Response Editors (Bottom) ──
        JPanel reqContainer = new JPanel(new BorderLayout());
        reqContainer.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "HTTP Request",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 11)
        ));
        reqContainer.add(requestEditor.uiComponent(), BorderLayout.CENTER);

        JPanel respContainer = new JPanel(new BorderLayout());
        respContainer.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "HTTP Response",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 11)
        ));
        respContainer.add(responseEditor.uiComponent(), BorderLayout.CENTER);

        JSplitPane parallelEditorsSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqContainer, respContainer);
        parallelEditorsSplit.setResizeWeight(0.5);
        parallelEditorsSplit.setDividerLocation(0.5);

        // Master Vertical Split: Table on Top, Parallel Editors on Bottom
        JSplitPane masterSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePanel, parallelEditorsSplit);
        masterSplit.setResizeWeight(0.48);

        add(topToolbar, BorderLayout.NORTH);
        add(masterSplit, BorderLayout.CENTER);
    }

    private void setupTable() {
        table.setRowHeight(22);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setRowSorter(new TableRowSorter<>(table.getModel()));

        // Classification-aware Cell Renderer
        TableCellRenderer classificationRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable tbl, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component comp = super.getTableCellRendererComponent(tbl, value, isSelected, hasFocus, row, col);
                int modelRow = tbl.convertRowIndexToModel(row);
                String classification = getClassificationAt(modelRow);

                boolean dark = isDarkMode();
                if (isSelected) {
                    comp.setBackground(tbl.getSelectionBackground());
                    comp.setForeground(tbl.getSelectionForeground());
                } else {
                    if ("True Positive".equalsIgnoreCase(classification)) {
                        comp.setBackground(dark ? new Color(30, 70, 32) : new Color(220, 245, 220));
                        comp.setForeground(dark ? new Color(210, 255, 210) : new Color(0, 100, 0));
                    } else if ("False Positive".equalsIgnoreCase(classification)) {
                        comp.setBackground(dark ? new Color(80, 25, 25) : new Color(255, 225, 225));
                        comp.setForeground(dark ? new Color(255, 210, 210) : new Color(140, 0, 0));
                    } else {
                        comp.setBackground(dark ? UIManager.getColor("Table.background") : Color.WHITE);
                        comp.setForeground(dark ? UIManager.getColor("Table.foreground") : Color.BLACK);
                    }
                }
                return comp;
            }
        };

        table.setDefaultRenderer(Object.class, classificationRenderer);
        table.setDefaultRenderer(Integer.class, classificationRenderer);
        table.setDefaultRenderer(Double.class, classificationRenderer);
        table.setDefaultRenderer(String.class, classificationRenderer);

        // Selection Listener for deep-linking HTTP editors
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow >= 0) {
                    int modelRow = table.convertRowIndexToModel(selectedRow);
                    handleFindingSelected(modelRow);
                }
            }
        });

        // Context Menu Setup
        setupContextMenu();

        // Keyboard Copy Setup
        setupKeyboardCopy();
    }

    private void setupContextMenu() {
        table.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { handlePopup(e); }
            @Override public void mouseReleased(MouseEvent e) { handlePopup(e); }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int clickedRow = table.rowAtPoint(e.getPoint());
                    int clickedCol = table.columnAtPoint(e.getPoint());
                    if (clickedRow >= 0) {
                        if (!table.isRowSelected(clickedRow)) {
                            table.setRowSelectionInterval(clickedRow, clickedRow);
                        }

                        JPopupMenu menu = new JPopupMenu();

                        // ── Classification Submenu / Items ──
                        JMenuItem tpItem = new JMenuItem("Mark as True Positive");
                        tpItem.addActionListener(ev -> markSelectedClassification("True Positive"));
                        menu.add(tpItem);

                        JMenuItem fpItem = new JMenuItem("Mark as False Positive");
                        fpItem.addActionListener(ev -> markSelectedClassification("False Positive"));
                        menu.add(fpItem);

                        JMenuItem resetClassItem = new JMenuItem("Reset Classification");
                        resetClassItem.addActionListener(ev -> markSelectedClassification("Not Classified"));
                        menu.add(resetClassItem);

                        menu.addSeparator();

                        // ── Copy Items ──
                        Object cellVal = table.getValueAt(clickedRow, clickedCol);
                        String cellStr = cellVal != null ? cellVal.toString() : "";
                        JMenuItem copyCellItem = new JMenuItem("Copy Cell Value");
                        copyCellItem.addActionListener(ev -> copyToClipboard(cellStr));
                        menu.add(copyCellItem);

                        JMenuItem copyFindingItem = new JMenuItem("Copy Finding Text");
                        copyFindingItem.addActionListener(ev -> {
                            int modelRow = table.convertRowIndexToModel(clickedRow);
                            copyToClipboard(getFindingTextAt(modelRow));
                        });
                        menu.add(copyFindingItem);

                        JMenuItem copyLocationItem = new JMenuItem("Copy Source Location");
                        copyLocationItem.addActionListener(ev -> {
                            int modelRow = table.convertRowIndexToModel(clickedRow);
                            copyToClipboard(getSourceLocationAt(modelRow));
                        });
                        menu.add(copyLocationItem);

                        menu.addSeparator();

                        JMenuItem jumpItem = new JMenuItem("Jump to in Response");
                        jumpItem.addActionListener(ev -> {
                            int modelRow = table.convertRowIndexToModel(clickedRow);
                            handleFindingSelected(modelRow);
                        });
                        menu.add(jumpItem);

                        JMenuItem copyTsvItem = new JMenuItem("Copy Selected Row(s) as TSV");
                        copyTsvItem.addActionListener(ev -> exportTsv(table));
                        menu.add(copyTsvItem);

                        menu.show(table, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private void markSelectedClassification(String classification) {
        int[] selectedRows = table.getSelectedRows();
        if (selectedRows.length == 0) return;

        for (int r : selectedRows) {
            int modelRow = table.convertRowIndexToModel(r);
            updateClassification(modelRow, classification);
        }

        applyFilter();
        if (autoSaveCallback != null) {
            autoSaveCallback.run();
        }
    }

    private void setupKeyboardCopy() {
        table.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_C) {
                    int r = table.getSelectedRow();
                    int c = table.getSelectedColumn();
                    if (r >= 0 && c >= 0) {
                        Object val = table.getValueAt(r, c);
                        if (val != null) {
                            copyToClipboard(val.toString());
                            e.consume();
                        }
                    }
                }
            }
        });
    }

    private void handleFindingSelected(int modelRow) {
        String sourceLoc = getSourceLocationAt(modelRow);
        JsFileEntry entry = findEntryForLocation(sourceLoc);

        if (entry == null) {
            requestEditor.setRequest(HttpRequest.httpRequest(""));
            responseEditor.setResponse(HttpResponse.httpResponse(""));
            return;
        }

        if (entry.getRequest() != null) {
            requestEditor.setRequest(entry.getRequest());
        } else {
            requestEditor.setRequest(HttpRequest.httpRequest(""));
        }

        HttpResponse response = entry.getResponse();
        if (response != null) {
            String findingText = getFindingTextAt(modelRow);
            int startOffset = getStartOffsetAt(modelRow);
            int endOffset = getEndOffsetAt(modelRow);

            int rawStart = startOffset;
            int rawEnd = endOffset;
            int bodyOffset = response.bodyOffset();

            if (rawStart >= 0 && rawEnd > rawStart) {
                rawStart += bodyOffset;
                rawEnd += bodyOffset;
            } else if (findingText != null && !findingText.isEmpty()) {
                String rawStr = response.toString();
                int idx = rawStr.indexOf(findingText);
                if (idx >= 0) {
                    rawStart = idx;
                    rawEnd = idx + findingText.length();
                }
            }

            if (rawStart >= 0 && rawEnd > rawStart && rawEnd <= response.toByteArray().length()) {
                try {
                    Marker marker = Marker.marker(Range.range(rawStart, rawEnd));
                    response = response.withMarkers(marker);
                } catch (Exception ignored) {}
            }

            responseEditor.setResponse(response);

            if (findingText != null && !findingText.isEmpty()) {
                try {
                    responseEditor.setSearchExpression(findingText);
                } catch (Exception ignored) {}
            }

            if (rawStart >= 0) {
                final int targetCaret = rawStart;
                SwingUtilities.invokeLater(() -> scrollTextComponent(responseEditor.uiComponent(), targetCaret));
            }
        } else {
            responseEditor.setResponse(HttpResponse.httpResponse(""));
        }
    }

    private JsFileEntry findEntryForLocation(String sourceLocation) {
        if (sourceLocation == null || dataStore == null) return null;
        for (JsFileEntry e : dataStore.getEntries()) {
            if (sourceLocation.equals(e.getUrl())) {
                return e;
            }
            if (sourceLocation.startsWith(e.getUrl()) || (e.getSourceMapLocation() != null && sourceLocation.startsWith(e.getSourceMapLocation()))) {
                return e;
            }
            if (e.getUnpackedProject() != null) {
                if (e.getUnpackedProject().getSourceMapUrl() != null && sourceLocation.startsWith(e.getUnpackedProject().getSourceMapUrl())) {
                    return e;
                }
            }
        }
        return null;
    }

    private void scrollTextComponent(Component c, int caretPos) {
        if (c instanceof JTextArea area) {
            try {
                area.setCaretPosition(Math.min(caretPos, area.getText().length()));
            } catch (Exception ignored) {}
        } else if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                scrollTextComponent(child, caretPos);
            }
        }
    }

    // ── On-Demand Mining Execution ───────────────────────────────────────────
    public void runMining() {
        if (isMining.get()) {
            JOptionPane.showMessageDialog(this, "Mining is already in progress.", "Mining In Progress", JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<JsFileEntry> entries = dataStore != null ? dataStore.getEntries() : Collections.emptyList();
        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No JavaScript files available to mine. Please load Proxy history or capture traffic first.", "Run Mining", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        isMining.set(true);
        runBtn.setEnabled(false);
        runBtn.setText("Running...");

        SwingWorker<Void, Integer> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                int total = entries.size();
                int numThreads = Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()));
                ExecutorService pool = Executors.newFixedThreadPool(numThreads);
                AtomicInteger processed = new AtomicInteger(0);

                try {
                    List<Future<?>> futures = new ArrayList<>(total);
                    for (JsFileEntry entry : entries) {
                        futures.add(pool.submit(() -> {
                            try {
                                // 1. Automatically fetch and unpack detected source maps if not yet unpacked
                                if (!entry.isUnpacked()) {
                                    String mapLoc = entry.getSourceMapLocation();
                                    if (mapLoc != null && !mapLoc.isBlank()) {
                                        String mapJson;
                                        if (entry.getPassiveMapStatus() == PassiveMapStatus.INLINE_BASE64) {
                                            mapJson = mapLoc;
                                        } else {
                                            mapJson = prober.fetchMapContent(entry, mapLoc);
                                        }
                                        if (mapJson != null && !mapJson.isBlank()) {
                                            UnpackedProject project = SourceMapUnpacker.unpack(mapLoc, mapJson);
                                            if (project != null && project.getTotalFiles() > 0) {
                                                entry.setUnpackedProject(project);
                                            }
                                        }
                                    }
                                }

                                // 2. Mine the raw JS Response code if present
                                if (entry.getResponse() != null) {
                                    String code = entry.getResponse().bodyToString();
                                    var jsMining = SecretAndEndpointMiner.mine(entry.getUrl(), "JS File", code);
                                    entry.setJsReconFindings(
                                        jsMining.secrets(),
                                        jsMining.endpoints(),
                                        jsMining.cloudUrls(),
                                        jsMining.dependencies(),
                                        jsMining.comments(),
                                        jsMining.securityBypasses()
                                    );
                                }
                            } catch (Exception ignored) {}
                            int count = processed.incrementAndGet();
                            publish(count);
                        }));
                    }
                    for (var f : futures) {
                        try { f.get(); } catch (Exception ignored) {}
                    }
                } finally {
                    pool.shutdownNow();
                }
                return null;
            }

            @Override
            protected void process(List<Integer> chunks) {
                if (!chunks.isEmpty()) {
                    int done = chunks.get(chunks.size() - 1);
                    statsLabel.setText(String.format("Analyzing assets (%d / %d)...", done, entries.size()));
                }
            }

            @Override
            protected void done() {
                isMining.set(false);
                runBtn.setEnabled(true);
                runBtn.setText("Run " + categoryTitle);
                refreshFromDataStore();
                if (onMiningFinished != null) {
                    onMiningFinished.run();
                }
            }
        };

        worker.execute();
    }

    public abstract void refreshFromDataStore();
    public abstract void applyFilter();
    protected abstract void addCategoryFiltersToToolbar(JPanel toolbar);
    protected abstract void resetCategoryFilters();
    protected abstract String getClassificationAt(int modelRow);
    protected abstract void updateClassification(int modelRow, String classification);
    protected abstract String getFindingTextAt(int modelRow);
    protected abstract int getStartOffsetAt(int modelRow);
    protected abstract int getEndOffsetAt(int modelRow);
    protected abstract String getSourceLocationAt(int modelRow);
    protected abstract void exportTsv(JTable table);

    protected boolean matchesClassification(String itemClassification) {
        if (classificationFilterBtn == null || classificationFilterBtn.isAllSelected()) {
            return true;
        }
        Set<String> selected = classificationFilterBtn.getSelected();
        if (selected == null || selected.isEmpty()) {
            return true;
        }
        String normalized = (itemClassification != null && !itemClassification.isBlank()) ? itemClassification : "Not Classified";
        return selected.contains(normalized);
    }

    protected void copyToClipboard(String text) {
        if (text == null) text = "";
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        } catch (Exception ignored) {}
    }

    public static boolean isDarkMode() {
        Color bg = UIManager.getColor("Table.background");
        if (bg == null) bg = Color.WHITE;
        double lum = 0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue();
        return lum < 128;
    }
}
