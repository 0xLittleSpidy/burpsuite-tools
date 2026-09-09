package com.littlespidy.uploadscanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.uploadscanner.model.StageType;
import com.littlespidy.uploadscanner.model.UploadEntry;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Activity log panel ("Done Uploads") providing multi-select filtering,
 * live search, log clearing, TSV export, and master-detail message inspection
 * with automatic search highlighting for ReDownloader markers.
 *
 * @author littlespidy
 */
public class ExecutionLogPanel extends JPanel {

    private final MontoyaApi api;
    private final UploadLogTableModel tableModel;
    private final JTable table;
    private final JLabel countLabel;

    private MultiSelectFilterButton stageFilterBtn;
    private MultiSelectFilterButton statusFilterBtn;
    private MultiSelectFilterButton methodFilterBtn;
    private JTextField searchField;

    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;

    public ExecutionLogPanel(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        this.tableModel = new UploadLogTableModel();
        this.table = new JTable(tableModel);
        this.countLabel = new JLabel("0 entries");

        initUI();
    }

    private void initUI() {
        // ── 1. Top Filter Toolbar ──
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(180, 180, 180, 80)));

        stageFilterBtn = new MultiSelectFilterButton(
                "Stage",
                List.of("All Stages", "Upload", "Preflight", "ReDownload"),
                sel -> refreshFilter()
        );

        statusFilterBtn = new MultiSelectFilterButton(
                "Status",
                List.of("All Statuses", "2xx", "3xx", "4xx", "5xx"),
                sel -> refreshFilter()
        );

        methodFilterBtn = new MultiSelectFilterButton(
                "Method",
                List.of("All Methods", "POST", "GET", "PUT", "DELETE"),
                sel -> refreshFilter()
        );

        searchField = new JTextField(15);
        searchField.putClientProperty("JTextField.placeholderText", "Search URL / Payload...");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { refreshFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { refreshFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { refreshFilter(); }
        });

        JButton clearBtn = new JButton("🗑️ Clear Log");
        clearBtn.setToolTipText("Clear all entries from the activity log");
        clearBtn.addActionListener(e -> {
            tableModel.clear();
            updateCountLabel();
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
        });

        JButton exportBtn = new JButton("💾 Export TSV");
        exportBtn.setToolTipText("Export logged requests and responses to a TSV file");
        exportBtn.addActionListener(e -> exportToTsv());

        countLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        countLabel.setForeground(Color.GRAY);

        toolbar.add(new JLabel("Filters:"));
        toolbar.add(stageFilterBtn);
        toolbar.add(statusFilterBtn);
        toolbar.add(methodFilterBtn);
        toolbar.add(new JLabel("Search:"));
        toolbar.add(searchField);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(clearBtn);
        toolbar.add(exportBtn);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(countLabel);

        add(toolbar, BorderLayout.NORTH);

        // ── 2. Table Setup & Styling ──
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.setRowHeight(22);

        // Column widths
        table.getColumnModel().getColumn(0).setPreferredWidth(50);   // #
        table.getColumnModel().getColumn(0).setMaxWidth(60);
        table.getColumnModel().getColumn(1).setPreferredWidth(90);   // Stage
        table.getColumnModel().getColumn(1).setMaxWidth(100);
        table.getColumnModel().getColumn(2).setPreferredWidth(65);   // Method
        table.getColumnModel().getColumn(2).setMaxWidth(75);
        table.getColumnModel().getColumn(3).setPreferredWidth(60);   // Status
        table.getColumnModel().getColumn(3).setMaxWidth(70);
        table.getColumnModel().getColumn(4).setPreferredWidth(190);  // Filename / Payload
        table.getColumnModel().getColumn(5).setPreferredWidth(80);   // Length
        table.getColumnModel().getColumn(5).setMaxWidth(90);
        table.getColumnModel().getColumn(6).setPreferredWidth(320);  // URL

        // Custom Cell Renderer for Status and Stage styling
        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable tbl, Object value,
                                                           boolean isSelected, boolean hasFocus,
                                                           int row, int column) {
                Component c = super.getTableCellRendererComponent(tbl, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    if (column == 3 && value instanceof Integer status) {
                        if (status >= 200 && status < 300) {
                            c.setForeground(new Color(40, 150, 40));
                        } else if (status >= 300 && status < 400) {
                            c.setForeground(new Color(30, 100, 200));
                        } else if (status >= 400 && status < 500) {
                            c.setForeground(new Color(200, 110, 0));
                        } else if (status >= 500) {
                            c.setForeground(new Color(210, 40, 40));
                        } else {
                            c.setForeground(tbl.getForeground());
                        }
                    } else if (column == 1 && value instanceof String stageStr) {
                        if (stageStr.equalsIgnoreCase("ReDownload")) {
                            c.setForeground(new Color(0, 130, 80));
                        } else if (stageStr.equalsIgnoreCase("Preflight")) {
                            c.setForeground(new Color(110, 50, 160));
                        } else {
                            c.setForeground(tbl.getForeground());
                        }
                    } else {
                        c.setForeground(tbl.getForeground());
                    }
                }
                return c;
            }
        });

        // ── 3. Detail View (Montoya Editors) ──
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        JTabbedPane viewerTabs = new JTabbedPane();
        viewerTabs.addTab("📤 Request", requestEditor.uiComponent());
        viewerTabs.addTab("📥 Response", responseEditor.uiComponent());

        // Row Selection Listener with Visual Marker & Search Highlighting
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) {
                    int modelRow = table.convertRowIndexToModel(selectedRow);
                    UploadEntry entry = tableModel.getEntryAt(modelRow);
                    displayEntry(entry);
                }
            }
        });

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), viewerTabs);
        splitPane.setResizeWeight(0.5);
        add(splitPane, BorderLayout.CENTER);
    }

    private void displayEntry(UploadEntry entry) {
        if (entry == null || entry.getRequestResponse() == null) {
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            return;
        }

        HttpRequestResponse rr = entry.getRequestResponse();
        requestEditor.setRequest(rr.request());

        if (rr.hasResponse()) {
            responseEditor.setResponse(rr.response());
        } else {
            responseEditor.setResponse(null);
        }

        // Automatic Visual Search Highlighting for ReDownloader Markers
        String searchMarker = entry.getExtractedMarkerText();
        if (searchMarker != null && !searchMarker.isEmpty()) {
            responseEditor.setSearchExpression(searchMarker);
            if (entry.getStage() == StageType.REDOWNLOAD) {
                requestEditor.setSearchExpression(searchMarker);
            }
        }
    }

    public void addLogEntry(UploadEntry entry) {
        SwingUtilities.invokeLater(() -> {
            tableModel.addEntry(entry);
            updateCountLabel();
        });
    }

    private void refreshFilter() {
        tableModel.applyFilters(
                stageFilterBtn.getSelected(),
                statusFilterBtn.getSelected(),
                methodFilterBtn.getSelected(),
                searchField.getText()
        );
        updateCountLabel();
    }

    private void updateCountLabel() {
        int displayed = tableModel.getRowCount();
        int total = tableModel.getAllEntries().size();
        if (displayed == total) {
            countLabel.setText(total + " entries");
        } else {
            countLabel.setText("Showing " + displayed + " of " + total + " entries");
        }
    }

    private void exportToTsv() {
        List<UploadEntry> entries = tableModel.getAllEntries();
        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Log is empty, nothing to export.", "Export TSV", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("upload_scanner_log.tsv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File target = chooser.getSelectedFile();
            try (FileWriter writer = new FileWriter(target)) {
                writer.write("ID\tStage\tMethod\tStatus\tFilename/Payload\tLength\tURL\n");
                for (UploadEntry e : entries) {
                    writer.write(String.format("%d\t%s\t%s\t%d\t%s\t%d\t%s\n",
                            e.getId(),
                            e.getStage().getDisplayName(),
                            e.getMethod(),
                            e.getStatusCode(),
                            e.getPayloadName(),
                            e.getResponseLength(),
                            e.getUrl()));
                }
                JOptionPane.showMessageDialog(this, "Successfully exported " + entries.size() + " entries to:\n" + target.getAbsolutePath(),
                        "Export TSV", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Failed to export TSV: " + ex.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
