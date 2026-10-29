// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.inputvalidation;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import com.protect7.authanalyzer.gui.main.MainPanel;
import com.protect7.authanalyzer.gui.util.DomainFilterDropDown_littlespidy;
import com.protect7.authanalyzer.gui.util.MethodFilterDropDown_littlespidy;
import com.protect7.authanalyzer.gui.util.PlaceholderTextField;
import com.protect7.authanalyzer.inputvalidation.InputValidationEngine_littlespidy;
import com.protect7.authanalyzer.inputvalidation.InputValidationTableModel_littlespidy;
import com.protect7.authanalyzer.inputvalidation.InputValidationTestResult_littlespidy;

/**
 * Suite tab for real-time viewing, filtering, and analysis of Input Validation parameter fuzz probes.
 */
public class InputValidationHistoryPanel_littlespidy extends JPanel {

    private static final long serialVersionUID = 1L;
    protected final MainPanel mainPanel;
    protected final InputValidationTableModel_littlespidy tableModel = new InputValidationTableModel_littlespidy();
    protected final JTable table = new JTable(tableModel);
    protected TableRowSorter<InputValidationTableModel_littlespidy> sorter;

    protected final MethodFilterDropDown_littlespidy methodFilterDropDown = new MethodFilterDropDown_littlespidy();
    protected final DomainFilterDropDown_littlespidy domainFilterDropDown = new DomainFilterDropDown_littlespidy();
    protected final JComboBox<String> findingsFilter = new JComboBox<>(new String[]{
            "All Findings", "Error Signature", "Reflected Input", "HTTP 5xx Server Error", "Status Shift", "Size Delta", "Clean"
    });
    protected final PlaceholderTextField filterText = new PlaceholderTextField(14);
    protected final JButton searchButton = new JButton("Search");

    protected final JButton payloadsConfigButton = new JButton("Payloads & Config");
    protected final JButton clearTableButton = new JButton("Clear Table");
    protected final JButton exportDataButton = new JButton("Export CSV");
    protected final JPanel topActionsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));

    private IMessageEditor fuzzedRequestEditor;
    private IMessageEditor fuzzedResponseEditor;
    private IMessageEditor baseRequestEditor;
    private IMessageEditor baseResponseEditor;
    private final JTextArea evidenceTextArea = new JTextArea();
    private final JLabel viewerInfoLabel = new JLabel("Select an input validation probe above to inspect full HTTP messages and evidence");

    private final AtomicInteger idCounter = new AtomicInteger(0);
    private IHttpRequestResponse currentlySelectedFuzzedMessage;

    public InputValidationHistoryPanel_littlespidy(MainPanel mainPanel) {
        this.mainPanel = mainPanel;
        setLayout(new BorderLayout());
        initUI();
    }

    protected void initUI() {
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BorderLayout(5, 4));
        topPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JPanel controlsRow = new JPanel(new BorderLayout(8, 2));
        JPanel leftFilters = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        leftFilters.add(methodFilterDropDown);
        leftFilters.add(domainFilterDropDown);
        leftFilters.add(new JLabel("Findings:"));
        leftFilters.add(findingsFilter);
        controlsRow.add(leftFilters, BorderLayout.WEST);

        JPanel centerSearch = new JPanel(new FlowLayout(FlowLayout.CENTER, 6, 0));
        filterText.setPlaceholder("Search URL / param...");
        centerSearch.add(filterText);
        searchButton.addActionListener(e -> tableModel.fireTableDataChanged());
        centerSearch.add(searchButton);
        controlsRow.add(centerSearch, BorderLayout.CENTER);

        initActionsPanel();
        controlsRow.add(topActionsPanel, BorderLayout.EAST);
        topPanel.add(controlsRow, BorderLayout.CENTER);
        add(topPanel, BorderLayout.NORTH);

        // Table setup
        table.setDefaultRenderer(String.class, new InputValidationCellRenderer());
        table.setDefaultRenderer(Integer.class, new InputValidationCellRenderer());

        sorter = new TableRowSorter<>(tableModel);
        sorter.setMaxSortKeys(1);
        sorter.setSortKeys(Collections.singletonList(new RowSorter.SortKey(0, SortOrder.DESCENDING)));

        methodFilterDropDown.addFilterChangeListener(() -> tableModel.fireTableDataChanged());
        domainFilterDropDown.addFilterChangeListener(() -> tableModel.fireTableDataChanged());
        findingsFilter.addActionListener(e -> tableModel.fireTableDataChanged());

        sorter.setRowFilter(new RowFilter<InputValidationTableModel_littlespidy, Integer>() {
            @Override
            public boolean include(Entry<? extends InputValidationTableModel_littlespidy, ? extends Integer> entry) {
                InputValidationTestResult_littlespidy res = entry.getModel().getResult(entry.getIdentifier());
                if (res == null) return false;

                if (!methodFilterDropDown.isMethodSelected(res.getMethod())) return false;
                if (!domainFilterDropDown.isDomainSelected(res.getHost())) return false;

                String selectedFinding = (String) findingsFilter.getSelectedItem();
                if (selectedFinding != null && !selectedFinding.equals("All Findings")) {
                    if (res.getAnomalyType() == null || !res.getAnomalyType().toLowerCase(Locale.ROOT).contains(selectedFinding.toLowerCase(Locale.ROOT))) {
                        return false;
                    }
                }

                String query = filterText.getText();
                if (query != null && !query.trim().isEmpty()) {
                    String q = query.trim().toLowerCase(Locale.ROOT);
                    boolean matches = (res.getHost() != null && res.getHost().toLowerCase(Locale.ROOT).contains(q))
                            || (res.getPath() != null && res.getPath().toLowerCase(Locale.ROOT).contains(q))
                            || (res.getParameterName() != null && res.getParameterName().toLowerCase(Locale.ROOT).contains(q))
                            || (res.getPayloadValue() != null && res.getPayloadValue().toLowerCase(Locale.ROOT).contains(q))
                            || (res.getAnomalyType() != null && res.getAnomalyType().toLowerCase(Locale.ROOT).contains(q));
                    if (!matches) return false;
                }
                return true;
            }
        });
        table.setRowSorter(sorter);

        JPanel tableContainer = new JPanel(new BorderLayout());
        tableContainer.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        tableContainer.add(new JScrollPane(table), BorderLayout.CENTER);

        // Viewer panel setup
        JPanel viewerPanel = new JPanel(new BorderLayout());
        viewerPanel.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        viewerInfoLabel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        viewerPanel.add(viewerInfoLabel, BorderLayout.NORTH);

        JTabbedPane viewerTabs = new JTabbedPane();
        initMessageEditors(viewerTabs);
        viewerPanel.add(viewerTabs, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableContainer, viewerPanel);
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
        payloadsConfigButton.addActionListener(e -> openPayloadsConfigDialog());
        clearTableButton.addActionListener(e -> clearTable());
        exportDataButton.addActionListener(e -> exportCsvData());

        topActionsPanel.add(payloadsConfigButton);
        topActionsPanel.add(clearTableButton);
        topActionsPanel.add(exportDataButton);
    }

    private void openPayloadsConfigDialog() {
        if (mainPanel != null && mainPanel.getConfigurationPanel() != null) {
            InputValidationPayloadsDialog_littlespidy dialog = new InputValidationPayloadsDialog_littlespidy(
                    this, mainPanel.getConfigurationPanel().getInputValidationConfig()
            );
            dialog.setVisible(true);
        }
    }

    private void initMessageEditors(JTabbedPane viewerTabs) {
        if (BurpExtender.callbacks != null) {
            IMessageEditorController controller = new IMessageEditorController() {
                @Override
                public IHttpService getHttpService() {
                    return currentlySelectedFuzzedMessage != null ? currentlySelectedFuzzedMessage.getHttpService() : null;
                }
                @Override
                public byte[] getRequest() {
                    return currentlySelectedFuzzedMessage != null ? currentlySelectedFuzzedMessage.getRequest() : new byte[0];
                }
                @Override
                public byte[] getResponse() {
                    return currentlySelectedFuzzedMessage != null ? currentlySelectedFuzzedMessage.getResponse() : new byte[0];
                }
            };
            fuzzedRequestEditor = BurpExtender.callbacks.createMessageEditor(controller, false);
            fuzzedResponseEditor = BurpExtender.callbacks.createMessageEditor(controller, false);
            baseRequestEditor = BurpExtender.callbacks.createMessageEditor(controller, false);
            baseResponseEditor = BurpExtender.callbacks.createMessageEditor(controller, false);

            viewerTabs.addTab("Fuzzed Request", fuzzedRequestEditor.getComponent());
            viewerTabs.addTab("Fuzzed Response", fuzzedResponseEditor.getComponent());
            viewerTabs.addTab("Base Request", baseRequestEditor.getComponent());
            viewerTabs.addTab("Base Response", baseResponseEditor.getComponent());

            evidenceTextArea.setEditable(false);
            evidenceTextArea.setFont(new JLabel().getFont());
            viewerTabs.addTab("Findings & Evidence", new JScrollPane(evidenceTextArea));
        }
    }

    private void displaySelectedResult() {
        int selectedViewRow = table.getSelectedRow();
        if (selectedViewRow < 0) return;
        int modelRow = table.convertRowIndexToModel(selectedViewRow);
        InputValidationTestResult_littlespidy result = tableModel.getResult(modelRow);
        if (result == null) return;

        currentlySelectedFuzzedMessage = result.getFuzzedRequestResponse();

        if (fuzzedRequestEditor != null && result.getFuzzedRequestResponse() != null) {
            fuzzedRequestEditor.setMessage(result.getFuzzedRequestResponse().getRequest(), true);
        }
        if (fuzzedResponseEditor != null && result.getFuzzedRequestResponse() != null) {
            fuzzedResponseEditor.setMessage(result.getFuzzedRequestResponse().getResponse(), false);
        }
        if (baseRequestEditor != null && result.getBaseRequestResponse() != null) {
            baseRequestEditor.setMessage(result.getBaseRequestResponse().getRequest(), true);
        }
        if (baseResponseEditor != null && result.getBaseRequestResponse() != null) {
            baseResponseEditor.setMessage(result.getBaseRequestResponse().getResponse(), false);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("ID: ").append(result.getId()).append("\n");
        sb.append("Category: ").append(result.getCategory()).append("\n");
        sb.append("Target Parameter: ").append(result.getParameterName()).append(" (Type: ").append(result.getParameterType()).append(")\n");
        sb.append("Fuzz Payload: ").append(result.getPayloadValue()).append("\n");
        sb.append("Status Code: ").append(result.getBaseStatusCode()).append(" (Base) -> ").append(result.getStatusCode()).append(" (Fuzzed)\n");
        sb.append("Response Length: ").append(result.getBaseLength()).append(" B (Base) -> ").append(result.getLength()).append(" B (Fuzzed)\n");
        sb.append("Size Delta: ").append(result.getSizeDiffPercent() >= 0 ? "+" : "").append(result.getSizeDiffPercent()).append("%\n");
        sb.append("Anomaly Finding: ").append(result.getAnomalyType()).append("\n\n");
        sb.append("Evidence Details:\n").append(result.getEvidence().isEmpty() ? "No specific error signature matched." : result.getEvidence()).append("\n");

        evidenceTextArea.setText(sb.toString());
        viewerInfoLabel.setText("Probe #" + result.getId() + " [" + result.getMethod() + " " + result.getPath() + "] - " + result.getAnomalyType());
    }

    public void analyzeRequestAsync(IHttpRequestResponse messageInfo) {
        if (mainPanel == null || mainPanel.getConfigurationPanel() == null) return;
        if (!mainPanel.getConfigurationPanel().isInputValidationRunning()) return;

        InputValidationEngine_littlespidy.executeTestsAsync(
                messageInfo,
                mainPanel.getConfigurationPanel().getInputValidationConfig(),
                result -> SwingUtilities.invokeLater(() -> {
                    tableModel.addResult(result);
                    domainFilterDropDown.updateDomains(Collections.singletonList(result.getHost()));
                }),
                idCounter
        );
    }

    public void clearTable() {
        tableModel.clear();
        domainFilterDropDown.clear();
        if (fuzzedRequestEditor != null) fuzzedRequestEditor.setMessage(new byte[0], true);
        if (fuzzedResponseEditor != null) fuzzedResponseEditor.setMessage(new byte[0], false);
        if (baseRequestEditor != null) baseRequestEditor.setMessage(new byte[0], true);
        if (baseResponseEditor != null) baseResponseEditor.setMessage(new byte[0], false);
        evidenceTextArea.setText("");
        viewerInfoLabel.setText("Table cleared.");
    }

    public void exportCsvData() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Input Validation Results as CSV");
        chooser.setSelectedFile(new File("input_validation_results.csv"));
        chooser.setFileFilter(new FileNameExtensionFilter("CSV (*.csv)", "csv"));
        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File f = chooser.getSelectedFile();
            if (!f.getName().toLowerCase(Locale.ROOT).endsWith(".csv")) {
                f = new File(f.getAbsolutePath() + ".csv");
            }
            try (PrintWriter writer = new PrintWriter(f, StandardCharsets.UTF_8)) {
                writer.println("ID,Category,Method,Host,Path,Parameter,Type,Payload,BaseStatus,Status,BaseLength,Length,DiffPercent,Anomaly,Evidence");
                for (InputValidationTestResult_littlespidy r : tableModel.getAllResults()) {
                    writer.printf("%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d,%d,%d,%d,%d,\"%s\",\"%s\"%n",
                            r.getId(),
                            escapeCsv(r.getCategory()),
                            escapeCsv(r.getMethod()),
                            escapeCsv(r.getHost()),
                            escapeCsv(r.getPath()),
                            escapeCsv(r.getParameterName()),
                            escapeCsv(r.getParameterType()),
                            escapeCsv(r.getPayloadValue()),
                            r.getBaseStatusCode(),
                            r.getStatusCode(),
                            r.getBaseLength(),
                            r.getLength(),
                            r.getSizeDiffPercent(),
                            escapeCsv(r.getAnomalyType()),
                            escapeCsv(r.getEvidence())
                    );
                }
                JOptionPane.showMessageDialog(this, "Exported " + tableModel.getRowCount() + " results successfully.", "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Failed to export CSV: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private String escapeCsv(String str) {
        if (str == null) return "";
        return str.replace("\"", "\"\"");
    }

    public InputValidationTableModel_littlespidy getTableModel() {
        return tableModel;
    }

    public AtomicInteger getIdCounter() {
        return idCounter;
    }

    private static class InputValidationCellRenderer extends DefaultTableCellRenderer {
        private static final Color COLOR_ERROR = new Color(217, 83, 79);
        private static final Color COLOR_REFLECTED = new Color(240, 173, 78);
        private static final Color COLOR_SHIFT = new Color(91, 192, 222);
        private static final Color COLOR_CLEAN = new Color(92, 184, 92);

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                int modelRow = table.convertRowIndexToModel(row);
                InputValidationTableModel_littlespidy model = (InputValidationTableModel_littlespidy) table.getModel();
                InputValidationTestResult_littlespidy res = model.getResult(modelRow);
                if (res != null) {
                    if (column == 8) { // Status column
                        int status = res.getStatusCode();
                        if (status >= 500) c.setForeground(COLOR_ERROR);
                        else if (status >= 400) c.setForeground(COLOR_REFLECTED);
                        else c.setForeground(COLOR_CLEAN);
                    } else if (column == 11) { // Anomaly column
                        String anomaly = res.getAnomalyType();
                        if (anomaly.contains("Error") || anomaly.contains("5xx")) c.setForeground(COLOR_ERROR);
                        else if (anomaly.contains("Reflected")) c.setForeground(COLOR_REFLECTED);
                        else if (anomaly.contains("Shift") || anomaly.contains("Delta")) c.setForeground(COLOR_SHIFT);
                        else c.setForeground(COLOR_CLEAN);
                    } else {
                        c.setForeground(table.getForeground());
                    }
                }
            }
            return c;
        }
    }
}
