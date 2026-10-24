// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.quickhelper.model.ExtensionItem_littlespidy;
import com.littlespidy.quickhelper.service.ExtensionCatalogService_littlespidy;
import com.littlespidy.quickhelper.service.ExtensionDownloaderService_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Main UI panel for the single-click extension downloader in Quick Helper.
 */
public class ExtensionDownloaderTab_littlespidy extends JPanel implements ExtensionDownloaderService_littlespidy.DownloadListener {

    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final MontoyaApi api;
    private final ExtensionCatalogService_littlespidy catalogService;
    private final ExtensionDownloaderService_littlespidy downloaderService;

    private final ExtensionTableModel_littlespidy tableModel;
    private final JTable extensionsTable;

    private final JTextField destFolderField;
    private final JButton downloadAllBtn;
    private final JButton downloadSelectedBtn;
    private final JButton cancelBtn;
    private final JButton browseBtn;
    private final JButton openFolderBtn;

    private final JLabel totalCountLabel;
    private final JLabel selectedCountLabel;
    private final JLabel completedCountLabel;
    private final JLabel statusSummaryLabel;
    private final JProgressBar progressBar;

    private final JTextArea logArea;

    public ExtensionDownloaderTab_littlespidy(MontoyaApi api,
                                            ExtensionCatalogService_littlespidy catalogService,
                                            ExtensionDownloaderService_littlespidy downloaderService) {
        this.api = api;
        this.catalogService = catalogService;
        this.downloaderService = downloaderService;
        this.downloaderService.addListener(this);

        setLayout(new BorderLayout(0, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));

        this.tableModel = new ExtensionTableModel_littlespidy(catalogService.getCatalog());
        this.extensionsTable = new JTable(tableModel);

        this.destFolderField = new JTextField(downloaderService.getDefaultDownloadDirectory().toAbsolutePath().toString(), 28);
        this.downloadAllBtn = new JButton("Download All Extensions (Single Click)");
        this.downloadSelectedBtn = new JButton("Download Selected");
        this.cancelBtn = new JButton("Cancel");
        this.browseBtn = new JButton("Browse...");
        this.openFolderBtn = new JButton("Open Download Folder");

        this.totalCountLabel = new JLabel("Total: " + catalogService.getExtensionCount());
        this.selectedCountLabel = new JLabel("Selected: " + catalogService.getExtensionCount());
        this.completedCountLabel = new JLabel("Downloaded: 0");
        this.statusSummaryLabel = new JLabel("Ready");
        this.progressBar = new JProgressBar(0, catalogService.getExtensionCount());

        this.logArea = new JTextArea();

        initUi();
        updateCounts();
    }

    private void initUi() {
        // Top Container: Info Banner + Controls + Progress
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));

        // 1. Info Banner
        JPanel bannerPanel = new JPanel(new BorderLayout());
        bannerPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                new EmptyBorder(8, 12, 8, 12)
        ));

        JLabel titleLabel = new JLabel("Quick Helper: Single-Click Extension Downloader");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));

        JLabel authorLabel = new JLabel("Author: littlespidy");
        authorLabel.setFont(authorLabel.getFont().deriveFont(Font.BOLD, 11f));

        JLabel descLabel = new JLabel("Download all 21 official pre-compiled Burp Suite extensions published by littlespidy. "
                + "Click 'Download All Extensions (Single Click)' to save all release JARs to your system.");
        descLabel.setFont(descLabel.getFont().deriveFont(Font.PLAIN, 11f));

        JPanel bannerTextPanel = new JPanel();
        bannerTextPanel.setLayout(new BoxLayout(bannerTextPanel, BoxLayout.Y_AXIS));
        bannerTextPanel.add(titleLabel);
        bannerTextPanel.add(Box.createVerticalStrut(3));
        bannerTextPanel.add(descLabel);

        bannerPanel.add(bannerTextPanel, BorderLayout.CENTER);
        bannerPanel.add(authorLabel, BorderLayout.EAST);
        topContainer.add(bannerPanel);
        topContainer.add(Box.createVerticalStrut(8));

        // 2. Main Toolbar Panel
        JPanel toolbarPanel = new JPanel();
        toolbarPanel.setLayout(new BoxLayout(toolbarPanel, BoxLayout.Y_AXIS));
        toolbarPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                new EmptyBorder(8, 10, 8, 10)
        ));

        // Row 1: Primary Action Buttons & Destination Folder
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));

        downloadAllBtn.setFont(downloadAllBtn.getFont().deriveFont(Font.BOLD, 12f));
        downloadAllBtn.setToolTipText("Download all 21 extension JAR files to the destination folder with a single click");
        downloadAllBtn.addActionListener(e -> triggerDownloadAll());
        row1.add(downloadAllBtn);

        downloadSelectedBtn.setFont(downloadSelectedBtn.getFont().deriveFont(Font.PLAIN, 11f));
        downloadSelectedBtn.setToolTipText("Download only the checked extensions from the table");
        downloadSelectedBtn.addActionListener(e -> triggerDownloadSelected());
        row1.add(downloadSelectedBtn);

        cancelBtn.setFont(cancelBtn.getFont().deriveFont(Font.PLAIN, 11f));
        cancelBtn.setEnabled(false);
        cancelBtn.setToolTipText("Cancel active downloads");
        cancelBtn.addActionListener(e -> downloaderService.cancelDownloads());
        row1.add(cancelBtn);

        row1.add(new JSeparator(SwingConstants.VERTICAL));

        JLabel destLabel = new JLabel("Destination:");
        destLabel.setFont(destLabel.getFont().deriveFont(Font.BOLD, 11f));
        row1.add(destLabel);
        destFolderField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        row1.add(destFolderField);

        browseBtn.setFont(browseBtn.getFont().deriveFont(Font.PLAIN, 11f));
        browseBtn.addActionListener(e -> browseDestinationFolder());
        row1.add(browseBtn);

        openFolderBtn.setFont(openFolderBtn.getFont().deriveFont(Font.PLAIN, 11f));
        openFolderBtn.setToolTipText("Open the destination folder in the system file manager");
        openFolderBtn.addActionListener(e -> openDestinationFolder());
        row1.add(openFolderBtn);

        toolbarPanel.add(row1);
        toolbarPanel.add(Box.createVerticalStrut(6));

        // Row 2: Selection Shortcuts & Search Filter
        JPanel row2 = new JPanel(new BorderLayout());

        JPanel selectionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.setFont(selectAllBtn.getFont().deriveFont(Font.PLAIN, 11f));
        selectAllBtn.addActionListener(e -> {
            tableModel.selectAll(true);
            updateCounts();
        });
        selectionPanel.add(selectAllBtn);

        JButton deselectAllBtn = new JButton("Deselect All");
        deselectAllBtn.setFont(deselectAllBtn.getFont().deriveFont(Font.PLAIN, 11f));
        deselectAllBtn.addActionListener(e -> {
            tableModel.selectAll(false);
            updateCounts();
        });
        selectionPanel.add(deselectAllBtn);

        row2.add(selectionPanel, BorderLayout.WEST);

        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JLabel filterLabel = new JLabel("Filter:");
        filterLabel.setFont(filterLabel.getFont().deriveFont(Font.BOLD, 11f));
        filterPanel.add(filterLabel);

        JTextField filterField = new JTextField(18);
        filterField.setFont(filterField.getFont().deriveFont(Font.PLAIN, 11f));
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { tableModel.setFilter(filterField.getText()); updateCounts(); }
            @Override
            public void removeUpdate(DocumentEvent e) { tableModel.setFilter(filterField.getText()); updateCounts(); }
            @Override
            public void changedUpdate(DocumentEvent e) { tableModel.setFilter(filterField.getText()); updateCounts(); }
        });
        filterPanel.add(filterField);

        row2.add(filterPanel, BorderLayout.EAST);
        toolbarPanel.add(row2);

        topContainer.add(toolbarPanel);
        topContainer.add(Box.createVerticalStrut(8));

        // 3. Progress & Metrics Panel
        JPanel progressPanel = new JPanel(new BorderLayout(10, 4));
        progressPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                new EmptyBorder(6, 10, 6, 10)
        ));

        JPanel metricsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 0));
        totalCountLabel.setFont(totalCountLabel.getFont().deriveFont(Font.BOLD, 11f));
        selectedCountLabel.setFont(selectedCountLabel.getFont().deriveFont(Font.BOLD, 11f));
        completedCountLabel.setFont(completedCountLabel.getFont().deriveFont(Font.BOLD, 11f));
        JLabel totalSizeLabel = new JLabel("Est. Total Size: ~180 MB");
        totalSizeLabel.setFont(totalSizeLabel.getFont().deriveFont(Font.PLAIN, 11f));

        metricsRow.add(totalCountLabel);
        metricsRow.add(selectedCountLabel);
        metricsRow.add(completedCountLabel);
        metricsRow.add(totalSizeLabel);

        progressPanel.add(metricsRow, BorderLayout.WEST);

        statusSummaryLabel.setFont(statusSummaryLabel.getFont().deriveFont(Font.BOLD, 11f));
        statusSummaryLabel.setHorizontalAlignment(SwingConstants.RIGHT);
        progressPanel.add(statusSummaryLabel, BorderLayout.EAST);

        progressBar.setStringPainted(true);
        progressBar.setString("0% (0 / " + catalogService.getExtensionCount() + ")");
        progressPanel.add(progressBar, BorderLayout.SOUTH);

        topContainer.add(progressPanel);

        add(topContainer, BorderLayout.NORTH);

        // Center: Extensions Table
        configureTable();
        JScrollPane tableScrollPane = new JScrollPane(extensionsTable);
        tableScrollPane.setPreferredSize(new Dimension(800, 240));
        add(tableScrollPane, BorderLayout.CENTER);

        // South: Split Panel (Activity Log + Installation Instructions)
        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        bottomSplit.setResizeWeight(0.6);
        bottomSplit.setContinuousLayout(true);
        bottomSplit.setPreferredSize(new Dimension(800, 160));

        // Log Console
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Download Activity Log"));

        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        logArea.setBackground(new Color(25, 25, 25));
        logArea.setForeground(new Color(200, 200, 200));
        JScrollPane logScroll = new JScrollPane(logArea);
        logPanel.add(logScroll, BorderLayout.CENTER);

        JPanel logActionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 2));
        JButton clearLogBtn = new JButton("Clear Log");
        clearLogBtn.setFont(clearLogBtn.getFont().deriveFont(Font.PLAIN, 10f));
        clearLogBtn.addActionListener(e -> logArea.setText(""));
        logActionPanel.add(clearLogBtn);
        logPanel.add(logActionPanel, BorderLayout.SOUTH);

        bottomSplit.setLeftComponent(logPanel);

        // Instructions Card
        JPanel instructPanel = new JPanel(new BorderLayout());
        instructPanel.setBorder(BorderFactory.createTitledBorder("Burp Suite Installation Instructions"));

        JTextPane instructPane = new JTextPane();
        instructPane.setEditable(false);
        instructPane.setContentType("text/html");
        instructPane.setText(buildInstructionsHtml());
        instructPane.setCaretPosition(0);
        JScrollPane instructScroll = new JScrollPane(instructPane);
        instructPanel.add(instructScroll, BorderLayout.CENTER);

        bottomSplit.setRightComponent(instructPanel);

        add(bottomSplit, BorderLayout.SOUTH);

        appendLog("Quick Helper Extension Downloader initialized with " + catalogService.getExtensionCount() + " extensions.", false);
        appendLog("Ready. Click 'Download All Extensions (Single Click)' to begin.", false);
    }

    private void configureTable() {
        extensionsTable.setRowHeight(24);
        extensionsTable.setFillsViewportHeight(true);
        extensionsTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);

        // Column widths
        extensionsTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        extensionsTable.getColumnModel().getColumn(0).setMaxWidth(60);
        extensionsTable.getColumnModel().getColumn(1).setPreferredWidth(190);
        extensionsTable.getColumnModel().getColumn(2).setPreferredWidth(130);
        extensionsTable.getColumnModel().getColumn(3).setPreferredWidth(230);
        extensionsTable.getColumnModel().getColumn(4).setPreferredWidth(75);
        extensionsTable.getColumnModel().getColumn(5).setPreferredWidth(180);

        // Custom renderer for status column
        extensionsTable.getColumnModel().getColumn(5).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus,
                                                           int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                String valStr = (value != null) ? value.toString() : "";
                if (!isSelected) {
                    if (valStr.startsWith("Completed")) {
                        c.setForeground(new Color(40, 160, 40));
                    } else if (valStr.startsWith("Downloading") || valStr.startsWith("Connecting")) {
                        c.setForeground(new Color(30, 130, 230));
                    } else if (valStr.startsWith("Failed")) {
                        c.setForeground(new Color(220, 50, 50));
                    } else {
                        c.setForeground(table.getForeground());
                    }
                }
                return c;
            }
        });

        tableModel.addTableModelListener(e -> updateCounts());
    }

    public void triggerDownloadAll() {
        if (downloaderService.isRunning()) {
            JOptionPane.showMessageDialog(this,
                    "A download task is already running. Please wait or cancel it first.",
                    "Download In Progress",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        tableModel.selectAll(true);
        Path destDir = getDestinationPath();
        setControlsDownloadingState(true);
        downloaderService.downloadAllAsync(tableModel.getAllItems(), destDir);
    }

    public void triggerDownloadSelected() {
        if (downloaderService.isRunning()) {
            JOptionPane.showMessageDialog(this,
                    "A download task is already running. Please wait or cancel it first.",
                    "Download In Progress",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<ExtensionItem_littlespidy> targets = tableModel.getAllItems().stream()
                .filter(ExtensionItem_littlespidy::isSelected)
                .toList();

        if (targets.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Please select at least one extension to download.",
                    "No Extensions Selected",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        Path destDir = getDestinationPath();
        setControlsDownloadingState(true);
        downloaderService.downloadSelectedAsync(tableModel.getAllItems(), destDir);
    }

    private Path getDestinationPath() {
        String pathStr = destFolderField.getText().trim();
        if (pathStr.startsWith("~")) {
            pathStr = System.getProperty("user.home", ".") + pathStr.substring(1);
        }
        return Paths.get(pathStr);
    }

    private void browseDestinationFolder() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Extension Download Destination Directory");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setAcceptAllFileFilterUsed(false);

        File current = getDestinationPath().toFile();
        if (current.exists()) {
            chooser.setCurrentDirectory(current);
        }

        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedDir = chooser.getSelectedFile();
            destFolderField.setText(selectedDir.getAbsolutePath());
        }
    }

    private void openDestinationFolder() {
        Path path = getDestinationPath();
        if (!downloaderService.openFolderInDesktop(path)) {
            JOptionPane.showMessageDialog(this,
                    "Destination directory: " + path.toAbsolutePath(),
                    "Destination Folder",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void setControlsDownloadingState(boolean downloading) {
        downloadAllBtn.setEnabled(!downloading);
        downloadSelectedBtn.setEnabled(!downloading);
        browseBtn.setEnabled(!downloading);
        cancelBtn.setEnabled(downloading);
    }

    private void updateCounts() {
        int total = tableModel.getAllItems().size();
        int selected = (int) tableModel.getAllItems().stream().filter(ExtensionItem_littlespidy::isSelected).count();
        int completed = (int) tableModel.getAllItems().stream().filter(i -> i.getStatus() == ExtensionItem_littlespidy.Status.COMPLETED).count();

        totalCountLabel.setText("Total: " + total);
        selectedCountLabel.setText("Selected: " + selected);
        completedCountLabel.setText("Downloaded: " + completed);

        int pct = (total > 0) ? (completed * 100) / total : 0;
        progressBar.setValue(completed);
        progressBar.setString(pct + "% (" + completed + " / " + total + ")");
    }

    private void appendLog(String message, boolean isError) {
        String time = LocalTime.now().format(TIME_FORMATTER);
        String prefix = isError ? "[ERROR] " : "[INFO] ";
        logArea.append("[" + time + "] " + prefix + message + "\n");
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    private String buildInstructionsHtml() {
        return "<html><body style='font-family:sans-serif; font-size:10px; margin:4px;'>"
                + "<b>How to load downloaded extensions into Burp Suite:</b>"
                + "<ol style='margin-left:14px; margin-top:4px;'>"
                + "<li>Open the top navigation tab <b>Extensions</b> -> <b>Installed</b>.</li>"
                + "<li>Click the <b>Add</b> button on the left panel.</li>"
                + "<li>Ensure <b>Extension type</b> is set to <b>Java</b>.</li>"
                + "<li>Click <b>Select file...</b> and navigate to your download folder:</li>"
                + "<code style='background-color:#eeeeee; padding:2px;'>~/Downloads/burpsuite-extensions/</code>"
                + "<li>Select any downloaded <b>.jar</b> file and click <b>Next</b>.</li>"
                + "<li>The extension will load immediately with its UI tabs and context menus.</li>"
                + "</ol>"
                + "</body></html>";
    }

    // DownloadListener Callbacks

    @Override
    public void onItemStarted(ExtensionItem_littlespidy item) {
        SwingUtilities.invokeLater(() -> {
            tableModel.itemUpdated(item);
            statusSummaryLabel.setText("Downloading " + item.getName() + "...");
        });
    }

    @Override
    public void onItemProgress(ExtensionItem_littlespidy item, int percent, long bytesRead, long totalBytes) {
        SwingUtilities.invokeLater(() -> tableModel.itemUpdated(item));
    }

    @Override
    public void onItemCompleted(ExtensionItem_littlespidy item, Path savedPath) {
        SwingUtilities.invokeLater(() -> {
            tableModel.itemUpdated(item);
            updateCounts();
        });
    }

    @Override
    public void onItemFailed(ExtensionItem_littlespidy item, String errorMessage) {
        SwingUtilities.invokeLater(() -> {
            tableModel.itemUpdated(item);
            updateCounts();
        });
    }

    @Override
    public void onBatchProgress(int completedCount, int totalCount, ExtensionItem_littlespidy currentItem) {
        SwingUtilities.invokeLater(() -> {
            statusSummaryLabel.setText("Downloading [" + (completedCount + 1) + "/" + totalCount + "]: " + currentItem.getName());
            updateCounts();
        });
    }

    @Override
    public void onBatchCompleted(int successCount, int failedCount, Path destinationDir) {
        SwingUtilities.invokeLater(() -> {
            setControlsDownloadingState(false);
            statusSummaryLabel.setText("Finished: " + successCount + " downloaded, " + failedCount + " failed");
            updateCounts();

            String msg = "Download batch completed.\n"
                    + "Successfully downloaded: " + successCount + " extension(s)\n"
                    + "Destination: " + destinationDir.toAbsolutePath() + "\n\n"
                    + "Follow the installation guide in the lower panel to load them into Burp Suite.";

            JOptionPane.showMessageDialog(this,
                    msg,
                    "Download Completed",
                    JOptionPane.INFORMATION_MESSAGE);
        });
    }

    @Override
    public void onLog(String message, boolean isError) {
        SwingUtilities.invokeLater(() -> appendLog(message, isError));
    }
}
