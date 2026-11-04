// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui;

import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
import com.littlespidy.sqlmapanalyzer.parser.DirectoryScanner;
import com.littlespidy.sqlmapanalyzer.persistence.SQLMapPersistenceManager;
import com.littlespidy.sqlmapanalyzer.util.OSUtils;
import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;

/**
 * Compact control bar for selecting SQLMap output directory and triggering scans.
 * Designed to fit cleanly on the far-right side of the navigation bar.
 * Plain ASCII text only.
 */
public class TopControlPanel extends JPanel {

    private final JTextField dirPathField;
    private final JButton btnBrowse;
    private final JButton btnScan;
    private final JLabel statusLabel;
    private final JProgressBar progressBar;

    private final SQLMapAnalyzerTab mainTab;
    private final SqlmapDataStore dataStore;
    private final SQLMapPersistenceManager persistenceManager;

    public TopControlPanel(SQLMapAnalyzerTab mainTab, SqlmapDataStore dataStore, SQLMapPersistenceManager persistenceManager) {
        this.mainTab = mainTab;
        this.dataStore = dataStore;
        this.persistenceManager = persistenceManager;

        setLayout(new FlowLayout(FlowLayout.RIGHT, 5, 2));
        setBorder(new EmptyBorder(2, 4, 2, 4));

        JLabel dirLabel = SwingUtils.createBoldLabel("Output Dir:");
        add(dirLabel);

        dirPathField = new JTextField();
        File defaultDir = OSUtils.getDefaultSqlmapOutputDir();
        dirPathField.setText(defaultDir.getAbsolutePath());
        dirPathField.setPreferredSize(new Dimension(210, 24));
        dirPathField.setToolTipText("SQLMap dump output directory");
        add(dirPathField);

        btnBrowse = SwingUtils.createStyledButton("Browse...");
        btnBrowse.setMargin(new Insets(2, 6, 2, 6));
        btnBrowse.addActionListener(e -> onBrowse());
        add(btnBrowse);

        btnScan = SwingUtils.createStyledButton("Scan / Import");
        btnScan.setFont(btnScan.getFont().deriveFont(Font.BOLD));
        btnScan.setMargin(new Insets(2, 6, 2, 6));
        btnScan.addActionListener(e -> startScan(new File(dirPathField.getText().trim())));
        add(btnScan);

        progressBar = new JProgressBar();
        progressBar.setVisible(false);
        progressBar.setPreferredSize(new Dimension(60, 16));
        add(progressBar);

        statusLabel = new JLabel("Ready");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 11));
        statusLabel.setForeground(Color.DARK_GRAY);
        statusLabel.setToolTipText("Status: Ready. Please select a SQLMap output directory.");
        add(statusLabel);
    }

    private void onBrowse() {
        File currentDir = new File(dirPathField.getText().trim());
        if (!currentDir.exists()) {
            currentDir = OSUtils.getDefaultSqlmapOutputDir();
        }

        JFileChooser chooser = new JFileChooser(currentDir);
        chooser.setDialogTitle("Select SQLMap Output Directory");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int res = chooser.showOpenDialog(this);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File selected = chooser.getSelectedFile();
            dirPathField.setText(selected.getAbsolutePath());
            startScan(selected);
        }
    }

    public void startScan(File rootDir) {
        if (rootDir == null || !rootDir.exists() || !rootDir.isDirectory()) {
            JOptionPane.showMessageDialog(this, "The specified directory does not exist or is not a directory:\n" +
                    (rootDir != null ? rootDir.getAbsolutePath() : "null"), "Invalid Directory", JOptionPane.ERROR_MESSAGE);
            return;
        }

        btnScan.setEnabled(false);
        btnBrowse.setEnabled(false);
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);
        statusLabel.setText("Scanning...");
        statusLabel.setToolTipText("Scanning directory " + rootDir.getName() + "...");

        SwingWorker<Void, String> worker = new SwingWorker<>() {
            private int foundDbs = 0;
            private int foundTables = 0;
            private String errorMessage = null;

            @Override
            protected Void doInBackground() {
                DirectoryScanner scanner = new DirectoryScanner();
                scanner.scanDirectory(rootDir, dataStore, new DirectoryScanner.ScanProgressListener() {
                    @Override
                    public void onProgress(String currentItem, int tableCount) {
                        SwingUtils.runOnEdt(() -> {
                            statusLabel.setText("Scanning (" + tableCount + ")");
                            statusLabel.setToolTipText("Scanning: " + currentItem + " (" + tableCount + " tables found)");
                        });
                    }

                    @Override
                    public void onComplete(int totalDatabases, int totalTables) {
                        foundDbs = totalDatabases;
                        foundTables = totalTables;
                    }

                    @Override
                    public void onError(String message, Throwable error) {
                        errorMessage = message;
                    }
                });
                return null;
            }

            @Override
            protected void done() {
                btnScan.setEnabled(true);
                btnBrowse.setEnabled(true);
                progressBar.setVisible(false);

                if (errorMessage != null) {
                    statusLabel.setText("Error");
                    statusLabel.setToolTipText(errorMessage);
                    JOptionPane.showMessageDialog(TopControlPanel.this, errorMessage, "Scan Warning", JOptionPane.WARNING_MESSAGE);
                } else {
                    statusLabel.setText(foundDbs + " DBs, " + foundTables + " Tables");
                    statusLabel.setToolTipText("Scan complete. Found " + foundDbs + " databases and " + foundTables + " tables.");
                    mainTab.refreshFromDataStore();
                    persistenceManager.triggerAutoSave();
                }
            }
        };

        worker.execute();
    }

    public void setDirectoryPath(String path) {
        dirPathField.setText(path != null ? path : "");
    }

    public void resetStatus() {
        statusLabel.setText("Ready");
        statusLabel.setToolTipText("Status: Ready. Please select a SQLMap output directory.");
        progressBar.setVisible(false);
    }
}
