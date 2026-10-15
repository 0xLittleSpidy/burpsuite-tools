// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.storage;

import com.littlespidy.responseinspector.engine.ResponseScanEngine;
import com.littlespidy.responseinspector.model.InScopeDomainManager;

import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 * Configuration dialog for Persistent Data Storage.
 * Enables users to view storage usage, change storage directory,
 * force immediate save, or explicitly delete stored data from disk.
 */
public class StorageConfigDialog extends JDialog {

    private final PersistentStorageManager storageManager;
    private final ResponseScanEngine scanEngine;
    private final InScopeDomainManager domainManager;
    private final Runnable refreshCallback;

    private final JTextField pathField;
    private final JLabel sizeLabel;
    private final JLabel lastSavedLabel;

    public StorageConfigDialog(
            Window parent,
            PersistentStorageManager storageManager,
            ResponseScanEngine scanEngine,
            InScopeDomainManager domainManager,
            Runnable refreshCallback
    ) {
        super(parent, "Persistent Storage Settings", ModalityType.APPLICATION_MODAL);
        this.storageManager = storageManager;
        this.scanEngine = scanEngine;
        this.domainManager = domainManager;
        this.refreshCallback = refreshCallback;

        setLayout(new BorderLayout(12, 12));
        setSize(650, 320);
        setLocationRelativeTo(parent);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        // Description
        JLabel desc = new JLabel("<html><b>Response Inspector Persistent Storage</b><br>"
                + "Data is saved locally so findings, classifications, and configurations are preserved "
                + "when Burp Suite is restarted or when the extension is reinstalled.</html>");
        desc.setAlignmentX(Component.LEFT_ALIGNMENT);
        mainPanel.add(desc);
        mainPanel.add(Box.createVerticalStrut(14));

        // Location Panel
        JPanel locationPanel = new JPanel(new BorderLayout(8, 6));
        locationPanel.setBorder(BorderFactory.createTitledBorder("Storage Directory"));
        locationPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        pathField = new JTextField(storageManager.getStorageDirectory().getAbsolutePath());
        pathField.setEditable(false);

        JButton browseBtn = new JButton("Change Directory...");
        browseBtn.addActionListener(e -> handleChangeDirectory());

        locationPanel.add(pathField, BorderLayout.CENTER);
        locationPanel.add(browseBtn, BorderLayout.EAST);
        mainPanel.add(locationPanel);
        mainPanel.add(Box.createVerticalStrut(10));

        // Stats Panel
        JPanel statsPanel = new JPanel(new GridLayout(2, 2, 8, 4));
        statsPanel.setBorder(BorderFactory.createTitledBorder("Status & Storage Statistics"));
        statsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        sizeLabel = new JLabel("Disk Usage: " + formatSize(storageManager.getStorageSizeBytes()));
        lastSavedLabel = new JLabel("Last Saved: " + storageManager.getLastModifiedFormatted());
        JLabel modeLabel = new JLabel("Persistence: Enabled (Survives Restarts & Reinstalls)");
        JLabel defaultDirLabel = new JLabel("Default: ~/.BurpSuite/response-inspector");

        statsPanel.add(sizeLabel);
        statsPanel.add(lastSavedLabel);
        statsPanel.add(modeLabel);
        statsPanel.add(defaultDirLabel);
        mainPanel.add(statsPanel);

        add(mainPanel, BorderLayout.CENTER);

        // Buttons Bar
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));

        JButton saveNowBtn = new JButton("Save Now");
        saveNowBtn.setToolTipText("Immediately write all current findings and configurations to disk");
        saveNowBtn.addActionListener(e -> {
            storageManager.saveNow();
            updateStats();
            JOptionPane.showMessageDialog(this, "Data successfully saved to:\n" + storageManager.getStorageDirectory().getAbsolutePath(), "Saved", JOptionPane.INFORMATION_MESSAGE);
        });

        JButton deleteDataBtn = new JButton("Delete Stored Data");
        deleteDataBtn.setForeground(new Color(180, 0, 0));
        deleteDataBtn.setToolTipText("Permanently delete stored data files from disk");
        deleteDataBtn.addActionListener(e -> handleDeleteData());

        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dispose());

        bottomBar.add(deleteDataBtn);
        bottomBar.add(new JSeparator(JSeparator.VERTICAL));
        bottomBar.add(saveNowBtn);
        bottomBar.add(closeBtn);

        add(bottomBar, BorderLayout.SOUTH);
    }

    private void handleChangeDirectory() {
        JFileChooser chooser = new JFileChooser(storageManager.getStorageDirectory());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("Select Persistent Storage Directory");

        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selected = chooser.getSelectedFile();
            if (selected != null) {
                storageManager.setStorageDirectory(selected);
                storageManager.saveNow();
                pathField.setText(selected.getAbsolutePath());
                updateStats();
                JOptionPane.showMessageDialog(this, "Persistent storage directory changed to:\n" + selected.getAbsolutePath(), "Directory Updated", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    private void handleDeleteData() {
        int opt = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to permanently delete all persistent storage files from disk?\n"
                        + "This will delete the saved findings and configuration files.\n\n"
                        + "Would you also like to clear in-memory findings for this session?",
                "Delete Stored Data",
                JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE
        );

        if (opt == JOptionPane.YES_OPTION) {
            // Delete from disk and clear memory
            storageManager.deleteStoredData();
            if (scanEngine != null) {
                scanEngine.clearAll();
            }
            if (domainManager != null) {
                domainManager.deselectAll();
            }
            if (refreshCallback != null) {
                refreshCallback.run();
            }
            updateStats();
            JOptionPane.showMessageDialog(this, "Persistent storage files deleted and findings cleared.", "Data Deleted", JOptionPane.INFORMATION_MESSAGE);
        } else if (opt == JOptionPane.NO_OPTION) {
            // Delete from disk only, keep memory
            storageManager.deleteStoredData();
            updateStats();
            JOptionPane.showMessageDialog(this, "Persistent storage files deleted from disk.\nCurrent in-memory findings were preserved.", "Storage Deleted", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void updateStats() {
        sizeLabel.setText("Disk Usage: " + formatSize(storageManager.getStorageSizeBytes()));
        lastSavedLabel.setText("Last Saved: " + storageManager.getLastModifiedFormatted());
    }

    private static String formatSize(long bytes) {
        if (bytes <= 0) return "0 B";
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
    }
}
