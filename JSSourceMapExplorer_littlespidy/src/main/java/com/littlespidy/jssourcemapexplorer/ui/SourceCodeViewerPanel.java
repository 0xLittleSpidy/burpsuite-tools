// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import com.littlespidy.jssourcemapexplorer.model.UnpackedSourceFile;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Monospace source code viewer with line numbers, metadata statistics,
 * copy tools, and file export options.
 *
 * @author littlespidy
 */
public class SourceCodeViewerPanel extends JPanel {

    private final JLabel filePathLabel = new JLabel("No file selected");
    private final JLabel fileStatsLabel = new JLabel("");
    private final JTextArea codeArea = new JTextArea();
    private final JTextArea lineNumbersArea = new JTextArea();

    private UnpackedSourceFile currentFile;
    private java.util.function.Consumer<UnpackedSourceFile> aiReviewListener;

    public void setAiReviewListener(java.util.function.Consumer<UnpackedSourceFile> listener) {
        this.aiReviewListener = listener;
    }

    public SourceCodeViewerPanel() {
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        // ── Top Header Toolbar ──
        JPanel topToolbar = new JPanel(new BorderLayout(5, 5));
        topToolbar.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));

        JPanel pathBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        filePathLabel.setFont(new Font(Font.MONOSPACED, Font.BOLD, 13));
        fileStatsLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        pathBox.add(filePathLabel);
        pathBox.add(fileStatsLabel);

        JPanel actionsBox = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        JButton aiReviewBtn = new JButton("🤖 AI Review");
        aiReviewBtn.setToolTipText("Send this file to AI Security Analyst (Local LLM / Antigravity)");
        aiReviewBtn.addActionListener(e -> {
            if (currentFile != null && aiReviewListener != null) {
                aiReviewListener.accept(currentFile);
            }
        });

        JButton copyBtn = new JButton("Copy Code");
        copyBtn.addActionListener(e -> copyCurrentCodeToClipboard());

        JButton saveBtn = new JButton("Save File As...");
        saveBtn.addActionListener(e -> saveCurrentFileToDisk());

        actionsBox.add(aiReviewBtn);
        actionsBox.add(copyBtn);
        actionsBox.add(saveBtn);

        topToolbar.add(pathBox, BorderLayout.WEST);
        topToolbar.add(actionsBox, BorderLayout.EAST);

        // ── Center Code Area ──
        codeArea.setEditable(false);
        codeArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        codeArea.setTabSize(4);

        lineNumbersArea.setEditable(false);
        lineNumbersArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        lineNumbersArea.setBackground(new Color(245, 245, 245));
        lineNumbersArea.setForeground(Color.GRAY);
        lineNumbersArea.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4));

        JScrollPane scrollPane = new JScrollPane(codeArea);
        scrollPane.setRowHeaderView(lineNumbersArea);

        add(topToolbar, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
    }

    public void displayFile(UnpackedSourceFile file) {
        this.currentFile = file;
        if (file == null) {
            filePathLabel.setText("No file selected");
            fileStatsLabel.setText("");
            codeArea.setText("");
            lineNumbersArea.setText("");
            return;
        }

        filePathLabel.setText(file.relativePath());
        int secretsCount = file.secrets() != null ? file.secrets().size() : 0;
        int endpointsCount = file.endpoints() != null ? file.endpoints().size() : 0;

        fileStatsLabel.setText(String.format(
            "(%d lines | %s | %d secrets | %d endpoints)",
            file.lineCount(),
            formatSize(file.sizeBytes()),
            secretsCount,
            endpointsCount
        ));

        codeArea.setText(file.content());
        codeArea.setCaretPosition(0);

        // Generate line numbers
        StringBuilder linesText = new StringBuilder();
        for (int i = 1; i <= file.lineCount(); i++) {
            linesText.append(i).append("\n");
        }
        lineNumbersArea.setText(linesText.toString());
    }

    private void copyCurrentCodeToClipboard() {
        if (currentFile != null && currentFile.content() != null) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                new StringSelection(currentFile.content()), null
            );
            JOptionPane.showMessageDialog(this, "Copied source code to clipboard!", "Copy Code", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void saveCurrentFileToDisk() {
        if (currentFile == null) return;

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new File(currentFile.fileName()));
        int choice = fileChooser.showSaveDialog(this);

        if (choice == JFileChooser.APPROVE_OPTION) {
            File chosen = fileChooser.getSelectedFile();
            try (FileOutputStream fos = new FileOutputStream(chosen)) {
                fos.write(currentFile.content().getBytes(StandardCharsets.UTF_8));
                JOptionPane.showMessageDialog(this, "Saved file to: " + chosen.getAbsolutePath(), "Save Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Failed to save file: " + ex.getMessage(), "Save Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private String formatSize(int bytes) {
        if (bytes <= 0) return "0 B";
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
    }
}
