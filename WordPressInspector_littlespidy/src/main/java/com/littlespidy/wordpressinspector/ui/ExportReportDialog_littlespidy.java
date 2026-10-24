// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.ui;

import com.littlespidy.wordpressinspector.engine.WordPressReportExporter_littlespidy;
import com.littlespidy.wordpressinspector.model.WordPressTarget_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileWriter;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Standalone dialog for viewing, copying, and saving practitioner Markdown/JSON reports.
 */
public class ExportReportDialog_littlespidy extends JDialog {

    private final WordPressTarget_littlespidy target;
    private final JTextArea reportArea;
    private final JComboBox<String> formatSelector;

    public ExportReportDialog_littlespidy(Window owner, WordPressTarget_littlespidy target) {
        super(owner, "Export Practitioner Report - " + target.getRootDomain(), ModalityType.APPLICATION_MODAL);
        this.target = target;

        setLayout(new BorderLayout(8, 8));
        setSize(780, 560);
        setLocationRelativeTo(owner);

        // Top Toolbar
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 8));
        topPanel.add(new JLabel("Report Format:"));
        formatSelector = new JComboBox<>(new String[]{"Markdown (.md)", "Structured JSON (.json)"});
        formatSelector.addActionListener(e -> updateReportText());
        topPanel.add(formatSelector);

        add(topPanel, BorderLayout.NORTH);

        // Center Content Area
        reportArea = new JTextArea();
        reportArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        reportArea.setEditable(false);
        reportArea.setCaretPosition(0);
        JScrollPane scrollPane = new JScrollPane(reportArea);
        add(scrollPane, BorderLayout.CENTER);

        // Bottom Controls
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        JButton copyBtn = new JButton("Copy to Clipboard");
        copyBtn.addActionListener(e -> copyToClipboard());
        bottomPanel.add(copyBtn);

        JButton saveBtn = new JButton("Save to File");
        saveBtn.addActionListener(e -> saveToFile());
        bottomPanel.add(saveBtn);

        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dispose());
        bottomPanel.add(closeBtn);

        add(bottomPanel, BorderLayout.SOUTH);

        updateReportText();
    }

    private void updateReportText() {
        if ("Structured JSON (.json)".equals(formatSelector.getSelectedItem())) {
            reportArea.setText(WordPressReportExporter_littlespidy.generateJson(target));
        } else {
            reportArea.setText(WordPressReportExporter_littlespidy.generateMarkdown(target));
        }
        reportArea.setCaretPosition(0);
    }

    private void copyToClipboard() {
        String text = reportArea.getText();
        if (text != null && !text.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
            JOptionPane.showMessageDialog(this, "Report copied to clipboard successfully.", "Copied", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void saveToFile() {
        boolean isJson = "Structured JSON (.json)".equals(formatSelector.getSelectedItem());
        String defaultName = "wordpress_report_" + target.getRootDomain().replace(".", "_") + (isJson ? ".json" : ".md");

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(defaultName));
        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(reportArea.getText());
                JOptionPane.showMessageDialog(this, "Report saved to: " + file.getAbsolutePath(), "Saved", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Failed to save file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
