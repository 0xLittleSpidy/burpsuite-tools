// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.runner;

import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyEvent;

/**
 * Compact, code-formatted dialog for viewing and copying the generated SQLMap CLI command.
 * Plain ASCII text only.
 */
public class CliCommandDialog_littlespidy extends JDialog {

    public CliCommandDialog_littlespidy(Window owner, String command) {
        super(owner, "SQLMap CLI Command", ModalityType.MODELESS);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(8, 8));
        setSize(600, 240);
        setLocationRelativeTo(owner);

        JPanel mainPanel = new JPanel(new BorderLayout(6, 6));
        mainPanel.setBorder(new EmptyBorder(10, 12, 10, 12));

        JLabel infoLabel = SwingUtils.createBoldLabel("Command copied to clipboard. You can paste and run it directly in your terminal:");
        mainPanel.add(infoLabel, BorderLayout.NORTH);

        JTextArea textArea = new JTextArea(command);
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setEditable(false);
        textArea.setBackground(new Color(43, 43, 43));
        textArea.setForeground(new Color(230, 230, 230));
        textArea.setCaretColor(Color.WHITE);
        textArea.setBorder(new EmptyBorder(6, 6, 6, 6));

        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        // Bottom bar
        JPanel bottomBar = new JPanel(new BorderLayout());
        JLabel statusLabel = new JLabel("Copied to clipboard.");
        statusLabel.setForeground(new Color(0, 128, 0));
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 11));

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton btnCopy = SwingUtils.createStyledButton("Copy Again");
        btnCopy.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(command), null);
            statusLabel.setText("Re-copied to clipboard.");
        });

        JButton btnClose = SwingUtils.createStyledButton("Close");
        btnClose.addActionListener(e -> dispose());

        btnPanel.add(btnCopy);
        btnPanel.add(btnClose);

        bottomBar.add(statusLabel, BorderLayout.WEST);
        bottomBar.add(btnPanel, BorderLayout.EAST);
        mainPanel.add(bottomBar, BorderLayout.SOUTH);

        add(mainPanel, BorderLayout.CENTER);

        // Bind Escape key to close dialog
        getRootPane().registerKeyboardAction(e -> dispose(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
    }

    public static void showCli(Component parent, String command) {
        Window window = SwingUtilities.getWindowAncestor(parent);
        CliCommandDialog_littlespidy dialog = new CliCommandDialog_littlespidy(window, command);
        dialog.setVisible(true);
    }
}
