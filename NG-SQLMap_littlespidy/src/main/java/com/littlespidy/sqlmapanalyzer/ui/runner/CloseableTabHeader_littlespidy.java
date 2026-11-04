// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.runner;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;

/**
 * Tab header component with double-click inline renaming and an ASCII close button.
 * Plain ASCII text only. Zero modal popups.
 */
public class CloseableTabHeader_littlespidy extends JPanel {

    private final JLabel titleLabel;
    private final JTextField editField;
    private final JButton closeButton;
    private final Consumer<String> onRename;
    private boolean editing = false;

    public CloseableTabHeader_littlespidy(String title, Consumer<String> onRename, Consumer<CloseableTabHeader_littlespidy> onClose) {
        this.onRename = onRename;
        setLayout(new FlowLayout(FlowLayout.LEFT, 4, 0));
        setOpaque(false);

        titleLabel = new JLabel(title);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 11));
        titleLabel.setToolTipText("Double-click to rename tab");

        editField = new JTextField();
        editField.setFont(titleLabel.getFont());
        editField.setBorder(BorderFactory.createLineBorder(Color.GRAY));

        titleLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    startEditing();
                }
            }
        });

        editField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    commitEditing();
                } else if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                    cancelEditing();
                }
            }
        });

        editField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                if (editing) {
                    commitEditing();
                }
            }
        });

        add(titleLabel);

        closeButton = new JButton("x");
        closeButton.setFont(new Font(Font.MONOSPACED, Font.BOLD, 10));
        closeButton.setMargin(new Insets(0, 3, 0, 3));
        closeButton.setBorder(new EmptyBorder(1, 3, 1, 3));
        closeButton.setContentAreaFilled(false);
        closeButton.setFocusPainted(false);
        closeButton.setToolTipText("Close Tab");

        closeButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                closeButton.setForeground(Color.RED);
            }
            @Override
            public void mouseExited(MouseEvent e) {
                closeButton.setForeground(Color.BLACK);
            }
        });

        closeButton.addActionListener(e -> {
            if (onClose != null) {
                onClose.accept(this);
            }
        });

        add(closeButton);
    }

    private void startEditing() {
        if (editing) return;
        editing = true;
        editField.setText(titleLabel.getText());
        int width = Math.max(90, titleLabel.getPreferredSize().width + 24);
        editField.setPreferredSize(new Dimension(width, 20));

        remove(titleLabel);
        add(editField, 0);
        revalidate();
        repaint();

        editField.requestFocusInWindow();
        editField.selectAll();
    }

    private void commitEditing() {
        if (!editing) return;
        String newTitle = editField.getText().trim();
        if (!newTitle.isEmpty()) {
            titleLabel.setText(newTitle);
            if (onRename != null) {
                onRename.accept(newTitle);
            }
        }
        stopEditing();
    }

    private void cancelEditing() {
        if (!editing) return;
        stopEditing();
    }

    private void stopEditing() {
        editing = false;
        remove(editField);
        add(titleLabel, 0);
        revalidate();
        repaint();
    }

    public void setTitle(String title) {
        titleLabel.setText(title);
        editField.setText(title);
    }

    public String getTitle() {
        return titleLabel.getText();
    }
}
