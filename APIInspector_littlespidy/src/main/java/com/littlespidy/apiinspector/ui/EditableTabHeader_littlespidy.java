// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * Custom tab header component providing in-place inline renaming on double-click
 * with zero modal popups, following strict Burp extension UI guidelines.
 */
public class EditableTabHeader_littlespidy extends JPanel {

    private final JTabbedPane tabbedPane;
    private final Component tabContent;
    private final JLabel titleLabel;
    private final JTextField editField;
    private final JButton closeButton;
    private boolean isEditing = false;
    private Runnable onCloseCallback;

    public EditableTabHeader_littlespidy(JTabbedPane tabbedPane, Component tabContent, String defaultTitle) {
        super(new FlowLayout(FlowLayout.LEFT, 4, 0));
        setOpaque(false);
        this.tabbedPane = tabbedPane;
        this.tabContent = tabContent;

        // Display label
        this.titleLabel = new JLabel(defaultTitle);
        this.titleLabel.setToolTipText("Double-click to rename tab");

        // Inline text field editor (hidden until double-click)
        this.editField = new JTextField();
        this.editField.setVisible(false);
        this.editField.setFont(titleLabel.getFont());
        this.editField.setColumns(Math.max(10, defaultTitle.length()));

        // Double-click to initiate inline editing
        this.titleLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    startEditing();
                }
            }
        });

        // Key bindings: Enter to commit, Escape to cancel
        this.editField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    commitEditing();
                } else if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                    cancelEditing();
                }
            }
        });

        // Commit on focus loss
        this.editField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                if (isEditing) {
                    commitEditing();
                }
            }
        });

        // Close button (plain ASCII 'x')
        this.closeButton = new JButton("x");
        this.closeButton.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 2));
        this.closeButton.setContentAreaFilled(false);
        this.closeButton.setFocusable(false);
        this.closeButton.setToolTipText("Close tab");
        this.closeButton.addActionListener(e -> {
            if (onCloseCallback != null) {
                onCloseCallback.run();
            }
            int idx = tabbedPane.indexOfComponent(tabContent);
            if (idx != -1) {
                tabbedPane.removeTabAt(idx);
            }
        });

        add(titleLabel);
        add(editField);
        add(closeButton);
    }

    public void setOnCloseCallback(Runnable callback) {
        this.onCloseCallback = callback;
    }

    public String getTitle() {
        return titleLabel.getText();
    }

    public void setTitle(String title) {
        titleLabel.setText(title);
        int idx = tabbedPane.indexOfComponent(tabContent);
        if (idx != -1) {
            tabbedPane.setTitleAt(idx, title);
        }
    }

    private void startEditing() {
        isEditing = true;
        editField.setText(titleLabel.getText());
        editField.setColumns(Math.max(10, titleLabel.getText().length()));
        titleLabel.setVisible(false);
        editField.setVisible(true);
        editField.requestFocusInWindow();
        editField.selectAll();
        revalidate();
        repaint();
    }

    private void commitEditing() {
        if (!isEditing) return;
        isEditing = false;
        String newTitle = editField.getText().trim();
        if (!newTitle.isEmpty()) {
            setTitle(newTitle);
        }
        editField.setVisible(false);
        titleLabel.setVisible(true);
        revalidate();
        repaint();
    }

    private void cancelEditing() {
        if (!isEditing) return;
        isEditing = false;
        editField.setVisible(false);
        titleLabel.setVisible(true);
        revalidate();
        repaint();
    }
}
