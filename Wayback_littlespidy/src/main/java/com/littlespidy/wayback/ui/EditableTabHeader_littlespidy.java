// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.function.Consumer;

public class EditableTabHeader_littlespidy extends JPanel {

    private final JTabbedPane tabbedPane;
    private final Component tabContent;
    private final JLabel titleLabel;
    private final JTextField editField;
    private final JButton closeButton;
    private boolean isEditing = false;
    private Consumer<Component> closeCallback;

    public EditableTabHeader_littlespidy(JTabbedPane tabbedPane, Component tabContent, String defaultTitle) {
        super(new FlowLayout(FlowLayout.LEFT, 4, 0));
        setOpaque(false);
        this.tabbedPane = tabbedPane;
        this.tabContent = tabContent;

        this.titleLabel = new JLabel(defaultTitle);
        this.titleLabel.setToolTipText("Double-click to rename tab");

        this.editField = new JTextField();
        this.editField.setVisible(false);
        this.editField.setFont(titleLabel.getFont());
        this.editField.setColumns(Math.max(10, defaultTitle.length()));

        this.titleLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    startEditing();
                }
            }
        });

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

        this.editField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                if (isEditing) {
                    commitEditing();
                }
            }
        });

        this.closeButton = new JButton("x");
        this.closeButton.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 2));
        this.closeButton.setContentAreaFilled(false);
        this.closeButton.setFocusable(false);
        this.closeButton.setToolTipText("Close tab");
        this.closeButton.addActionListener(e -> {
            if (closeCallback != null) {
                closeCallback.accept(tabContent);
            } else {
                int idx = tabbedPane.indexOfComponent(tabContent);
                if (idx != -1) {
                    tabbedPane.removeTabAt(idx);
                }
            }
        });

        add(titleLabel);
        add(editField);
        add(closeButton);
    }

    public void setCloseCallback(Consumer<Component> closeCallback) {
        this.closeCallback = closeCallback;
    }

    private void startEditing() {
        isEditing = true;
        editField.setText(titleLabel.getText());
        editField.setColumns(Math.max(8, titleLabel.getText().length()));
        titleLabel.setVisible(false);
        editField.setVisible(true);
        revalidate();
        editField.requestFocusInWindow();
        editField.selectAll();
    }

    private void commitEditing() {
        if (!isEditing) return;
        isEditing = false;
        String newTitle = editField.getText().trim();
        if (!newTitle.isEmpty()) {
            titleLabel.setText(newTitle);
            int idx = tabbedPane.indexOfComponent(tabContent);
            if (idx != -1) {
                tabbedPane.setTitleAt(idx, newTitle);
            }
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

    public void updateTitle(String text) {
        titleLabel.setText(text);
        int idx = tabbedPane.indexOfComponent(tabContent);
        if (idx != -1) {
            tabbedPane.setTitleAt(idx, text);
        }
    }

    public String getTitle() {
        return titleLabel.getText();
    }
}
