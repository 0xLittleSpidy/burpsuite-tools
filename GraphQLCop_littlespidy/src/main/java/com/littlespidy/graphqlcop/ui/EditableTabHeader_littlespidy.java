// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;

public class EditableTabHeader_littlespidy extends JPanel {
    private final JLabel titleLabel;
    private final JTextField editField;
    private final Consumer<String> titleChangeConsumer;

    public EditableTabHeader_littlespidy(String title, JTabbedPane tabbedPane, Component tabComponent,
                                         Consumer<String> titleChangeConsumer, Runnable closeAction) {
        super(new FlowLayout(FlowLayout.LEFT, 4, 0));
        setOpaque(false);
        this.titleChangeConsumer = titleChangeConsumer;

        titleLabel = new JLabel(title);
        editField = new JTextField(title);
        editField.setVisible(false);

        titleLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    startEditing();
                }
            }
        });

        editField.addActionListener(e -> finishEditing());
        editField.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                finishEditing();
            }
        });

        JButton closeBtn = new JButton("x");
        closeBtn.setMargin(new Insets(0, 4, 0, 4));
        closeBtn.setFocusable(false);
        closeBtn.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
        closeBtn.setContentAreaFilled(false);
        closeBtn.addActionListener(e -> {
            if (closeAction != null) {
                closeAction.run();
            }
        });

        add(titleLabel);
        add(editField);
        add(closeBtn);
    }

    private void startEditing() {
        editField.setText(titleLabel.getText());
        titleLabel.setVisible(false);
        editField.setVisible(true);
        editField.requestFocusInWindow();
        editField.selectAll();
        revalidate();
    }

    private void finishEditing() {
        String newText = editField.getText().trim();
        if (!newText.isEmpty()) {
            titleLabel.setText(newText);
            if (titleChangeConsumer != null) {
                titleChangeConsumer.accept(newText);
            }
        }
        editField.setVisible(false);
        titleLabel.setVisible(true);
        revalidate();
    }

    public void setTitle(String text) {
        titleLabel.setText(text);
        editField.setText(text);
    }

    public String getTitle() {
        return titleLabel.getText();
    }
}
