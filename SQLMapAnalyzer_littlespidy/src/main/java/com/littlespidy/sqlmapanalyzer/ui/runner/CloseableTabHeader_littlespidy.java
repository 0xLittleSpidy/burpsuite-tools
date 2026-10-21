// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.runner;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;

/**
 * Tab header component with a label and an ASCII close button.
 * Plain ASCII text only.
 */
public class CloseableTabHeader_littlespidy extends JPanel {

    private final JLabel titleLabel;
    private final JButton closeButton;

    public CloseableTabHeader_littlespidy(String title, Consumer<CloseableTabHeader_littlespidy> onClose) {
        setLayout(new FlowLayout(FlowLayout.LEFT, 4, 0));
        setOpaque(false);

        titleLabel = new JLabel(title);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 11));
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

    public void setTitle(String title) {
        titleLabel.setText(title);
    }

    public String getTitle() {
        return titleLabel.getText();
    }
}
