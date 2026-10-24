// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Tab header component containing a title label and a clean ASCII [X] close button.
 */
public class CloseableTabHeader_littlespidy extends JPanel {

    public interface TabCloseListener {
        void onTabClosed();
    }

    public CloseableTabHeader_littlespidy(String title, TabCloseListener closeListener) {
        super(new FlowLayout(FlowLayout.LEFT, 4, 0));
        setOpaque(false);

        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
        add(titleLabel);

        if (closeListener != null) {
            JLabel closeBtn = new JLabel("[X]");
            closeBtn.setFont(new Font("Monospaced", Font.BOLD, 10));
            closeBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            closeBtn.setToolTipText("Close Domain Tab");
            closeBtn.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    closeListener.onTabClosed();
                }

                @Override
                public void mouseEntered(MouseEvent e) {
                    closeBtn.setForeground(Color.RED);
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    closeBtn.setForeground(null);
                }
            });
            add(closeBtn);
        }
    }
}
