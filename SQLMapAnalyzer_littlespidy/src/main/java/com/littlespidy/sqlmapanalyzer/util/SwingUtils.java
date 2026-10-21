// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.util;

import javax.swing.*;
import java.awt.*;

/**
 * Swing helper methods for threading and UI styling.
 * Plain ASCII text only.
 */
public final class SwingUtils {

    private SwingUtils() {}

    public static void runOnEdt(Runnable task) {
        if (SwingUtilities.isEventDispatchThread()) {
            task.run();
        } else {
            SwingUtilities.invokeLater(task);
        }
    }

    public static JButton createStyledButton(String text) {
        JButton button = new JButton(text);
        button.setFocusPainted(false);
        button.setMargin(new Insets(4, 10, 4, 10));
        return button;
    }

    public static JLabel createBoldLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD));
        return label;
    }
}
