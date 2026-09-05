// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Custom table cell renderer for HTTP status codes with visual color coding:
 * 2xx: Green
 * 3xx: Blue
 * 4xx: Orange
 * 5xx: Red
 */
public class StatusCodeRenderer extends DefaultTableCellRenderer {

    private static final Color COLOR_2XX = new Color(34, 139, 34);
    private static final Color COLOR_3XX = new Color(30, 144, 255);
    private static final Color COLOR_4XX = new Color(220, 120, 0);
    private static final Color COLOR_5XX = new Color(205, 38, 38);

    public StatusCodeRenderer() {
        setHorizontalAlignment(SwingConstants.CENTER);
    }

    @Override
    public Component getTableCellRendererComponent(
            JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column
    ) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if (!isSelected && value != null) {
            try {
                int status = Integer.parseInt(value.toString());
                if (status >= 200 && status < 300) {
                    c.setForeground(COLOR_2XX);
                } else if (status >= 300 && status < 400) {
                    c.setForeground(COLOR_3XX);
                } else if (status >= 400 && status < 500) {
                    c.setForeground(COLOR_4XX);
                } else if (status >= 500 && status < 600) {
                    c.setForeground(COLOR_5XX);
                } else {
                    c.setForeground(table.getForeground());
                }
                setFont(getFont().deriveFont(Font.BOLD));
            } catch (NumberFormatException ignored) {
                c.setForeground(table.getForeground());
            }
        }

        return c;
    }
}
