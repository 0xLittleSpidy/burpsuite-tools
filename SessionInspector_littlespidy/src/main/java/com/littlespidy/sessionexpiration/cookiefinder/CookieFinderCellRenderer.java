// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiefinder;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Cell renderer for Session Cookie Finder table, highlighting identified session tokens,
 * HTTP status codes, and verdicts.
 *
 * @author littlespidy
 */
public class CookieFinderCellRenderer extends DefaultTableCellRenderer {

    private static final Color COLOR_RED = new Color(220, 53, 69);
    private static final Color COLOR_GREEN = new Color(40, 167, 69);
    private static final Color COLOR_BLUE = new Color(23, 162, 184);
    private static final Color COLOR_PURPLE = new Color(111, 66, 193);
    private static final Color COLOR_ORANGE = new Color(253, 126, 20);
    private static final Color COLOR_GRAY = new Color(108, 117, 125);

    @Override
    public Component getTableCellRendererComponent(
            JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column
    ) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if (!isSelected) {
            c.setBackground(table.getBackground());
            c.setForeground(table.getForeground());
            setFont(getFont().deriveFont(Font.PLAIN));

            if (column == 4) { // HTTP Status
                if (value instanceof Number) {
                    long code = ((Number) value).longValue();
                    setFont(getFont().deriveFont(Font.BOLD));
                    if (code >= 200 && code < 300) {
                        c.setForeground(COLOR_GREEN);
                    } else if (code >= 300 && code < 400) {
                        c.setForeground(COLOR_BLUE);
                    } else if (code == 401 || code == 403) {
                        c.setForeground(COLOR_RED);
                    } else if (code >= 400 && code < 500) {
                        c.setForeground(COLOR_ORANGE);
                    } else if (code >= 500) {
                        c.setForeground(COLOR_PURPLE);
                    }
                }
            } else if (column == 7) { // Verdict
                if (value instanceof String str) {
                    setFont(getFont().deriveFont(Font.BOLD));
                    if (str.contains("Session Token")) {
                        c.setForeground(COLOR_RED);
                    } else if (str.contains("Baseline")) {
                        c.setForeground(COLOR_GREEN);
                    } else if (str.contains("Anonymous")) {
                        c.setForeground(COLOR_PURPLE);
                    } else if (str.contains("Suspicious") || str.contains("Significant")) {
                        c.setForeground(COLOR_ORANGE);
                    } else if (str.contains("Optional")) {
                        c.setForeground(COLOR_GRAY);
                    }
                }
            } else if (column == 1) { // Component Tested
                if (value instanceof String str) {
                    if (str.startsWith("Cookie:")) {
                        c.setForeground(COLOR_BLUE);
                    } else if (str.startsWith("Header:") || str.startsWith("Custom:")) {
                        c.setForeground(COLOR_PURPLE);
                    }
                }
            }
        }

        return c;
    }
}
