// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.ui;

import com.littlespidy.sessionexpiration.model.SessionState;
import com.littlespidy.sessionexpiration.model.TimerInterval;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Custom table cell renderer for rendering session states, status codes,
 * and interval statuses with visual color coding.
 *
 * @author littlespidy
 */
public class StatusCellRenderer extends DefaultTableCellRenderer {

    private static final Color COLOR_GREEN = new Color(46, 139, 87);
    private static final Color COLOR_RED = new Color(205, 43, 43);
    private static final Color COLOR_ORANGE = new Color(218, 120, 10);
    private static final Color COLOR_BLUE = new Color(30, 144, 255);
    private static final Color COLOR_PURPLE = new Color(138, 43, 226);
    private static final Color COLOR_GRAY = new Color(128, 128, 128);

    @Override
    public Component getTableCellRendererComponent(
            JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column
    ) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if (!isSelected) {
            c.setBackground(table.getBackground());
            c.setForeground(table.getForeground());
            setFont(getFont().deriveFont(Font.PLAIN));

            if (value instanceof SessionState) {
                SessionState state = (SessionState) value;
                setFont(getFont().deriveFont(Font.BOLD));
                switch (state) {
                    case ACTIVE:
                    case COMPLETED:
                        c.setForeground(COLOR_GREEN);
                        break;
                    case EXPIRED:
                        c.setForeground(COLOR_RED);
                        break;
                    case RUNNING:
                        c.setForeground(COLOR_PURPLE);
                        break;
                    case PENDING:
                        c.setForeground(COLOR_ORANGE);
                        break;
                    case CANCELLED:
                    case ERROR:
                        c.setForeground(COLOR_GRAY);
                        break;
                }
            } else if (value instanceof TimerInterval.IntervalStatus) {
                TimerInterval.IntervalStatus st = (TimerInterval.IntervalStatus) value;
                setFont(getFont().deriveFont(Font.BOLD));
                switch (st) {
                    case PASSED:
                        c.setForeground(COLOR_GREEN);
                        break;
                    case EXPIRED:
                        c.setForeground(COLOR_RED);
                        break;
                    case RUNNING:
                        c.setForeground(COLOR_PURPLE);
                        break;
                    case SCHEDULED:
                        c.setForeground(COLOR_BLUE);
                        break;
                    case CANCELLED:
                    case ERROR:
                        c.setForeground(COLOR_GRAY);
                        break;
                }
            } else if (value instanceof Integer) {
                int code = (Integer) value;
                setFont(getFont().deriveFont(Font.BOLD));
                if (code >= 200 && code < 300) {
                    c.setForeground(COLOR_GREEN);
                } else if (code >= 300 && code < 400) {
                    c.setForeground(COLOR_BLUE);
                } else if (code >= 400 && code < 500) {
                    c.setForeground(COLOR_ORANGE);
                } else if (code >= 500) {
                    c.setForeground(COLOR_RED);
                }
            } else if (value instanceof String) {
                String str = (String) value;
                if (str.startsWith("Expired")) {
                    setFont(getFont().deriveFont(Font.BOLD));
                    c.setForeground(COLOR_RED);
                } else if (str.startsWith("Active")) {
                    setFont(getFont().deriveFont(Font.BOLD));
                    c.setForeground(COLOR_GREEN);
                }
            }
        }

        return c;
    }
}
