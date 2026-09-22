// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Custom table cell renderer providing color highlights for session expiration,
 * pause, and retry events.
 *
 * @author littlespidy
 */
public class ActivityCellRenderer extends DefaultTableCellRenderer {

    private static final Color RED_BG = new Color(254, 226, 226);
    private static final Color RED_FG = new Color(153, 27, 27);

    private static final Color AMBER_BG = new Color(254, 243, 199);
    private static final Color AMBER_FG = new Color(146, 64, 14);

    private static final Color GREEN_BG = new Color(220, 252, 231);
    private static final Color GREEN_FG = new Color(22, 101, 52);

    private static final Color BLUE_BG = new Color(224, 242, 254);
    private static final Color BLUE_FG = new Color(7, 89, 133);

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                   boolean isSelected, boolean hasFocus,
                                                   int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if (isSelected) {
            return c;
        }

        // Get Event Type from column 7
        Object eventObj = table.getValueAt(row, 7);
        String event = (eventObj != null) ? eventObj.toString() : "";

        if (event.contains("EXPIRED")) {
            c.setBackground(RED_BG);
            c.setForeground(RED_FG);
            if (column == 7) setFont(getFont().deriveFont(Font.BOLD));
        } else if (event.contains("PAUSED")) {
            c.setBackground(AMBER_BG);
            c.setForeground(AMBER_FG);
            if (column == 7) setFont(getFont().deriveFont(Font.BOLD));
        } else if (event.contains("RESUMED") || event.contains("UPDATED") || event.contains("RETRIED")) {
            c.setBackground(GREEN_BG);
            c.setForeground(GREEN_FG);
            if (column == 7) setFont(getFont().deriveFont(Font.BOLD));
        } else if (event.contains("INJECTED")) {
            c.setBackground(table.getBackground());
            c.setForeground(table.getForeground());
        } else {
            c.setBackground(table.getBackground());
            c.setForeground(table.getForeground());
        }

        // Center align ID, Time, Method, Status
        if (column == 0 || column == 1 || column == 2 || column == 3 || column == 6) {
            setHorizontalAlignment(SwingConstants.CENTER);
        } else {
            setHorizontalAlignment(SwingConstants.LEFT);
        }

        return c;
    }
}
