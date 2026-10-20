// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.ui;

import com.littlespidy.ssoinspector.model.IssueSeverity;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class SeverityCellRenderer extends DefaultTableCellRenderer {

    private static final Color COLOR_HIGH_BG = new Color(180, 40, 40);
    private static final Color COLOR_HIGH_FG = Color.WHITE;

    private static final Color COLOR_MEDIUM_BG = new Color(210, 105, 30);
    private static final Color COLOR_MEDIUM_FG = Color.WHITE;

    private static final Color COLOR_LOW_BG = new Color(205, 160, 30);
    private static final Color COLOR_LOW_FG = Color.BLACK;

    private static final Color COLOR_INFO_BG = new Color(70, 130, 180);
    private static final Color COLOR_INFO_FG = Color.WHITE;

    private static final Color COLOR_CLEAN_BG = new Color(46, 139, 87);
    private static final Color COLOR_CLEAN_FG = Color.WHITE;

    public SeverityCellRenderer() {
        setHorizontalAlignment(SwingConstants.CENTER);
        setOpaque(true);
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                   boolean isSelected, boolean hasFocus,
                                                   int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if (value == null) {
            setText("");
            return c;
        }

        String strVal = value.toString();
        IssueSeverity severity = IssueSeverity.fromString(strVal);

        if (!isSelected) {
            switch (severity) {
                case HIGH -> {
                    c.setBackground(COLOR_HIGH_BG);
                    c.setForeground(COLOR_HIGH_FG);
                }
                case MEDIUM -> {
                    c.setBackground(COLOR_MEDIUM_BG);
                    c.setForeground(COLOR_MEDIUM_FG);
                }
                case LOW -> {
                    c.setBackground(COLOR_LOW_BG);
                    c.setForeground(COLOR_LOW_FG);
                }
                case INFORMATION -> {
                    c.setBackground(COLOR_INFO_BG);
                    c.setForeground(COLOR_INFO_FG);
                }
                case CLEAN -> {
                    c.setBackground(COLOR_CLEAN_BG);
                    c.setForeground(COLOR_CLEAN_FG);
                }
            }
        }

        setText(severity.getLabel().toUpperCase());
        return c;
    }
}
