// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.attacker.ui;

import com.littlespidy.jwtcomparator.attacker.model.TokenAttackResult;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Color-coded table cell renderer for the Token Attacker matrix.
 * Visualizes HTTP status codes, security assessments, and error conditions.
 */
public class AttackCellRenderer extends DefaultTableCellRenderer {

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                   boolean isSelected, boolean hasFocus,
                                                   int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        setHorizontalAlignment(SwingConstants.CENTER);
        setToolTipText(null);
        setFont(table.getFont());

        boolean isDark = isDarkTheme(table);

        if (value instanceof TokenAttackResult) {
            TokenAttackResult result = (TokenAttackResult) value;
            setText(result.getDisplayText());

            String tooltip = String.format("<html><b>%s</b><br>Status: %d %s<br>Length: %,d bytes<br>Time: %d ms%s</html>",
                    result.getTokenName(),
                    result.getStatusCode(),
                    result.getStatusReason(),
                    result.getResponseLength(),
                    result.getResponseTimeMs(),
                    result.getError() != null && !result.getError().isEmpty() ? "<br>Error: " + result.getError() : "");
            setToolTipText(tooltip);

            if (!isSelected) {
                switch (result.getStatusType()) {
                    case ACCEPTED:
                        setBackground(isDark ? new Color(25, 75, 35) : new Color(225, 248, 225));
                        setForeground(isDark ? new Color(130, 245, 140) : new Color(0, 115, 0));
                        setFont(getFont().deriveFont(Font.BOLD));
                        break;
                    case REJECTED:
                        setBackground(isDark ? new Color(70, 30, 30) : new Color(255, 230, 230));
                        setForeground(isDark ? new Color(250, 140, 140) : new Color(160, 25, 25));
                        break;
                    case REDIRECT:
                        setBackground(isDark ? new Color(75, 65, 25) : new Color(255, 250, 215));
                        setForeground(isDark ? new Color(245, 210, 100) : new Color(150, 100, 0));
                        break;
                    case SERVER_ERROR:
                        setBackground(isDark ? new Color(75, 25, 65) : new Color(252, 225, 245));
                        setForeground(isDark ? new Color(240, 120, 200) : new Color(150, 20, 100));
                        setFont(getFont().deriveFont(Font.BOLD));
                        break;
                    case FAILED:
                        setBackground(isDark ? new Color(50, 50, 50) : new Color(240, 240, 240));
                        setForeground(isDark ? new Color(170, 170, 170) : new Color(110, 110, 110));
                        break;
                    default:
                        setBackground(isDark ? new Color(45, 45, 45) : new Color(248, 248, 248));
                        setForeground(table.getForeground());
                        break;
                }
            }
        } else if (value instanceof String) {
            String str = (String) value;
            setText(str);

            if (column == 2) {
                // Endpoint / Path column
                setHorizontalAlignment(SwingConstants.LEFT);
                setToolTipText(str);
            } else if (column == 1) {
                // Method column
                setFont(getFont().deriveFont(Font.BOLD));
            }

            // Assessment column
            if (!isSelected) {
                if (str.startsWith("🚨")) {
                    setBackground(isDark ? new Color(85, 25, 25) : new Color(255, 220, 220));
                    setForeground(isDark ? new Color(255, 120, 120) : new Color(170, 0, 0));
                    setFont(getFont().deriveFont(Font.BOLD));
                } else if (str.startsWith("⚠️")) {
                    setBackground(isDark ? new Color(75, 55, 20) : new Color(255, 242, 210));
                    setForeground(isDark ? new Color(250, 185, 75) : new Color(160, 95, 0));
                    setFont(getFont().deriveFont(Font.BOLD));
                } else if (str.startsWith("✔")) {
                    setBackground(isDark ? new Color(25, 65, 30) : new Color(230, 252, 230));
                    setForeground(isDark ? new Color(120, 230, 130) : new Color(20, 125, 30));
                } else if (str.startsWith("🔒")) {
                    setBackground(isDark ? new Color(45, 45, 55) : new Color(240, 240, 248));
                    setForeground(isDark ? new Color(180, 180, 220) : new Color(80, 80, 130));
                } else if (!isSelected) {
                    setBackground(table.getBackground());
                    setForeground(table.getForeground());
                }
            }
        } else if (value == null) {
            setText("-");
            if (!isSelected) {
                setBackground(table.getBackground());
                setForeground(Color.GRAY);
            }
        }

        if (isSelected) {
            setBackground(table.getSelectionBackground());
            setForeground(table.getSelectionForeground());
        }

        return c;
    }

    private boolean isDarkTheme(JTable table) {
        Color bg = table.getBackground();
        if (bg == null) return false;
        double luminance = (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue());
        return luminance < 128;
    }
}
