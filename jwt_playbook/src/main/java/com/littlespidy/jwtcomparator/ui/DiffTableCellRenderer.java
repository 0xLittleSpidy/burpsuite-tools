// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import com.littlespidy.jwtcomparator.model.ComparisonRow;
import com.littlespidy.jwtcomparator.model.DiffType;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Custom table cell renderer with theme-aware color coding for JWT claim diffs.
 */
public class DiffTableCellRenderer extends DefaultTableCellRenderer {

    // Light Theme Colors
    private static final Color LIGHT_MISMATCH_BG = new Color(255, 243, 205); // soft amber
    private static final Color LIGHT_MISSING_BG  = new Color(248, 215, 218); // soft red
    private static final Color LIGHT_MATCH_BG    = new Color(255, 255, 255);
    private static final Color LIGHT_MISSING_FG  = new Color(114, 28, 36);

    // Dark Theme Colors
    private static final Color DARK_MISMATCH_BG  = new Color(65, 50, 20);  // dark amber
    private static final Color DARK_MISSING_BG   = new Color(60, 25, 25);  // dark reddish
    private static final Color DARK_MATCH_BG     = new Color(35, 37, 40);
    private static final Color DARK_MISSING_FG   = new Color(255, 150, 150);

    private final Font regularFont = new Font(Font.MONOSPACED, Font.PLAIN, 12);
    private final Font boldFont = new Font(Font.MONOSPACED, Font.BOLD, 12);
    private final Font italicFont = new Font(Font.MONOSPACED, Font.ITALIC, 12);

    public static boolean isDarkMode() {
        Color bg = UIManager.getColor("Panel.background");
        if (bg == null) return false;
        double luminance = (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue()) / 255;
        return luminance < 0.5;
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                   boolean isSelected, boolean hasFocus,
                                                   int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if (table.getModel() instanceof ComparisonTableModel) {
            ComparisonTableModel model = (ComparisonTableModel) table.getModel();
            int modelRow = table.convertRowIndexToModel(row);
            ComparisonRow compRow = model.getRowAt(modelRow);

            if (compRow != null) {
                boolean dark = isDarkMode();
                String textVal = (value != null) ? value.toString() : "";

                if (!isSelected) {
                    if (compRow.getDiffType() == DiffType.MISMATCH) {
                        c.setBackground(dark ? DARK_MISMATCH_BG : LIGHT_MISMATCH_BG);
                    } else if (compRow.getDiffType() == DiffType.PARTIAL_ABSENT) {
                        c.setBackground(dark ? DARK_MISSING_BG : LIGHT_MISSING_BG);
                    } else {
                        c.setBackground(dark ? DARK_MATCH_BG : LIGHT_MATCH_BG);
                    }
                    c.setForeground(UIManager.getColor("Table.foreground"));
                }

                // Specific styling for missing values
                if ("[MISSING]".equalsIgnoreCase(textVal)) {
                    c.setFont(italicFont);
                    if (!isSelected) {
                        c.setForeground(dark ? DARK_MISSING_FG : LIGHT_MISSING_FG);
                    }
                } else if (column == 0 || column == 1) {
                    // Section or Claim Key
                    c.setFont(boldFont);
                } else {
                    c.setFont(regularFont);
                }

                // Tooltip
                if (compRow.isTimestamp()) {
                    setToolTipText("Timestamp claim (" + compRow.getClaimKey() + ")");
                } else {
                    setToolTipText(textVal);
                }
            }
        }

        return c;
    }
}
