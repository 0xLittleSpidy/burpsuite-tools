// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.ui.common;

import javax.swing.JTable;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Central color manager providing consistent, visually distinct domain colors
 * across Cache, CSP, and HSTS inspectors. Contains a curated palette of 64 colors
 * (exceeding the 50 color requirement) generated via golden-ratio hue dispersion.
 *
 * @author littlespidy
 */
public class DomainColorManager_littlespidy {

    public static final int PALETTE_SIZE = 64;

    public record DomainStyle(Color bgTint, Color textAccent) {}

    private static final DomainStyle[] LIGHT_PALETTE = new DomainStyle[PALETTE_SIZE];
    private static final DomainStyle[] DARK_PALETTE  = new DomainStyle[PALETTE_SIZE];

    static {
        for (int i = 0; i < PALETTE_SIZE; i++) {
            float hue = (float) ((i * 0.618033988749895) % 1.0);
            LIGHT_PALETTE[i] = new DomainStyle(
                    Color.getHSBColor(hue, 0.16f, 0.96f),
                    Color.getHSBColor(hue, 0.88f, 0.35f)
            );
            DARK_PALETTE[i] = new DomainStyle(
                    Color.getHSBColor(hue, 0.42f, 0.24f),
                    Color.getHSBColor(hue, 0.30f, 0.95f)
            );
        }
    }

    private static final Map<String, Integer> DOMAIN_COLOR_INDICES = new ConcurrentHashMap<>();
    private static final AtomicInteger COUNTER = new AtomicInteger(0);

    public static int getDomainColorIndex(String domain) {
        if (domain == null || domain.isBlank() || domain.equalsIgnoreCase("(unknown)")) {
            return -1;
        }
        return DOMAIN_COLOR_INDICES.computeIfAbsent(domain.trim().toLowerCase(), k -> COUNTER.getAndIncrement() % PALETTE_SIZE);
    }

    public static DomainStyle getStyleForDomain(String domain, boolean isDark) {
        int idx = getDomainColorIndex(domain);
        if (idx < 0) return null;
        return isDark ? DARK_PALETTE[idx] : LIGHT_PALETTE[idx];
    }

    public static boolean isDarkTheme(Color c) {
        if (c == null) return false;
        double lum = 0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue();
        return lum < 128;
    }

    public static void applyDomainStyle(Component c, JTable table, String domain, boolean isSelected) {
        if (isSelected) {
            c.setBackground(table.getSelectionBackground());
            c.setForeground(table.getSelectionForeground());
            return;
        }
        boolean dark = isDarkTheme(table.getBackground());
        DomainStyle style = getStyleForDomain(domain, dark);
        if (style != null) {
            c.setBackground(style.bgTint());
            c.setForeground(style.textAccent());
            c.setFont(c.getFont().deriveFont(Font.BOLD));
        } else {
            c.setBackground(table.getBackground());
            c.setForeground(table.getForeground());
        }
    }

    public static void clear() {
        DOMAIN_COLOR_INDICES.clear();
        COUNTER.set(0);
    }
}
