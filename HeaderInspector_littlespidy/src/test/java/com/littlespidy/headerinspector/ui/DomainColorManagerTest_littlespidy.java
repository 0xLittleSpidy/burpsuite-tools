// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.ui;

import com.littlespidy.headerinspector.ui.common.DomainColorManager_littlespidy;
import com.littlespidy.headerinspector.ui.common.DomainColorManager_littlespidy.DomainStyle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Tests the DomainColorManager_littlespidy palette size, deterministic mapping,
 * and light/dark theme contrast.
 *
 * @author littlespidy
 */
class DomainColorManagerTest_littlespidy {

    @BeforeEach
    void setUp() {
        DomainColorManager_littlespidy.clear();
    }

    @Test
    void testPaletteSizeExceedsFifty() {
        assertTrue(DomainColorManager_littlespidy.PALETTE_SIZE > 50,
                "Palette size must exceed 50 distinct colors, actual: " + DomainColorManager_littlespidy.PALETTE_SIZE);
        assertEquals(64, DomainColorManager_littlespidy.PALETTE_SIZE);
    }

    @Test
    void testConsistentColorAssignmentAcrossCalls() {
        String domain = "api.example.com";
        int idx1 = DomainColorManager_littlespidy.getDomainColorIndex(domain);
        int idx2 = DomainColorManager_littlespidy.getDomainColorIndex(domain);
        int idx3 = DomainColorManager_littlespidy.getDomainColorIndex("API.EXAMPLE.COM");

        assertEquals(idx1, idx2, "Color index should be identical for the same domain");
        assertEquals(idx1, idx3, "Color index should be case-insensitive for domains");
        assertTrue(idx1 >= 0 && idx1 < DomainColorManager_littlespidy.PALETTE_SIZE);
    }

    @Test
    void testMultipleDomainsReceiveDistinctColors() {
        Set<Integer> indices = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            int idx = DomainColorManager_littlespidy.getDomainColorIndex("sub" + i + ".example.com");
            indices.add(idx);
        }
        assertEquals(50, indices.size(), "50 unique domains should receive 50 distinct color indices without collisions");
    }

    @Test
    void testStylesForLightAndDarkThemes() {
        String domain = "auth.testsite.org";

        DomainStyle lightStyle = DomainColorManager_littlespidy.getStyleForDomain(domain, false);
        assertNotNull(lightStyle);
        assertNotNull(lightStyle.bgTint());
        assertNotNull(lightStyle.textAccent());

        DomainStyle darkStyle = DomainColorManager_littlespidy.getStyleForDomain(domain, true);
        assertNotNull(darkStyle);
        assertNotNull(darkStyle.bgTint());
        assertNotNull(darkStyle.textAccent());

        assertNotEquals(lightStyle.bgTint(), darkStyle.bgTint(), "Light and dark theme backgrounds should differ");
    }

    @Test
    void testNullAndBlankDomainsReturnNegativeIndex() {
        assertEquals(-1, DomainColorManager_littlespidy.getDomainColorIndex(null));
        assertEquals(-1, DomainColorManager_littlespidy.getDomainColorIndex(""));
        assertEquals(-1, DomainColorManager_littlespidy.getDomainColorIndex("   "));
        assertEquals(-1, DomainColorManager_littlespidy.getDomainColorIndex("(unknown)"));
        assertNull(DomainColorManager_littlespidy.getStyleForDomain(null, false));
    }

    @Test
    void testDarkThemeDetection() {
        assertTrue(DomainColorManager_littlespidy.isDarkTheme(new Color(40, 40, 40)));
        assertFalse(DomainColorManager_littlespidy.isDarkTheme(new Color(250, 250, 250)));
        assertFalse(DomainColorManager_littlespidy.isDarkTheme(null));
    }
}
