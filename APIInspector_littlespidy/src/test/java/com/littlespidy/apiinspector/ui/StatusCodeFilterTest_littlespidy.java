// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class StatusCodeFilterTest_littlespidy {

    @Test
    @DisplayName("Verify dynamic status code registration and filter matching")
    public void testStatusCodeFilterRegistration() {
        StatusCodeFilterDropDown_littlespidy filter = new StatusCodeFilterDropDown_littlespidy();

        // Initially matches all when nothing is registered or all are selected
        assertTrue(filter.matches(200));

        // Register several status codes
        filter.registerStatusCode(200);
        filter.registerStatusCode(404);
        filter.registerStatusCode(500);

        Set<Integer> available = filter.getAvailableStatusCodes();
        assertTrue(available.contains(200));
        assertTrue(available.contains(404));
        assertTrue(available.contains(500));
        assertEquals(3, available.size());

        // Default state: all selected, so matches all
        assertTrue(filter.matches(200));
        assertTrue(filter.matches(404));
        assertTrue(filter.matches(500));
        assertFalse(filter.matches(403)); // Not registered

        // Select only 200
        filter.setSelectedStatusCodes(Set.of(200));
        assertTrue(filter.matches(200));
        assertFalse(filter.matches(404));
        assertFalse(filter.matches(500));

        // Select 404 and 500
        filter.setSelectedStatusCodes(Set.of(404, 500));
        assertFalse(filter.matches(200));
        assertTrue(filter.matches(404));
        assertTrue(filter.matches(500));
    }

    @Test
    @DisplayName("Verify clear removes all registered status codes")
    public void testStatusCodeFilterClear() {
        StatusCodeFilterDropDown_littlespidy filter = new StatusCodeFilterDropDown_littlespidy();
        filter.registerStatusCode(200);
        filter.registerStatusCode(302);
        assertEquals(2, filter.getAvailableStatusCodes().size());

        filter.clear();
        assertEquals(0, filter.getAvailableStatusCodes().size());
        assertTrue(filter.matches(200));
    }
}
