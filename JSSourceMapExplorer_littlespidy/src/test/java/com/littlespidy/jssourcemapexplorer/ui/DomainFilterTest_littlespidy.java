// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class DomainFilterTest_littlespidy {

    @Test
    public void testMatchesDomainEmptyOrAll() {
        // Null or empty selectedDomains should match any host
        assertTrue(MultiSelectFilterButton.matchesDomain("example.com", null));
        assertTrue(MultiSelectFilterButton.matchesDomain("example.com", Set.of()));

        // "All Domains" sentinel matches any host
        assertTrue(MultiSelectFilterButton.matchesDomain("example.com", Set.of("All Domains")));
        assertTrue(MultiSelectFilterButton.matchesDomain("cdn.cloudflare.com", Set.of("All Domains")));
    }

    @Test
    public void testMatchesDomainExactAndSubdomain() {
        Set<String> selected = Set.of("example.com", "target.org");

        // Exact matches
        assertTrue(MultiSelectFilterButton.matchesDomain("example.com", selected));
        assertTrue(MultiSelectFilterButton.matchesDomain("target.org", selected));

        // Subdomain matches
        assertTrue(MultiSelectFilterButton.matchesDomain("api.example.com", selected));
        assertTrue(MultiSelectFilterButton.matchesDomain("sub.deep.api.example.com", selected));
        assertTrue(MultiSelectFilterButton.matchesDomain("auth.target.org", selected));

        // Unmatched domains
        assertFalse(MultiSelectFilterButton.matchesDomain("google-analytics.com", selected));
        assertFalse(MultiSelectFilterButton.matchesDomain("notexample.com", selected));
        assertFalse(MultiSelectFilterButton.matchesDomain("anothertarget.org", selected));
    }

    @Test
    public void testMatchesDomainCaseAndPortInsensitive() {
        Set<String> selected = Set.of("Example.COM");

        assertTrue(MultiSelectFilterButton.matchesDomain("EXAMPLE.COM", selected));
        assertTrue(MultiSelectFilterButton.matchesDomain("api.example.com", selected));
        assertTrue(MultiSelectFilterButton.matchesDomain("example.com:8443", selected));
        assertTrue(MultiSelectFilterButton.matchesDomain("api.example.com:443", selected));
    }

    @Test
    public void testMultiSelectFilterButtonDynamicOptions() {
        MultiSelectFilterButton btn = new MultiSelectFilterButton(
            "Domains",
            List.of("All Domains"),
            sel -> {}
        );

        assertTrue(btn.isAllSelected());

        // Update with newly discovered in-scope domains
        btn.setOptions(List.of("All Domains", "app.example.com", "api.example.com"), true);

        // All should be checked by default
        assertTrue(btn.isAllSelected());
        assertEquals(Set.of("app.example.com", "api.example.com"), btn.getSelected());

        // Deselect one domain
        btn.clearSelection();
        assertTrue(btn.getSelected().isEmpty());
        assertTrue(btn.isAllSelected()); // clearSelection = pass-all

        // Check only 1 domain
        btn.setOptions(List.of("All Domains", "app.example.com", "api.example.com"), false);
        btn.selectAll();
        assertTrue(btn.isAllSelected());
    }
}
