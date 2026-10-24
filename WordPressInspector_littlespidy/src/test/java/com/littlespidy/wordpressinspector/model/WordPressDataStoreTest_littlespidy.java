// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.model;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 */
public class WordPressDataStoreTest_littlespidy {

    @Test
    public void testNormalizeHost() {
        assertEquals("example.com", WordPressDataStore_littlespidy.normalizeHost("https://example.com/wp-admin/"));
        assertEquals("example.com", WordPressDataStore_littlespidy.normalizeHost("http://example.com:8080/test"));
        assertEquals("sub.domain.org", WordPressDataStore_littlespidy.normalizeHost("sub.domain.org"));
    }

    @Test
    public void testGetOrCreateTarget() {
        WordPressDataStore_littlespidy store = new WordPressDataStore_littlespidy();
        WordPressTarget_littlespidy t1 = store.getOrCreateTarget("https://target.corp/", "target.corp");
        assertNotNull(t1);
        assertEquals("target.corp", t1.getRootDomain());

        WordPressTarget_littlespidy t2 = store.getOrCreateTarget("https://target.corp/some-path", "target.corp");
        assertSame(t1, t2);
        assertEquals(1, store.getAllTargets().size());
    }

    @Test
    public void test24HourCache() {
        WordPressDataStore_littlespidy store = new WordPressDataStore_littlespidy();
        store.getConfig().setCache24hEnabled(true);

        VulnerabilityEntry_littlespidy v = new VulnerabilityEntry_littlespidy("Test", "XSS", "1.0", "CVE-2024-0001");
        store.putCacheEntry("plugin", "woocommerce", List.of(v));

        WordPressDataStore_littlespidy.CachedApiEntry_littlespidy cached = store.getCachedEntry("plugin", "woocommerce");
        assertNotNull(cached);
        assertTrue(cached.isValid());
        assertEquals(1, cached.getVulnerabilities().size());

        // Test cache disabled
        store.getConfig().setCache24hEnabled(false);
        assertNull(store.getCachedEntry("plugin", "woocommerce"));
    }
}
