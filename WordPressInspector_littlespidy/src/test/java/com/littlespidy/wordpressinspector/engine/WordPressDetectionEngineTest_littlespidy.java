// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.engine;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 */
public class WordPressDetectionEngineTest_littlespidy {

    @Test
    public void testIsWordPressTraffic() {
        String wpBody = "<html><head><meta name=\"generator\" content=\"WordPress 6.2.2\"></head><body>"
                + "<script src=\"/wp-content/plugins/woocommerce/assets/client/blocks/wc-settings.js\"></script>"
                + "<link rel=\"stylesheet\" href=\"/wp-content/themes/twentytwentythree/style.css\">"
                + "</body></html>";

        assertTrue(WordPressDetectionEngine_littlespidy.isWordPressTraffic(wpBody, List.of()));

        String nonWpBody = "<html><head><title>Node Express API</title></head><body><h1>Hello</h1></body></html>";
        assertFalse(WordPressDetectionEngine_littlespidy.isWordPressTraffic(nonWpBody, List.of("Server: nginx")));

        // Test headers detection
        List<String> wpHeaders = List.of("X-Pingback: https://example.com/xmlrpc.php", "Content-Type: text/html");
        assertTrue(WordPressDetectionEngine_littlespidy.isWordPressTraffic("", wpHeaders));
    }

    @Test
    public void testExtractVersion() {
        String metaTag = "<meta name=\"generator\" content=\"WordPress 6.4.1\" />";
        assertEquals("6.4.1", WordPressDetectionEngine_littlespidy.extractVersion(metaTag));

        String feedGenerator = "<generator>https://wordpress.org/?v=6.3.2</generator>";
        String opmlGenerator = "generator=\"WordPress/6.2\"";
        assertEquals("6.2", WordPressDetectionEngine_littlespidy.extractVersion(opmlGenerator));
    }

    @Test
    public void testExtractPluginsAndThemes() {
        String content = "href=\"/wp-content/plugins/woocommerce/style.css\" "
                + "src=\"/wp-content/plugins/elementor/assets/js/frontend.js\" "
                + "href=\"/wp-content/themes/astra/style.css\"";

        Set<String> plugins = WordPressDetectionEngine_littlespidy.extractPlugins(content);
        assertTrue(plugins.contains("woocommerce"));
        assertTrue(plugins.contains("elementor"));
        assertEquals(2, plugins.size());

        Set<String> themes = WordPressDetectionEngine_littlespidy.extractThemes(content);
        assertTrue(themes.contains("astra"));
        assertEquals(1, themes.size());
    }

    @Test
    public void testIsHighRiskPlugin() {
        assertTrue(WordPressDetectionEngine_littlespidy.isHighRiskPlugin("woocommerce"));
        assertTrue(WordPressDetectionEngine_littlespidy.isHighRiskPlugin("contact-form-7"));
        assertTrue(WordPressDetectionEngine_littlespidy.isHighRiskPlugin("elementor"));
        assertFalse(WordPressDetectionEngine_littlespidy.isHighRiskPlugin("custom-internal-widget-littlespidy"));
    }
}
