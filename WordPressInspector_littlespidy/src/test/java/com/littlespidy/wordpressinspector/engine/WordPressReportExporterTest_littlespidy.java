// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.engine;

import com.google.gson.JsonParser;
import com.littlespidy.wordpressinspector.model.PluginFinding_littlespidy;
import com.littlespidy.wordpressinspector.model.ThemeFinding_littlespidy;
import com.littlespidy.wordpressinspector.model.VulnerabilityEntry_littlespidy;
import com.littlespidy.wordpressinspector.model.WordPressTarget_littlespidy;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 */
public class WordPressReportExporterTest_littlespidy {

    @Test
    public void testReportGeneration() {
        WordPressTarget_littlespidy target = new WordPressTarget_littlespidy("https://blog.test-site.org/", "blog.test-site.org");
        target.setDetectedVersion("6.2.2");

        VulnerabilityEntry_littlespidy coreVuln = new VulnerabilityEntry_littlespidy(
                "WordPress <= 6.2.2 - Directory Traversal", "Path Traversal", "6.3.0", "CVE-2023-38000"
        );
        target.setCoreVulnerabilities(List.of(coreVuln));

        PluginFinding_littlespidy plugin = new PluginFinding_littlespidy("woocommerce");
        plugin.setDetectedVersion("8.1.1");
        plugin.setVulnerabilities(List.of(
                new VulnerabilityEntry_littlespidy("Arbitrary File Upload", "RCE", "8.2.0", "CVE-2023-47777")
        ));
        target.addPlugin(plugin);

        ThemeFinding_littlespidy theme = new ThemeFinding_littlespidy("twentytwentythree");
        theme.setDetectedVersion("1.1");
        target.addTheme(theme);

        // 1. Verify Markdown
        String markdown = WordPressReportExporter_littlespidy.generateMarkdown(target);
        assertNotNull(markdown);
        assertTrue(markdown.contains("blog.test-site.org"));
        assertTrue(markdown.contains("6.2.2"));
        assertTrue(markdown.contains("woocommerce"));
        assertTrue(markdown.contains("CVE-2023-38000"));
        assertTrue(markdown.contains("CVE-2023-47777"));

        // Verify strictly no AI prompts or "AI-ready" sections exist
        assertFalse(markdown.toLowerCase().contains("ai-ready"));
        assertFalse(markdown.toLowerCase().contains("provide your analysis below"));

        // 2. Verify JSON
        String json = WordPressReportExporter_littlespidy.generateJson(target);
        assertNotNull(json);
        assertTrue(json.contains("scan_metadata"));
        assertTrue(json.contains("woocommerce"));
        assertDoesNotThrow(() -> JsonParser.parseString(json));
    }
}
