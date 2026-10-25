// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import com.littlespidy.jssourcemapexplorer.engine.JsBeautifier_littlespidy;
import com.littlespidy.jssourcemapexplorer.model.ActiveProbeStatus;
import com.littlespidy.jssourcemapexplorer.model.JsFileEntry;
import com.littlespidy.jssourcemapexplorer.model.PassiveMapStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying Active .map column, title case status,
 * JS Beautifier formatting, and tab model structure.
 *
 * @author littlespidy
 */
class JsInspectorImprovementsTest_littlespidy {

    @Test
    @DisplayName("Verify Active .map column name and Title Case values")
    void testActiveMapColumnAndValues() {
        JsFilesTableModel model = new JsFilesTableModel();

        assertEquals("Active .map", model.getColumnName(6), "Column 6 must be named 'Active .map'");

        JsFileEntry entry = new JsFileEntry(
            1,
            "https://target.com/assets/app.js",
            "target.com",
            "/assets/app.js",
            200,
            1024,
            true,
            "1st Party",
            PassiveMapStatus.NOT_FOUND,
            null,
            null,
            null,
            ZonedDateTime.now()
        );

        model.updateData(List.of(entry));

        // Default state: not probed yet
        assertEquals("-", model.getValueAt(0, 6), "Unprobed row should display '-'");

        // Pass status
        entry.setActiveProbeStatus(ActiveProbeStatus.PASS);
        assertEquals("Pass", model.getValueAt(0, 6), "Pass status must display 'Pass' in Title Case");

        // Fail status
        entry.setActiveProbeStatus(ActiveProbeStatus.FAIL);
        assertEquals("Fail", model.getValueAt(0, 6), "Fail status must display 'Fail' in Title Case");

        // Probing status
        entry.setActiveProbeStatus(ActiveProbeStatus.PROBING);
        assertEquals("Probing...", model.getValueAt(0, 6), "Probing status must display 'Probing...'");
    }

    @Test
    @DisplayName("Verify JsBeautifier formats minified JavaScript properly")
    void testJsBeautifierFormatting() {
        String minifiedJs = "function test(){const a=1;if(a>0){console.log(\"hello world\");}}";
        String beautified = JsBeautifier_littlespidy.beautify(minifiedJs);

        assertNotNull(beautified);
        assertTrue(beautified.contains("\n"), "Beautified JS should contain line breaks");
        assertTrue(beautified.contains("  "), "Beautified JS should contain indentation");
        assertTrue(beautified.contains("\"hello world\""), "String literals must be preserved intact");
    }

    @Test
    @DisplayName("Verify JsBeautifier preserves strings with semicolons and braces")
    void testJsBeautifierStringPreservation() {
        String jsWithSpecialStrings = "const query = 'query { user(id: 1) { name; email } }';";
        String formatted = JsBeautifier_littlespidy.beautify(jsWithSpecialStrings);

        assertTrue(formatted.contains("'query { user(id: 1) { name; email } }'"), "Strings with braces and semicolons must remain untouched");
    }

    @Test
    @DisplayName("Verify Source map Viewer sub-tab and parallel split layout")
    void testSourceMapViewerSubTabAndParallelLayout() throws IOException {
        Path tabPath = Path.of("src/main/java/com/littlespidy/jssourcemapexplorer/ui/JSSourceMapExplorerTab.java");
        assertTrue(Files.exists(tabPath), "JSSourceMapExplorerTab.java must exist");

        String content = Files.readString(tabPath);
        assertTrue(content.contains("\"Source map Viewer\""), "Sub-tab must be named 'Source map Viewer'");
        assertFalse(content.contains("\"SourceMap (.map) HTTP Message\""), "Old tab title 'SourceMap (.map) HTTP Message' must be removed");
        assertTrue(content.contains("mapViewerSplit = new JSplitPane("), "Source map viewer must use a split pane");
        assertTrue(content.contains("JSplitPane.HORIZONTAL_SPLIT"), "Source map viewer split must be horizontal (parallel)");
        assertTrue(content.contains("mapRequestContainer.setBorder("), "Request pane must have its own border container");
        assertTrue(content.contains("mapResponseContainer.setBorder("), "Response pane must have its own border container");
    }
}
