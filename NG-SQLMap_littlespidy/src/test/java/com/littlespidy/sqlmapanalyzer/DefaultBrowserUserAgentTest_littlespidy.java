// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;

public class DefaultBrowserUserAgentTest_littlespidy {

    @Test
    public void testDefaultUserAgentIsNormalBrowser() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://example.com/test?id=1");

        String agent = options.getAgent();
        assertNotNull(agent);
        assertTrue(agent.contains("Mozilla/5.0"), "Agent should contain Mozilla/5.0");
        assertTrue(agent.contains("Chrome/"), "Agent should contain modern Chrome version");
        assertFalse(agent.toLowerCase().contains("sqlmap"), "Default agent must not identify as sqlmap");

        // Verify CLI command
        String cli = options.buildCommandLine();
        assertTrue(cli.contains("--user-agent=\"Mozilla/5.0"), "CLI must contain normal browser user agent flag");

        // Verify Option Map
        Map<String, Object> map = options.toOptionMap();
        assertEquals(SqlmapTaskOptions.DEFAULT_BROWSER_USER_AGENT, map.get("agent"));
    }
}
