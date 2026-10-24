// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop;

import com.littlespidy.graphqlcop.inql.CycleScanner_littlespidy;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class CycleScannerTest_littlespidy {

    @Test
    public void testDetectCycles() {
        String mockSchema = "{\n" +
                "  \"data\": {\n" +
                "    \"__schema\": {\n" +
                "      \"types\": [\n" +
                "        {\n" +
                "          \"name\": \"Author\",\n" +
                "          \"fields\": [\n" +
                "            { \"name\": \"id\", \"type\": { \"name\": \"ID\" } },\n" +
                "            { \"name\": \"posts\", \"type\": { \"name\": \"Post\" } }\n" +
                "          ]\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"Post\",\n" +
                "          \"fields\": [\n" +
                "            { \"name\": \"id\", \"type\": { \"name\": \"ID\" } },\n" +
                "            { \"name\": \"author\", \"type\": { \"name\": \"Author\" } }\n" +
                "          ]\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  }\n" +
                "}";

        List<CycleScanner_littlespidy.CycleFinding> cycles = CycleScanner_littlespidy.detectCycles(mockSchema, 5);
        assertNotNull(cycles);
        assertFalse(cycles.isEmpty(), "Should detect cycle between Author and Post");

        CycleScanner_littlespidy.CycleFinding first = cycles.get(0);
        assertTrue(first.getPathDisplay().contains("Author") && first.getPathDisplay().contains("Post"));
        assertNotNull(first.recursionQuery);
        assertTrue(first.recursionQuery.contains("query CyclicAmplificationDoS"));
    }
}
