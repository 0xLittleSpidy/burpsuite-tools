// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop;

import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import com.littlespidy.graphqlcop.inql.BatchQueryGenerator_littlespidy;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class BatchQueryGeneratorTest_littlespidy {

    @Test
    public void testArrayBatchGeneration() {
        String single = "query { user(id: 1) { name } }";
        String json = BatchQueryGenerator_littlespidy.generateArrayBatch(single, 5);

        assertNotNull(json);
        JsonArray arr = JsonParser.parseString(json).getAsJsonArray();
        assertEquals(5, arr.size());
        assertEquals(single, arr.get(0).getAsJsonObject().get("query").getAsString());
    }

    @Test
    public void testAliasBatchGeneration() {
        String base = "user(id: 1) { name }";
        String query = BatchQueryGenerator_littlespidy.generateAliasBatch(base, 10);

        assertNotNull(query);
        assertTrue(query.contains("alias_1: user(id: 1) { name }"));
        assertTrue(query.contains("alias_10: user(id: 1) { name }"));
    }
}
