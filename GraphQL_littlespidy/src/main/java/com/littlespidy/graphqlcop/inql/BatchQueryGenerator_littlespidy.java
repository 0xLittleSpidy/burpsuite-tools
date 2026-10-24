// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.inql;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class BatchQueryGenerator_littlespidy {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public static String generateArrayBatch(String singleQuery, int batchSize) {
        if (singleQuery == null || singleQuery.trim().isEmpty()) {
            singleQuery = "query { __typename }";
        }
        JsonArray array = new JsonArray();
        for (int i = 0; i < batchSize; i++) {
            JsonObject item = new JsonObject();
            item.addProperty("query", singleQuery.trim());
            array.add(item);
        }
        return GSON.toJson(array);
    }

    public static String generateAliasBatch(String baseSelection, int batchSize) {
        if (baseSelection == null || baseSelection.trim().isEmpty()) {
            baseSelection = "__typename";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("query AliasBatchDos {\n");
        for (int i = 1; i <= batchSize; i++) {
            sb.append("  alias_").append(i).append(": ").append(baseSelection.trim()).append("\n");
        }
        sb.append("}\n");
        return sb.toString();
    }
}
