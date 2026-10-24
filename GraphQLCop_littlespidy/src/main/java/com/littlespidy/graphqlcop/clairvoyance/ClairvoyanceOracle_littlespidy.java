// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.clairvoyance;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.littlespidy.graphqlcop.engine.AuditProbe_littlespidy;
import com.littlespidy.graphqlcop.engine.HttpHelper_littlespidy;
import com.littlespidy.graphqlcop.model.AuditFinding_littlespidy;
import com.littlespidy.graphqlcop.model.AuditProbeType_littlespidy;
import com.littlespidy.graphqlcop.model.AuditSeverity_littlespidy;
import com.littlespidy.graphqlcop.model.HttpLogEntry_littlespidy;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ClairvoyanceOracle_littlespidy implements AuditProbe_littlespidy {
    private static final Pattern SINGLE_SUGGESTION_PATTERN = Pattern.compile(
            "Cannot query field ['\"]([_a-zA-Z0-9]+)['\"] on type ['\"][_a-zA-Z0-9]+['\"]\\. Did you mean ['\"]([_a-zA-Z0-9]+)['\"]\\?",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern MULTI_SUGGESTION_PATTERN = Pattern.compile(
            "Did you mean (['\"][_a-zA-Z0-9]+['\"](?:,\\s*['\"][_a-zA-Z0-9]+['\"])*)(?:\\s*or\\s*['\"]([_a-zA-Z0-9]+)['\"])?\\?",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern WORD_PATTERN = Pattern.compile("['\"]([_a-zA-Z0-9]+)['\"]");

    private static final List<String> DEFAULT_WORDLIST = Arrays.asList(
            "user", "users", "account", "accounts", "profile", "profiles", "admin", "login",
            "auth", "me", "viewer", "node", "nodes", "id", "name", "email", "post", "posts",
            "comment", "comments", "item", "items", "order", "orders", "product", "products",
            "setting", "settings", "role", "roles", "token", "session", "search", "query",
            "mutation", "version", "status", "health", "system", "config", "configuration"
    );

    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.CLAIRVOYANCE;
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();
        ReconstructedSchema result = reconstructSchema(api, targetUrl, customHeaders, logConsumer, 40);

        if (!result.discoveredFields.isEmpty()) {
            AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                    UUID.randomUUID().toString(),
                    AuditProbeType_littlespidy.CLAIRVOYANCE,
                    AuditSeverity_littlespidy.MEDIUM,
                    "Blind GraphQL Schema Recovered via Clairvoyance Oracle",
                    "Discovered " + result.discoveredFields.size() + " schema fields across types using recursive error suggestion analysis:\n" +
                            String.join(", ", result.discoveredFields),
                    "Disable GraphQL field suggestions in production to prevent blind schema harvesting when introspection is disabled.",
                    "Allows attackers to completely map hidden APIs, schemas, and sensitive parameters without introspection.",
                    targetUrl,
                    "",
                    ""
            );
            findings.add(finding);
        }
        return findings;
    }

    public static class ReconstructedSchema {
        public final Set<String> discoveredFields = new LinkedHashSet<>();
        public final String schemaJson;

        public ReconstructedSchema(Set<String> discoveredFields, String schemaJson) {
            this.discoveredFields.addAll(discoveredFields);
            this.schemaJson = schemaJson;
        }
    }

    public ReconstructedSchema reconstructSchema(MontoyaApi api, String targetUrl, String customHeaders,
                                                 Consumer<HttpLogEntry_littlespidy> logConsumer, int maxWordsToTest) {
        Set<String> recovered = new LinkedHashSet<>();
        List<String> words = loadWords(maxWordsToTest);

        for (String word : words) {
            String testQuery = "{\"query\": \"query { " + word + "_probe_xyz }\"}";
            HttpRequestResponse pair = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders, testQuery,
                    "Clairvoyance Probe: " + word, logConsumer);

            if (pair != null && pair.response() != null) {
                String body = HttpHelper_littlespidy.getResponseBody(pair);
                extractSuggestions(body, recovered);
            }
        }

        // Construct synthetic schema JSON from recovered fields
        JsonObject schemaRoot = new JsonObject();
        JsonObject schemaObj = new JsonObject();
        JsonArray typesArr = new JsonArray();

        JsonObject queryType = new JsonObject();
        queryType.addProperty("name", "Query");
        JsonArray fieldsArr = new JsonArray();
        for (String field : recovered) {
            JsonObject f = new JsonObject();
            f.addProperty("name", field);
            JsonObject t = new JsonObject();
            t.addProperty("name", "String");
            f.add("type", t);
            fieldsArr.add(f);
        }
        queryType.add("fields", fieldsArr);
        typesArr.add(queryType);

        schemaObj.add("types", typesArr);
        JsonObject dataObj = new JsonObject();
        dataObj.add("__schema", schemaObj);
        schemaRoot.add("data", dataObj);

        return new ReconstructedSchema(recovered, schemaRoot.toString());
    }

    private void extractSuggestions(String body, Set<String> recovered) {
        Matcher singleMatcher = SINGLE_SUGGESTION_PATTERN.matcher(body);
        while (singleMatcher.find()) {
            recovered.add(singleMatcher.group(2));
        }

        Matcher multiMatcher = MULTI_SUGGESTION_PATTERN.matcher(body);
        while (multiMatcher.find()) {
            String multi = multiMatcher.group(1);
            if (multi != null) {
                Matcher wm = WORD_PATTERN.matcher(multi);
                while (wm.find()) {
                    recovered.add(wm.group(1));
                }
            }
            String last = multiMatcher.group(2);
            if (last != null && !last.isEmpty()) {
                recovered.add(last);
            }
        }
    }

    private List<String> loadWords(int limit) {
        List<String> words = new ArrayList<>();
        try (InputStream is = getClass().getResourceAsStream("/clairvoyance/wordlist.txt")) {
            if (is != null) {
                BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
                String line;
                while ((line = br.readLine()) != null && words.size() < limit) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        words.add(line);
                    }
                }
            }
        } catch (Exception ignored) {}

        if (words.isEmpty()) {
            words.addAll(DEFAULT_WORDLIST);
        }
        return words;
    }
}
