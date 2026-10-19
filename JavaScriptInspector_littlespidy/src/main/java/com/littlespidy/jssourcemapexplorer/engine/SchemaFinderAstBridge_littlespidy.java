// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.DiscoveredGraphQLOperation;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Bridge to execute the external SchemaFinder 3-pass Babel AST engine
 * when Node.js is available on the system.
 *
 * Provides deep lexical scope binding resolution for complex minified or bundled
 * JavaScript assets.
 *
 * @author littlespidy
 */
public class SchemaFinderAstBridge_littlespidy {

    private static final AtomicBoolean NODE_CHECKED = new AtomicBoolean(false);
    private static volatile boolean NODE_AVAILABLE = false;
    private static volatile File SCHEMA_FINDER_SCRIPT = null;

    private static final Pattern SENSITIVE_FIELDS_PATTERN = Pattern.compile(
        "(?i)\\b(password|passwd|secret|token|apiKey|api_key|auth|ssn|creditCard|privateKey|admin|role|jwt)\\b"
    );

    private static final Pattern CRITICAL_MUTATIONS_PATTERN = Pattern.compile(
        "(?i)\\b(delete|remove|drop|truncate|reset|update|change|grant|revoke|promote|transfer|admin|execute)\\b"
    );

    public static boolean isNodeAvailable() {
        if (!NODE_CHECKED.get()) {
            checkNodeAvailability();
            findSchemaFinderScript();
            NODE_CHECKED.set(true);
        }
        return NODE_AVAILABLE && SCHEMA_FINDER_SCRIPT != null && SCHEMA_FINDER_SCRIPT.exists();
    }

    private static synchronized void checkNodeAvailability() {
        try {
            Process process = new ProcessBuilder("node", "-v").start();
            boolean finished = process.waitFor(3, TimeUnit.SECONDS);
            if (finished && process.exitValue() == 0) {
                NODE_AVAILABLE = true;
            }
        } catch (Exception ignored) {
            NODE_AVAILABLE = false;
        }
    }

    private static synchronized void findSchemaFinderScript() {
        List<File> candidates = List.of(
            new File("SchemaFinder/schemafinder.js"),
            new File("../SchemaFinder/schemafinder.js"),
            new File(System.getProperty("user.dir"), "SchemaFinder/schemafinder.js"),
            new File(System.getProperty("user.home"), "myextra/burpsuite-extensions/JavaScriptInspector_littlespidy/SchemaFinder/schemafinder.js")
        );

        for (File candidate : candidates) {
            if (candidate.exists() && candidate.isFile()) {
                SCHEMA_FINDER_SCRIPT = candidate.getAbsoluteFile();
                return;
            }
        }
    }

    /**
     * Executes SchemaFinder on the provided code content via a temporary file
     * and returns the AST-extracted operations.
     */
    public static List<DiscoveredGraphQLOperation> extractWithBabelAst(
        String sourceLocation,
        String sourceType,
        String code
    ) {
        if (!isNodeAvailable()) {
            return Collections.emptyList();
        }

        if (code == null || code.isBlank() || code.length() < 12) {
            return Collections.emptyList();
        }

        Path tempDir = null;
        try {
            tempDir = Files.createTempDirectory("schemafinder_ast_");
            Path tempInput = tempDir.resolve("input.js");
            Path tempOutput = tempDir.resolve("output.json");

            Files.writeString(tempInput, code, StandardCharsets.UTF_8);

            ProcessBuilder pb = new ProcessBuilder(
                "node",
                SCHEMA_FINDER_SCRIPT.getAbsolutePath(),
                "-i", tempInput.toAbsolutePath().toString(),
                "-o", tempOutput.toAbsolutePath().toString(),
                "--aggressive"
            );
            pb.directory(SCHEMA_FINDER_SCRIPT.getParentFile());
            pb.redirectErrorStream(true);

            Process process = pb.start();
            boolean finished = process.waitFor(15, TimeUnit.SECONDS);

            if (!finished) {
                process.destroyForcibly();
                return Collections.emptyList();
            }

            if (Files.exists(tempOutput)) {
                String jsonContent = Files.readString(tempOutput, StandardCharsets.UTF_8);
                return parseSchemaFinderOutput(sourceLocation, sourceType, jsonContent);
            }

        } catch (Exception ignored) {
        } finally {
            if (tempDir != null) {
                try {
                    deleteRecursively(tempDir.toFile());
                } catch (Exception ignored) {}
            }
        }

        return Collections.emptyList();
    }

    private static List<DiscoveredGraphQLOperation> parseSchemaFinderOutput(
        String sourceLocation,
        String sourceType,
        String json
    ) {
        if (json == null || json.isBlank() || !json.trim().startsWith("[")) {
            return Collections.emptyList();
        }

        List<DiscoveredGraphQLOperation> list = new ArrayList<>();

        // Parse JSON array of operation objects without heavy external dependencies
        List<Map<String, String>> rawOps = parseSimpleJsonArray(json);

        for (Map<String, String> raw : rawOps) {
            String operation = raw.get("operation");
            if (operation == null || operation.isBlank()) continue;

            String name = raw.getOrDefault("name", "Anonymous");
            String context = raw.getOrDefault("context", "ast_analysis");
            String opType = detectOperationType(operation);
            String risk = classifyRisk(opType, name, operation);
            Map<String, Object> vars = GraphQLMiner_littlespidy.extractVariablesFromSignature(operation);
            String varsJson = GraphQLMiner_littlespidy.buildVariablesJson(vars);

            list.add(new DiscoveredGraphQLOperation(
                sourceLocation,
                sourceType,
                name,
                opType,
                operation,
                vars,
                varsJson,
                "/graphql",
                "Babel AST",
                context,
                risk,
                1,
                0,
                0,
                operation.length() > 100 ? operation.substring(0, 97) + "..." : operation
            ));
        }

        return list;
    }

    private static List<Map<String, String>> parseSimpleJsonArray(String json) {
        List<Map<String, String>> items = new ArrayList<>();
        int idx = json.indexOf('{');
        while (idx != -1) {
            int closeIdx = findClosingBrace(json, idx);
            if (closeIdx == -1) break;
            String objStr = json.substring(idx + 1, closeIdx);
            Map<String, String> map = new HashMap<>();

            extractField(objStr, "operation", map);
            extractField(objStr, "name", map);
            extractField(objStr, "context", map);

            if (map.containsKey("operation")) {
                items.add(map);
            }
            idx = json.indexOf('{', closeIdx + 1);
        }
        return items;
    }

    private static void extractField(String objStr, String key, Map<String, String> map) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        Matcher m = p.matcher(objStr);
        if (m.find()) {
            map.put(key, unescapeJson(m.group(1)));
        }
    }

    private static String unescapeJson(String s) {
        return s.replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\r", "\r")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
    }

    private static int findClosingBrace(String text, int openIdx) {
        int depth = 0;
        boolean inQuote = false;
        for (int i = openIdx; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '"' && (i == 0 || text.charAt(i - 1) != '\\')) {
                inQuote = !inQuote;
                continue;
            }
            if (inQuote) continue;

            if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    private static String detectOperationType(String query) {
        String stripped = query.stripLeading();
        if (stripped.startsWith("mutation")) return "Mutation";
        if (stripped.startsWith("subscription")) return "Subscription";
        if (stripped.startsWith("fragment")) return "Fragment";
        return "Query";
    }

    private static String classifyRisk(String opType, String opName, String query) {
        if ("Mutation".equalsIgnoreCase(opType)) {
            if (CRITICAL_MUTATIONS_PATTERN.matcher(opName).find() || CRITICAL_MUTATIONS_PATTERN.matcher(query).find()) {
                return "Critical Mutation";
            }
            return "Mutation";
        }
        if (SENSITIVE_FIELDS_PATTERN.matcher(query).find() || SENSITIVE_FIELDS_PATTERN.matcher(opName).find()) {
            return "Sensitive Fields";
        }
        return "Standard";
    }

    private static void deleteRecursively(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursively(child);
                }
            }
        }
        file.delete();
    }
}
