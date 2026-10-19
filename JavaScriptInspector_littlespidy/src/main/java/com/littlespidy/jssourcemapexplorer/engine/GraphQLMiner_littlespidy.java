// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.DiscoveredGraphQLOperation;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * High-performance, zero-dependency native Java engine for extracting GraphQL
 * operations from JavaScript files and unpacked source maps.
 *
 * Implements:
 * 1. Balanced-brace recursive depth walker for operations and fragments.
 * 2. String concatenation resolution and escape sequence decoding.
 * 3. Tagged template recognition (gql, graphql, apollo, loader, etc.).
 * 4. React and Apollo hook detection (useQuery, useMutation, etc.).
 * 5. Apollo client method call detection (client.query, client.mutate, etc.).
 * 6. HTTP client body parsing (fetch, axios, ky, etc.).
 * 7. Inline JSON serialized query detection ("query": "...").
 * 8. Base64-encoded query decoding.
 * 9. Comment scanner for commented-out operations (single-line and block).
 * 10. Variable signature parser and typed mock JSON synthesizer.
 * 11. Security risk classifier (Critical Mutation, Sensitive Fields, Standard).
 *
 * @author littlespidy
 */
public class GraphQLMiner_littlespidy {

    private static final Set<String> GQL_TAGS = Set.of(
        "gql", "graphql", "apollo", "loader", "parse",
        "gqlTag", "GraphQL", "GQL", "graphqlTag"
    );

    private static final Set<String> HTTP_CLIENTS = Set.of(
        "fetch", "axios", "request", "got", "superagent", "ky", "$http", "http"
    );

    private static final Pattern OPERATION_KEYWORD_PATTERN = Pattern.compile(
        "(?m)\\b(query|mutation|subscription|fragment)\\b(?:\\s+([A-Za-z0-9_]+))?"
    );

    private static final Pattern TAGGED_TEMPLATE_PATTERN = Pattern.compile(
        "\\b(gql|graphql|apollo|loader|parse|gqlTag|GraphQL|GQL|graphqlTag)\\s*`([\\s\\S]*?)`"
    );

    private static final Pattern REACT_HOOK_PATTERN = Pattern.compile(
        "\\b(useQuery|useMutation|useSubscription|useLazyQuery)\\s*\\(\\s*([\\s\\S]*?)[,\\)]"
    );

    private static final Pattern CLIENT_METHOD_PATTERN = Pattern.compile(
        "\\.(query|mutate|subscribe|watchQuery|readQuery|writeQuery)\\s*\\(\\s*\\{([\\s\\S]*?)\\}\\s*\\)"
    );

    private static final Pattern INLINE_JSON_QUERY_PATTERN = Pattern.compile(
        "[\"'](?:query|mutation)[\"']\\s*:\\s*[\"']((?:[^\"'\\\\]|\\\\.)*)[\"']"
    );

    private static final Pattern BASE64_CANDIDATE_PATTERN = Pattern.compile(
        "[\"']([A-Za-z0-9+/]{28,}={0,2})[\"']"
    );

    private static final Pattern COMMENT_BLOCK_PATTERN = Pattern.compile(
        "/\\*[\\s\\S]*?\\*/|//[^\r\n]*"
    );

    private static final Pattern ENDPOINT_URL_PATTERN = Pattern.compile(
        "[\"']((?:https?:)?//[^\"'\\s]+|/[a-zA-Z0-9_./-]*graphql[a-zA-Z0-9_./-]*)[\"']",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern SENSITIVE_FIELDS_PATTERN = Pattern.compile(
        "(?i)(password|passwd|pwd|secret|token|apiKey|api_key|auth|ssn|creditCard|credit_card|privateKey|private_key|admin|role|roles|jwt|email|emails|phone|mobile|bearer|hash|salt|credential|credentials)"
    );

    private static final Pattern CRITICAL_MUTATIONS_PATTERN = Pattern.compile(
        "(?i)(delete|remove|drop|truncate|reset|update|change|grant|revoke|promote|transfer|admin|execute|destroy|purge)"
    );

    /**
     * Mines all GraphQL operations from the given JavaScript content.
     */
    public static List<DiscoveredGraphQLOperation> mine(String sourceLocation, String sourceType, String code) {
        if (code == null || code.isBlank() || code.length() < 12) {
            return Collections.emptyList();
        }

        Map<String, DiscoveredGraphQLOperation> operations = new LinkedHashMap<>();
        String correlatedEndpoint = findCorrelatedEndpoint(code);

        // 1. Direct and Balanced-Brace Scan on raw code
        scanForBalancedOperations(sourceLocation, sourceType, code, "Balanced Brace", correlatedEndpoint, operations);

        // 2. String Concatenation Resolution Scan
        String resolvedConcat = resolveStringConcatenations(code);
        if (!resolvedConcat.equals(code)) {
            scanForBalancedOperations(sourceLocation, sourceType, resolvedConcat, "Resolved Concatenation", correlatedEndpoint, operations);
        }

        // 3. Tagged Template Expressions (gql`...`)
        Matcher taggedMatcher = TAGGED_TEMPLATE_PATTERN.matcher(code);
        while (taggedMatcher.find()) {
            String tagName = taggedMatcher.group(1);
            String body = taggedMatcher.group(2);
            parseAndRegister(sourceLocation, sourceType, body, "Tagged Template (" + tagName + ")",
                correlatedEndpoint, taggedMatcher.start(), taggedMatcher.end(), code, operations);
        }

        // 4. React/Apollo Hooks (useQuery, useMutation, etc.)
        Matcher hookMatcher = REACT_HOOK_PATTERN.matcher(code);
        while (hookMatcher.find()) {
            String hookName = hookMatcher.group(1);
            String arg = hookMatcher.group(2).trim();
            if (arg.contains("{") && arg.contains("}")) {
                parseAndRegister(sourceLocation, sourceType, arg, "React Hook (" + hookName + ")",
                    correlatedEndpoint, hookMatcher.start(), hookMatcher.end(), code, operations);
            }
        }

        // 5. Apollo Client Method Calls (.query({ query: ... }))
        Matcher clientMatcher = CLIENT_METHOD_PATTERN.matcher(code);
        while (clientMatcher.find()) {
            String method = clientMatcher.group(1);
            String optionsBody = clientMatcher.group(2);
            Matcher innerGql = OPERATION_KEYWORD_PATTERN.matcher(optionsBody);
            if (innerGql.find()) {
                parseAndRegister(sourceLocation, sourceType, optionsBody.substring(innerGql.start()),
                    "Apollo Client (." + method + ")", correlatedEndpoint, clientMatcher.start(), clientMatcher.end(), code, operations);
            }
        }

        // 6. HTTP Client Call Bodies (fetch, axios.post, etc.)
        scanHttpClientBodies(sourceLocation, sourceType, code, correlatedEndpoint, operations);

        // 7. Inline JSON Serialized Query blocks
        Matcher jsonMatcher = INLINE_JSON_QUERY_PATTERN.matcher(code);
        while (jsonMatcher.find()) {
            String rawQuery = decodeEscapes(jsonMatcher.group(1));
            if (containsGqlKeywords(rawQuery)) {
                parseAndRegister(sourceLocation, sourceType, rawQuery, "Inline JSON Query",
                    correlatedEndpoint, jsonMatcher.start(), jsonMatcher.end(), code, operations);
            }
        }

        // 8. Base64 Encoded Query Candidates
        Matcher b64Matcher = BASE64_CANDIDATE_PATTERN.matcher(code);
        while (b64Matcher.find()) {
            String candidate = b64Matcher.group(1);
            String decoded = tryDecodeBase64Gql(candidate);
            if (decoded != null) {
                parseAndRegister(sourceLocation, sourceType, decoded, "Base64 Decoded",
                    correlatedEndpoint, b64Matcher.start(), b64Matcher.end(), code, operations);
            }
        }

        // 9. Comments Mining (both single-line and multi-line blocks)
        Matcher commentMatcher = COMMENT_BLOCK_PATTERN.matcher(code);
        while (commentMatcher.find()) {
            String comment = commentMatcher.group();
            String cleaned = comment.replaceAll("^(/\\*+|//+)", "").replaceAll("\\*+/$", "").trim();
            if (containsGqlKeywords(cleaned)) {
                scanForBalancedOperations(sourceLocation, sourceType, cleaned, "Commented-out Code", correlatedEndpoint, operations);
            }
        }

        return new ArrayList<>(operations.values());
    }

    private static void scanForBalancedOperations(
        String sourceLocation,
        String sourceType,
        String text,
        String technique,
        String correlatedEndpoint,
        Map<String, DiscoveredGraphQLOperation> operations
    ) {
        Matcher matcher = OPERATION_KEYWORD_PATTERN.matcher(text);
        while (matcher.find()) {
            int keywordStart = matcher.start();
            int openBrace = text.indexOf('{', keywordStart);
            if (openBrace == -1) continue;

            int closeBrace = findMatchingBrace(text, openBrace);
            if (closeBrace == -1) continue;

            String candidate = text.substring(keywordStart, closeBrace + 1).trim();
            if (candidate.length() < 12) continue;

            int line = getLineNumber(text, keywordStart);
            String snippet = getSnippet(text, keywordStart, closeBrace + 1);

            registerOperation(sourceLocation, sourceType, candidate, technique,
                correlatedEndpoint, line, keywordStart, closeBrace + 1, snippet, operations);
        }
    }

    private static void scanHttpClientBodies(
        String sourceLocation,
        String sourceType,
        String code,
        String correlatedEndpoint,
        Map<String, DiscoveredGraphQLOperation> operations
    ) {
        for (String client : HTTP_CLIENTS) {
            String patternStr = "\\b" + Pattern.quote(client) + "\\s*\\([^,\\)]*,\\s*(\\{[\\s\\S]*?\\})\\s*\\)";
            Pattern p = Pattern.compile(patternStr);
            Matcher m = p.matcher(code);
            while (m.find()) {
                String body = m.group(1);
                if (containsGqlKeywords(body)) {
                    parseAndRegister(sourceLocation, sourceType, body, "HTTP Client (" + client + ")",
                        correlatedEndpoint, m.start(), m.end(), code, operations);
                }
            }
        }
    }

    private static void parseAndRegister(
        String sourceLocation,
        String sourceType,
        String rawText,
        String technique,
        String correlatedEndpoint,
        int startOffset,
        int endOffset,
        String fullCode,
        Map<String, DiscoveredGraphQLOperation> operations
    ) {
        String decoded = decodeEscapes(rawText);
        Matcher matcher = OPERATION_KEYWORD_PATTERN.matcher(decoded);
        boolean foundAny = false;

        while (matcher.find()) {
            int kwStart = matcher.start();
            int openBrace = decoded.indexOf('{', kwStart);
            if (openBrace == -1) continue;

            int closeBrace = findMatchingBrace(decoded, openBrace);
            if (closeBrace == -1) continue;

            String extracted = decoded.substring(kwStart, closeBrace + 1).trim();
            if (extracted.length() < 12) continue;

            int line = getLineNumber(fullCode, startOffset);
            String snippet = getSnippet(fullCode, startOffset, endOffset);

            registerOperation(sourceLocation, sourceType, extracted, technique,
                correlatedEndpoint, line, startOffset, endOffset, snippet, operations);
            foundAny = true;
        }

        if (!foundAny && decoded.contains("{") && decoded.contains("}")) {
            int openBrace = decoded.indexOf('{');
            int closeBrace = findMatchingBrace(decoded, openBrace);
            if (closeBrace != -1) {
                String candidate = decoded.substring(openBrace, closeBrace + 1).trim();
                if (candidate.length() >= 12) {
                    int line = getLineNumber(fullCode, startOffset);
                    String snippet = getSnippet(fullCode, startOffset, endOffset);
                    registerOperation(sourceLocation, sourceType, candidate, technique,
                        correlatedEndpoint, line, startOffset, endOffset, snippet, operations);
                }
            }
        }
    }

    private static void registerOperation(
        String sourceLocation,
        String sourceType,
        String rawQuery,
        String technique,
        String correlatedEndpoint,
        int line,
        int startOffset,
        int endOffset,
        String snippet,
        Map<String, DiscoveredGraphQLOperation> operations
    ) {
        String normalizedQuery = normalizeQuery(rawQuery);
        if (normalizedQuery == null || normalizedQuery.isBlank()) return;

        String opType = detectOperationType(normalizedQuery);
        String opName = extractOperationName(normalizedQuery);
        Map<String, Object> variables = extractVariablesFromSignature(normalizedQuery);
        String variablesJson = buildVariablesJson(variables);
        String risk = classifyRisk(opType, opName, normalizedQuery);

        String deduplicationKey = opType + ":" + opName + ":" + normalizedQuery.replaceAll("\\s+", " ").strip();

        if (!operations.containsKey(deduplicationKey)) {
            operations.put(deduplicationKey, new DiscoveredGraphQLOperation(
                sourceLocation,
                sourceType,
                opName,
                opType,
                normalizedQuery,
                variables,
                variablesJson,
                correlatedEndpoint,
                "Native Java",
                technique,
                risk,
                line,
                startOffset,
                endOffset,
                snippet
            ));
        }
    }

    private static int findMatchingBrace(String text, int openBraceIdx) {
        int depth = 0;
        boolean inQuote = false;
        char quoteChar = 0;
        boolean inComment = false;

        for (int i = openBraceIdx; i < text.length(); i++) {
            char c = text.charAt(i);
            char next = (i + 1 < text.length()) ? text.charAt(i + 1) : 0;

            if (inQuote) {
                if (c == '\\') {
                    i++; // skip escaped character
                } else if (c == quoteChar) {
                    inQuote = false;
                }
                continue;
            }

            if (inComment) {
                if (c == '\n') {
                    inComment = false;
                }
                continue;
            }

            if (c == '"' || c == '\'') {
                inQuote = true;
                quoteChar = c;
                continue;
            }

            if (c == '#') {
                inComment = true;
                continue;
            }

            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    private static String resolveStringConcatenations(String code) {
        return code
            .replaceAll("['\"]\\s*\\+\\s*['\"]", "")
            .replaceAll("`\\s*\\+\\s*`", "");
    }

    private static String decodeEscapes(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char next = s.charAt(i + 1);
                switch (next) {
                    case 'n': sb.append('\n'); i++; break;
                    case 't': sb.append('\t'); i++; break;
                    case 'r': sb.append('\r'); i++; break;
                    case '"': sb.append('"'); i++; break;
                    case '\'': sb.append('\''); i++; break;
                    case '\\': sb.append('\\'); i++; break;
                    case 'u':
                        if (i + 5 < s.length()) {
                            try {
                                int codePoint = Integer.parseInt(s.substring(i + 2, i + 6), 16);
                                sb.append((char) codePoint);
                                i += 5;
                            } catch (NumberFormatException ignored) {
                                sb.append(c);
                            }
                        } else {
                            sb.append(c);
                        }
                        break;
                    case 'x':
                        if (i + 3 < s.length()) {
                            try {
                                int codePoint = Integer.parseInt(s.substring(i + 2, i + 4), 16);
                                sb.append((char) codePoint);
                                i += 3;
                            } catch (NumberFormatException ignored) {
                                sb.append(c);
                            }
                        } else {
                            sb.append(c);
                        }
                        break;
                    default:
                        sb.append(c);
                        break;
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String tryDecodeBase64Gql(String candidate) {
        try {
            byte[] bytes = Base64.getDecoder().decode(candidate.trim());
            String decoded = new String(bytes, StandardCharsets.UTF_8);
            if (containsGqlKeywords(decoded)) {
                return decoded;
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static boolean containsGqlKeywords(String text) {
        if (text == null) return false;
        return text.contains("query") || text.contains("mutation")
            || text.contains("subscription") || text.contains("fragment");
    }

    private static String detectOperationType(String query) {
        String stripped = query.stripLeading();
        if (stripped.startsWith("mutation")) return "Mutation";
        if (stripped.startsWith("subscription")) return "Subscription";
        if (stripped.startsWith("fragment")) return "Fragment";
        return "Query";
    }

    private static String extractOperationName(String query) {
        Matcher m = Pattern.compile("^(?:query|mutation|subscription|fragment)\\s+([A-Za-z0-9_]+)").matcher(query.stripLeading());
        if (m.find()) {
            return m.group(1);
        }
        return "Anonymous";
    }

    public static Map<String, Object> extractVariablesFromSignature(String query) {
        Map<String, Object> vars = new LinkedHashMap<>();
        int sigStart = query.indexOf('(');
        int braceIdx = query.indexOf('{');
        if (sigStart == -1 || (braceIdx != -1 && sigStart > braceIdx)) {
            return vars;
        }

        int sigEnd = query.indexOf(')', sigStart);
        if (sigEnd == -1) return vars;

        String signature = query.substring(sigStart + 1, sigEnd);
        String[] params = signature.split(",");
        for (String param : params) {
            Matcher m = Pattern.compile("\\$([A-Za-z0-9_]+)\\s*:\\s*([A-Za-z0-9_!\\[\\]]+)").matcher(param);
            if (m.find()) {
                String varName = m.group(1);
                String varType = m.group(2);
                vars.put(varName, inferDefaultValue(varType));
            }
        }
        return vars;
    }

    private static Object inferDefaultValue(String type) {
        if (type == null) return "";
        if (type.contains("[") || type.contains("]")) {
            return Collections.emptyList();
        }
        String cleanType = type.replaceAll("[!\\[\\]]", "").trim();
        if (cleanType.matches("(?i)String|ID|UUID")) return "";
        if (cleanType.matches("(?i)Int|Integer|Float|Number|Long")) return 0;
        if (cleanType.equalsIgnoreCase("Boolean")) return false;
        return Collections.emptyMap();
    }

    public static String buildVariablesJson(Map<String, Object> vars) {
        if (vars == null || vars.isEmpty()) return "{}";
        StringBuilder sb = new StringBuilder("{\n");
        int count = 0;
        for (Map.Entry<String, Object> entry : vars.entrySet()) {
            count++;
            sb.append("  \"").append(entry.getKey()).append("\": ");
            Object val = entry.getValue();
            if (val instanceof String) {
                sb.append("\"").append(val).append("\"");
            } else if (val instanceof Number || val instanceof Boolean) {
                sb.append(val);
            } else if (val instanceof List) {
                sb.append("[]");
            } else {
                sb.append("{}");
            }
            if (count < vars.size()) {
                sb.append(",");
            }
            sb.append("\n");
        }
        sb.append("}");
        return sb.toString();
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

    private static String findCorrelatedEndpoint(String code) {
        Matcher m = ENDPOINT_URL_PATTERN.matcher(code);
        if (m.find()) {
            return m.group(1);
        }
        return "/graphql";
    }

    private static String normalizeQuery(String raw) {
        if (raw == null) return null;
        String clean = raw.trim();
        if (clean.length() < 10) return null;
        if (!clean.endsWith("}") && clean.contains("}")) {
            int lastBrace = clean.lastIndexOf('}');
            clean = clean.substring(0, lastBrace + 1);
        }
        return clean;
    }

    private static int getLineNumber(String text, int offset) {
        int line = 1;
        int limit = Math.min(Math.max(0, offset), text.length());
        for (int i = 0; i < limit; i++) {
            if (text.charAt(i) == '\n') line++;
        }
        return line;
    }

    private static String getSnippet(String text, int start, int end) {
        int s = Math.max(0, start - 20);
        int e = Math.min(text.length(), end + 20);
        String sub = text.substring(s, e).replaceAll("\\s+", " ").strip();
        return sub.length() > 140 ? sub.substring(0, 137) + "..." : sub;
    }
}
