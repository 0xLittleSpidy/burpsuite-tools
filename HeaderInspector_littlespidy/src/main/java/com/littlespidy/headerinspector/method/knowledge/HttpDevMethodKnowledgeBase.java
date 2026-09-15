// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.method.knowledge;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Fast, offline, in-memory knowledge base containing HTTP methods
 * and WebDAV/proxy extensions scraped directly from https://http.dev.
 *
 * Provides O(1) case-insensitive lookups, safe/idempotent/cacheable properties,
 * detailed semantic explanations, and official RFC specifications without network calls.
 *
 * @author littlespidy
 */
public class HttpDevMethodKnowledgeBase {

    private static final String RESOURCE_PATH_1 = "/com/littlespidy/headerinspector/method/knowledge/http_dev_methods.json";
    private static final String RESOURCE_PATH_2 = "/http_dev_methods.json";

    private static final Map<String, HttpDevMethodDoc> METHODS_MAP = new HashMap<>();
    private static final List<HttpDevMethodDoc> ALL_METHODS = new ArrayList<>();
    private static boolean initialized = false;

    static {
        ensureLoaded();
    }

    private static synchronized void ensureLoaded() {
        if (initialized) return;
        try {
            InputStream in = HttpDevMethodKnowledgeBase.class.getResourceAsStream(RESOURCE_PATH_1);
            if (in == null) {
                in = HttpDevMethodKnowledgeBase.class.getResourceAsStream(RESOURCE_PATH_2);
            }
            if (in == null) {
                in = Thread.currentThread().getContextClassLoader().getResourceAsStream("http_dev_methods.json");
            }

            if (in != null) {
                String json;
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    json = sb.toString();
                }

                List<HttpDevMethodDoc> docs = parseJson(json);
                for (HttpDevMethodDoc doc : docs) {
                    METHODS_MAP.put(doc.name().toUpperCase(Locale.ROOT), doc);
                    ALL_METHODS.add(doc);
                }
                ALL_METHODS.sort(Comparator.comparing(HttpDevMethodDoc::name, String.CASE_INSENSITIVE_ORDER));
            }
        } catch (Exception e) {
            System.err.println("[HeaderInspector] Failed to initialize HttpDevMethodKnowledgeBase: " + e.getMessage());
        } finally {
            initialized = true;
        }
    }

    /**
     * Looks up an HTTP method by name (case-insensitive).
     *
     * @param methodName Method name to look up (e.g. "GET", "POST")
     * @return HttpDevMethodDoc or null if unknown
     */
    public static HttpDevMethodDoc get(String methodName) {
        if (methodName == null || methodName.isBlank()) return null;
        ensureLoaded();
        return METHODS_MAP.get(methodName.trim().toUpperCase(Locale.ROOT));
    }

    /**
     * Returns whether the given method is present in the knowledge base.
     */
    public static boolean isKnown(String methodName) {
        return get(methodName) != null;
    }

    /**
     * Returns whether the method is safe according to RFC 9110 / http.dev.
     */
    public static boolean isSafe(String methodName) {
        HttpDevMethodDoc doc = get(methodName);
        return doc != null && doc.safe();
    }

    /**
     * Returns whether the method is idempotent according to RFC 9110 / http.dev.
     */
    public static boolean isIdempotent(String methodName) {
        HttpDevMethodDoc doc = get(methodName);
        return doc != null && doc.idempotent();
    }

    /**
     * Returns the cacheability description (e.g. "Yes", "No", "Conditional").
     */
    public static String getCacheable(String methodName) {
        HttpDevMethodDoc doc = get(methodName);
        return doc != null ? doc.cacheable() : "Unknown";
    }

    /**
     * Returns an unmodifiable list of all methods in the knowledge base.
     */
    public static List<HttpDevMethodDoc> getAll() {
        ensureLoaded();
        return Collections.unmodifiableList(ALL_METHODS);
    }

    /**
     * Returns the total count of methods loaded.
     */
    public static int totalCount() {
        ensureLoaded();
        return ALL_METHODS.size();
    }

    /**
     * Robust bracket-counting JSON parser for the embedded dataset.
     */
    private static List<HttpDevMethodDoc> parseJson(String json) {
        List<HttpDevMethodDoc> list = new ArrayList<>();
        List<String> objects = splitTopLevelObjects(json);

        for (String block : objects) {
            String name = extractString(block, "name");
            String slug = extractString(block, "slug");
            boolean safe = extractBoolean(block, "safe");
            boolean idempotent = extractBoolean(block, "idempotent");
            String cacheable = extractString(block, "cacheable");
            String summary = extractString(block, "summary");
            String explanation = extractString(block, "explanation");
            String referenceUrl = extractString(block, "referenceUrl");
            List<HttpDevMethodDoc.Specification> specs = extractSpecs(block);

            if (!name.isEmpty()) {
                list.add(new HttpDevMethodDoc(name, slug, safe, idempotent, cacheable, summary, explanation, referenceUrl, specs));
            }
        }
        return list;
    }

    private static List<String> splitTopLevelObjects(String json) {
        List<String> list = new ArrayList<>();
        int depth = 0;
        int start = -1;
        boolean inString = false;
        boolean escaped = false;

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') {
                inString = !inString;
                continue;
            }
            if (!inString) {
                if (c == '{') {
                    if (depth == 1 && start == -1) {
                        start = i;
                    }
                    depth++;
                } else if (c == '}') {
                    depth--;
                    if (depth == 1 && start != -1) {
                        list.add(json.substring(start, i + 1));
                        start = -1;
                    }
                } else if (c == '[') {
                    depth++;
                } else if (c == ']') {
                    depth--;
                }
            }
        }
        return list;
    }

    private static String extractString(String block, String key) {
        String search = "\"" + key + "\"";
        int keyIdx = block.indexOf(search);
        if (keyIdx == -1) return "";
        int colonIdx = block.indexOf(':', keyIdx + search.length());
        if (colonIdx == -1) return "";
        int quoteStart = block.indexOf('"', colonIdx + 1);
        if (quoteStart == -1) return "";

        StringBuilder sb = new StringBuilder();
        boolean escaped = false;
        for (int i = quoteStart + 1; i < block.length(); i++) {
            char c = block.charAt(i);
            if (escaped) {
                switch (c) {
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'u' -> {
                        if (i + 4 < block.length()) {
                            String hex = block.substring(i + 1, i + 5);
                            try {
                                sb.append((char) Integer.parseInt(hex, 16));
                                i += 4;
                            } catch (NumberFormatException e) {
                                sb.append("\\u");
                            }
                        } else {
                            sb.append("\\u");
                        }
                    }
                    default -> sb.append(c);
                }
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                return sb.toString();
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static boolean extractBoolean(String block, String key) {
        String search = "\"" + key + "\"";
        int keyIdx = block.indexOf(search);
        if (keyIdx == -1) return false;
        int colonIdx = block.indexOf(':', keyIdx + search.length());
        if (colonIdx == -1) return false;
        int nextComma = block.indexOf(',', colonIdx + 1);
        int nextBrace = block.indexOf('}', colonIdx + 1);
        int endIdx = (nextComma != -1 && nextBrace != -1) ? Math.min(nextComma, nextBrace) : Math.max(nextComma, nextBrace);
        if (endIdx == -1) endIdx = block.length();
        String val = block.substring(colonIdx + 1, endIdx).trim();
        return Boolean.parseBoolean(val);
    }

    private static List<HttpDevMethodDoc.Specification> extractSpecs(String block) {
        List<HttpDevMethodDoc.Specification> specs = new ArrayList<>();
        int specsIdx = block.indexOf("\"specifications\"");
        if (specsIdx == -1) return specs;
        int arrStart = block.indexOf('[', specsIdx);
        int arrEnd = block.indexOf(']', arrStart);
        if (arrStart == -1 || arrEnd == -1) return specs;

        String inner = block.substring(arrStart + 1, arrEnd);
        int cursor = 0;
        while (cursor < inner.length()) {
            int objStart = inner.indexOf('{', cursor);
            if (objStart == -1) break;
            int objEnd = inner.indexOf('}', objStart);
            if (objEnd == -1) break;

            String itemBlock = inner.substring(objStart, objEnd + 1);
            String title = extractString(itemBlock, "title");
            String url = extractString(itemBlock, "url");
            if (!title.isEmpty() && !url.isEmpty()) {
                specs.add(new HttpDevMethodDoc.Specification(title, url));
            }
            cursor = objEnd + 1;
        }
        return specs;
    }
}
