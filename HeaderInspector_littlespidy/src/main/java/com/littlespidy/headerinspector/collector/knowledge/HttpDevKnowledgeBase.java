// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.collector.knowledge;

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
 * Fast, offline, in-memory knowledge base containing 307 HTTP headers across 54 categories
 * scraped directly from https://http.dev.
 *
 * Provides O(1) case-insensitive lookups, category extraction, exact explanation text,
 * directive listings, and official specification URLs without requiring external network calls.
 *
 * @author littlespidy
 */
public class HttpDevKnowledgeBase {

    private static final String RESOURCE_PATH_1 = "/com/littlespidy/headerinspector/collector/knowledge/http_dev_headers.json";
    private static final String RESOURCE_PATH_2 = "/http_dev_headers.json";

    private static final Map<String, HttpDevHeaderDoc> HEADERS_MAP = new HashMap<>();
    private static final List<HttpDevHeaderDoc> ALL_HEADERS = new ArrayList<>();
    private static final Set<String> ALL_CATEGORIES = new TreeSet<>();
    private static boolean initialized = false;

    static {
        ensureLoaded();
    }

    private static synchronized void ensureLoaded() {
        if (initialized) return;
        try {
            InputStream in = HttpDevKnowledgeBase.class.getResourceAsStream(RESOURCE_PATH_1);
            if (in == null) {
                in = HttpDevKnowledgeBase.class.getResourceAsStream(RESOURCE_PATH_2);
            }
            if (in == null) {
                in = Thread.currentThread().getContextClassLoader().getResourceAsStream("http_dev_headers.json");
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

                List<HttpDevHeaderDoc> docs = parseJson(json);
                for (HttpDevHeaderDoc doc : docs) {
                    HEADERS_MAP.put(doc.name().toLowerCase(Locale.ROOT), doc);
                    ALL_HEADERS.add(doc);
                    if (doc.category() != null && !doc.category().isBlank()) {
                        ALL_CATEGORIES.add(doc.category());
                    }
                }
                ALL_HEADERS.sort(Comparator.comparing(HttpDevHeaderDoc::name, String.CASE_INSENSITIVE_ORDER));
            }
        } catch (Exception e) {
            System.err.println("[HeaderInspector] Failed to initialize HttpDevKnowledgeBase: " + e.getMessage());
        } finally {
            initialized = true;
        }
    }

    /**
     * Looks up an HTTP header by name (case-insensitive).
     *
     * @param headerName Header name to look up
     * @return HttpDevHeaderDoc or null if unknown
     */
    public static HttpDevHeaderDoc get(String headerName) {
        if (headerName == null || headerName.isBlank()) return null;
        ensureLoaded();
        return HEADERS_MAP.get(headerName.trim().toLowerCase(Locale.ROOT));
    }

    /**
     * Returns the category for the given header name, or "Custom / Vendor" if not recognized.
     */
    public static String getCategory(String headerName) {
        HttpDevHeaderDoc doc = get(headerName);
        if (doc != null && doc.category() != null && !doc.category().isBlank()) {
            return doc.category();
        }
        return "Custom / Vendor";
    }

    /**
     * Returns whether the given header is present in the standard http.dev knowledge base.
     */
    public static boolean isKnown(String headerName) {
        return get(headerName) != null;
    }

    /**
     * Returns an unmodifiable list of all headers in the knowledge base.
     */
    public static List<HttpDevHeaderDoc> getAll() {
        ensureLoaded();
        return Collections.unmodifiableList(ALL_HEADERS);
    }

    /**
     * Returns the total count of headers loaded.
     */
    public static int totalCount() {
        ensureLoaded();
        return ALL_HEADERS.size();
    }

    /**
     * Robust bracket-counting JSON parser for the embedded dataset.
     */
    private static List<HttpDevHeaderDoc> parseJson(String json) {
        List<HttpDevHeaderDoc> list = new ArrayList<>();
        List<String> objects = splitTopLevelObjects(json);

        for (String block : objects) {
            String name = extractString(block, "name");
            String slug = extractString(block, "slug");
            String category = extractString(block, "category");
            String summary = extractString(block, "summary");
            String explanation = extractString(block, "explanation");
            String directives = extractString(block, "directives");
            String referenceUrl = extractString(block, "referenceUrl");
            List<HttpDevHeaderDoc.Specification> specs = extractSpecs(block);

            if (!name.isEmpty()) {
                list.add(new HttpDevHeaderDoc(name, slug, category, summary, explanation, directives, referenceUrl, specs));
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
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        Matcher m = p.matcher(block);
        if (m.find()) {
            return unescapeJson(m.group(1));
        }
        return "";
    }

    private static List<HttpDevHeaderDoc.Specification> extractSpecs(String block) {
        List<HttpDevHeaderDoc.Specification> specs = new ArrayList<>();
        Pattern specBlockPattern = Pattern.compile("\"specifications\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL);
        Matcher blockMatcher = specBlockPattern.matcher(block);
        if (blockMatcher.find()) {
            String inner = blockMatcher.group(1);
            Pattern itemPattern = Pattern.compile("\"title\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s*,\\s*\"url\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
            Matcher itemMatcher = itemPattern.matcher(inner);
            while (itemMatcher.find()) {
                specs.add(new HttpDevHeaderDoc.Specification(
                        unescapeJson(itemMatcher.group(1)),
                        unescapeJson(itemMatcher.group(2))
                ));
            }
        }
        return specs;
    }

    private static String unescapeJson(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char next = s.charAt(++i);
                switch (next) {
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'u' -> {
                        if (i + 4 < s.length()) {
                            String hex = s.substring(i + 1, i + 5);
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
                    default -> sb.append(next);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
