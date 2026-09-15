// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.status.knowledge;

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
 * Fast, offline, in-memory knowledge base containing 136 HTTP status codes
 * (standard 1xx-5xx plus Cloudflare, Nginx, Akamai, and Edgio vendor codes)
 * scraped directly from https://http.dev.
 *
 * Provides O(1) integer code lookups, class classification, client actions,
 * SEO impact explanations, and official RFC specifications without network calls.
 *
 * @author littlespidy
 */
public class HttpDevStatusKnowledgeBase {

    private static final String RESOURCE_PATH_1 = "/com/littlespidy/headerinspector/status/knowledge/http_dev_statuses.json";
    private static final String RESOURCE_PATH_2 = "/http_dev_statuses.json";

    private static final Map<Integer, HttpDevStatusDoc> STATUSES_MAP = new HashMap<>();
    private static final List<HttpDevStatusDoc> ALL_STATUSES = new ArrayList<>();
    private static boolean initialized = false;

    static {
        ensureLoaded();
    }

    private static synchronized void ensureLoaded() {
        if (initialized) return;
        try {
            InputStream in = HttpDevStatusKnowledgeBase.class.getResourceAsStream(RESOURCE_PATH_1);
            if (in == null) {
                in = HttpDevStatusKnowledgeBase.class.getResourceAsStream(RESOURCE_PATH_2);
            }
            if (in == null) {
                in = Thread.currentThread().getContextClassLoader().getResourceAsStream("http_dev_statuses.json");
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

                List<HttpDevStatusDoc> docs = parseJson(json);
                for (HttpDevStatusDoc doc : docs) {
                    STATUSES_MAP.put(doc.code(), doc);
                    ALL_STATUSES.add(doc);
                }
                ALL_STATUSES.sort(Comparator.comparingInt(HttpDevStatusDoc::code));
            }
        } catch (Exception e) {
            System.err.println("[HeaderInspector] Failed to initialize HttpDevStatusKnowledgeBase: " + e.getMessage());
        } finally {
            initialized = true;
        }
    }

    /**
     * Looks up an HTTP status code by number.
     *
     * @param code Three-digit HTTP status code (e.g. 200, 404, 500)
     * @return HttpDevStatusDoc or null if unknown
     */
    public static HttpDevStatusDoc get(int code) {
        ensureLoaded();
        return STATUSES_MAP.get(code);
    }

    /**
     * Looks up an HTTP status code by string representation or name.
     */
    public static HttpDevStatusDoc get(String codeOrName) {
        if (codeOrName == null || codeOrName.isBlank()) return null;
        ensureLoaded();
        try {
            int code = Integer.parseInt(codeOrName.trim());
            return get(code);
        } catch (NumberFormatException ignored) {}

        String lower = codeOrName.trim().toLowerCase(Locale.ROOT);
        for (HttpDevStatusDoc doc : ALL_STATUSES) {
            if (doc.name().toLowerCase(Locale.ROOT).equals(lower)) {
                return doc;
            }
        }
        return null;
    }

    public static boolean isKnown(int code) {
        return get(code) != null;
    }

    public static String getReasonPhrase(int code) {
        HttpDevStatusDoc doc = get(code);
        return doc != null ? doc.name() : "Status " + code;
    }

    public static String getStatusClass(int code) {
        HttpDevStatusDoc doc = get(code);
        if (doc != null) return doc.statusClass();
        if (code >= 100 && code <= 199) return "1xx Informational";
        if (code >= 200 && code <= 299) return "2xx Success";
        if (code >= 300 && code <= 399) return "3xx Redirection";
        if (code >= 400 && code <= 499) return "4xx Client Error";
        if (code >= 500 && code <= 599) return "5xx Server Error";
        return "Extended / Custom";
    }

    public static List<HttpDevStatusDoc> getAll() {
        ensureLoaded();
        return Collections.unmodifiableList(ALL_STATUSES);
    }

    public static int totalCount() {
        ensureLoaded();
        return ALL_STATUSES.size();
    }

    /**
     * Robust bracket-counting JSON parser for the embedded dataset.
     */
    private static List<HttpDevStatusDoc> parseJson(String json) {
        List<HttpDevStatusDoc> list = new ArrayList<>();
        List<String> objects = splitTopLevelObjects(json);

        for (String block : objects) {
            int code = extractInt(block, "code");
            String name = extractString(block, "name");
            String slug = extractString(block, "slug");
            String statusClass = extractString(block, "statusClass");
            String meaning = extractString(block, "meaning");
            String clientAction = extractString(block, "clientAction");
            String summary = extractString(block, "summary");
            String explanation = extractString(block, "explanation");
            String referenceUrl = extractString(block, "referenceUrl");
            List<HttpDevStatusDoc.Specification> specs = extractSpecs(block);

            if (code > 0) {
                list.add(new HttpDevStatusDoc(code, name, slug, statusClass, meaning, clientAction, summary, explanation, referenceUrl, specs));
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

    private static int extractInt(String block, String key) {
        String search = "\"" + key + "\"";
        int keyIdx = block.indexOf(search);
        if (keyIdx == -1) return 0;
        int colonIdx = block.indexOf(':', keyIdx + search.length());
        if (colonIdx == -1) return 0;
        int nextComma = block.indexOf(',', colonIdx + 1);
        int nextBrace = block.indexOf('}', colonIdx + 1);
        int endIdx = (nextComma != -1 && nextBrace != -1) ? Math.min(nextComma, nextBrace) : Math.max(nextComma, nextBrace);
        if (endIdx == -1) endIdx = block.length();
        String val = block.substring(colonIdx + 1, endIdx).trim();
        try {
            return Integer.parseInt(val);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static List<HttpDevStatusDoc.Specification> extractSpecs(String block) {
        List<HttpDevStatusDoc.Specification> specs = new ArrayList<>();
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
                specs.add(new HttpDevStatusDoc.Specification(title, url));
            }
            cursor = objEnd + 1;
        }
        return specs;
    }
}
