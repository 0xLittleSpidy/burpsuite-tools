// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiestore.knowledge;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * In-memory offline knowledge base and cache containing cookie definitions,
 * classifications, and behavior descriptions scraped from https://www.cookiesearch.org/.
 *
 * Provides instant O(1) case-insensitive lookups, category extraction, and supports
 * dynamic runtime insertion of live-crawled cookies.
 *
 * @author littlespidy
 */
public class CookieSearchKnowledgeBase {

    private static final String RESOURCE_PATH_1 = "/com/littlespidy/sessionexpiration/cookiestore/knowledge/cookiesearch_cookies.json";
    private static final String RESOURCE_PATH_2 = "/cookiesearch_cookies.json";

    private static final Map<String, CookieDocRecord> COOKIES_MAP = new ConcurrentHashMap<>();
    private static final List<CookieDocRecord> ALL_COOKIES = new ArrayList<>();
    private static final Set<String> ALL_CATEGORIES = new TreeSet<>();
    private static boolean initialized = false;

    static {
        ensureLoaded();
    }

    private static synchronized void ensureLoaded() {
        if (initialized) return;
        try {
            InputStream in = CookieSearchKnowledgeBase.class.getResourceAsStream(RESOURCE_PATH_1);
            if (in == null) {
                in = CookieSearchKnowledgeBase.class.getResourceAsStream(RESOURCE_PATH_2);
            }
            if (in == null) {
                in = Thread.currentThread().getContextClassLoader().getResourceAsStream("cookiesearch_cookies.json");
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

                List<CookieDocRecord> docs = parseJson(json);
                for (CookieDocRecord doc : docs) {
                    COOKIES_MAP.put(doc.name().toLowerCase(Locale.ROOT), doc);
                    ALL_COOKIES.add(doc);
                    if (doc.category() != null && !doc.category().isBlank()) {
                        ALL_CATEGORIES.add(doc.category());
                    }
                }
                ALL_COOKIES.sort(Comparator.comparing(CookieDocRecord::name, String.CASE_INSENSITIVE_ORDER));
            }
        } catch (Exception e) {
            System.err.println("[SessionInspector] Failed to initialize CookieSearchKnowledgeBase: " + e.getMessage());
        } finally {
            initialized = true;
        }
    }

    /**
     * Look up a cookie definition by name (case-insensitive).
     */
    public static CookieDocRecord get(String cookieName) {
        if (cookieName == null || cookieName.isBlank()) return null;
        ensureLoaded();
        return COOKIES_MAP.get(cookieName.trim().toLowerCase(Locale.ROOT));
    }

    /**
     * Cache or update a cookie definition in memory.
     */
    public static void put(CookieDocRecord doc) {
        if (doc == null || doc.name() == null || doc.name().isBlank()) return;
        ensureLoaded();
        COOKIES_MAP.put(doc.name().trim().toLowerCase(Locale.ROOT), doc);
    }

    /**
     * Returns whether the given cookie is present in the knowledge base.
     */
    public static boolean isKnown(String cookieName) {
        return get(cookieName) != null;
    }

    /**
     * Returns category name or "Uncategorized" if not found.
     */
    public static String getCategory(String cookieName) {
        CookieDocRecord doc = get(cookieName);
        if (doc != null && doc.category() != null && !doc.category().isBlank()) {
            return doc.category();
        }
        return "Uncategorized";
    }

    public static int totalCount() {
        ensureLoaded();
        return COOKIES_MAP.size();
    }

    public static Collection<CookieDocRecord> getAll() {
        ensureLoaded();
        return Collections.unmodifiableCollection(COOKIES_MAP.values());
    }

    private static List<CookieDocRecord> parseJson(String json) {
        List<CookieDocRecord> list = new ArrayList<>();
        List<String> objects = splitTopLevelObjects(json);

        for (String block : objects) {
            String name = extractString(block, "name");
            String category = extractString(block, "category");
            String cookieId = extractString(block, "cookie_id");
            String url = extractString(block, "url");
            String script = extractString(block, "script");
            String description = extractString(block, "description");
            String referenceUrl = extractString(block, "reference_url");
            List<String> related = extractStringList(block, "related");

            if (!name.isEmpty()) {
                list.add(new CookieDocRecord(name, category, cookieId, url, script, description, referenceUrl, related));
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

    private static List<String> extractStringList(String block, String key) {
        List<String> result = new ArrayList<>();
        Pattern listPattern = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL);
        Matcher listMatcher = listPattern.matcher(block);
        if (listMatcher.find()) {
            String inner = listMatcher.group(1);
            Pattern itemPattern = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"");
            Matcher itemMatcher = itemPattern.matcher(inner);
            while (itemMatcher.find()) {
                result.add(unescapeJson(itemMatcher.group(1)));
            }
        }
        return result;
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
