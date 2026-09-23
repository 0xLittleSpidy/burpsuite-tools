// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiestore.knowledge;

import javax.swing.SwingUtilities;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Live HTTP client and web scraper for https://www.cookiesearch.org/.
 *
 * Automatically fetches and parses cookie metadata (category, description, script/provider,
 * associated URLs, and related cookies) on demand without blocking the Swing EDT.
 *
 * @author littlespidy
 */
public class CookieSearchFetcher {

    private static final String BASE_URL = "https://www.cookiesearch.org/cookies/?cookie-id=";
    private static final String SEARCH_URL = "https://www.cookiesearch.org/cookies/?filter-type=cookie-name&search-term=";

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .connectTimeout(Duration.ofSeconds(6))
            .build();

    private static final ExecutorService EXECUTOR = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "CookieSearch-Fetcher-Thread");
        t.setDaemon(true);
        return t;
    });

    /**
     * Asynchronously fetches cookie documentation from cookiesearch.org,
     * delivering the result onto the Swing Event Dispatch Thread (EDT).
     *
     * @param cookieName The cookie name to query
     * @param callback   Callback receiving the resulting CookieDocRecord on the EDT
     */
    public static void fetchAsync(String cookieName, Consumer<CookieDocRecord> callback) {
        if (cookieName == null || cookieName.isBlank()) {
            if (callback != null) {
                SwingUtilities.invokeLater(() -> callback.accept(null));
            }
            return;
        }

        // 1. Check in-memory cache first
        CookieDocRecord cached = CookieSearchKnowledgeBase.get(cookieName);
        if (cached != null) {
            if (callback != null) {
                SwingUtilities.invokeLater(() -> callback.accept(cached));
            }
            return;
        }

        // 2. Fetch live in background thread
        EXECUTOR.submit(() -> {
            CookieDocRecord fetched = fetchSync(cookieName);
            if (callback != null) {
                SwingUtilities.invokeLater(() -> callback.accept(fetched));
            }
        });
    }

    /**
     * Synchronously fetches cookie documentation from cookiesearch.org.
     */
    public static CookieDocRecord fetchSync(String cookieName) {
        if (cookieName == null || cookieName.isBlank()) return null;

        String trimmed = cookieName.trim();
        CookieDocRecord cached = CookieSearchKnowledgeBase.get(trimmed);
        if (cached != null) {
            return cached;
        }

        try {
            String targetUrl = BASE_URL + URLEncoder.encode(trimmed, StandardCharsets.UTF_8);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                    .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                    .GET()
                    .build();

            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() == 200 && response.body() != null) {
                CookieDocRecord parsed = parseHtml(trimmed, targetUrl, response.body());
                if (parsed != null && parsed.hasDescription()) {
                    CookieSearchKnowledgeBase.put(parsed);
                    return parsed;
                }
            }
        } catch (Exception e) {
            System.err.println("[SessionInspector] Error fetching cookie '" + trimmed + "' from cookiesearch.org: " + e.getMessage());
        }

        // Fallback: Infer heuristics or unknown notice
        CookieDocRecord fallback = createInferredOrUnknownRecord(trimmed);
        CookieSearchKnowledgeBase.put(fallback);
        return fallback;
    }

    private static CookieDocRecord parseHtml(String cookieName, String referenceUrl, String html) {
        String name = extractRegex(html, "<p class=\"cname\">([^<]+)</p>", cookieName);
        String category = extractRegex(html, "<p class=\"ccat\">([^<]+)</p>", "");
        String cookieId = extractRegex(html, "<strong>Cookie ID</strong>:\\s*&nbsp;<span>([^<]*)</span>", cookieName);
        String url = extractRegex(html, "<strong>URL</strong>:\\s*&nbsp;<span>([^<]*)</span>", "");
        String script = extractRegex(html, "<strong>Script</strong>:\\s*&nbsp;<span>([^<]*)</span>", "");
        String description = extractRegex(html, "<strong>Description</strong>:\\s*&nbsp;<span>(.*?)</span>", "");

        description = cleanHtml(description);

        if (description.isBlank() && category.isBlank()) {
            return null; // Not found on cookiesearch.org
        }

        if (category.isBlank()) {
            category = "Others";
        }

        // Extract related cookies
        List<String> related = new ArrayList<>();
        Pattern relPattern = Pattern.compile("href=\"[^\"]*cookie-id=([^\"]+)\">([^<]+)</a>");
        Matcher relMatcher = relPattern.matcher(html);
        while (relMatcher.find()) {
            String relName = cleanHtml(relMatcher.group(2)).trim();
            if (!relName.equalsIgnoreCase(cookieName) && !related.contains(relName)) {
                related.add(relName);
            }
        }

        return new CookieDocRecord(
                name.isBlank() ? cookieName : name,
                category,
                cookieId.isBlank() ? cookieName : cookieId,
                url,
                script,
                description,
                referenceUrl,
                related
        );
    }

    private static CookieDocRecord createInferredOrUnknownRecord(String cookieName) {
        String lower = cookieName.toLowerCase(Locale.ROOT);
        String category = "Others";
        String description;
        String script = "";

        if (lower.contains("session") || lower.contains("sess") || lower.contains("sid") || lower.contains("phpsessid")
                || lower.contains("jsessionid") || lower.contains("token") || lower.contains("auth") || lower.contains("jwt")
                || lower.contains("login") || lower.contains("connect.sid")) {
            category = "Necessary";
            description = "Likely application session or authentication identifier. "
                    + "Typically required to maintain the user's logged-in session state and access control across HTTP transactions. "
                    + "Removing or modifying this cookie usually terminates authenticated session access.";
        } else if (lower.contains("csrf") || lower.contains("xsrf") || lower.contains("antixsrf")) {
            category = "Necessary";
            description = "Cross-Site Request Forgery (CSRF) anti-tampering token. "
                    + "Used by web applications to validate state-changing requests and defend against unauthorized forged actions.";
        } else if (lower.startsWith("_ga") || lower.startsWith("_gid") || lower.startsWith("_gat") || lower.contains("analytics")
                || lower.contains("utm") || lower.contains("pixel") || lower.contains("amplitude") || lower.contains("mixpanel")) {
            category = "Analytics";
            description = "Web analytics and traffic measurement cookie. "
                    + "Used to record visitor metrics, navigation funnels, and usage statistics.";
        } else if (lower.contains("cf_") || lower.contains("cloudflare") || lower.contains("akamai") || lower.contains("awsalb")) {
            category = "Necessary";
            description = "Reverse proxy, Content Delivery Network (CDN), or load balancer infrastructure cookie. "
                    + "Used to manage client routing affinity and edge security protections.";
        } else {
            description = "This cookie was observed in HTTP traffic but is not currently indexed in cookiesearch.org. "
                    + "It may be a custom proprietary session token, an internal application state parameter, or a vendor-specific identifier.";
        }

        String searchUrl = SEARCH_URL + URLEncoder.encode(cookieName, StandardCharsets.UTF_8);
        return new CookieDocRecord(
                cookieName,
                category,
                cookieName,
                "",
                script,
                description,
                searchUrl,
                List.of()
        );
    }

    private static String extractRegex(String html, String regex, String fallback) {
        Pattern pattern = Pattern.compile(regex, Pattern.DOTALL);
        Matcher matcher = pattern.matcher(html);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return fallback;
    }

    private static String cleanHtml(String text) {
        if (text == null) return "";
        return text.replaceAll("<[^>]+>", "")
                .replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#039;", "'")
                .replace("&nbsp;", " ")
                .trim();
    }
}
