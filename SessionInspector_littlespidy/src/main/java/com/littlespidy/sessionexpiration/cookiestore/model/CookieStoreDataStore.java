// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiestore.model;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe central data store for collected cookies and their observed values.
 * Parses request Cookie headers and response Set-Cookie headers, groups multiple unique
 * values under their respective cookie names, tracks repetition counts, and provides filtering.
 *
 * @author littlespidy
 */
public class CookieStoreDataStore {

    private final Map<String, CookieNameGroup> cookieGroups = new LinkedHashMap<>();
    private final AtomicInteger idGen = new AtomicInteger(1);
    private int totalMessagesProcessed = 0;

    public synchronized void ingest(HttpRequestResponse item) {
        if (item == null || item.request() == null) return;
        ingestInternal(item.request(), item.hasResponse() ? item.response() : null, item);
    }

    public synchronized void ingest(burp.api.montoya.proxy.ProxyHttpRequestResponse item) {
        if (item == null || item.request() == null) return;
        HttpRequest req = item.request();
        HttpResponse resp = item.hasResponse() ? item.response() : null;
        HttpRequestResponse hrr = (req != null && resp != null)
                ? HttpRequestResponse.httpRequestResponse(req, resp) : null;
        ingestInternal(req, resp, hrr);
    }

    private void ingestInternal(HttpRequest req, HttpResponse resp, HttpRequestResponse item) {
        totalMessagesProcessed++;

        String domain = (req.httpService() != null && req.httpService().host() != null)
                ? req.httpService().host() : "";
        String url = (req.url() != null) ? req.url() : "";
        String method = (req.method() != null) ? req.method().toUpperCase(Locale.ROOT) : "GET";
        int statusCode = (resp != null) ? resp.statusCode() : 0;

        // 1. Ingest Request Cookies (from Cookie: header)
        if (req.headers() != null) {
            for (HttpHeader h : req.headers()) {
                if (h != null && h.name() != null && h.name().equalsIgnoreCase("Cookie")) {
                    parseRequestCookies(h.value(), domain, item, url, method, statusCode);
                }
            }
        }

        // 2. Ingest Response Cookies (from Set-Cookie: headers)
        if (resp != null && resp.headers() != null) {
            for (HttpHeader h : resp.headers()) {
                if (h != null && h.name() != null && h.name().equalsIgnoreCase("Set-Cookie")) {
                    parseResponseCookie(h.value(), domain, item, url, method, statusCode);
                }
            }
        }
    }

    private void parseRequestCookies(String headerVal, String domain, HttpRequestResponse item,
                                     String url, String method, int statusCode) {
        if (headerVal == null || headerVal.trim().isEmpty()) return;
        String[] pairs = headerVal.split(";\\s*");
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String name = pair.substring(0, eq).trim();
                String val = pair.substring(eq + 1).trim();
                if (!name.isEmpty()) {
                    String lower = name.toLowerCase(Locale.ROOT);
                    CookieNameGroup group = cookieGroups.computeIfAbsent(
                            lower,
                            k -> new CookieNameGroup(name, CookieSource.REQUEST)
                    );
                    group.addCookieValue(idGen, val, CookieSource.REQUEST, domain, "", item, url, method, statusCode);
                }
            }
        }
    }

    private void parseResponseCookie(String headerVal, String domain, HttpRequestResponse item,
                                      String url, String method, int statusCode) {
        if (headerVal == null || headerVal.trim().isEmpty()) return;
        String[] parts = headerVal.split(";\\s*");
        if (parts.length == 0) return;

        // First part is name=value
        String first = parts[0];
        int eq = first.indexOf('=');
        if (eq > 0) {
            String name = first.substring(0, eq).trim();
            String val = first.substring(eq + 1).trim();

            // The remaining parts are cookie attributes (HttpOnly, Secure, SameSite, Path, Domain, Expires/Max-Age)
            StringBuilder attrBuilder = new StringBuilder();
            for (int i = 1; i < parts.length; i++) {
                if (attrBuilder.length() > 0) attrBuilder.append("; ");
                attrBuilder.append(parts[i].trim());
            }
            String attributes = attrBuilder.toString();

            if (!name.isEmpty()) {
                String lower = name.toLowerCase(Locale.ROOT);
                CookieNameGroup group = cookieGroups.computeIfAbsent(
                        lower,
                        k -> new CookieNameGroup(name, CookieSource.RESPONSE)
                );
                group.addCookieValue(idGen, val, CookieSource.RESPONSE, domain, attributes, item, url, method, statusCode);
            }
        }
    }

    public synchronized void clear() {
        cookieGroups.clear();
        totalMessagesProcessed = 0;
        idGen.set(1);
    }

    public synchronized List<CookieNameGroup> getFilteredGroups(
            CookieSource sourceFilter,
            String domainFilter,
            String searchFilter) {
        List<CookieNameGroup> result = new ArrayList<>();
        for (CookieNameGroup g : cookieGroups.values()) {
            if (g.matches(sourceFilter, domainFilter, searchFilter)) {
                result.add(g);
            }
        }
        // Sort alphabetically by cookie name
        result.sort((a, b) -> a.displayName().compareToIgnoreCase(b.displayName()));
        return result;
    }

    public synchronized int totalCookiesCount() {
        return cookieGroups.size();
    }

    public synchronized int totalUniqueValuesCount() {
        int count = 0;
        for (CookieNameGroup g : cookieGroups.values()) {
            count += g.uniqueValuesCount();
        }
        return count;
    }

    public synchronized int totalDomainsCount() {
        Set<String> all = new HashSet<>();
        for (CookieNameGroup g : cookieGroups.values()) {
            all.addAll(g.allDomains());
        }
        return all.size();
    }

    public synchronized int totalOccurrences() {
        int sum = 0;
        for (CookieNameGroup g : cookieGroups.values()) {
            sum += g.totalOccurrences();
        }
        return sum;
    }

    public synchronized int totalMessagesProcessed() {
        return totalMessagesProcessed;
    }

    public synchronized String exportToTsv() {
        StringBuilder sb = new StringBuilder();
        sb.append("Cookie Name\tSource\tValue\tOccurrences (Repeated)\tDomains\tAttributes\tSample URL\tStatus\n");
        for (CookieNameGroup g : cookieGroups.values()) {
            for (CookieValueRecord r : g.getValues()) {
                sb.append(g.displayName()).append("\t")
                  .append(r.source().getDisplayName()).append("\t")
                  .append(r.value()).append("\t")
                  .append(r.occurrences()).append("\t")
                  .append(r.domainsFormatted()).append("\t")
                  .append(r.attributes()).append("\t")
                  .append(r.sampleUrl()).append("\t")
                  .append(r.sampleStatusCode()).append("\n");
            }
        }
        return sb.toString();
    }
}
