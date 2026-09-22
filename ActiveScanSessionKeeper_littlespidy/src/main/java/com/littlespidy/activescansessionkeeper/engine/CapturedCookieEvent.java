// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.engine;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Event containing session cookie(s) intercepted from Burp Proxy traffic
 * during an interactive user login session.
 *
 * @author littlespidy
 */
public class CapturedCookieEvent {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final String cookieString;
    private final String sourceUrl;
    private final String method;
    private final String timestamp;
    private final Map<String, String> cookieMap;

    public CapturedCookieEvent(String cookieString, String sourceUrl, String method) {
        this.cookieString = cookieString;
        this.sourceUrl = sourceUrl;
        this.method = method;
        this.timestamp = LocalDateTime.now().format(TIME_FMT);
        this.cookieMap = parseCookieMap(cookieString);
    }

    private static Map<String, String> parseCookieMap(String raw) {
        Map<String, String> map = new LinkedHashMap<>();
        if (raw == null || raw.trim().isEmpty()) {
            return map;
        }
        String[] pairs = raw.split(";\\s*");
        for (String p : pairs) {
            int eq = p.indexOf('=');
            if (eq > 0) {
                map.put(p.substring(0, eq).trim(), p.substring(eq + 1).trim());
            }
        }
        return Collections.unmodifiableMap(map);
    }

    public String getCookieString() {
        return cookieString;
    }

    public String getSourceUrl() {
        return sourceUrl;
    }

    public String getMethod() {
        return method;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public Map<String, String> getCookieMap() {
        return cookieMap;
    }

    @Override
    public String toString() {
        return "[" + timestamp + " " + method + " " + sourceUrl + "] " + cookieString;
    }
}
