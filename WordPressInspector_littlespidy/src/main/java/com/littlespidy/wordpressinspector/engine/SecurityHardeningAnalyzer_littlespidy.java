// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.engine;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Probes for common security hardening measures and defense plugins.
 */
public class SecurityHardeningAnalyzer_littlespidy {

    private static final Map<String, String> KNOWN_SECURITY_PLUGINS = Map.of(
            "wordfence", "Wordfence Security",
            "ithemes-security", "iThemes Security / Solid Security",
            "sucuri", "Sucuri Security",
            "all-in-one-wp-security", "All In One WP Security & Firewall",
            "wp-hide", "WP Hide & Security Enhancer",
            "hide-my-wp", "Hide My WP"
    );

    public static List<String> analyzeHardening(String baseUrl, String homepageContent) {
        List<String> findings = new ArrayList<>();
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            return findings;
        }

        String root = baseUrl.trim().replaceAll("/+$", "");

        // Check homepage for security plugins
        if (homepageContent != null) {
            String lower = homepageContent.toLowerCase();
            for (Map.Entry<String, String> entry : KNOWN_SECURITY_PLUGINS.entrySet()) {
                if (lower.contains(entry.getKey())) {
                    findings.add("Security Plugin Detected: " + entry.getValue());
                }
            }
            if (!lower.contains("<meta name=\"generator\"") && !lower.contains("<meta name='generator'")) {
                findings.add("Generator meta tag removed / hidden from HTML");
            }
        }

        // Test readme.html
        int readmeCode = checkEndpointCode(root + "/readme.html");
        if (readmeCode == 403 || readmeCode == 404) {
            findings.add("readme.html blocked / removed (HTTP " + readmeCode + ")");
        } else if (readmeCode == 200) {
            findings.add("readme.html exposed publicly (HTTP 200)");
        }

        // Test wp-config.php
        int configCode = checkEndpointCode(root + "/wp-config.php");
        if (configCode == 403) {
            findings.add("wp-config.php access restricted (HTTP 403)");
        }

        return findings;
    }

    private static int checkEndpointCode(String urlStr) {
        try {
            URL url = URI.create(urlStr).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setInstanceFollowRedirects(false);
            return conn.getResponseCode();
        } catch (Exception e) {
            return -1;
        }
    }
}
