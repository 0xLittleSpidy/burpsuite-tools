// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.engine;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Client for fetching public plugin information from WordPress.org API.
 */
public class WordPressOrgClient_littlespidy {

    private static final String WP_ORG_API_URL = "https://api.wordpress.org/plugins/info/1.0/";

    public static String fetchLatestPluginVersion(String slug) {
        if (slug == null || slug.trim().isEmpty()) {
            return null;
        }
        String cleanSlug = WordPressDetectionEngine_littlespidy.normalizeSlug(slug);
        try {
            URL url = URI.create(WP_ORG_API_URL + cleanSlug + ".json").toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "WordPressInspector-littlespidy/1.0.0");
            conn.setConnectTimeout(6000);
            conn.setReadTimeout(6000);

            if (conn.getResponseCode() == 200) {
                try (InputStream is = conn.getInputStream();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line);
                    }
                    JsonObject obj = JsonParser.parseString(sb.toString()).getAsJsonObject();
                    if (obj.has("version") && !obj.get("version").isJsonNull()) {
                        return obj.get("version").getAsString();
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }
}
