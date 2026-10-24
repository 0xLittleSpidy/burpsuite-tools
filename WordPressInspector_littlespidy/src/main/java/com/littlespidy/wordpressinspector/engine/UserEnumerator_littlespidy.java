// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.engine;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.littlespidy.wordpressinspector.model.UserFinding_littlespidy;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Enumerates WordPress users through REST API and author redirect probes.
 */
public class UserEnumerator_littlespidy {

    private static final Pattern AUTHOR_URL_PATTERN = Pattern.compile("/author/([^/\"\\s\\?]+)", Pattern.CASE_INSENSITIVE);

    public static List<UserFinding_littlespidy> enumerateUsers(String baseUrl) {
        List<UserFinding_littlespidy> users = new ArrayList<>();
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            return users;
        }

        String root = baseUrl.trim().replaceAll("/+$", "");

        // 1. Enumerate via REST API
        try {
            URL url = URI.create(root + "/wp-json/wp/v2/users").toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);

            if (conn.getResponseCode() == 200) {
                try (InputStream is = conn.getInputStream();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line);
                    }
                    JsonElement parsed = JsonParser.parseString(sb.toString());
                    if (parsed.isJsonArray()) {
                        JsonArray arr = parsed.getAsJsonArray();
                        for (JsonElement el : arr) {
                            if (el.isJsonObject()) {
                                JsonObject uObj = el.getAsJsonObject();
                                int id = uObj.has("id") ? uObj.get("id").getAsInt() : 0;
                                String name = uObj.has("name") ? uObj.get("name").getAsString() : "Unknown";
                                String slug = uObj.has("slug") ? uObj.get("slug").getAsString() : name;
                                String link = uObj.has("link") ? uObj.get("link").getAsString() : "";

                                UserFinding_littlespidy user = new UserFinding_littlespidy(id, slug, name, slug, "REST API (/wp-json/wp/v2/users)");
                                user.setProfileUrl(link);
                                users.add(user);
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {
            // REST API disabled, proceed to redirect check
        }

        // 2. Fallback or augment with author redirect (?author=1..5)
        if (users.isEmpty()) {
            for (int authorId = 1; authorId <= 5; authorId++) {
                try {
                    URL url = URI.create(root + "/?author=" + authorId).toURL();
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");
                    conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                    conn.setConnectTimeout(6000);
                    conn.setReadTimeout(6000);
                    conn.setInstanceFollowRedirects(false);

                    int code = conn.getResponseCode();
                    String location = conn.getHeaderField("Location");
                    if ((code == 301 || code == 302) && location != null) {
                        Matcher m = AUTHOR_URL_PATTERN.matcher(location);
                        if (m.find()) {
                            String username = m.group(1);
                            UserFinding_littlespidy user = new UserFinding_littlespidy(
                                    authorId, username, username, username, "Author Redirect (/?author=" + authorId + ")"
                            );
                            user.setProfileUrl(location);
                            users.add(user);
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        }

        return users;
    }
}
