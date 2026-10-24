// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.engine;

import com.littlespidy.wordpressinspector.model.RestApiResult_littlespidy;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Discovers and audits standard WordPress REST API routes.
 */
public class RestApiProber_littlespidy {

    private static final List<String[]> ROUTES = List.of(
            new String[]{"/wp-json/", "API Root"},
            new String[]{"/wp-json/wp/v2/users", "Users Endpoint"},
            new String[]{"/wp-json/wp/v2/posts", "Posts Endpoint"},
            new String[]{"/wp-json/wp/v2/pages", "Pages Endpoint"},
            new String[]{"/wp-json/wp/v2/media", "Media Endpoint"}
    );

    public static RestApiResult_littlespidy probeRestApi(String baseUrl) {
        RestApiResult_littlespidy result = new RestApiResult_littlespidy();
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            return result;
        }

        String root = baseUrl.trim().replaceAll("/+$", "");
        for (String[] route : ROUTES) {
            String path = route[0];
            String name = route[1];
            try {
                URL url = URI.create(root + path).toURL();
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                conn.setConnectTimeout(6000);
                conn.setReadTimeout(6000);
                conn.setInstanceFollowRedirects(false);

                int code = conn.getResponseCode();
                boolean accessible = (code == 200);
                result.addEndpoint(path, name + " (HTTP " + code + ")", accessible);

                if (accessible) {
                    if (path.contains("users")) {
                        result.setUsersExposed(true);
                    }
                    if (path.contains("posts")) {
                        result.setPostsExposed(true);
                    }
                }
            } catch (Exception ignored) {
                result.addEndpoint(path, name + " (Error)", false);
            }
        }
        return result;
    }
}
