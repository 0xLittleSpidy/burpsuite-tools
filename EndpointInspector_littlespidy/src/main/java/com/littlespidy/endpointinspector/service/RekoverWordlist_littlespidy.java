// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector.service;

import java.util.*;

/**
 * Probability-weighted reconnaissance wordlist built as an L1->L2->L3 tree,
 * covering the top 80% of paths found in real-world targets following reKover's Pareto principles.
 *
 * @author littlespidy
 */
public final class RekoverWordlist_littlespidy {

    private RekoverWordlist_littlespidy() {}

    private static final List<String> ROOTS = List.of(
        "login", "logout", "register", "signup", "2fa", "reset-password", "dashboard", "profile", "account", "blog", "settings",
        ".env", ".htaccess", ".DS_Store", ".gitlab-ci.yml", ".github/workflows",
        ".git/HEAD", ".well-known/security.txt",
        "config.json", "config.php", "config.yml", "web.config",
        "phpinfo.php", "info.php",
        "robots.txt", "sitemap.xml", "security.txt",
        "README.md", "CHANGELOG", "LICENSE", "Dockerfile", "docker-compose.yml",
        "backup", "backup.sql", "backup.zip", "db.sql", "dump.sql",
        "uploads", "files", "static", "assets", "media", "images", "download", "downloads",
        "wp-login.php", "wp-includes", "wp-cron.php", "wp-config.php.bak",
        "xmlrpc.php", "feed",
        "telescope", "horizon",
        "storage/logs/laravel.log", "_ignition/health-check",
        "django-admin", "__debug__",
        "swagger", "swagger.json", "openapi.json", "openapi.yaml",
        "api-docs", "v3/api-docs", "redoc", "graphiql", "playground",
        "health", "status", "metrics", "ping", "version", "info", "monitoring",
        "server-status", "server-info",
        "administrator", "panel", "controlpanel", "manage", "backend", "console", "shell",
        "test", "debug", "dev", "staging", "old",
        "search", "ajax", "app", "install", "user", "users", "upload"
    );

    private static final Map<String, List<String>> L2 = new LinkedHashMap<>();
    static {
        L2.put("admin", List.of("login", "users", "dashboard", "settings"));
        L2.put("settings", List.of("billing", "notifications", "security"));
        L2.put("api", List.of("v1", "v2", "v3", "docs", "swagger", "internal"));
        L2.put("actuator", List.of("env", "health", "mappings", "heapdump", "metrics", "beans", "httptrace", "threaddump", "loggers"));
        L2.put("wp-admin", List.of("admin-ajax.php"));
        L2.put("wp-json", List.of("wp"));
        L2.put("wp-content", List.of("uploads", "plugins", "themes"));
        L2.put(".git", List.of("HEAD", "config"));
        L2.put("swagger-ui", List.of("index.html"));
        L2.put("graphql", List.of("playground", "graphiql"));
        L2.put("api/internal", List.of("config", "debug", "flags"));
    }

    private static final Map<String, List<String>> L3 = new LinkedHashMap<>();
    static {
        L3.put("api/v1", List.of("users", "auth", "status", "health", "admin", "upload"));
        L3.put("api/v2", List.of("users", "export", "reports"));
        L3.put("api/v3", List.of("users"));
        L3.put("wp-json/wp", List.of("v2"));
    }

    private static final List<String> DEEP = List.of(
        "api/v1/auth/2fa/verify",
        "api/v1/auth/forgot-password",
        "api/v1/auth/login",
        "api/v1/auth/logout",
        "api/v1/auth/oauth",
        "api/v1/auth/register",
        "api/v1/auth/reset-password",
        "api/v1/auth/saml",
        "api/v1/auth/token",
        "wp-json/wp/v2/users",
        "wp-json/wp/v2/posts",
        "wp-json/wp/v2/media"
    );

    /**
     * Builds and returns the deduplicated list of Pareto tree paths.
     */
    public static List<String> buildWordlist() {
        Set<String> words = new LinkedHashSet<>(ROOTS);

        for (Map.Entry<String, List<String>> entry : L2.entrySet()) {
            String l1 = entry.getKey();
            words.add(l1);
            for (String l2Item : entry.getValue()) {
                String key = l1 + "/" + l2Item;
                words.add(key);
                List<String> l3List = L3.get(key);
                if (l3List != null) {
                    for (String l3Item : l3List) {
                        words.add(key + "/" + l3Item);
                    }
                }
            }
        }

        words.addAll(DEEP);
        return new ArrayList<>(words);
    }
}
