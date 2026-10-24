// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.engine;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Fast passive detection engine for identifying WordPress installations,
 * core versions, plugins, and themes from HTTP traffic.
 */
public class WordPressDetectionEngine_littlespidy {

    private static final List<Pattern> WP_PATTERNS = List.of(
            Pattern.compile("/wp-content/themes/[^\"\\s]+\\.css", Pattern.CASE_INSENSITIVE),
            Pattern.compile("/wp-content/plugins/[^\"\\s]+\\.js", Pattern.CASE_INSENSITIVE),
            Pattern.compile("/wp-includes/js/[^\"\\s]+\\.js", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<meta name=\"generator\" content=\"WordPress", Pattern.CASE_INSENSITIVE),
            Pattern.compile("wp-emoji-release\\.min\\.js", Pattern.CASE_INSENSITIVE),
            Pattern.compile("/wp-json/wp/v2/", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<link[^>]+wp-content/themes/", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<script[^>]+wp-includes/js/", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<link[^>]+wp-includes/css/", Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> VERSION_PATTERNS = List.of(
            Pattern.compile("<meta\\s+name=[\"']generator[\"']\\s+content=[\"']WordPress\\s+(\\d+\\.\\d+(?:\\.\\d+)?)[\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"version\"\\s*:\\s*\"(\\d+\\.\\d+(?:\\.\\d+)?)\""),
            Pattern.compile("generator=[\"']WordPress/(\\d+\\.\\d+(?:\\.\\d+)?)[\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<generator>.*WordPress/(\\d+\\.\\d+(?:\\.\\d+)?)</generator>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("[?&]ver=(\\d+\\.\\d+(?:\\.\\d+)?)[&'\"]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("[?&]v=(\\d+\\.\\d+(?:\\.\\d+)?)", Pattern.CASE_INSENSITIVE)
    );

    private static final Pattern PLUGIN_PATTERN = Pattern.compile("/wp-content/plugins/([^/\"\\s\\?]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern THEME_PATTERN = Pattern.compile("/wp-content/themes/([^/\"\\s\\?]+)", Pattern.CASE_INSENSITIVE);

    // Curated catalog of 80+ high-risk WordPress plugins prone to frequent vulnerabilities
    public static final Set<String> HIGH_RISK_PLUGINS = Set.of(
            "contact-form-7", "wpforms-lite", "wpforms", "ninja-forms", "formidable",
            "gravityforms", "caldera-forms", "contact-form-7-to-database-extension",
            "woocommerce", "woocommerce-payments", "woo-gutenberg-products-block",
            "easy-digital-downloads", "wp-ecommerce",
            "elementor", "elementor-pro", "beaver-builder", "divi-builder", "visual-composer",
            "siteorigin-panels", "wp-bakery", "fusion-builder",
            "yoast", "wordpress-seo", "all-in-one-seo-pack", "rank-math", "seo-by-rank-math",
            "wordfence", "ithemes-security", "sucuri-scanner", "all-in-one-wp-security-and-firewall",
            "better-wp-security", "loginizer", "limit-login-attempts-reloaded",
            "updraftplus", "all-in-one-wp-migration", "duplicator", "backupbuddy",
            "backup-guard", "wp-db-backup",
            "wp-super-cache", "w3-total-cache", "wp-fastest-cache", "autoptimize",
            "wp-optimize", "litespeed-cache",
            "jetpack", "akismet", "classic-editor", "duplicate-post", "really-simple-ssl",
            "google-analytics-for-wordpress", "wp-mail-smtp", "redirection", "broken-link-checker",
            "wp-smushit", "regenerate-thumbnails", "enable-media-replace",
            "memberpress", "paid-memberships-pro", "ultimate-member", "learndash",
            "lifterlms", "tutor", "sensei",
            "revslider", "slider-revolution", "metaslider", "smart-slider-3", "nextgen-gallery",
            "envira-gallery", "photo-gallery",
            "social-warfare", "monarch", "shareaholic", "addtoany", "jetpack-social",
            "wp-file-manager", "download-manager", "simple-file-list",
            "wpml", "polylang", "translatepress", "weglot",
            "advanced-custom-fields", "custom-post-type-ui", "wp-statistics",
            "insert-headers-and-footers", "code-snippets", "post-smtp"
    );

    public static boolean isWordPressTraffic(String responseBody, List<String> headers) {
        if (responseBody != null) {
            for (Pattern pattern : WP_PATTERNS) {
                if (pattern.matcher(responseBody).find()) {
                    return true;
                }
            }
        }
        if (headers != null) {
            for (String header : headers) {
                String lower = header.toLowerCase();
                if (lower.contains("x-pingback") && lower.contains("xmlrpc.php")) {
                    return true;
                }
                if (lower.contains("link") && lower.contains("/wp-json/")) {
                    return true;
                }
                if (lower.contains("wordpress")) {
                    return true;
                }
            }
        }
        return false;
    }

    public static String extractVersion(String content) {
        if (content == null || content.isEmpty()) {
            return null;
        }
        for (Pattern pattern : VERSION_PATTERNS) {
            Matcher matcher = pattern.matcher(content);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return null;
    }

    public static Set<String> extractPlugins(String content) {
        Set<String> plugins = new LinkedHashSet<>();
        if (content == null) return plugins;

        Matcher matcher = PLUGIN_PATTERN.matcher(content);
        while (matcher.find()) {
            String slug = normalizeSlug(matcher.group(1));
            if (isValidSlug(slug)) {
                plugins.add(slug);
            }
        }
        return plugins;
    }

    public static Set<String> extractThemes(String content) {
        Set<String> themes = new LinkedHashSet<>();
        if (content == null) return themes;

        Matcher matcher = THEME_PATTERN.matcher(content);
        while (matcher.find()) {
            String slug = normalizeSlug(matcher.group(1));
            if (isValidSlug(slug)) {
                themes.add(slug);
            }
        }
        return themes;
    }

    public static boolean isHighRiskPlugin(String slug) {
        if (slug == null) return false;
        String normalized = normalizeSlug(slug);
        return HIGH_RISK_PLUGINS.contains(normalized);
    }

    public static String normalizeSlug(String slug) {
        if (slug == null) return "";
        return slug.trim().toLowerCase().replace('_', '-').replace(' ', '-');
    }

    private static boolean isValidSlug(String slug) {
        if (slug == null || slug.length() < 2 || slug.length() > 64) {
            return false;
        }
        // Exclude common false positives or asset names
        return !slug.endsWith(".js") && !slug.endsWith(".css") && !slug.endsWith(".png") && !slug.contains("..");
    }
}
