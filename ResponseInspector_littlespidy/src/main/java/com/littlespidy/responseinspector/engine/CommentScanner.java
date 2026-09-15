// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InspectorDataStore;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans HTTP responses for developer comments (single-line //, multi-line /* *\/, HTML <!-- -->).
 *
 * <p>Comment types are stored in {@code patternName} and comment categories
 * (TODO/FIXME, Credentials/Auth, Debug/Config, General) are stored in {@code matchLocation}
 * so both can be filtered independently via MultiSelectFilterButton.
 *
 * <p>Patterns ported from JSSourceMapExplorer's SecretAndEndpointMiner.
 */
public class CommentScanner {

    /** Matches single-line (//), multi-line (/* *\/) and HTML (<!-- -->) comments. */
    private static final Pattern COMMENT_SCAN_PATTERN = Pattern.compile(
        "(/\\*[\\s\\S]*?\\*/)|(<![\\-]{2}[\\s\\S]*?[\\-]{2}>)|(?<!:)\\/\\/(?![/\\*])[^\\r\\n]*"
    );

    private static final Pattern COMMENT_TODO_PATTERN =
        Pattern.compile("(?i)\\b(todo|fixme|hack|xxx|bug|temp|workaround|revisit|cleanup)\\b");
    private static final Pattern COMMENT_CRED_PATTERN =
        Pattern.compile("(?i)\\b(password|passwd|secret|token|apikey|api_key|auth|bearer|credential|admin|root|private_key)\\b");
    private static final Pattern COMMENT_DEBUG_PATTERN =
        Pattern.compile("(?i)\\b(debug|test|dev|staging|localhost|internal|mock|deprecated|danger|security)\\b");

    /** Max comment entries per response to avoid flooding the table. */
    private static final int MAX_COMMENTS_PER_RESPONSE = 500;

    public List<FindingEntry> scan(HttpRequestResponse requestResponse, InspectorDataStore dataStore) {
        List<FindingEntry> findings = new ArrayList<>();
        if (requestResponse == null || requestResponse.response() == null) {
            return findings;
        }

        HttpResponse response = requestResponse.response();
        String body = ScannerUtils.convertByteArrayToString(response.body());
        if (body.isEmpty()) {
            return findings;
        }

        Set<String> seen = new HashSet<>();
        Matcher matcher = COMMENT_SCAN_PATTERN.matcher(body);
        int count = 0;

        while (matcher.find() && count < MAX_COMMENTS_PER_RESPONSE) {
            String raw = matcher.group();
            if (raw == null || raw.contains("sourceMappingURL=")) continue;

            // Clean comment delimiters
            String clean = raw
                .replaceAll("^(/\\*+|<!--|//+)", "")
                .replaceAll("(\\*/|-->)$", "")
                .replaceAll("[\\r\\n]+", " ")
                .trim();

            if (clean.isEmpty() || clean.length() < 3 || clean.matches("^[=\\-_*#~\\s]+$")) {
                continue;
            }

            // Deduplicate by text
            if (!seen.add(clean)) continue;

            String commentType;
            if (raw.startsWith("//")) {
                commentType = "Single-Line (//)";
            } else if (raw.startsWith("/*")) {
                commentType = "Multi-Line (/* */)";
            } else {
                commentType = "HTML (<!-- -->)";
            }

            String category;
            if (COMMENT_TODO_PATTERN.matcher(clean).find()) {
                category = "TODO / FIXME";
            } else if (COMMENT_CRED_PATTERN.matcher(clean).find()) {
                category = "Credentials / Auth";
            } else if (COMMENT_DEBUG_PATTERN.matcher(clean).find()) {
                category = "Debug / Config";
            } else {
                category = "General";
            }

            String excerpt = clean.length() > 200 ? clean.substring(0, 200) + "..." : clean;
            int start = matcher.start();
            int end   = matcher.end();

            // patternName = comment type; matchLocation = semantic category
            findings.add(FindingEntry.create(
                dataStore.nextId(),
                FindingCategory.COMMENT,
                commentType,   // ← used as "Finding Type" column & type filter
                excerpt,       // ← used as "Match Excerpt" column
                category,      // ← used as "Location" column & category filter
                requestResponse,
                start,
                end
            ));
            count++;
        }

        return findings;
    }

    /** All distinct comment type values for the MultiSelectFilterButton. */
    public static List<String> getCommentTypes() {
        return List.of("All Types", "Single-Line (//)", "Multi-Line (/* */)", "HTML (<!-- -->)");
    }

    /** All distinct comment category values for the MultiSelectFilterButton. */
    public static List<String> getCommentCategories() {
        return List.of("All Categories", "TODO / FIXME", "Credentials / Auth", "Debug / Config", "General");
    }
}
