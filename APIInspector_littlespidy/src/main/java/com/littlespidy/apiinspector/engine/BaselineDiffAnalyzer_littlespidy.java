// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Locale;

/**
 * Analyzes probe responses against baseline responses to categorize findings.
 */
public class BaselineDiffAnalyzer_littlespidy {

    public static String analyze(HttpResponse baselineResponse, HttpResponse probeResponse) {
        if (probeResponse == null) {
            return "CONNECTION ERROR";
        }

        int probeStatus = probeResponse.statusCode();
        int probeLength = probeResponse.body() != null ? probeResponse.body().length() : 0;
        String probeBodyText = probeResponse.bodyToString();
        String probeBodyLower = probeBodyText != null ? probeBodyText.toLowerCase(Locale.ROOT) : "";

        if (baselineResponse == null) {
            if (probeStatus >= 200 && probeStatus < 300) {
                return "ACTIVE (" + probeStatus + " OK)";
            }
            return "STATUS " + probeStatus;
        }

        int baseStatus = baselineResponse.statusCode();
        int baseLength = baselineResponse.body() != null ? baselineResponse.body().length() : 0;
        String baseBodyText = baselineResponse.bodyToString();

        // Check for version deprecation or unrecognized version error messages
        boolean hasVersionKeywords = probeBodyLower.contains("version")
                && (probeBodyLower.contains("deprecat") || probeBodyLower.contains("unsupported")
                || probeBodyLower.contains("invalid") || probeBodyLower.contains("not supported")
                || probeBodyLower.contains("unknown"));

        if (hasVersionKeywords) {
            return "VERSION ERROR / DEPRECATED (" + probeStatus + ")";
        }

        // Status shift from 404 to 200
        if (baseStatus == 404 && probeStatus >= 200 && probeStatus < 300) {
            return "STATUS SHIFT: 404 -> " + probeStatus + " (NEW ENDPOINT)";
        }

        // Status shift from 401/403 to 200 (Potential Auth Bypass via older/newer API)
        if ((baseStatus == 401 || baseStatus == 403) && probeStatus >= 200 && probeStatus < 300) {
            return "AUTH BYPASS SHIFT: " + baseStatus + " -> " + probeStatus + " (ALERT)";
        }

        // Both are 200 OK
        if (probeStatus >= 200 && probeStatus < 300 && baseStatus >= 200 && baseStatus < 300) {
            int delta = probeLength - baseLength;
            if (delta == 0 && probeBodyText != null && probeBodyText.equals(baseBodyText)) {
                return "SAME AS BASELINE";
            }
            String deltaStr = (delta >= 0 ? "+" : "") + delta + " B";
            return "ACTIVE ALTERNATIVE (DELTA: " + deltaStr + ")";
        }

        if (probeStatus == baseStatus && probeLength == baseLength) {
            return "SAME AS BASELINE (" + probeStatus + ")";
        }

        if (probeStatus == 404) {
            return "NOT FOUND (404)";
        }

        if (probeStatus == 400 || probeStatus == 422) {
            return "CLIENT ERROR (" + probeStatus + ")";
        }

        if (probeStatus >= 500) {
            return "SERVER ERROR (" + probeStatus + ")";
        }

        return "STATUS " + probeStatus + " (DIFF: " + (probeLength - baseLength) + " B)";
    }
}
