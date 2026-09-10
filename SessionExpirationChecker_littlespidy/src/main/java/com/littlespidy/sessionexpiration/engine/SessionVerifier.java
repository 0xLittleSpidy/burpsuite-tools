// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.engine;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Heuristic verifier comparing probe responses against baseline responses
 * to determine whether an authenticated session remains active or has expired.
 *
 * @author littlespidy
 */
public class SessionVerifier {

    private static final List<String> EXPIRY_KEYWORDS = Arrays.asList(
            "session expired",
            "session has expired",
            "session timeout",
            "session has timed out",
            "token expired",
            "token has expired",
            "invalid token",
            "invalid session",
            "session is invalid",
            "authentication required",
            "please log in",
            "please sign in",
            "log in again",
            "sign in again",
            "you have been logged out",
            "logged out",
            "unauthorized access"
    );

    private static final List<String> LOGIN_PATH_KEYWORDS = Arrays.asList(
            "login",
            "signin",
            "sign-in",
            "log-in",
            "auth",
            "authenticate",
            "sso",
            "oauth",
            "cas"
    );

    public static class VerificationVerdict {
        private final boolean expired;
        private final String signal;
        private final String details;

        public VerificationVerdict(boolean expired, String signal, String details) {
            this.expired = expired;
            this.signal = signal;
            this.details = details;
        }

        public boolean isExpired() {
            return expired;
        }

        public String getSignal() {
            return signal;
        }

        public String getDetails() {
            return details;
        }
    }

    /**
     * Compares probe response against baseline response to detect session expiration.
     */
    public static VerificationVerdict verify(HttpResponse baseline, HttpResponse probe) {
        if (probe == null) {
            return new VerificationVerdict(false, "No Response", "No response received from target host.");
        }

        int probeStatus = probe.statusCode();
        int baselineStatus = (baseline != null) ? baseline.statusCode() : 200;

        // ── 1. HTTP 401 Unauthorized ─────────────────────────────────────────
        if (probeStatus == 401) {
            return new VerificationVerdict(true, "Expired (401 Unauthorized)",
                    "Server returned HTTP 401 Unauthorized, indicating credentials/session are rejected.");
        }

        // ── 2. HTTP 403 Forbidden (when baseline was not 403) ────────────────
        if (probeStatus == 403 && baselineStatus != 403) {
            return new VerificationVerdict(true, "Expired (403 Forbidden)",
                    "Status changed from baseline " + baselineStatus + " to 403 Forbidden.");
        }

        // ── 3. Redirect to Login / Auth Endpoint ──────────────────────────────
        if (probeStatus >= 300 && probeStatus < 400) {
            String location = probe.headerValue("Location");
            if (location != null) {
                String locLower = location.toLowerCase(Locale.ROOT);
                for (String kw : LOGIN_PATH_KEYWORDS) {
                    if (locLower.contains(kw)) {
                        return new VerificationVerdict(true, "Expired (Redirect to " + location + ")",
                                "Probe was redirected (" + probeStatus + ") to login/auth endpoint: " + location);
                    }
                }
            }
            if (baselineStatus == 200) {
                return new VerificationVerdict(true, "Expired (200 -> " + probeStatus + " Redirect)",
                        "Baseline returned 200 OK but probe was redirected (" + probeStatus + ").");
            }
        }

        // ── 4. Set-Cookie Invalidation (Max-Age=0 / expired 1970) ───────────
        for (HttpHeader header : probe.headers()) {
            if (header.name().equalsIgnoreCase("Set-Cookie")) {
                String val = header.value().toLowerCase(Locale.ROOT);
                if (val.contains("max-age=0") || val.contains("1970") || val.contains("expires=thu, 01 jan 1970")) {
                    return new VerificationVerdict(true, "Expired (Cookie Invalidation Header)",
                            "Response contains Set-Cookie clearing the session cookie.");
                }
            }
        }

        // ── 5. Response Body Keyword Analysis ────────────────────────────────
        String probeBody = probe.bodyToString();
        String baselineBody = (baseline != null) ? baseline.bodyToString() : "";

        if (probeBody != null && !probeBody.isEmpty()) {
            String probeLower = probeBody.toLowerCase(Locale.ROOT);
            String baselineLower = baselineBody.toLowerCase(Locale.ROOT);

            for (String kw : EXPIRY_KEYWORDS) {
                if (probeLower.contains(kw) && !baselineLower.contains(kw)) {
                    return new VerificationVerdict(true, "Expired (Keyword: \"" + kw + "\")",
                            "Probe response contains session expiry keyword not present in baseline: \"" + kw + "\"");
                }
            }
        }

        // ── 6. Significant Status Code Shift ─────────────────────────────────
        if (baselineStatus == 200 && (probeStatus == 400 || probeStatus == 404 || probeStatus == 500)) {
            return new VerificationVerdict(true, "Expired? (Status 200 -> " + probeStatus + ")",
                    "Status changed unexpectedly from 200 OK to " + probeStatus + ".");
        }

        // ── 7. Session appears Active ─────────────────────────────────────────
        long probeLen = probe.toByteArray().length();
        long baseLen = (baseline != null) ? baseline.toByteArray().length() : probeLen;
        long delta = probeLen - baseLen;
        String deltaStr = (delta >= 0 ? "+" : "") + delta;

        return new VerificationVerdict(false, "Active (" + probeStatus + " OK)",
                "Session active. Status: " + probeStatus + ", Length: " + probeLen + " bytes (" + deltaStr + " vs baseline).");
    }
}
