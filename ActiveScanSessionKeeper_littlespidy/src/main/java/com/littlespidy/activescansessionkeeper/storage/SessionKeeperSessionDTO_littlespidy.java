// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.storage;

import java.util.ArrayList;
import java.util.List;

/**
 * Data transfer objects for persistent storage of Active Scan Session Keeper state.
 * Plain ASCII text only.
 */
public class SessionKeeperSessionDTO_littlespidy {

    public static class SessionRootDTO {
        public String formatVersion = "1.0";
        public String savedAt;

        // Configuration
        public boolean enabled = true;
        public boolean monitorScanner = true;
        public boolean monitorRepeater = false;
        public boolean monitorIntruder = false;
        public boolean monitorExtensions = false;
        public boolean inScopeOnly = false;
        public String targetHostFilter = "*";

        // Cookie configuration
        public String cookieMode = "FULL_COOKIE_HEADER";
        public String targetCookieNames = "JSESSIONID, PHPSESSID, token, session, connect.sid, sessionid";
        public String cookieValue = "";
        public String fullCookieHeader = "";
        public boolean updateAuthBearer = false;
        public String authBearerToken = "";

        // Scanner behavior
        public boolean autoRetryOnExpire = true;
        public boolean soundAlertOnExpire = true;

        // Expiration criteria
        public boolean checkStatusCodes = true;
        public String statusCodes = "401, 403, 419, 440, 498";
        public boolean checkRedirects = true;
        public String redirectLocationRegex = ".*(login|signin|sign-in|log-in|auth|authenticate|sso|oauth|cas).*";
        public boolean checkBodyKeywords = true;
        public String bodyKeywords = "";
        public boolean checkSetCookieInvalidation = true;
        public boolean checkBodyLengthDrop = false;
        public int bodyLengthDropThreshold = 150;
        public boolean checkCustomRegex = false;
        public String customRegexPattern = "";

        // Log entries
        public List<ScanActivityEntryDTO> logEntries = new ArrayList<>();
    }

    public static class ScanActivityEntryDTO {
        public long id;
        public String timestamp;
        public String tool;
        public String method;
        public String host;
        public String url;
        public int statusCode;
        public String eventType;
        public String details;

        public boolean hasRequestResponse;
        public String requestBase64;
        public String responseBase64;
        public String reqHost;
        public int reqPort;
        public boolean reqSecure;
    }
}
