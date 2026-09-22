// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.config;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;

/**
 * Thread-safe configuration holding settings for Active Scan Session Keeper.
 * Contains cookie substitution rules, scope filters, and customizable expiration criteria.
 *
 * @author littlespidy
 */
public class SessionKeeperConfig {

    private volatile boolean enabled = true;
    private volatile boolean monitorScanner = true;
    private volatile boolean monitorRepeater = false;
    private volatile boolean monitorIntruder = false;
    private volatile boolean monitorExtensions = false;
    private volatile boolean inScopeOnly = false;
    private volatile String targetHostFilter = "*";

    // ── Cookie Configuration ──
    private volatile CookieMode cookieMode = CookieMode.FULL_COOKIE_HEADER;
    private volatile String targetCookieNames = "JSESSIONID, PHPSESSID, token, session, connect.sid, sessionid";
    private volatile String cookieValue = "";
    private volatile String fullCookieHeader = "";
    private volatile boolean updateAuthBearer = false;
    private volatile String authBearerToken = "";

    // ── Scanner Behavior ──
    private volatile boolean autoRetryOnExpire = true;
    private volatile boolean soundAlertOnExpire = true;

    // ── Expiration Criteria ──
    private volatile boolean checkStatusCodes = true;
    private volatile String statusCodes = "401, 403, 419, 440, 498";

    private volatile boolean checkRedirects = true;
    private volatile String redirectLocationRegex = ".*(login|signin|sign-in|log-in|auth|authenticate|sso|oauth|cas).*";

    private volatile boolean checkBodyKeywords = true;
    private volatile String bodyKeywords = String.join("\n", Arrays.asList(
            "session expired",
            "session has expired",
            "session timeout",
            "session has timed out",
            "your session has ended",
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
            "unauthorized access",
            "access denied",
            "\"invalid_token\"",
            "\"expired_token\""
    ));

    private volatile boolean checkSetCookieInvalidation = true;
    private volatile boolean checkBodyLengthDrop = false;
    private volatile int bodyLengthDropThreshold = 150;

    private volatile boolean checkCustomRegex = false;
    private volatile String customRegexPattern = "";

    private final List<Runnable> changeListeners = new CopyOnWriteArrayList<>();

    public void addChangeListener(Runnable listener) {
        changeListeners.add(listener);
    }

    public void removeChangeListener(Runnable listener) {
        changeListeners.remove(listener);
    }

    public void notifyChanged() {
        for (Runnable r : changeListeners) {
            try {
                r.run();
            } catch (Exception ignored) {}
        }
    }

    // ── Helpers ──

    public Set<Integer> parseStatusCodes() {
        Set<Integer> codes = new HashSet<>();
        if (statusCodes == null || statusCodes.trim().isEmpty()) {
            return codes;
        }
        String[] parts = statusCodes.split("[,\\s]+");
        for (String p : parts) {
            try {
                codes.add(Integer.parseInt(p.trim()));
            } catch (NumberFormatException ignored) {}
        }
        return codes;
    }

    public List<String> parseCookieNames() {
        List<String> names = new ArrayList<>();
        if (targetCookieNames == null || targetCookieNames.trim().isEmpty()) {
            return names;
        }
        String[] parts = targetCookieNames.split("[,\\s]+");
        for (String p : parts) {
            String trimmed = p.trim();
            if (!trimmed.isEmpty()) {
                names.add(trimmed);
            }
        }
        return names;
    }

    public List<String> parseBodyKeywords() {
        List<String> list = new ArrayList<>();
        if (bodyKeywords == null || bodyKeywords.trim().isEmpty()) {
            return list;
        }
        String[] lines = bodyKeywords.split("\r?\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                list.add(trimmed);
            }
        }
        return list;
    }

    public boolean matchesHost(String host) {
        if (targetHostFilter == null || targetHostFilter.trim().isEmpty() || targetHostFilter.equals("*")) {
            return true;
        }
        if (host == null) {
            return false;
        }
        String target = targetHostFilter.trim().toLowerCase(Locale.ROOT);
        String h = host.toLowerCase(Locale.ROOT);
        if (target.startsWith("*.")) {
            String suffix = target.substring(1);
            return h.endsWith(suffix) || h.equals(target.substring(2));
        }
        return h.equalsIgnoreCase(target) || h.endsWith("." + target);
    }

    // ── Getters and Setters ──

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; notifyChanged(); }

    public boolean isMonitorScanner() { return monitorScanner; }
    public void setMonitorScanner(boolean monitorScanner) { this.monitorScanner = monitorScanner; notifyChanged(); }

    public boolean isMonitorRepeater() { return monitorRepeater; }
    public void setMonitorRepeater(boolean monitorRepeater) { this.monitorRepeater = monitorRepeater; notifyChanged(); }

    public boolean isMonitorIntruder() { return monitorIntruder; }
    public void setMonitorIntruder(boolean monitorIntruder) { this.monitorIntruder = monitorIntruder; notifyChanged(); }

    public boolean isMonitorExtensions() { return monitorExtensions; }
    public void setMonitorExtensions(boolean monitorExtensions) { this.monitorExtensions = monitorExtensions; notifyChanged(); }

    public boolean isInScopeOnly() { return inScopeOnly; }
    public void setInScopeOnly(boolean inScopeOnly) { this.inScopeOnly = inScopeOnly; notifyChanged(); }

    public String getTargetHostFilter() { return targetHostFilter; }
    public void setTargetHostFilter(String targetHostFilter) { this.targetHostFilter = targetHostFilter; notifyChanged(); }

    public CookieMode getCookieMode() { return cookieMode; }
    public void setCookieMode(CookieMode cookieMode) { this.cookieMode = cookieMode; notifyChanged(); }

    public String getTargetCookieNames() { return targetCookieNames; }
    public void setTargetCookieNames(String targetCookieNames) { this.targetCookieNames = targetCookieNames; notifyChanged(); }

    public String getCookieValue() { return cookieValue; }
    public void setCookieValue(String cookieValue) { this.cookieValue = cookieValue; notifyChanged(); }

    public String getFullCookieHeader() { return fullCookieHeader; }
    public void setFullCookieHeader(String fullCookieHeader) { this.fullCookieHeader = fullCookieHeader; notifyChanged(); }

    public boolean isUpdateAuthBearer() { return updateAuthBearer; }
    public void setUpdateAuthBearer(boolean updateAuthBearer) { this.updateAuthBearer = updateAuthBearer; notifyChanged(); }

    public String getAuthBearerToken() { return authBearerToken; }
    public void setAuthBearerToken(String authBearerToken) { this.authBearerToken = authBearerToken; notifyChanged(); }

    public boolean isAutoRetryOnExpire() { return autoRetryOnExpire; }
    public void setAutoRetryOnExpire(boolean autoRetryOnExpire) { this.autoRetryOnExpire = autoRetryOnExpire; notifyChanged(); }

    public boolean isSoundAlertOnExpire() { return soundAlertOnExpire; }
    public void setSoundAlertOnExpire(boolean soundAlertOnExpire) { this.soundAlertOnExpire = soundAlertOnExpire; notifyChanged(); }

    public boolean isCheckStatusCodes() { return checkStatusCodes; }
    public void setCheckStatusCodes(boolean checkStatusCodes) { this.checkStatusCodes = checkStatusCodes; notifyChanged(); }

    public String getStatusCodes() { return statusCodes; }
    public void setStatusCodes(String statusCodes) { this.statusCodes = statusCodes; notifyChanged(); }

    public boolean isCheckRedirects() { return checkRedirects; }
    public void setCheckRedirects(boolean checkRedirects) { this.checkRedirects = checkRedirects; notifyChanged(); }

    public String getRedirectLocationRegex() { return redirectLocationRegex; }
    public void setRedirectLocationRegex(String redirectLocationRegex) { this.redirectLocationRegex = redirectLocationRegex; notifyChanged(); }

    public boolean isCheckBodyKeywords() { return checkBodyKeywords; }
    public void setCheckBodyKeywords(boolean checkBodyKeywords) { this.checkBodyKeywords = checkBodyKeywords; notifyChanged(); }

    public String getBodyKeywords() { return bodyKeywords; }
    public void setBodyKeywords(String bodyKeywords) { this.bodyKeywords = bodyKeywords; notifyChanged(); }

    public boolean isCheckSetCookieInvalidation() { return checkSetCookieInvalidation; }
    public void setCheckSetCookieInvalidation(boolean checkSetCookieInvalidation) { this.checkSetCookieInvalidation = checkSetCookieInvalidation; notifyChanged(); }

    public boolean isCheckBodyLengthDrop() { return checkBodyLengthDrop; }
    public void setCheckBodyLengthDrop(boolean checkBodyLengthDrop) { this.checkBodyLengthDrop = checkBodyLengthDrop; notifyChanged(); }

    public int getBodyLengthDropThreshold() { return bodyLengthDropThreshold; }
    public void setBodyLengthDropThreshold(int bodyLengthDropThreshold) { this.bodyLengthDropThreshold = bodyLengthDropThreshold; notifyChanged(); }

    public boolean isCheckCustomRegex() { return checkCustomRegex; }
    public void setCheckCustomRegex(boolean checkCustomRegex) { this.checkCustomRegex = checkCustomRegex; notifyChanged(); }

    public String getCustomRegexPattern() { return customRegexPattern; }
    public void setCustomRegexPattern(String customRegexPattern) { this.customRegexPattern = customRegexPattern; notifyChanged(); }
}
