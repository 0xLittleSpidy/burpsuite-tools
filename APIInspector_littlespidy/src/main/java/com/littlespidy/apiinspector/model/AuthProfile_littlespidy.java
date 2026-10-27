// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

/**
 * Configuration profile for authenticating API requests.
 */
public class AuthProfile_littlespidy {

    private String id;
    private String name;
    private AuthType_littlespidy authType;

    // Bearer Token
    private String bearerToken;

    // API Key
    private String apiKeyName;
    private String apiKeyValue;
    private ApiKeyLocation_littlespidy apiKeyLocation;

    // Basic Auth
    private String basicUsername;
    private String basicPassword;

    // Cookie
    private String cookieName;
    private String cookieValue;

    // Custom Header
    private String customHeaderName;
    private String customHeaderValue;

    // Unauthenticated profile flag and raw session headers / strip headers
    private boolean unauthenticated;
    private String rawHeaders;

    // Unauthenticated comparison setting
    private boolean testUnauthenticatedComparison;

    public AuthProfile_littlespidy() {
        this.id = UUID.randomUUID().toString();
        this.name = "Default Profile";
        this.authType = AuthType_littlespidy.BEARER_TOKEN;
        this.bearerToken = "";
        this.apiKeyName = "X-API-Key";
        this.apiKeyValue = "";
        this.apiKeyLocation = ApiKeyLocation_littlespidy.HEADER;
        this.basicUsername = "";
        this.basicPassword = "";
        this.cookieName = "sessionid";
        this.cookieValue = "";
        this.customHeaderName = "Authorization";
        this.customHeaderValue = "";
        this.unauthenticated = false;
        this.rawHeaders = "";
        this.testUnauthenticatedComparison = true;
    }

    public AuthProfile_littlespidy(String name, AuthType_littlespidy authType) {
        this();
        this.name = name != null ? name : "Default Profile";
        this.authType = authType != null ? authType : AuthType_littlespidy.BEARER_TOKEN;
    }

    public AuthProfile_littlespidy copy() {
        AuthProfile_littlespidy clone = new AuthProfile_littlespidy();
        clone.id = UUID.randomUUID().toString();
        clone.name = this.name + " (Copy)";
        clone.authType = this.authType;
        clone.bearerToken = this.bearerToken;
        clone.apiKeyName = this.apiKeyName;
        clone.apiKeyValue = this.apiKeyValue;
        clone.apiKeyLocation = this.apiKeyLocation;
        clone.basicUsername = this.basicUsername;
        clone.basicPassword = this.basicPassword;
        clone.cookieName = this.cookieName;
        clone.cookieValue = this.cookieValue;
        clone.customHeaderName = this.customHeaderName;
        clone.customHeaderValue = this.customHeaderValue;
        clone.unauthenticated = this.unauthenticated;
        clone.rawHeaders = this.rawHeaders;
        clone.testUnauthenticatedComparison = this.testUnauthenticatedComparison;
        return clone;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name != null ? name : "";
    }

    public AuthType_littlespidy getAuthType() {
        return authType != null ? authType : AuthType_littlespidy.BEARER_TOKEN;
    }

    public void setAuthType(AuthType_littlespidy authType) {
        this.authType = authType != null ? authType : AuthType_littlespidy.BEARER_TOKEN;
    }

    public String getBearerToken() {
        return bearerToken != null ? bearerToken : "";
    }

    public void setBearerToken(String bearerToken) {
        this.bearerToken = bearerToken != null ? bearerToken : "";
    }

    public String getApiKeyName() {
        return apiKeyName != null ? apiKeyName : "X-API-Key";
    }

    public void setApiKeyName(String apiKeyName) {
        this.apiKeyName = apiKeyName != null ? apiKeyName : "";
    }

    public String getApiKeyValue() {
        return apiKeyValue != null ? apiKeyValue : "";
    }

    public void setApiKeyValue(String apiKeyValue) {
        this.apiKeyValue = apiKeyValue != null ? apiKeyValue : "";
    }

    public ApiKeyLocation_littlespidy getApiKeyLocation() {
        return apiKeyLocation != null ? apiKeyLocation : ApiKeyLocation_littlespidy.HEADER;
    }

    public void setApiKeyLocation(ApiKeyLocation_littlespidy apiKeyLocation) {
        this.apiKeyLocation = apiKeyLocation != null ? apiKeyLocation : ApiKeyLocation_littlespidy.HEADER;
    }

    public String getBasicUsername() {
        return basicUsername != null ? basicUsername : "";
    }

    public void setBasicUsername(String basicUsername) {
        this.basicUsername = basicUsername != null ? basicUsername : "";
    }

    public String getBasicPassword() {
        return basicPassword != null ? basicPassword : "";
    }

    public void setBasicPassword(String basicPassword) {
        this.basicPassword = basicPassword != null ? basicPassword : "";
    }

    public String getCookieName() {
        return cookieName != null ? cookieName : "sessionid";
    }

    public void setCookieName(String cookieName) {
        this.cookieName = cookieName != null ? cookieName : "";
    }

    public String getCookieValue() {
        return cookieValue != null ? cookieValue : "";
    }

    public void setCookieValue(String cookieValue) {
        this.cookieValue = cookieValue != null ? cookieValue : "";
    }

    public String getCustomHeaderName() {
        return customHeaderName != null ? customHeaderName : "";
    }

    public void setCustomHeaderName(String customHeaderName) {
        this.customHeaderName = customHeaderName != null ? customHeaderName : "";
    }

    public String getCustomHeaderValue() {
        return customHeaderValue != null ? customHeaderValue : "";
    }

    public void setCustomHeaderValue(String customHeaderValue) {
        this.customHeaderValue = customHeaderValue != null ? customHeaderValue : "";
    }

    public boolean isUnauthenticated() {
        return unauthenticated;
    }

    public void setUnauthenticated(boolean unauthenticated) {
        this.unauthenticated = unauthenticated;
    }

    public String getRawHeaders() {
        return rawHeaders != null ? rawHeaders : "";
    }

    public void setRawHeaders(String rawHeaders) {
        this.rawHeaders = rawHeaders != null ? rawHeaders : "";
    }

    public boolean isTestUnauthenticatedComparison() {
        return testUnauthenticatedComparison;
    }

    public void setTestUnauthenticatedComparison(boolean testUnauthenticatedComparison) {
        this.testUnauthenticatedComparison = testUnauthenticatedComparison;
    }

    public String getBasicAuthHeaderValue() {
        String creds = (basicUsername != null ? basicUsername : "") + ":" + (basicPassword != null ? basicPassword : "");
        return "Basic " + Base64.getEncoder().encodeToString(creds.getBytes(StandardCharsets.UTF_8));
    }

    public String getMaskedSummary() {
        if (unauthenticated) {
            if (rawHeaders != null && !rawHeaders.isBlank()) {
                String singleLine = rawHeaders.replaceAll("[\\r\\n]+", ", ").trim();
                return "Unauth (Strip: " + singleLine + ")";
            }
            return "Unauth (Strip Auth Headers)";
        }
        if (rawHeaders != null && !rawHeaders.isBlank()) {
            String[] lines = rawHeaders.split("[\\r\\n]+");
            if (lines.length == 1) {
                return lines[0].trim();
            }
            return lines[0].trim() + " (+" + (lines.length - 1) + " more)";
        }
        switch (getAuthType()) {
            case BEARER_TOKEN:
                return "Bearer " + maskSecret(bearerToken);
            case API_KEY:
                return apiKeyName + " (" + (apiKeyLocation != null ? apiKeyLocation.getDisplayName() : "Header") + "): " + maskSecret(apiKeyValue);
            case BASIC_AUTH:
                return "Basic: " + basicUsername + ":****";
            case COOKIE:
                return "Cookie: " + cookieName + "=" + maskSecret(cookieValue);
            case CUSTOM_HEADER:
                return customHeaderName + ": " + maskSecret(customHeaderValue);
            default:
                return "Configured";
        }
    }

    private String maskSecret(String secret) {
        if (secret == null || secret.isEmpty()) return "[Not Set]";
        if (secret.length() <= 6) return "******";
        return secret.substring(0, 3) + "..." + secret.substring(secret.length() - 2);
    }

    @Override
    public String toString() {
        if (unauthenticated) {
            return name + " (Unauth)";
        }
        return name + " (Auth)";
    }
}
