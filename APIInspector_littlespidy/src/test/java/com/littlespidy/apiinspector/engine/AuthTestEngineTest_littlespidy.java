// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.apiinspector.model.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class AuthTestEngineTest_littlespidy {

    @Test
    @DisplayName("Build request with Bearer token authentication")
    public void testBearerTokenRequestConstruction() {
        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("GET", "/api/v1/profile", "User Profile");

        AuthProfile_littlespidy profile = new AuthProfile_littlespidy("Admin Bearer", AuthType_littlespidy.BEARER_TOKEN);
        profile.setBearerToken("secret_jwt_token_12345");

        HttpRequest req = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, profile, true);
        assertNotNull(req);
        assertEquals("https://api.example.com/api/v1/profile", req.url());
        assertTrue(req.hasHeader("Authorization"));
        assertEquals("Bearer secret_jwt_token_12345", req.headerValue("Authorization"));

        // Unauthenticated version should not contain Authorization header
        HttpRequest unauthReq = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, profile, false);
        assertFalse(unauthReq.hasHeader("Authorization"));
    }

    @Test
    @DisplayName("Build request with API Key in Header and Query Param")
    public void testApiKeyRequestConstruction() {
        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("GET", "/api/data", "Data API");

        // Header API Key
        AuthProfile_littlespidy headerProf = new AuthProfile_littlespidy("Header Key", AuthType_littlespidy.API_KEY);
        headerProf.setApiKeyName("X-Service-Key");
        headerProf.setApiKeyValue("key_abc_987");
        headerProf.setApiKeyLocation(ApiKeyLocation_littlespidy.HEADER);

        HttpRequest headerReq = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, headerProf, true);
        assertTrue(headerReq.hasHeader("X-Service-Key"));
        assertEquals("key_abc_987", headerReq.headerValue("X-Service-Key"));

        // Query Param API Key
        AuthProfile_littlespidy queryProf = new AuthProfile_littlespidy("Query Key", AuthType_littlespidy.API_KEY);
        queryProf.setApiKeyName("apiKey");
        queryProf.setApiKeyValue("query_secret_val");
        queryProf.setApiKeyLocation(ApiKeyLocation_littlespidy.QUERY_PARAM);

        HttpRequest queryReq = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, queryProf, true);
        assertTrue(queryReq.url().contains("apiKey=query_secret_val"));

        // Unauthenticated should not have query key
        HttpRequest queryUnauth = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, queryProf, false);
        assertFalse(queryUnauth.url().contains("apiKey=query_secret_val"));
    }

    @Test
    @DisplayName("Build request with Basic Authentication")
    public void testBasicAuthRequestConstruction() {
        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("GET", "/admin/dashboard", "Admin Dashboard");

        AuthProfile_littlespidy profile = new AuthProfile_littlespidy("Basic Admin", AuthType_littlespidy.BASIC_AUTH);
        profile.setBasicUsername("admin");
        profile.setBasicPassword("P@ssw0rd123");

        HttpRequest req = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, profile, true);
        assertTrue(req.hasHeader("Authorization"));
        String authHeader = req.headerValue("Authorization");
        assertTrue(authHeader.startsWith("Basic "));

        HttpRequest unauthReq = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, profile, false);
        assertFalse(unauthReq.hasHeader("Authorization"));
    }

    @Test
    @DisplayName("Build request with Cookie and Custom Header")
    public void testCookieAndCustomHeaderConstruction() {
        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("GET", "/session/info", "Session Info");

        AuthProfile_littlespidy cookieProf = new AuthProfile_littlespidy("Cookie Auth", AuthType_littlespidy.COOKIE);
        cookieProf.setCookieName("authToken");
        cookieProf.setCookieValue("sess_xyz_777");

        HttpRequest cookieReq = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, cookieProf, true);
        assertTrue(cookieReq.hasHeader("Cookie"));
        assertEquals("authToken=sess_xyz_777", cookieReq.headerValue("Cookie"));

        AuthProfile_littlespidy customProf = new AuthProfile_littlespidy("Custom Token", AuthType_littlespidy.CUSTOM_HEADER);
        customProf.setCustomHeaderName("X-Custom-Client-Token");
        customProf.setCustomHeaderValue("client_tok_999");

        HttpRequest customReq = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, customProf, true);
        assertTrue(customReq.hasHeader("X-Custom-Client-Token"));
        assertEquals("client_tok_999", customReq.headerValue("X-Custom-Client-Token"));
    }

    @Test
    @DisplayName("Replace path variables and inject request body")
    public void testPathVariablesAndRequestBody() {
        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("POST", "/api/v1/organizations/{orgId}/users", "Create User");
        ep.setPathParams(Map.of("orgId", "42"));
        ep.setRequestBodySample("{\"name\":\"Alice\",\"role\":\"Admin\"}");
        ep.setContentType("application/json");

        HttpRequest req = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, null, false);
        assertEquals("https://api.example.com/api/v1/organizations/42/users", req.url());
        assertEquals("POST", req.method());
        assertEquals("{\"name\":\"Alice\",\"role\":\"Admin\"}", req.bodyToString());
        assertEquals("application/json", req.headerValue("Content-Type"));
    }
}
