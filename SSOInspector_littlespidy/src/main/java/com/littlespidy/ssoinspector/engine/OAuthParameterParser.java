// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.engine;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import com.littlespidy.ssoinspector.model.OAuthParam;
import org.json.JSONObject;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class OAuthParameterParser {

    private static final Map<String, String> IANA_PARAM_DESCRIPTIONS = new HashMap<>();

    static {
        IANA_PARAM_DESCRIPTIONS.put("client_id", "Client identifier issued to the client by authorization server (RFC 6749 2.2)");
        IANA_PARAM_DESCRIPTIONS.put("client_secret", "Confidential secret known only to client and auth server (RFC 6749 2.3.1)");
        IANA_PARAM_DESCRIPTIONS.put("response_type", "OAuth flow response mode: code, token, id_token, or combinations (RFC 6749 3.1.1)");
        IANA_PARAM_DESCRIPTIONS.put("redirect_uri", "Redirection URI where server sends authorization response (RFC 6749 3.1.2)");
        IANA_PARAM_DESCRIPTIONS.put("scope", "Requested access privileges/permissions list (RFC 6749 3.3)");
        IANA_PARAM_DESCRIPTIONS.put("state", "Opaque CSRF prevention token maintained between request and callback (RFC 6749 10.12)");
        IANA_PARAM_DESCRIPTIONS.put("code", "Single-use authorization code exchanged for access token (RFC 6749 4.1.2)");
        IANA_PARAM_DESCRIPTIONS.put("grant_type", "OAuth grant type (authorization_code, client_credentials, password, refresh_token)");
        IANA_PARAM_DESCRIPTIONS.put("access_token", "Bearer token granting access to protected resource (RFC 6750)");
        IANA_PARAM_DESCRIPTIONS.put("refresh_token", "Credential used to obtain new access tokens (RFC 6749 1.5)");
        IANA_PARAM_DESCRIPTIONS.put("id_token", "OpenID Connect signed identity assertion in JWT format (OIDC Core 1.0)");
        IANA_PARAM_DESCRIPTIONS.put("token_type", "Token type, typically 'Bearer' (RFC 6749 7.1)");
        IANA_PARAM_DESCRIPTIONS.put("expires_in", "Lifetime in seconds for access token expiration (RFC 6749 5.1)");
        IANA_PARAM_DESCRIPTIONS.put("nonce", "String value used to associate client session with ID Token against replay (OIDC 3.1.2.1)");
        IANA_PARAM_DESCRIPTIONS.put("prompt", "Space-delimited list specifying re-authentication or consent requirements (none, login, consent, select_account)");
        IANA_PARAM_DESCRIPTIONS.put("max_age", "Allowable elapsed time in seconds since last user authentication (OIDC 3.1.2.1)");
        IANA_PARAM_DESCRIPTIONS.put("code_challenge", "PKCE challenge derived from code_verifier (RFC 7636 4.2)");
        IANA_PARAM_DESCRIPTIONS.put("code_challenge_method", "PKCE transform method: S256 (recommended) or plain (RFC 7636 4.3)");
        IANA_PARAM_DESCRIPTIONS.put("code_verifier", "PKCE high-entropy cryptographic random string (RFC 7636 4.1)");
        IANA_PARAM_DESCRIPTIONS.put("request_uri", "URI pointing to request object containing authorization parameters (RFC 9101)");
        IANA_PARAM_DESCRIPTIONS.put("request", "JWT containing authorization request parameters (RFC 9101)");
        IANA_PARAM_DESCRIPTIONS.put("acr_values", "Authentication Context Class Reference values requested (OIDC 3.1.2.1 / RFC 8176)");
        IANA_PARAM_DESCRIPTIONS.put("response_mode", "Mechanism used to return authorization response (query, fragment, form_post)");
        IANA_PARAM_DESCRIPTIONS.put("resource", "Target protected resource identifier (RFC 8707)");
        IANA_PARAM_DESCRIPTIONS.put("audience", "Audience parameter identifying intended recipient");
        IANA_PARAM_DESCRIPTIONS.put("assertion", "Assertion value used in assertion-based authorization (RFC 7521)");
        IANA_PARAM_DESCRIPTIONS.put("client_assertion", "Client assertion for client authentication (RFC 7523)");
        IANA_PARAM_DESCRIPTIONS.put("client_assertion_type", "Assertion type indicator (e.g. urn:ietf:params:oauth:client-assertion-type:jwt-bearer)");
    }

    private static final Set<String> SENSITIVE_PARAM_NAMES = new HashSet<>(Arrays.asList(
            "client_secret", "code", "access_token", "refresh_token", "id_token",
            "password", "code_verifier", "assertion", "client_assertion"
    ));

    public static List<OAuthParam> parseParameters(HttpRequest request) {
        List<OAuthParam> result = new ArrayList<>();
        if (request == null) {
            return result;
        }

        Set<String> processedKeys = new HashSet<>();

        // 1. Process parameters provided by Montoya request
        if (request.parameters() != null) {
            for (HttpParameter p : request.parameters()) {
                String name = p.name();
                String rawValue = p.value();
                OAuthParam.ParamLocation loc = switch (p.type()) {
                    case URL -> OAuthParam.ParamLocation.QUERY;
                    case BODY -> OAuthParam.ParamLocation.BODY;
                    case COOKIE -> OAuthParam.ParamLocation.COOKIE;
                    default -> OAuthParam.ParamLocation.QUERY;
                };

                String decoded = decodeValue(rawValue);
                boolean isStandard = IANA_PARAM_DESCRIPTIONS.containsKey(name.toLowerCase());
                boolean isSensitive = SENSITIVE_PARAM_NAMES.contains(name.toLowerCase());
                String desc = IANA_PARAM_DESCRIPTIONS.getOrDefault(name.toLowerCase(), "Custom or vendor-specific parameter");

                result.add(new OAuthParam(name, rawValue, decoded, loc, desc, isStandard, isSensitive));
                processedKeys.add((loc.name() + ":" + name).toLowerCase());
            }
        }

        // 2. Parse Authorization header
        String authHeader = request.headerValue("Authorization");
        if (authHeader != null && !authHeader.isBlank()) {
            if (authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7).trim();
                String decodedToken = decodeValue(token);
                result.add(new OAuthParam("Authorization (Bearer)", token, decodedToken,
                        OAuthParam.ParamLocation.HEADER, "Bearer token transmitted in HTTP Authorization header (RFC 6750)", true, true));
            } else if (authHeader.startsWith("Basic ")) {
                String b64 = authHeader.substring(6).trim();
                String decodedAuth = decodeBase64Safe(b64);
                result.add(new OAuthParam("Authorization (Basic)", b64, decodedAuth,
                        OAuthParam.ParamLocation.HEADER, "HTTP Basic authentication credentials in header (RFC 6749 2.3.1)", true, true));
            }
        }

        // 3. Fallback manual parsing for query string if parameters() missed any
        String query = extractQueryString(request.url());
        if (query != null && !query.isEmpty()) {
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                if (pair.isEmpty()) continue;
                int idx = pair.indexOf('=');
                String key = (idx > 0) ? pair.substring(0, idx) : pair;
                String val = (idx > 0 && idx < pair.length() - 1) ? pair.substring(idx + 1) : "";

                String comboKey = "query:" + key.toLowerCase();
                if (!processedKeys.contains(comboKey)) {
                    String decoded = decodeValue(val);
                    boolean isStandard = IANA_PARAM_DESCRIPTIONS.containsKey(key.toLowerCase());
                    boolean isSensitive = SENSITIVE_PARAM_NAMES.contains(key.toLowerCase());
                    String desc = IANA_PARAM_DESCRIPTIONS.getOrDefault(key.toLowerCase(), "Custom or vendor-specific parameter");

                    result.add(new OAuthParam(key, val, decoded, OAuthParam.ParamLocation.QUERY, desc, isStandard, isSensitive));
                    processedKeys.add(comboKey);
                }
            }
        }

        // 4. Try parsing JSON body if Content-Type is application/json
        String contentType = request.headerValue("Content-Type");
        if (contentType != null && contentType.toLowerCase().contains("application/json")) {
            String body = request.bodyToString();
            if (body != null && body.trim().startsWith("{")) {
                try {
                    JSONObject obj = new JSONObject(body);
                    for (String key : obj.keySet()) {
                        String comboKey = "body:" + key.toLowerCase();
                        if (!processedKeys.contains(comboKey)) {
                            Object valObj = obj.get(key);
                            String rawVal = String.valueOf(valObj);
                            String decoded = decodeValue(rawVal);
                            boolean isStandard = IANA_PARAM_DESCRIPTIONS.containsKey(key.toLowerCase());
                            boolean isSensitive = SENSITIVE_PARAM_NAMES.contains(key.toLowerCase());
                            String desc = IANA_PARAM_DESCRIPTIONS.getOrDefault(key.toLowerCase(), "JSON body parameter");

                            result.add(new OAuthParam(key, rawVal, decoded, OAuthParam.ParamLocation.BODY, desc, isStandard, isSensitive));
                            processedKeys.add(comboKey);
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        }

        return result;
    }

    public static String decodeValue(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }

        // Check if value is a JWT (format: header.payload.signature)
        if (looksLikeJwt(value)) {
            String decodedJwt = tryDecodeJwt(value);
            if (decodedJwt != null) {
                return decodedJwt;
            }
        }

        // Standard URL decoding
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private static boolean looksLikeJwt(String text) {
        if (text == null) return false;
        String[] parts = text.split("\\.");
        return parts.length == 3 && parts[0].startsWith("ey");
    }

    private static String tryDecodeJwt(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) return null;

            String headerJson = new String(Base64.getUrlDecoder().decode(padBase64(parts[0])), StandardCharsets.UTF_8);
            String payloadJson = new String(Base64.getUrlDecoder().decode(padBase64(parts[1])), StandardCharsets.UTF_8);

            return "JWT Header: " + headerJson + " | JWT Payload: " + payloadJson;
        } catch (Exception e) {
            return null;
        }
    }

    private static String padBase64(String base64) {
        int rem = base64.length() % 4;
        if (rem == 2) return base64 + "==";
        if (rem == 3) return base64 + "=";
        return base64;
    }

    private static String decodeBase64Safe(String base64) {
        try {
            return new String(Base64.getDecoder().decode(base64), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return base64;
        }
    }

    private static String extractQueryString(String url) {
        if (url == null) return null;
        int idx = url.indexOf('?');
        if (idx >= 0 && idx < url.length() - 1) {
            return url.substring(idx + 1);
        }
        return null;
    }
}
