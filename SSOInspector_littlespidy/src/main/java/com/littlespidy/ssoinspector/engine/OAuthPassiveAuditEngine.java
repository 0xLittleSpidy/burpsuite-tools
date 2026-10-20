// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.ssoinspector.model.*;

import java.util.*;

public class OAuthPassiveAuditEngine {

    public static List<SSOAuditIssue> audit(HttpRequestResponse requestResponse, List<OAuthParam> parameters, OAuthFlowType flowType) {
        List<SSOAuditIssue> issues = new ArrayList<>();
        if (requestResponse == null || requestResponse.request() == null) {
            return issues;
        }

        HttpRequest request = requestResponse.request();
        String url = request.url();
        String path = request.path();
        String method = request.method();

        Map<String, OAuthParam> paramMap = new HashMap<>();
        if (parameters != null) {
            for (OAuthParam p : parameters) {
                paramMap.put(p.getName().toLowerCase(), p);
            }
        }

        boolean isOpenId = isScopeOpenId(paramMap) || (paramMap.containsKey("response_type") && paramMap.get("response_type").getRawValue().contains("id_token"));

        // 1. Exposure of Client Secret in URL
        OAuthParam clientSecretParam = paramMap.get("client_secret");
        if (clientSecretParam != null && clientSecretParam.getLocation() == OAuthParam.ParamLocation.QUERY) {
            issues.add(new SSOAuditIssue(
                    "OAUTHv2/OpenID Exposure of Client Secret in URL",
                    IssueSeverity.HIGH,
                    IssueConfidence.CERTAIN,
                    "The client secret was detected as a URL query parameter: " + clientSecretParam.getRawValue() +
                            ". Transmitting client credentials in the URL query string exposes them to server access logs, browser history, proxy logs, and Referer headers.",
                    "Transmit client credentials exclusively in the HTTP request body using POST with Content-Type application/x-www-form-urlencoded, or via the HTTP Authorization header (Basic auth per RFC 6749 Section 2.3.1).",
                    "RFC 6749 Section 2.3.1 (Client Authentication); OAuth 2.0 Security Best Current Practice",
                    requestResponse,
                    false
            ));
        }

        // 2. Client Secret detected on GET request
        if (clientSecretParam != null && "GET".equalsIgnoreCase(method)) {
            issues.add(new SSOAuditIssue(
                    "OAUTHv2/OpenID Client Secret Sent via GET Method",
                    IssueSeverity.HIGH,
                    IssueConfidence.CERTAIN,
                    "A client secret was sent using HTTP GET. Client credentials must never be passed in GET requests.",
                    "Use HTTP POST with request body parameters or HTTP Authorization header.",
                    "RFC 6749 Section 2.3.1",
                    requestResponse,
                    false
            ));
        }

        // 3. Authorization Code flow without PKCE
        if (flowType == OAuthFlowType.AUTHORIZATION_CODE) {
            issues.add(new SSOAuditIssue(
                    "OAUTHv2/OpenID Authorization Code Flow without PKCE Protection",
                    IssueSeverity.MEDIUM,
                    IssueConfidence.CERTAIN,
                    "The Authorization Code flow was initiated without Proof Key for Code Exchange (PKCE, RFC 7636). " +
                            "Without PKCE, authorization codes intercepted on public clients (mobile apps, SPAs, desktop apps) can be exchanged by an attacker for access tokens.",
                    "Implement PKCE (RFC 7636) by generating a high-entropy code_verifier, computing code_challenge=BASE64URL(SHA256(code_verifier)), and passing code_challenge_method=S256 in authorization requests.",
                    "RFC 7636 (Proof Key for Code Exchange by OAuth Public Clients); OAuth 2.0 Security BCP Section 2.1.1",
                    requestResponse,
                    false
            ));
        }

        // 4. PKCE configured with code_challenge_method=plain
        OAuthParam challengeMethodParam = paramMap.get("code_challenge_method");
        if (challengeMethodParam != null && "plain".equalsIgnoreCase(challengeMethodParam.getRawValue().trim())) {
            issues.add(new SSOAuditIssue(
                    "OAUTHv2/OpenID PKCE Configured with Plaintext Transform",
                    IssueSeverity.MEDIUM,
                    IssueConfidence.CERTAIN,
                    "The PKCE code_challenge_method was explicitly set to 'plain'. When using 'plain', code_challenge equals code_verifier, " +
                            "nullifying cryptographic protection if the authorization request is inspected.",
                    "Always set code_challenge_method=S256 and transmit SHA-256 hashed code challenges.",
                    "RFC 7636 Section 4.2 & Section 4.3",
                    requestResponse,
                    false
            ));
        }

        // 5. Insecure Flow: Implicit Flow Detected
        if (flowType == OAuthFlowType.IMPLICIT) {
            issues.add(new SSOAuditIssue(
                    "OAUTHv2/OpenID Implicit Flow Detected (Deprecated)",
                    IssueSeverity.MEDIUM,
                    IssueConfidence.CERTAIN,
                    "The OAuth/OpenID Implicit Flow is being used (response_type=token or id_token). " +
                            "The Implicit Flow returns access tokens directly in URL fragments (#access_token=...), which are easily leaked through browser history, script injection, and Referer headers. The OAuth working group has officially deprecated the Implicit Flow.",
                    "Migrate to the Authorization Code Flow with PKCE (RFC 7636) and CORS-enabled token endpoints.",
                    "OAuth 2.0 Security Best Current Practice Section 2.1.2; RFC 6749 Section 4.2",
                    requestResponse,
                    false
            ));
        }

        // 6. Insecure Flow: Resource Owner Password Credentials (ROPC)
        if (flowType == OAuthFlowType.RESOURCE_OWNER_PASSWORD) {
            issues.add(new SSOAuditIssue(
                    "OAUTHv2 Resource Owner Password Credentials Flow Detected (Deprecated)",
                    IssueSeverity.HIGH,
                    IssueConfidence.CERTAIN,
                    "The application utilizes the Resource Owner Password Credentials grant (grant_type=password). " +
                            "This grant requires users to input their plaintext credentials directly into the client application, breaking the core OAuth principle of credential isolation and increasing credential theft exposure.",
                    "Discontinue use of grant_type=password. Migrate user authentication to standard Authorization Code with PKCE redirection flows.",
                    "OAuth 2.0 Security Best Current Practice Section 2.4; RFC 6749 Section 4.3",
                    requestResponse,
                    false
            ));
        }

        // 7. Missing or Weak State Parameter (CSRF check)
        OAuthParam stateParam = paramMap.get("state");
        if (isAuthorizationRequest(paramMap, path)) {
            if (stateParam == null || stateParam.getRawValue().isBlank()) {
                issues.add(new SSOAuditIssue(
                        "OAUTHv2/OpenID Missing State Parameter (CSRF Risk)",
                        IssueSeverity.MEDIUM,
                        IssueConfidence.FIRM,
                        "The authorization request does not include a 'state' parameter. " +
                                "The 'state' parameter binds the authorization request with the client's session, mitigating Cross-Site Request Forgery (CSRF) and Login CSRF attacks.",
                        "Always generate an unpredictable, cryptographically random, session-bound state token and validate it when handling the authorization callback.",
                        "RFC 6749 Section 10.12 (Cross-Site Request Forgery); OAuth 2.0 Security BCP Section 2.1",
                        requestResponse,
                        false
                ));
            } else {
                String stateVal = stateParam.getRawValue();
                if (stateVal.length() < 8 || calculateShannonEntropy(stateVal) < 2.0) {
                    issues.add(new SSOAuditIssue(
                            "OAUTHv2/OpenID Weak State Parameter Detected",
                            IssueSeverity.LOW,
                            IssueConfidence.FIRM,
                            "The 'state' parameter value (" + stateVal + ") appears to have low entropy or short length (" + stateVal.length() + " chars). " +
                                    "A predictable state value enables attackers to forge authorization responses and perform login CSRF attacks.",
                            "Use a cryptographically secure pseudo-random number generator (CSPRNG) with at least 128 bits of entropy (e.g. 16+ random bytes encoded with Base64URL).",
                            "RFC 6749 Section 10.12",
                            requestResponse,
                            false
                    ));
                }
            }
        }

        // 8. Missing or Weak Nonce Parameter (OpenID Connect)
        if (isOpenId && isAuthorizationRequest(paramMap, path)) {
            OAuthParam nonceParam = paramMap.get("nonce");
            if (nonceParam == null || nonceParam.getRawValue().isBlank()) {
                issues.add(new SSOAuditIssue(
                        "OpenID Flow Missing Nonce Parameter",
                        IssueSeverity.LOW,
                        IssueConfidence.FIRM,
                        "The OpenID Connect authorization request does not include a 'nonce' parameter. " +
                                "The 'nonce' parameter connects the client session with the issued ID Token, providing anti-replay protection.",
                        "Generate a unique, cryptographically random nonce per authentication session, pass it in authorization requests, and verify that the claim 'nonce' in the resulting ID Token matches exactly.",
                        "OpenID Connect Core 1.0 Section 3.1.2.1",
                        requestResponse,
                        false
                ));
            } else {
                String nonceVal = nonceParam.getRawValue();
                if (nonceVal.length() < 8 || calculateShannonEntropy(nonceVal) < 2.0) {
                    issues.add(new SSOAuditIssue(
                            "OpenID Weak Nonce Parameter",
                            IssueSeverity.LOW,
                            IssueConfidence.FIRM,
                            "The 'nonce' parameter value (" + nonceVal + ") has low length or entropy. " +
                                    "Predictable nonces weaken replay mitigations against stolen ID tokens.",
                            "Use a CSPRNG with at least 128 bits of randomness to generate nonces.",
                            "OpenID Connect Core 1.0 Section 3.1.2.1",
                            requestResponse,
                            false
                    ));
                }
            }
        }

        // 9. Secret Token or Code Leakage in Referer Header
        String referer = request.headerValue("Referer");
        if (referer != null && !referer.isBlank()) {
            if (referer.contains("code=") || referer.contains("access_token=") || referer.contains("id_token=")) {
                issues.add(new SSOAuditIssue(
                        "OAUTHv2/OpenID Leakage of Secret Token or Code in Referer Header",
                        IssueSeverity.HIGH,
                        IssueConfidence.CERTAIN,
                        "The HTTP Referer header leaked sensitive authorization parameters: " + referer +
                                ". External links, third-party assets, or tracking scripts loaded on the callback page will receive this code or token.",
                        "Implement strict Referrer-Policy: no-referrer or same-origin headers, and exchange authorization codes immediately before redirecting to pages with third-party assets.",
                        "RFC 6749 Section 10.13; OAuth 2.0 Security BCP Section 4.3",
                        requestResponse,
                        false
                ));
            }
        }

        // 10. Request_Uri Parameter Detected (SSRF Indicator)
        OAuthParam reqUriParam = paramMap.get("request_uri");
        if (reqUriParam != null && !reqUriParam.getRawValue().isBlank()) {
            issues.add(new SSOAuditIssue(
                    "OpenID/OAuth Flow with Request_Uri Parameter Detected (Potential SSRF Surface)",
                    IssueSeverity.LOW,
                    IssueConfidence.CERTAIN,
                    "The authorization request utilizes the 'request_uri' parameter: " + reqUriParam.getRawValue() +
                            ". The authorization server fetches the request object over the network from this URI, creating a potential Server-Side Request Forgery (SSRF) vector if the server lacks strict domain whitelist enforcement.",
                    "Verify that the Authorization Server validates the scheme, host, and port of request_uri against pre-registered client URIs.",
                    "OpenID Connect Core 1.0 Section 6.2; RFC 9101 (The OAuth 2.0 Rich Authorization Requests / JWT-Secured Authorization Request)",
                    requestResponse,
                    false
            ));
        }

        // 11. Well-Known Configuration file exposed
        if (path != null && (path.contains("/.well-known/openid-configuration") || path.contains("/.well-known/oauth-authorization-server"))) {
            issues.add(new SSOAuditIssue(
                    "OAUTHv2/OpenID Configuration Files in Well-Known URLs",
                    IssueSeverity.INFORMATION,
                    IssueConfidence.CERTAIN,
                    "Found publicly accessible OAuth 2.0 / OpenID Connect metadata configuration at: " + url +
                            ". Inspect the configuration for supported response types, algorithms (e.g. none), endpoints, and claim types.",
                    "Ensure only intended endpoints and modern cryptographic algorithms are enabled.",
                    "RFC 8414 (OAuth 2.0 Authorization Server Metadata); OpenID Connect Discovery 1.0",
                    requestResponse,
                    false
            ));
        }

        // 12. Check Response (Token Lifetime & Refresh Token checks)
        if (requestResponse.hasResponse() && requestResponse.response() != null) {
            HttpResponse resp = requestResponse.response();
            String respBody = resp.bodyToString();
            if (respBody != null && respBody.contains("expires_in")) {
                int expiresIn = extractExpiresIn(respBody);
                if (expiresIn > 86400) {
                    issues.add(new SSOAuditIssue(
                            "OAUTHv2 Flow Excessive Lifetime for Secret Tokens",
                            IssueSeverity.LOW,
                            IssueConfidence.FIRM,
                            "The access token was issued with an excessive lifetime of " + expiresIn + " seconds (> 24 hours). " +
                                    "Long-lived access tokens dramatically increase the window of opportunity for token theft and abuse.",
                            "Reduce access token lifetime (recommended: 10 minutes to 1 hour) and rely on refresh tokens with refresh token rotation.",
                            "RFC 6749 Section 5.1; OAuth 2.0 Security BCP Section 4.14",
                            requestResponse,
                            false
                    ));
                }
            }

            // Client Credentials Flow improperly releasing refresh tokens
            if (flowType == OAuthFlowType.CLIENT_CREDENTIALS && respBody != null && respBody.contains("refresh_token")) {
                issues.add(new SSOAuditIssue(
                        "OAUTHv2 Client Credentials Flow Improper Release of Refresh Token",
                        IssueSeverity.LOW,
                        IssueConfidence.FIRM,
                        "The authorization server released a refresh_token in response to a client_credentials grant. " +
                                "Per RFC 6749 Section 4.4.3, a refresh token SHOULD NOT be included in Client Credentials responses because the client can authenticate directly whenever needed.",
                        "Do not issue refresh tokens for the client_credentials grant type.",
                        "RFC 6749 Section 4.4.3",
                        requestResponse,
                        false
                ));
            }
        }

        return issues;
    }

    private static boolean isScopeOpenId(Map<String, OAuthParam> paramMap) {
        OAuthParam scope = paramMap.get("scope");
        return scope != null && scope.getRawValue().toLowerCase().contains("openid");
    }

    private static boolean isAuthorizationRequest(Map<String, OAuthParam> paramMap, String path) {
        if (paramMap.containsKey("response_type") || paramMap.containsKey("client_id")) {
            return true;
        }
        return path != null && (path.contains("/authorize") || path.contains("/auth") || path.contains("/oauth2/v"));
    }

    private static int extractExpiresIn(String body) {
        try {
            int idx = body.indexOf("\"expires_in\"");
            if (idx >= 0) {
                int col = body.indexOf(':', idx);
                if (col >= 0) {
                    int end = body.length();
                    for (int i = col + 1; i < body.length(); i++) {
                        char ch = body.charAt(i);
                        if (ch == ',' || ch == '}' || ch == '\n' || ch == '\r') {
                            end = i;
                            break;
                        }
                    }
                    if (end > col) {
                        String num = body.substring(col + 1, end).trim();
                        return Integer.parseInt(num.replaceAll("[^0-9]", ""));
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return 0;
    }

    public static double calculateShannonEntropy(String input) {
        if (input == null || input.isEmpty()) {
            return 0.0;
        }
        Map<Character, Integer> counts = new HashMap<>();
        for (char c : input.toCharArray()) {
            counts.put(c, counts.getOrDefault(c, 0) + 1);
        }
        double entropy = 0.0;
        int len = input.length();
        for (int count : counts.values()) {
            double prob = (double) count / len;
            entropy -= prob * (Math.log(prob) / Math.log(2));
        }
        return entropy;
    }
}
