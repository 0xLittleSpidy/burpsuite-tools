// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredSecret;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * KeyHacks Credential Verification Engine.
 *
 * <p>Integrates the complete KeyHacks verification knowledge base covering 89+ services.
 * Dynamically maps detected secrets directly to standard HTTP/1.1 requests coupled with
 * proper HttpService targets for instant dispatch to Burp Repeater.
 *
 * @author littlespidy
 */
public class SecretVerifierService {

    public record VerificationRequestDetails(
        String serviceName,
        String host,
        int port,
        boolean secure,
        String method,
        String path,
        Map<String, String> headers,
        String body,
        String rawRequest
    ) {}

    public record SecretVerificationSpec(
        String serviceName,
        String signatureRule,
        String curlCommand,
        String httpMethod,
        String endpointUrl,
        Map<String, String> headers,
        String requestBody,
        String validResponseIndicator,
        String invalidResponseIndicator,
        String safetyNotes,
        String documentationUrl
    ) {}

    private record TemplateEntry(
        String title,
        List<String> keywords,
        String curlTemplate,
        String validNote,
        String invalidNote,
        String docUrl
    ) {}

    private static final List<TemplateEntry> TEMPLATES = new ArrayList<>();

    static {
        loadTemplates();
    }

    private static void loadTemplates() {
        try (InputStream is = SecretVerifierService.class.getResourceAsStream("/com/littlespidy/jssourcemapexplorer/keyhacks_verifications.tsv")) {
            if (is != null) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("\t");
                    if (parts.length < 6) continue;
                    String title = parts[0].trim();
                    List<String> kws = Arrays.stream(parts[1].split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .toList();
                    String curl = parts[2].trim().replace(" \\n ", "\n");
                    String valid = parts[3].trim();
                    String invalid = parts[4].trim();
                    String doc = parts[5].trim();
                    TEMPLATES.add(new TemplateEntry(title, kws, curl, valid, invalid, doc));
                }
            }
        } catch (Exception ignored) {}
    }

    /**
     * Generates a complete verification specification for the given discovered secret.
     */
    public static SecretVerificationSpec generateVerification(DiscoveredSecret secret) {
        if (secret == null) return getUniversalFallback("No secret provided", "");

        String rawToken = secret.secretValue() != null ? secret.secretValue().strip() : "";
        String ruleName = secret.technique() != null ? secret.technique() : "";
        String category = secret.category() != null ? secret.category() : "";

        String searchContext = (ruleName + " " + category + " " + rawToken).toLowerCase(Locale.ROOT);

        // 1. Check for specific high-fidelity services first
        TemplateEntry matchedTemplate = findMatchingTemplate(ruleName, category, rawToken);

        if (matchedTemplate != null) {
            return buildSpecFromTemplate(matchedTemplate, ruleName, rawToken);
        }

        // 2. Fallback to generic verification
        return getUniversalFallback(ruleName, rawToken);
    }

    private static TemplateEntry findMatchingTemplate(String ruleName, String category, String token) {
        // High-confidence prefix shortcuts
        if (token.startsWith("xox")) {
            for (TemplateEntry t : TEMPLATES) {
                if (t.title().equalsIgnoreCase("Slack API token")) return t;
            }
        }
        if (token.startsWith("https://hooks.slack.com")) {
            for (TemplateEntry t : TEMPLATES) {
                if (t.title().equalsIgnoreCase("Slack Webhook")) return t;
            }
        }
        if (token.startsWith("sk_live_") || token.startsWith("rk_live_")) {
            for (TemplateEntry t : TEMPLATES) {
                if (t.title().equalsIgnoreCase("Stripe Live Token")) return t;
            }
        }
        if (token.startsWith("ghp_") || token.startsWith("github_pat_")) {
            for (TemplateEntry t : TEMPLATES) {
                if (t.title().equalsIgnoreCase("Github Token")) return t;
            }
        }
        if (token.startsWith("glpat-")) {
            for (TemplateEntry t : TEMPLATES) {
                if (t.title().equalsIgnoreCase("Gitlab personal access token")) return t;
            }
        }
        if (token.startsWith("sk-proj-") || (token.startsWith("sk-") && token.contains("T3BlbkFJ"))) {
            for (TemplateEntry t : TEMPLATES) {
                if (t.title().equalsIgnoreCase("OPENAI API KEY")) return t;
            }
        }
        if (token.startsWith("sk-ant-")) {
            for (TemplateEntry t : TEMPLATES) {
                if (t.title().toLowerCase().contains("anthropic")) return t;
            }
        }

        // Scored matching across words in ruleName and category
        String combined = (ruleName + " " + category).toLowerCase(Locale.ROOT);
        String[] words = combined.split("[^a-zA-Z0-9]+");

        TemplateEntry bestMatch = null;
        int maxScore = 0;

        Set<String> stopWords = Set.of("auth", "token", "tokens", "key", "keys", "secret", "secrets", "api", "credential", "credentials", "internal", "custom", "scan", "entropy", "ghostjs", "curated", "saas", "client", "header", "hardcoded");
        for (TemplateEntry t : TEMPLATES) {
            int score = 0;
            String tTitleLower = t.title().toLowerCase(Locale.ROOT);
            for (String w : words) {
                if (w.length() < 3 || stopWords.contains(w)) continue;
                if (tTitleLower.contains(w)) {
                    score += 5;
                }
                for (String kw : t.keywords()) {
                    if (kw.equalsIgnoreCase(w)) {
                        score += 3;
                    }
                }
            }
            if (score > maxScore) {
                maxScore = score;
                bestMatch = t;
            }
        }

        return maxScore >= 5 ? bestMatch : null;
    }

    private static SecretVerificationSpec buildSpecFromTemplate(TemplateEntry t, String ruleName, String token) {
        String substitutedCurl = injectToken(t.curlTemplate(), token);
        ParsedCurl parsed = parseCurlCommand(substitutedCurl, token);

        return new SecretVerificationSpec(
            t.title(),
            ruleName,
            formatMultiLineCurl(substitutedCurl),
            parsed.method,
            parsed.url,
            parsed.headers,
            parsed.body,
            t.validNote(),
            t.invalidNote(),
            "Non-destructive, read-only credential identity check from KeyHacks.",
            t.docUrl()
        );
    }

    private static String injectToken(String template, String token) {
        if (template == null) return "";
        if (token == null || token.isEmpty()) return template;

        String result = template;
        boolean replaced = false;

        // AWS specific
        if (token.startsWith("AKIA") || token.startsWith("ASIA")) {
            if (result.contains("AWS_ACCESS_KEY_ID=xxxx")) {
                result = result.replace("AWS_ACCESS_KEY_ID=xxxx", "AWS_ACCESS_KEY_ID=" + token);
                replaced = true;
            }
        }

        // Common KeyHacks placeholder patterns (ordered from most specific to least specific)
        String[] placeholders = {
            "YOUR_OPENAI_API_KEY", "SENDGRID_TOKEN", "YOUR_MAPBOX_ACCESS_TOKEN",
            "YOUR_DELIGHTED_API_KEY", "<your_access_token>", "<YOUR_API_TOKEN>",
            "{here your token}", "{YOUR_API_KEY}", "<YOUR-API-KEY>",
            "<TOKEN>", "TOKEN_HERE", "API_KEY_HERE", "KEY_HERE", "ACCESS_TOKEN_HERE",
            "ACCESS_TOKEN", "token_here", "YOUR_API_KEY", "your_api_token", "<your_token>",
            "{API_KEY}", "{keyhere}", "{API_Key}", "<api_key>", "[API-KEY-HERE]",
            "[AUHT_TOKEN]", "<token>", "APIKEY", "APIKEYHERE", "<Passkey>", "<TOKEN_HERE>",
            "<ACCESS_TOKEN>", "<API_KEY>", "{access-token}", ":api_key", "custom_token",
            "WPENGINE_APIKEY", "{recordKey}", "PROJECT_REGISTRATION_TOKEN",
            "xxxx", "TOKEN", "API_KEY"
        };

        // Specific handling for Slack
        if (result.contains("xoxp-TOKEN_HERE") && token.startsWith("xox")) {
            result = result.replace("xoxp-TOKEN_HERE", token);
            replaced = true;
        } else if (result.contains("xoxb-TOKEN_HERE") && token.startsWith("xox")) {
            result = result.replace("xoxb-TOKEN_HERE", token);
            replaced = true;
        }

        for (String ph : placeholders) {
            if (result.contains(ph)) {
                result = result.replace(ph, token);
                replaced = true;
            }
        }

        // Handle URL replacement if the token is an entire webhook URL (e.g. Slack/Discord)
        if (token.startsWith("http://") || token.startsWith("https://")) {
            result = result.replaceAll("https?://hooks\\.slack\\.com/services/[^\"'\\s]+", token);
            result = result.replaceAll("https?://discord\\.com/api/webhooks/[^\"'\\s]+", token);
            result = result.replace("YOUR_WEBHOOK_URL", token);
            result = result.replace("webhook_url_here", token);
            replaced = true;
        }

        // If no placeholder was matched but command is a curl with basic or bearer auth, append or substitute
        if (!replaced && result.startsWith("curl") && !result.contains(token)) {
            if (result.contains("Bearer")) {
                result = result.replaceAll("Bearer\\s+[A-Za-z0-9._~+/-]+", "Bearer " + token);
            } else if (result.contains("-u ") || result.contains("--user ")) {
                result = result.replaceAll("(-u|--user)\\s+['\"]?[^\\s\"']+['\"]?", "$1 \"" + token + ":\"");
            }
        }

        return result;
    }

    private static String formatMultiLineCurl(String singleLine) {
        if (singleLine == null) return "";
        // Clean multi-line formatting with backslashes
        String formatted = singleLine.trim();
        if (!formatted.contains("\n") && formatted.length() > 60) {
            formatted = formatted
                .replace(" -H ", " \\\n  -H ")
                .replace(" --header ", " \\\n  --header ")
                .replace(" -d ", " \\\n  -d ")
                .replace(" --data ", " \\\n  --data ")
                .replace(" -u ", " \\\n  -u ")
                .replace(" --user ", " \\\n  --user ")
                .replace(" -X ", " \\\n  -X ");
        }
        return formatted;
    }

    private static SecretVerificationSpec getUniversalFallback(String ruleName, String token) {
        String curl = "curl -s -X GET \"https://api.target.com/user\" \\\n" +
            "  -H \"Authorization: Bearer " + (token.isEmpty() ? "<TOKEN>" : token) + "\" \\\n" +
            "  -H \"Accept: application/json\"";

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Accept", "application/json");

        return new SecretVerificationSpec(
            "Generic API Credential / Token",
            ruleName,
            curl,
            "GET",
            "https://api.target.com/user",
            headers,
            null,
            "HTTP 200/201 Success indicating valid, active authentication.",
            "HTTP 401/403 Unauthorized/Forbidden indicating revoked or invalid credentials.",
            "Universal fallback template. Replace 'https://api.target.com/user' with your target service's userinfo or ping endpoint.",
            "https://github.com/streaak/keyhacks"
        );
    }

    private record ParsedCurl(String method, String url, Map<String, String> headers, String body) {}

    private static ParsedCurl parseCurlCommand(String curlCmd, String fallbackToken) {
        String method = "GET";
        String url = "";
        Map<String, String> headers = new LinkedHashMap<>();
        String body = null;

        if (curlCmd == null || curlCmd.isBlank()) {
            return new ParsedCurl(method, url, headers, body);
        }

        // Extract method
        Matcher mMeth = Pattern.compile("(?:-[a-zA-Z]*X|--request)\\s*['\"]?([A-Z]+)['\"]?").matcher(curlCmd);
        if (mMeth.find()) {
            method = mMeth.group(1);
        } else if (curlCmd.contains(" -d ") || curlCmd.contains(" --data ") || curlCmd.contains(" -XPOST ") || curlCmd.contains("-X POST")) {
            method = "POST";
        }

        // Extract URL
        Matcher mUrl = Pattern.compile("['\"](https?://[^\"'\\s]+)['\"]").matcher(curlCmd);
        if (mUrl.find()) {
            url = mUrl.group(1);
        } else {
            Matcher mRawUrl = Pattern.compile("\\b(https?://[^\\s\"'>]+)").matcher(curlCmd);
            if (mRawUrl.find()) {
                url = mRawUrl.group(1);
            }
        }

        // Extract Headers
        Matcher mHdr = Pattern.compile("(?:-H|--header)\\s+['\"]([^'\"]+)['\"]").matcher(curlCmd);
        while (mHdr.find()) {
            String headerLine = mHdr.group(1);
            int idx = headerLine.indexOf(':');
            if (idx > 0) {
                headers.put(headerLine.substring(0, idx).trim(), headerLine.substring(idx + 1).trim());
            }
        }

        // Extract Basic Auth (-u / --user)
        Matcher mAuth = Pattern.compile("(?:-u|--user)\\s+['\"]?([^'\"\\s]+)['\"]?").matcher(curlCmd);
        if (mAuth.find()) {
            String creds = mAuth.group(1);
            String b64 = Base64.getEncoder().encodeToString(creds.getBytes(StandardCharsets.UTF_8));
            headers.put("Authorization", "Basic " + b64);
        }

        // Extract Body (-d / --data)
        Matcher mBody = Pattern.compile("(?:-d|--data|--data-binary)\\s+['\"]([^'\"]+)['\"]").matcher(curlCmd);
        if (mBody.find()) {
            body = mBody.group(1);
        }

        return new ParsedCurl(method, url, headers, body);
    }

    /**
     * Builds full HTTP verification details ready for direct Repeater dispatch.
     * Fully unit-testable without requiring Montoya runtime.
     */
    public static VerificationRequestDetails getVerificationRequestDetails(DiscoveredSecret secret) {
        if (secret == null) {
            return buildFallbackDetails("Generic Secret", "api.target.com", 443, true, "UNKNOWN_TOKEN");
        }

        String rawToken = secret.secretValue() != null ? secret.secretValue().strip() : "";
        String ruleName = secret.technique() != null ? secret.technique() : "";
        String category = secret.category() != null ? secret.category() : "";
        String sourceUrl = secret.sourceLocation() != null ? secret.sourceLocation() : "";

        // 1. AWS Access Key Check (starts with AKIA or ASIA or rule contains AWS)
        if (rawToken.startsWith("AKIA") || rawToken.startsWith("ASIA") || ruleName.toLowerCase().contains("aws access key")) {
            String body = "Action=GetCallerIdentity&Version=2011-06-15";
            Map<String, String> hdrs = new LinkedHashMap<>();
            hdrs.put("Host", "sts.amazonaws.com");
            hdrs.put("Content-Type", "application/x-www-form-urlencoded");
            hdrs.put("User-Agent", "aws-cli/2.0");
            hdrs.put("Accept", "application/json, text/xml");
            hdrs.put("X-Amz-KeyId", rawToken);

            String raw = "POST / HTTP/1.1\r\n" +
                "Host: sts.amazonaws.com\r\n" +
                "User-Agent: aws-cli/2.0\r\n" +
                "Accept: application/json, text/xml\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "X-Amz-KeyId: " + rawToken + "\r\n" +
                "Content-Length: " + body.length() + "\r\n" +
                "Connection: close\r\n\r\n" +
                body;

            return new VerificationRequestDetails(
                "AWS STS (GetCallerIdentity)",
                "sts.amazonaws.com",
                443,
                true,
                "POST",
                "/",
                hdrs,
                body,
                raw
            );
        }

        // 2. Match KeyHacks Template
        TemplateEntry matchedTemplate = findMatchingTemplate(ruleName, category, rawToken);

        if (matchedTemplate != null) {
            String substituted = injectToken(matchedTemplate.curlTemplate(), rawToken);
            ParsedCurl parsed = parseCurlCommand(substituted, rawToken);

            String url = parsed.url;
            String host = "api.target.com";
            int port = 443;
            boolean secure = true;
            String path = "/";

            if (url != null && !url.isEmpty()) {
                url = sanitizeUrl(url, rawToken, sourceUrl);
                try {
                    java.net.URI uri = java.net.URI.create(url);
                    if (uri.getHost() != null && !uri.getHost().isEmpty()) {
                        host = uri.getHost();
                    }
                    secure = uri.getScheme() == null || !uri.getScheme().equalsIgnoreCase("http");
                    port = uri.getPort() > 0 ? uri.getPort() : (secure ? 443 : 80);
                    path = uri.getRawPath() != null && !uri.getRawPath().isEmpty() ? uri.getRawPath() : "/";
                    if (uri.getRawQuery() != null && !uri.getRawQuery().isEmpty()) {
                        path += "?" + uri.getRawQuery();
                    }
                } catch (Exception e) {
                    host = extractHostFromUrl(url);
                    int slashIdx = url.indexOf('/', url.indexOf("://") + 3);
                    path = slashIdx >= 0 ? url.substring(slashIdx) : "/";
                }
            } else {
                String srcHost = extractHostFromUrl(sourceUrl);
                if (!srcHost.isEmpty()) {
                    host = srcHost;
                }
            }

            host = sanitizeHost(host);

            Map<String, String> headers = new LinkedHashMap<>(parsed.headers);
            String method = parsed.method != null && !parsed.method.isBlank() ? parsed.method : "GET";
            String body = parsed.body;

            // Ensure standard Host and User-Agent
            headers.put("Host", host);
            if (!headers.containsKey("User-Agent")) {
                headers.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BurpJSRecon/1.0");
            }
            if (!headers.containsKey("Accept")) {
                headers.put("Accept", "application/json, text/plain, */*");
            }
            headers.put("Connection", "close");

            // Build standard HTTP/1.1 wire string with CRLF
            StringBuilder sb = new StringBuilder();
            sb.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
            sb.append("Host: ").append(host).append("\r\n");
            for (Map.Entry<String, String> h : headers.entrySet()) {
                if (h.getKey().equalsIgnoreCase("Host") || h.getKey().equalsIgnoreCase("Content-Length")) continue;
                sb.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
            }

            if (body != null && !body.isEmpty()) {
                byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
                sb.append("Content-Length: ").append(bodyBytes.length).append("\r\n\r\n");
                sb.append(body);
            } else if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method)) {
                sb.append("Content-Length: 0\r\n\r\n");
            } else {
                sb.append("\r\n");
            }

            return new VerificationRequestDetails(
                matchedTemplate.title(),
                host,
                port,
                secure,
                method,
                path,
                headers,
                body,
                sb.toString()
            );
        }

        // 3. Universal Fallback
        String fallbackHost = extractHostFromUrl(sourceUrl);
        if (fallbackHost.isEmpty()) fallbackHost = "api.target.com";
        return buildFallbackDetails(ruleName, fallbackHost, 443, true, rawToken);
    }

    private static VerificationRequestDetails buildFallbackDetails(String serviceName, String host, int port, boolean secure, String token) {
        String cleanHost = sanitizeHost(host);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Host", cleanHost);
        headers.put("Authorization", "Bearer " + token);
        headers.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BurpJSRecon/1.0");
        headers.put("Accept", "application/json, text/plain, */*");
        headers.put("Connection", "close");

        String raw = "GET /user HTTP/1.1\r\n" +
            "Host: " + cleanHost + "\r\n" +
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) BurpJSRecon/1.0\r\n" +
            "Authorization: Bearer " + token + "\r\n" +
            "Accept: application/json, text/plain, */*\r\n" +
            "Connection: close\r\n\r\n";

        return new VerificationRequestDetails(
            serviceName != null && !serviceName.isEmpty() ? serviceName : "Generic API Credential",
            cleanHost,
            port,
            secure,
            "GET",
            "/user",
            headers,
            null,
            raw
        );
    }

    private static String sanitizeUrl(String url, String token, String sourceUrl) {
        if (url == null || url.isEmpty()) return "https://api.target.com/user";
        String res = url.trim();

        if (!res.startsWith("http://") && !res.startsWith("https://")) {
            res = "https://" + res;
        }

        res = res.replace("{subdomain}", "api")
                 .replace("{target}", "api")
                 .replace("<example-app-id>", "application")
                 .replace("<example-appid>", "application")
                 .replace("instance_name", "login")
                 .replace("domain.freshdesk.com", "api.freshdesk.com")
                 .replace("<dc>", "us1")
                 .replace("your-grafana-server-url.com", "grafana.target.com")
                 .replace("api_endpoint_here", "api.abtasty.com/v1/campaigns")
                 .replace("YOUR_WEBHOOK_URL", "outlook.office.com/webhook/test")
                 .replace("webhook_url_here", "hooks.zapier.com/hooks/catch/test")
                 .replace("{APP_ID}", "app-12345")
                 .replace("<APP_ID>", "app-12345")
                 .replace("SPACE_ID_HERE", "space-123")
                 .replace("USERNAME_HERE", "user")
                 .replace("{user-id}", "me")
                 .replace("{projectId}", "project-123")
                 .replace("{recordKey}", token)
                 .replace("{ip_address}", "8.8.8.8");

        return res;
    }

    private static String sanitizeHost(String host) {
        if (host == null || host.isEmpty()) return "api.target.com";
        String clean = host.replaceAll("[<{][^>}]*[>}]", "api")
                           .replaceAll("[^a-zA-Z0-9.-]", "");
        if (clean.isEmpty()) return "api.target.com";
        return clean;
    }

    private static String extractHostFromUrl(String url) {
        if (url == null || url.isEmpty()) return "";
        try {
            int schemeIdx = url.indexOf("://");
            String afterScheme = schemeIdx >= 0 ? url.substring(schemeIdx + 3) : url;
            int slashIdx = afterScheme.indexOf('/');
            String hostAndPort = slashIdx >= 0 ? afterScheme.substring(0, slashIdx) : afterScheme;
            int colonIdx = hostAndPort.indexOf(':');
            return colonIdx >= 0 ? hostAndPort.substring(0, colonIdx) : hostAndPort;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Builds a native Montoya HttpRequest with attached HttpService for direct Repeater dispatch.
     */
    public static HttpRequest buildVerificationRequest(DiscoveredSecret sec) {
        VerificationRequestDetails details = getVerificationRequestDetails(sec);
        if (details == null) return null;
        try {
            HttpService service = HttpService.httpService(details.host(), details.port(), details.secure());
            return HttpRequest.httpRequest(service, details.rawRequest());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Converts a verification specification into a Montoya HttpRequest for Repeater dispatch.
     */
    public static HttpRequest buildHttpRequest(SecretVerificationSpec spec) {
        if (spec == null || spec.endpointUrl() == null || !spec.endpointUrl().startsWith("http")) {
            return null;
        }

        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(spec.endpointUrl());

            if (spec.httpMethod() != null && !spec.httpMethod().isBlank()) {
                req = req.withMethod(spec.httpMethod());
            }

            if (spec.headers() != null) {
                for (Map.Entry<String, String> h : spec.headers().entrySet()) {
                    req = req.withAddedHeader(h.getKey(), h.getValue());
                }
            }

            if (spec.requestBody() != null && !spec.requestBody().isBlank()) {
                req = req.withBody(spec.requestBody());
            }

            return req;
        } catch (Exception e) {
            return null;
        }
    }
}
