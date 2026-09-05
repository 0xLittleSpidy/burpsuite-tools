// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InspectorDataStore;

import java.util.*;

/**
 * Scans HTTP responses (both Headers and Body) for exposed secrets, tokens,
 * cloud storage buckets, and cryptographic credentials.
 * Implements the Two-Stage Refiner Regex technique and pattern set ported from sensitive-discoverer.
 */
public class SecretScanner {

    private final List<RefinerRule> rules = new ArrayList<>();

    public SecretScanner() {
        initRules();
    }

    private void initRules() {
        // ── Two-Stage Refiner Regex Rules (Cloud Buckets & OAuth IDs) ──────────

        // AWS S3 Buckets: anchor matches domain suffix, refiner captures bucket prefix
        rules.add(RefinerRule.ofRefined(
                "AWS S3 Bucket",
                "s3(\\.dualstack|-acce(lerate|sspoint))?\\.([a-z]{1,8}-[a-z]{1,16}-\\d{1,3}\\.)?amazonaws\\.com",
                "[a-z\\d\\-]{3,63}\\.$",
                true,
                false
        ));

        // Azure Blob Storage
        rules.add(RefinerRule.ofRefined(
                "Azure Blob Storage",
                "blob\\.core\\.windows\\.net",
                "[a-z\\d\\-]{3,63}\\.$",
                true,
                false
        ));

        // Firebase Realtime Database
        rules.add(RefinerRule.ofRefined(
                "Firebase Database URL",
                "\\.(firebase(io\\.com|database\\.app))",
                "[0-9a-zA-Z\\.\\-]{1,64}$",
                true,
                false
        ));

        // Google OAuth Client ID
        rules.add(RefinerRule.ofRefined(
                "Google OAuth Client ID",
                "\\.apps\\.googleusercontent\\.com",
                "\\d{1,20}-\\w{32}$",
                true,
                false
        ));

        // Microsoft Teams Incoming Webhook
        rules.add(RefinerRule.ofRefined(
                "Microsoft Teams Webhook",
                "\\.webhook\\.office\\.com",
                "\\w+$",
                true,
                true
        ));

        // ── Cloud Credentials & Tokens ────────────────────────────────────────

        // AWS Access Key ID (AKIA, ASIA, etc.)
        rules.add(RefinerRule.ofSimple("AWS Access Key ID",
                "\\bA(BIA|CCA|GPA|I(DA|PA)|KIA|N(PA|VA)|PKA|ROA|S(CA|IA))[a-zA-Z0-9]{16,17}\\b",
                false));

        // AWS Secret Access Key
        rules.add(RefinerRule.ofSimple("AWS Secret Access Key",
                "(?i)aws(?:_secret)?(?:_access)?(?:_key)?\\s*[:=]\\s*['\"]([0-9a-zA-Z/+=]{40})['\"]",
                true));

        // Amazon MWS Auth Token
        rules.add(RefinerRule.ofSimple("Amazon MWS Auth Token",
                "(?i)amzn\\.mws\\.[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                true));

        // Amazon ARN
        rules.add(RefinerRule.ofSimple("Amazon ARN",
                "\\barn:aws(-(cn|us-gov|iso-[bcd]))?:[\\w/.\\-]{1,63}:([\\w/.\\-]{0,63}:){2}([\\w:/.\\-]{0,1023})\\b",
                false));

        // Google Cloud Storage (gs://)
        rules.add(RefinerRule.ofSimple("Google Cloud Storage",
                "\\bgs://[a-z\\d\\-]{3,63}\\b",
                false));

        // Google API Key
        rules.add(RefinerRule.ofSimple("Google API Key",
                "\\bAIza[0-9A-Za-z\\-_]{35}\\b",
                true));

        // Google OAuth Access Token
        rules.add(RefinerRule.ofSimple("Google OAuth Token",
                "\\bya29\\.[0-9A-Za-z\\-_]{32,64}\\b",
                true));

        // Google OAuth Client Secret
        rules.add(RefinerRule.ofSimple("Google OAuth Client Secret",
                "\\bGOCSPX-[0-9a-zA-Z\\-_]{28}\\b",
                true));

        // OpenAI API Key
        rules.add(RefinerRule.ofSimple("OpenAI API Key",
                "\\bsk-[a-zA-Z0-9]{40,128}(?![\\w\\-])\\b",
                true));

        // GitHub Personal Access Token (classic & fine-grained)
        rules.add(RefinerRule.ofSimple("GitHub Personal Access Token",
                "\\bgh[pousr]_[a-zA-Z0-9]{36,40}\\b",
                true));

        // GitHub Fine-Grained Personal Access Token
        rules.add(RefinerRule.ofSimple("GitHub Fine-Grained Token",
                "\\bgithub_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}\\b",
                true));

        // Slack Incoming Webhook
        rules.add(RefinerRule.ofSimple("Slack Incoming Webhook",
                "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
                true));

        // Slack Token
        rules.add(RefinerRule.ofSimple("Slack Bot/User Token",
                "\\bx(ox[psboare]|app)(-[a-zA-Z0-9]{1,64}){1,5}\\b",
                true));

        // Square Token
        rules.add(RefinerRule.ofSimple("Square Token",
                "\\bsq0(atp|csp|idp)-[0-9A-Za-z\\-_]{22,43}\\b",
                true));

        // MailGun API Key
        rules.add(RefinerRule.ofSimple("MailGun API Key",
                "\\bkey-[0-9a-f]{32}(?!\\w)\\b",
                true));

        // NuGet API Key
        rules.add(RefinerRule.ofSimple("NuGet API Key",
                "\\boy2[a-z0-9]{43}(?![a-z0-9])\\b",
                true));

        // Microsoft Teams / Office 365 Webhook
        rules.add(RefinerRule.ofSimple("Office 365 Connector Webhook",
                "outlook\\.office(365)?\\.com/webhook/[\\w\\-@]{1,128}",
                true));

        // Stripe API Key (Secret / Restricted)
        rules.add(RefinerRule.ofSimple("Stripe API Key",
                "\\b[rs]k_(live|test)_[0-9a-zA-Z]{24,34}\\b",
                true));

        // Stripe Webhook Secret
        rules.add(RefinerRule.ofSimple("Stripe Webhook Secret",
                "\\bwhsec_[0-9a-zA-Z]{32}\\b",
                true));

        // Twilio API Key
        rules.add(RefinerRule.ofSimple("Twilio API Key",
                "\\bSK[0-9a-zA-Z]{32}\\b",
                true));

        // SendGrid API Key
        rules.add(RefinerRule.ofSimple("SendGrid API Key",
                "\\bSG\\.[a-zA-Z0-9_\\-\\.]{66}\\b",
                true));

        // Private Key Header
        rules.add(RefinerRule.ofSimple("Private Key Header",
                "-----BEGIN (?:[A-Z0-9_]+ )?PRIVATE KEY-----",
                false));

        // JSON Web Token (JWT)
        rules.add(RefinerRule.ofSimple("JSON Web Token (JWT)",
                "\\beyJ[a-zA-Z0-9_-]{10,}\\.eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_\\-\\./+=]*\\b",
                true));

        // Generic API Key assignment
        rules.add(RefinerRule.ofSimple("Generic API Key",
                "(?i)(?:api[_-]?key|apikey|x-api-key)\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-+=\\/\\\\]{16,64})['\"]",
                true));

        // Generic Secret assignment
        rules.add(RefinerRule.ofSimple("Generic Secret",
                "(?i)(?:client[_-]?secret|app[_-]?secret|secret[_-]?key)\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-+=\\/\\\\]{16,64})['\"]",
                true));

        // Environment File Leak
        rules.add(RefinerRule.ofSimple("Environment Configuration (.env)",
                "(?i)(?:DB_PASSWORD|DATABASE_URL|APP_KEY|SECRET_KEY_BASE)\\s*=\\s*['\"]?[^\\r\\n'\"]+['\"]?",
                true));
    }

    public List<FindingEntry> scan(HttpRequestResponse requestResponse, InspectorDataStore dataStore) {
        List<FindingEntry> findings = new ArrayList<>();
        if (requestResponse == null || requestResponse.response() == null) {
            return findings;
        }

        HttpResponse response = requestResponse.response();

        // 1. Scan Response Headers (e.g. Set-Cookie tokens, Location redirects to S3/Firebase)
        String headers = ScannerUtils.extractHeadersString(response);
        if (!headers.isEmpty()) {
            scanSection(headers, "Response Headers", requestResponse, dataStore, findings);
        }

        // 2. Scan Response Body
        String body = ScannerUtils.convertByteArrayToString(response.body());
        if (!body.isEmpty()) {
            scanSection(body, "Response Body", requestResponse, dataStore, findings);
        }

        return findings;
    }

    private void scanSection(
            String content,
            String location,
            HttpRequestResponse requestResponse,
            InspectorDataStore dataStore,
            List<FindingEntry> findings
    ) {
        Set<String> seenInThisSection = new HashSet<>();
        for (RefinerRule rule : rules) {
            List<RefinerRule.MatchResult> matches = rule.findMatches(content);
            for (RefinerRule.MatchResult mr : matches) {
                if (seenInThisSection.add(rule.name() + "|" + mr.value())) {
                    String displayVal = rule.maskMatch() ? maskSecret(mr.value()) : mr.value();
                    findings.add(FindingEntry.create(
                            dataStore.nextId(),
                            FindingCategory.SECRET,
                            rule.name(),
                            displayVal,
                            location,
                            requestResponse,
                            mr.startOffset(),
                            mr.endOffset()
                    ));
                }
            }
        }
    }

    public List<String> getRuleNames() {
        return rules.stream().map(RefinerRule::name).toList();
    }

    private static String maskSecret(String secret) {
        if (secret == null || secret.length() <= 8) {
            return "****";
        }
        int keep = Math.min(4, secret.length() / 4);
        return secret.substring(0, keep) + "..." + secret.substring(secret.length() - keep);
    }
}
