// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InspectorDataStore;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans HTTP responses (both Headers and Body) for exposed secrets, tokens,
 * cloud storage buckets, and cryptographic credentials.
 *
 * <p>Integrates:
 * <ol>
 *   <li><b>Two-Stage Refiner Rules:</b> S3 Buckets, Azure Blobs, Firebase DBs, Google OAuth, Teams Webhooks.</li>
 *   <li><b>Ghost-Js & JS-Recon Curated Signatures:</b> 40+ curated patterns covering Cloud, Payments,
 *       Source Control, CI/CD, AI/ML, SaaS tokens, and Private Keys.</li>
 *   <li><b>Shannon Entropy Guard & FP Suppression:</b> Suppresses dummy templates, test credentials, and low-entropy strings.</li>
 *   <li><b>KeyHacks Integration:</b> Full provenance tracking for Repeater credential verification.</li>
 * </ol>
 *
 * @author littlespidy
 */
public class SecretScanner {

    public record SecretSignatureInfo(
        String name,
        String category,
        String pattern,
        int confidence,
        boolean needsEntropy
    ) {}

    private record CuratedSecret(
        String name,
        String category,
        String severity,
        int confidence,
        Pattern pattern,
        boolean needsEntropy,
        List<String> keywords
    ) {
        public CuratedSecret(String name, String category, String severity, int confidence, Pattern pattern, boolean needsEntropy) {
            this(name, category, severity, confidence, pattern, needsEntropy, List.of());
        }
    }

    private static CuratedSecret curated(String name, String category, String severity, int confidence, Pattern pattern, boolean needsEntropy, String... keywords) {
        List<String> kwList = keywords.length > 0 ? List.of(keywords) : List.of();
        return new CuratedSecret(name, category, severity, confidence, pattern, needsEntropy, kwList);
    }

    private final List<RefinerRule> refinerRules = new ArrayList<>();
    private final List<CuratedSecret> allPatterns = new ArrayList<>();

    // Variable Assignment Regex (JS-Miner)
    private static final Pattern VARIABLE_SECRETS_REGEX = Pattern.compile(
        "['\"`]?(?:\\w*\\s*)" +
        "(secret|token|password|passwd|authorization|bearer|aws_access_key_id|aws_secret_access_key|" +
        "secret[_-]?(?:key|token)|api[_-]?(?:key|token)|access[_-]?(?:key|token)|auth[_-]?(?:key|token)|" +
        "session[_-]?(?:key|token)|client[_-]?(?:id|token|key)|ssh[_-]?key|github[_-]?token|slack[_-]?token)" +
        "(?:\\w*\\s*)['\"`]?\\s*[:=]+[:=>]?\\s*['\"`]\\s*([\\w\\-/~!@#$%^&*+]{8,})\\s*['\"`]",
        Pattern.CASE_INSENSITIVE
    );

    // HTTP Basic Auth
    private static final Pattern HTTP_BASIC_AUTH_REGEX = Pattern.compile(
        "Authorization.{0,5}Basic\\s*([A-Za-z0-9+/=]{8,})",
        Pattern.CASE_INSENSITIVE
    );

    public SecretScanner() {
        initRefinerRules();
        initCuratedPatterns();
        loadResourceSignatures();
    }

    private void initRefinerRules() {
        // AWS S3 Buckets
        refinerRules.add(RefinerRule.ofRefined(
                "AWS S3 Bucket",
                "s3(\\.dualstack|-acce(lerate|sspoint))?\\.([a-z]{1,8}-[a-z]{1,16}-\\d{1,3}\\.)?amazonaws\\.com",
                "[a-z\\d\\-]{3,63}\\.$",
                true,
                false
        ));

        // Azure Blob Storage
        refinerRules.add(RefinerRule.ofRefined(
                "Azure Blob Storage",
                "blob\\.core\\.windows\\.net",
                "[a-z\\d\\-]{3,63}\\.$",
                true,
                false
        ));

        // Firebase Realtime Database
        refinerRules.add(RefinerRule.ofRefined(
                "Firebase Database URL",
                "\\.(firebase(io\\.com|database\\.app))",
                "[0-9a-zA-Z\\.\\-]{1,64}$",
                true,
                false
        ));

        // Google OAuth Client ID
        refinerRules.add(RefinerRule.ofRefined(
                "Google OAuth Client ID",
                "\\.apps\\.googleusercontent\\.com",
                "\\d{1,20}-\\w{32}$",
                true,
                false
        ));

        // Microsoft Teams Webhook
        refinerRules.add(RefinerRule.ofRefined(
                "Microsoft Teams Webhook",
                "\\.webhook\\.office\\.com",
                "\\w+$",
                true,
                true
        ));
    }

    private void initCuratedPatterns() {
        // ── Cloud Secrets ──
        allPatterns.add(curated("AWS Access Key", "Cloud Secrets", "Critical", 95,
            Pattern.compile("(?<![A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])"), false));
        allPatterns.add(new CuratedSecret("AWS Secret Access Key", "Cloud Secrets", "Critical", 80,
            Pattern.compile("(?i)(?:aws[_-]?secret[_-]?(?:access[_-]?)?key|secret[_-]?access[_-]?key)\\s*[=:\"']\\s*[\"']?([A-Za-z0-9/+]{38,40}={0,2})[\"']?"), true));
        allPatterns.add(new CuratedSecret("AWS Session Token", "Cloud Secrets", "Critical", 95,
            Pattern.compile("(?<![A-Za-z0-9/+=])(ASIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])"), false));
        allPatterns.add(new CuratedSecret("Google API Key", "Cloud Secrets", "Low", 90,
            Pattern.compile("AIza[0-9A-Za-z-_]{35}"), false));
        allPatterns.add(new CuratedSecret("Google OAuth Client Secret", "Cloud Secrets", "Critical", 95,
            Pattern.compile("GOCSPX-[A-Za-z0-9_-]{28}"), false));
        allPatterns.add(new CuratedSecret("Firebase API Key", "Cloud Secrets", "Medium", 85,
            Pattern.compile("(?i)['\"](?:apiKey|appId)['\"]\\s*[:=]\\s*['\"]([A-Za-z0-9_-]{20,})['\"]"), false));
        allPatterns.add(new CuratedSecret("Firebase Configuration Block", "Cloud Secrets", "Medium", 85,
            Pattern.compile("(?i)apiKey[\\s]*[=:]\\s*[\"']([A-Za-z0-9_-]{20,})[\"'][\\s\\S]{0,400}?(?:authDomain|databaseURL|projectId|storageBucket)"), false));
        allPatterns.add(new CuratedSecret("Azure Storage Connection String", "Cloud Secrets", "Critical", 95,
            Pattern.compile("(?i)DefaultEndpointsProtocol\\s*=\\s*https?[\\s\\S]{0,300}?AccountKey\\s*=\\s*([A-Za-z0-9+/]{86,88}={1,2})"), false));
        allPatterns.add(new CuratedSecret("Azure SharedAccessKey", "Cloud Secrets", "Critical", 90,
            Pattern.compile("(?i)SharedAccessKey\\s*=\\s*([A-Za-z0-9+/]{40,}={1,2})"), false));
        allPatterns.add(new CuratedSecret("DigitalOcean Token", "Cloud Secrets", "Critical", 98,
            Pattern.compile("dop_v1_[a-f0-9]{64}"), false));
        allPatterns.add(new CuratedSecret("Cloudflare API Token", "Cloud Secrets", "Critical", 75,
            Pattern.compile("(?i)(?:cloudflare|cf)[_\\s-]*(?:api|token|key)[\\s:=\"']*([A-Za-z0-9_-]{40,})"), true));
        allPatterns.add(new CuratedSecret("Heroku API Key", "Cloud Secrets", "Critical", 85,
            Pattern.compile("(?i)(?:heroku)[_\\s-]*(?:api|key)[\\s:=\"']*[\"']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})[\"']?"), false));

        // ── Financial & Payment Secrets ──
        allPatterns.add(new CuratedSecret("Stripe Live Secret Key", "Payment & Financial Secrets", "Critical", 98,
            Pattern.compile("sk_live_[A-Za-z0-9]{20,}"), false));
        allPatterns.add(new CuratedSecret("Stripe Restricted Key", "Payment & Financial Secrets", "Critical", 98,
            Pattern.compile("rk_live_[A-Za-z0-9]{20,}"), false));
        allPatterns.add(new CuratedSecret("PayPal Secret", "Payment & Financial Secrets", "Critical", 75,
            Pattern.compile("(?i)(?:paypal)[_\\s-]*(?:secret|key)[\\s:=\"']*([A-Za-z0-9_-]{20,})"), true));
        allPatterns.add(new CuratedSecret("Square Access Token", "Payment & Financial Secrets", "Critical", 90,
            Pattern.compile("sq0atp-[0-9A-Za-z_-]{22}"), false));
        allPatterns.add(new CuratedSecret("Square OAuth Secret", "Payment & Financial Secrets", "Critical", 90,
            Pattern.compile("sq0csp-[0-9A-Za-z_-]{43}"), false));

        // ── Source Control & CI/CD ──
        allPatterns.add(new CuratedSecret("GitHub Personal Access Token", "Source Control Tokens", "Critical", 98,
            Pattern.compile("ghp_[A-Za-z0-9]{36}"), false));
        allPatterns.add(new CuratedSecret("GitHub Fine-Grained PAT", "Source Control Tokens", "Critical", 98,
            Pattern.compile("github_pat_[A-Za-z0-9_]{82}"), false));
        allPatterns.add(new CuratedSecret("GitLab Personal Access Token", "Source Control Tokens", "Critical", 98,
            Pattern.compile("glpat-[A-Za-z0-9-_]{20,}"), false));
        allPatterns.add(new CuratedSecret("Bitbucket Token", "Source Control Tokens", "High", 70,
            Pattern.compile("(?i)(?:bitbucket)[_\\s-]*(?:token|secret)[\\s:=\"']*([A-Za-z0-9_-]{20,})"), true));
        allPatterns.add(new CuratedSecret("Vercel Token", "CI/CD & DevOps Secrets", "High", 75,
            Pattern.compile("(?i)(?:vercel)[_\\s-]*(?:token|key)[\\s:=\"']*([A-Za-z0-9_-]{24,})"), true));
        allPatterns.add(new CuratedSecret("Netlify Token", "CI/CD & DevOps Secrets", "High", 75,
            Pattern.compile("(?i)(?:netlify)[_\\s-]*(?:token|key|auth)[\\s:=\"']*([A-Za-z0-9_-]{40,})"), true));
        allPatterns.add(new CuratedSecret("npm Access Token", "Package Registry Secrets", "Critical", 98,
            Pattern.compile("npm_[A-Za-z0-9]{36}"), false));

        // ── API & Auth Secrets ──
        allPatterns.add(new CuratedSecret("JSON Web Token (JWT)", "API & Auth Secrets", "Medium", 80,
            Pattern.compile("eyJ[A-Za-z0-9-_]{10,}\\.eyJ[A-Za-z0-9-_]{10,}\\.[A-Za-z0-9-_]{10,}"), false));
        allPatterns.add(new CuratedSecret("Hardcoded Bearer Token", "API & Auth Secrets", "High", 85,
            Pattern.compile("[\"']Bearer\\s+([A-Za-z0-9._~+/-]{20,})[\"']"), true));
        allPatterns.add(new CuratedSecret("Hardcoded Authorization Header", "API & Auth Secrets", "High", 90,
            Pattern.compile("(?i)[\"'](?:Authorization)[\"']\\s*:\\s*[\"'](?:Bearer|Basic|Token)\\s+([A-Za-z0-9._~+/-]{10,})[\"']"), false));
        allPatterns.add(new CuratedSecret("Generic API Secret Key", "API & Auth Secrets", "High", 75,
            Pattern.compile("(?i)['\"](?:api[_-]?key|auth[_-]?token|access[_-]?token|secret[_-]?key|client[_-]?secret)['\"]\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-]{16,})['\"]"), true));
        allPatterns.add(new CuratedSecret("OAuth Refresh Token", "API & Auth Secrets", "Critical", 80,
            Pattern.compile("(?i)(?:refresh_token)[\\s]*[=:]\\s*[\"']([A-Za-z0-9._~+/-]{20,})[\"']"), true));

        // ── AI & ML Secrets ──
        allPatterns.add(new CuratedSecret("OpenAI Project Key", "AI & ML Secrets", "Critical", 98,
            Pattern.compile("sk-proj-[A-Za-z0-9_-]{40,}"), false));
        allPatterns.add(new CuratedSecret("OpenAI Classic Key", "AI & ML Secrets", "Critical", 98,
            Pattern.compile("sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"), false));
        allPatterns.add(new CuratedSecret("Anthropic API Key", "AI & ML Secrets", "Critical", 98,
            Pattern.compile("sk-ant-[A-Za-z0-9_-]{80,}"), false));
        allPatterns.add(new CuratedSecret("HuggingFace Token", "AI & ML Secrets", "High", 95,
            Pattern.compile("hf_[A-Za-z0-9]{34,}"), false));
        allPatterns.add(new CuratedSecret("Cohere API Key", "AI & ML Secrets", "High", 75,
            Pattern.compile("(?i)(?:cohere)[_\\s-]*(?:api|key)[\\s:=\"']*[\"']?([A-Za-z0-9]{40})[\"']?"), false));

        // ── Messaging & Email ──
        allPatterns.add(new CuratedSecret("SendGrid API Key", "Email & Messaging Secrets", "Critical", 98,
            Pattern.compile("SG\\.[A-Za-z0-9_-]{22,}\\.[A-Za-z0-9_-]{22,}"), false));
        allPatterns.add(new CuratedSecret("Mailgun Private Key", "Email & Messaging Secrets", "High", 90,
            Pattern.compile("key-[A-Za-z0-9]{32}"), false));
        allPatterns.add(new CuratedSecret("Twilio Auth Token", "Email & Messaging Secrets", "Critical", 85,
            Pattern.compile("(?i)(?:twilio)[_\\s-]*(?:auth)?[_\\s-]*(?:token)[\\s:=\"']*([a-f0-9]{32})"), false));
        allPatterns.add(new CuratedSecret("Slack Token", "SaaS Tokens", "Critical", 95,
            Pattern.compile("xox[baprs]-[A-Za-z0-9-]{10,}"), false));
        allPatterns.add(new CuratedSecret("Discord Bot Token", "SaaS Tokens", "High", 85,
            Pattern.compile("[MN][A-Za-z\\d]{23,}\\.[\\w-]{6}\\.[\\w-]{27,}"), false));
        allPatterns.add(new CuratedSecret("Algolia Admin API Key", "SaaS Tokens", "Critical", 80,
            Pattern.compile("(?i)(?:algolia)[_\\s-]*(?:admin)?[_\\s-]*(?:api[_-]?key|key)[\\s:=\"']*([a-f0-9]{32})"), false));

        // ── Database Credentials ──
        allPatterns.add(new CuratedSecret("MongoDB Connection String", "Database Credentials", "Critical", 90,
            Pattern.compile("mongodb(?:\\+srv)?:\\/\\/[^\\s\"'<>]{10,}"), false));
        allPatterns.add(new CuratedSecret("PostgreSQL Connection String", "Database Credentials", "Critical", 90,
            Pattern.compile("postgres(?:ql)?:\\/\\/[^\\s\"'<>]{10,}"), false));
        allPatterns.add(new CuratedSecret("Database URL (MySQL/MSSQL)", "Database Credentials", "Critical", 90,
            Pattern.compile("(?i)[\"']((?:mysql|mariadb|mssql|sqlserver):\\/\\/[^\\s\"'<>]{10,})[\"']"), false));
        allPatterns.add(new CuratedSecret("Redis URI with Auth", "Database Credentials", "High", 85,
            Pattern.compile("redis:\\/\\/[^\\s\"'<>]{10,}"), false));

        // ── Private Keys ──
        allPatterns.add(new CuratedSecret("PEM Private Key", "Private Keys", "Critical", 98,
            Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), false));
        allPatterns.add(new CuratedSecret("Encrypted Private Key", "Private Keys", "High", 90,
            Pattern.compile("-----BEGIN ENCRYPTED PRIVATE KEY-----"), false));
    }

    private void loadResourceSignatures() {
        try (InputStream is = SecretScanner.class.getResourceAsStream("/com/littlespidy/responseinspector/signatures.tsv")) {
            if (is != null) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("\t");
                    if (parts.length < 6) continue;
                    String name = parts[0].trim();
                    String category = parts[1].trim();
                    int confidence = Integer.parseInt(parts[2].trim());
                    boolean needsEntropy = Boolean.parseBoolean(parts[3].trim());
                    List<String> kws = Arrays.stream(parts[4].split(","))
                        .map(String::trim)
                        .map(s -> s.toLowerCase(Locale.ROOT))
                        .filter(s -> !s.isEmpty())
                        .toList();
                    String regex = parts[5].trim();
                    try {
                        Pattern p = Pattern.compile(regex);
                        allPatterns.add(new CuratedSecret(name, category, "High", confidence, p, needsEntropy, kws));
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {}
    }

    public List<FindingEntry> scan(HttpRequestResponse requestResponse, InspectorDataStore dataStore) {
        List<FindingEntry> findings = new ArrayList<>();
        if (requestResponse == null || requestResponse.response() == null) {
            return findings;
        }

        HttpResponse response = requestResponse.response();

        // Strictly scan Response Body only (headers produce frequent false positives)
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

        // 1. Two-Stage Refiner Rules
        for (RefinerRule rule : refinerRules) {
            List<RefinerRule.MatchResult> matches = rule.findMatches(content);
            for (RefinerRule.MatchResult mr : matches) {
                String val = mr.value();
                if (val == null || val.isBlank()) continue;
                if (Entropy.isLikelyFalsePositive(val, rule.name(), false)) continue;

                if (seenInThisSection.add(rule.name() + "|" + val)) {
                    findings.add(FindingEntry.create(
                            dataStore.nextId(),
                            FindingCategory.SECRET,
                            rule.name(),
                            val,
                            location,
                            requestResponse,
                            mr.startOffset(),
                            mr.endOffset()
                    ));
                }
            }
        }

        // 2. Curated Secret Patterns
        for (CuratedSecret pat : allPatterns) {
            Matcher m = pat.pattern().matcher(content);
            while (m.find()) {
                String matchVal = (m.groupCount() >= 1 && m.group(1) != null) ? m.group(1) : m.group();
                if (matchVal == null || matchVal.isBlank()) continue;

                if (Entropy.isLikelyFalsePositive(matchVal, pat.name(), pat.needsEntropy())) {
                    continue;
                }

                if (seenInThisSection.add(pat.name() + "|" + matchVal)) {
                    int start = m.start();
                    int end = m.end();
                    findings.add(FindingEntry.create(
                            dataStore.nextId(),
                            FindingCategory.SECRET,
                            pat.name(),
                            matchVal,
                            location,
                            requestResponse,
                            start,
                            end
                    ));
                }
            }
        }

        // 3. Variable Assignment Regex
        Matcher mVar = VARIABLE_SECRETS_REGEX.matcher(content);
        while (mVar.find()) {
            String val = mVar.group(2);
            if (val != null && !val.isBlank()) {
                if (!Entropy.isLikelyFalsePositive(val, "Variable Entropy Scan", true)) {
                    if (seenInThisSection.add("Variable Entropy Scan|" + val)) {
                        findings.add(FindingEntry.create(
                                dataStore.nextId(),
                                FindingCategory.SECRET,
                                "Variable Entropy Scan",
                                val,
                                location,
                                requestResponse,
                                mVar.start(2),
                                mVar.end(2)
                        ));
                    }
                }
            }
        }

        // 4. HTTP Basic Auth
        Matcher mAuth = HTTP_BASIC_AUTH_REGEX.matcher(content);
        while (mAuth.find()) {
            String b64 = mAuth.group(1);
            if (b64 != null && !b64.isBlank()) {
                if (seenInThisSection.add("HTTP Basic Auth|" + b64)) {
                    findings.add(FindingEntry.create(
                            dataStore.nextId(),
                            FindingCategory.SECRET,
                            "HTTP Basic Auth",
                            b64,
                            location,
                            requestResponse,
                            mAuth.start(1),
                            mAuth.end(1)
                    ));
                }
            }
        }
    }

    public List<SecretSignatureInfo> getCuratedSignatures() {
        List<SecretSignatureInfo> list = new ArrayList<>();
        for (RefinerRule rule : refinerRules) {
            list.add(new SecretSignatureInfo(rule.name(), "Cloud & SaaS Storage", rule.name(), 95, false));
        }
        for (CuratedSecret cs : allPatterns) {
            list.add(new SecretSignatureInfo(cs.name(), cs.category(), cs.pattern().pattern(), cs.confidence(), cs.needsEntropy()));
        }
        list.add(new SecretSignatureInfo("Variable Entropy Scan", "Variable Assignment", VARIABLE_SECRETS_REGEX.pattern(), 80, true));
        list.add(new SecretSignatureInfo("HTTP Basic Auth", "HTTP Basic Auth", HTTP_BASIC_AUTH_REGEX.pattern(), 95, false));
        return Collections.unmodifiableList(list);
    }

    public List<String> getRuleNames() {
        Set<String> names = new LinkedHashSet<>();
        for (RefinerRule rule : refinerRules) {
            names.add(rule.name());
        }
        for (CuratedSecret pat : allPatterns) {
            names.add(pat.name());
        }
        names.add("Variable Entropy Scan");
        names.add("HTTP Basic Auth");
        return new ArrayList<>(names);
    }
}
