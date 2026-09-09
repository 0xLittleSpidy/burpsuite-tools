// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.*;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * High-performance, zero-dependency intelligence miner for JavaScript source files
 * and unpacked Source Maps.
 *
 * <p>Integrates:
 * <ol>
 *   <li><b>Ghost-Js Secrets Engine:</b> 40+ curated signatures with category, severity,
 *       confidence, Shannon entropy scoring, and false-positive suppression.</li>
 *   <li><b>js-recon Reconnaissance:</b> Webpack chunk extraction, client-side route
 *       extraction (Next.js, Vue, React), and LinkFinder 5-arm endpoint detection.</li>
 *   <li><b>Performance & Zero-Freeze Protections:</b> 5MB size ceiling, execution
 *       deadline budget (prevents ReDoS), and exact start/end character offsets for
 *       native Burp deep-linking navigation.</li>
 * </ol>
 *
 * @author littlespidy
 */
public class SecretAndEndpointMiner {

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

    private static final List<CuratedSecret> CURATED_PATTERNS = List.of(
        // ── Cloud Secrets ──
        curated("AWS Access Key", "Cloud Secrets", "Critical", 95,
            Pattern.compile("(?<![A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])"), false),
        new CuratedSecret("AWS Secret Access Key", "Cloud Secrets", "Critical", 80,
            Pattern.compile("(?i)(?:aws[_-]?secret[_-]?(?:access[_-]?)?key|secret[_-]?access[_-]?key)\\s*[=:\"']\\s*[\"']?([A-Za-z0-9/+]{38,40}={0,2})[\"']?"), true),
        new CuratedSecret("AWS Session Token", "Cloud Secrets", "Critical", 95,
            Pattern.compile("(?<![A-Za-z0-9/+=])(ASIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])"), false),
        new CuratedSecret("Google API Key", "Cloud Secrets", "Low", 90,
            Pattern.compile("AIza[0-9A-Za-z-_]{35}"), false),
        new CuratedSecret("Google OAuth Client Secret", "Cloud Secrets", "Critical", 95,
            Pattern.compile("GOCSPX-[A-Za-z0-9_-]{28}"), false),
        new CuratedSecret("Firebase API Key", "Cloud Secrets", "Medium", 85,
            Pattern.compile("(?i)['\"](?:apiKey|appId)['\"]\\s*[:=]\\s*['\"]([A-Za-z0-9_-]{20,})['\"]"), false),
        new CuratedSecret("Firebase Configuration Block", "Cloud Secrets", "Medium", 85,
            Pattern.compile("(?i)apiKey[\\s]*[=:]\\s*[\"']([A-Za-z0-9_-]{20,})[\"'][\\s\\S]{0,400}?(?:authDomain|databaseURL|projectId|storageBucket)"), false),
        new CuratedSecret("Azure Storage Connection String", "Cloud Secrets", "Critical", 95,
            Pattern.compile("(?i)DefaultEndpointsProtocol\\s*=\\s*https?[\\s\\S]{0,300}?AccountKey\\s*=\\s*([A-Za-z0-9+/]{86,88}={1,2})"), false),
        new CuratedSecret("Azure SharedAccessKey", "Cloud Secrets", "Critical", 90,
            Pattern.compile("(?i)SharedAccessKey\\s*=\\s*([A-Za-z0-9+/]{40,}={1,2})"), false),
        new CuratedSecret("DigitalOcean Token", "Cloud Secrets", "Critical", 98,
            Pattern.compile("dop_v1_[a-f0-9]{64}"), false),
        new CuratedSecret("Cloudflare API Token", "Cloud Secrets", "Critical", 75,
            Pattern.compile("(?i)(?:cloudflare|cf)[_\\s-]*(?:api|token|key)[\\s:=\"']*([A-Za-z0-9_-]{40,})"), true),
        new CuratedSecret("Heroku API Key", "Cloud Secrets", "Critical", 85,
            Pattern.compile("(?i)(?:heroku)[_\\s-]*(?:api|key)[\\s:=\"']*[\"']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})[\"']?"), false),

        // ── Financial & Payment Secrets ──
        new CuratedSecret("Stripe Live Secret Key", "Payment & Financial Secrets", "Critical", 98,
            Pattern.compile("sk_live_[A-Za-z0-9]{20,}"), false),
        new CuratedSecret("Stripe Restricted Key", "Payment & Financial Secrets", "Critical", 98,
            Pattern.compile("rk_live_[A-Za-z0-9]{20,}"), false),
        new CuratedSecret("PayPal Secret", "Payment & Financial Secrets", "Critical", 75,
            Pattern.compile("(?i)(?:paypal)[_\\s-]*(?:secret|key)[\\s:=\"']*([A-Za-z0-9_-]{20,})"), true),
        new CuratedSecret("Square Access Token", "Payment & Financial Secrets", "Critical", 90,
            Pattern.compile("sq0atp-[0-9A-Za-z_-]{22}"), false),
        new CuratedSecret("Square OAuth Secret", "Payment & Financial Secrets", "Critical", 90,
            Pattern.compile("sq0csp-[0-9A-Za-z_-]{43}"), false),

        // ── Source Control & CI/CD ──
        new CuratedSecret("GitHub Personal Access Token", "Source Control Tokens", "Critical", 98,
            Pattern.compile("ghp_[A-Za-z0-9]{36}"), false),
        new CuratedSecret("GitHub Fine-Grained PAT", "Source Control Tokens", "Critical", 98,
            Pattern.compile("github_pat_[A-Za-z0-9_]{82}"), false),
        new CuratedSecret("GitLab Personal Access Token", "Source Control Tokens", "Critical", 98,
            Pattern.compile("glpat-[A-Za-z0-9-_]{20,}"), false),
        new CuratedSecret("Bitbucket Token", "Source Control Tokens", "High", 70,
            Pattern.compile("(?i)(?:bitbucket)[_\\s-]*(?:token|secret)[\\s:=\"']*([A-Za-z0-9_-]{20,})"), true),
        new CuratedSecret("Vercel Token", "CI/CD & DevOps Secrets", "High", 75,
            Pattern.compile("(?i)(?:vercel)[_\\s-]*(?:token|key)[\\s:=\"']*([A-Za-z0-9_-]{24,})"), true),
        new CuratedSecret("Netlify Token", "CI/CD & DevOps Secrets", "High", 75,
            Pattern.compile("(?i)(?:netlify)[_\\s-]*(?:token|key|auth)[\\s:=\"']*([A-Za-z0-9_-]{40,})"), true),
        new CuratedSecret("npm Access Token", "Package Registry Secrets", "Critical", 98,
            Pattern.compile("npm_[A-Za-z0-9]{36}"), false),

        // ── API & Auth Secrets ──
        new CuratedSecret("JSON Web Token (JWT)", "API & Auth Secrets", "Medium", 80,
            Pattern.compile("eyJ[A-Za-z0-9-_]{10,}\\.eyJ[A-Za-z0-9-_]{10,}\\.[A-Za-z0-9-_]{10,}"), false),
        new CuratedSecret("Hardcoded Bearer Token", "API & Auth Secrets", "High", 85,
            Pattern.compile("[\"']Bearer\\s+([A-Za-z0-9._~+/-]{20,})[\"']"), true),
        new CuratedSecret("Hardcoded Authorization Header", "API & Auth Secrets", "High", 90,
            Pattern.compile("(?i)[\"'](?:Authorization)[\"']\\s*:\\s*[\"'](?:Bearer|Basic|Token)\\s+([A-Za-z0-9._~+/-]{10,})[\"']"), false),
        new CuratedSecret("Generic API Secret Key", "API & Auth Secrets", "High", 75,
            Pattern.compile("(?i)['\"](?:api[_-]?key|auth[_-]?token|access[_-]?token|secret[_-]?key|client[_-]?secret)['\"]\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-]{16,})['\"]"), true),
        new CuratedSecret("OAuth Refresh Token", "API & Auth Secrets", "Critical", 80,
            Pattern.compile("(?i)(?:refresh_token)[\\s]*[=:]\\s*[\"']([A-Za-z0-9._~+/-]{20,})[\"']"), true),

        // ── AI & ML Secrets ──
        new CuratedSecret("OpenAI Project Key", "AI & ML Secrets", "Critical", 98,
            Pattern.compile("sk-proj-[A-Za-z0-9_-]{40,}"), false),
        new CuratedSecret("OpenAI Classic Key", "AI & ML Secrets", "Critical", 98,
            Pattern.compile("sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"), false),
        new CuratedSecret("Anthropic API Key", "AI & ML Secrets", "Critical", 98,
            Pattern.compile("sk-ant-[A-Za-z0-9_-]{80,}"), false),
        new CuratedSecret("HuggingFace Token", "AI & ML Secrets", "High", 95,
            Pattern.compile("hf_[A-Za-z0-9]{34,}"), false),
        new CuratedSecret("Cohere API Key", "AI & ML Secrets", "High", 75,
            Pattern.compile("(?i)(?:cohere)[_\\s-]*(?:api|key)[\\s:=\"']*[\"']?([A-Za-z0-9]{40})[\"']?"), false),

        // ── Messaging & Email ──
        new CuratedSecret("SendGrid API Key", "Email & Messaging Secrets", "Critical", 98,
            Pattern.compile("SG\\.[A-Za-z0-9_-]{22,}\\.[A-Za-z0-9_-]{22,}"), false),
        new CuratedSecret("Mailgun Private Key", "Email & Messaging Secrets", "High", 90,
            Pattern.compile("key-[A-Za-z0-9]{32}"), false),
        new CuratedSecret("Twilio Auth Token", "Email & Messaging Secrets", "Critical", 85,
            Pattern.compile("(?i)(?:twilio)[_\\s-]*(?:auth)?[_\\s-]*(?:token)[\\s:=\"']*([a-f0-9]{32})"), false),
        new CuratedSecret("Slack Token", "SaaS Tokens", "Critical", 95,
            Pattern.compile("xox[baprs]-[A-Za-z0-9-]{10,}"), false),
        new CuratedSecret("Discord Bot Token", "SaaS Tokens", "High", 85,
            Pattern.compile("[MN][A-Za-z\\d]{23,}\\.[\\w-]{6}\\.[\\w-]{27,}"), false),
        new CuratedSecret("Algolia Admin API Key", "SaaS Tokens", "Critical", 80,
            Pattern.compile("(?i)(?:algolia)[_\\s-]*(?:admin)?[_\\s-]*(?:api[_-]?key|key)[\\s:=\"']*([a-f0-9]{32})"), false),

        // ── Database Credentials ──
        new CuratedSecret("MongoDB Connection String", "Database Credentials", "Critical", 90,
            Pattern.compile("mongodb(?:\\+srv)?:\\/\\/[^\\s\"'<>]{10,}"), false),
        new CuratedSecret("PostgreSQL Connection String", "Database Credentials", "Critical", 90,
            Pattern.compile("postgres(?:ql)?:\\/\\/[^\\s\"'<>]{10,}"), false),
        new CuratedSecret("Database URL (MySQL/MSSQL)", "Database Credentials", "Critical", 90,
            Pattern.compile("(?i)[\"']((?:mysql|mariadb|mssql|sqlserver):\\/\\/[^\\s\"'<>]{10,})[\"']"), false),
        new CuratedSecret("Redis URI with Auth", "Database Credentials", "High", 85,
            Pattern.compile("redis:\\/\\/[^\\s\"'<>]{10,}"), false),

        // ── Private Keys ──
        new CuratedSecret("PEM Private Key", "Private Keys", "Critical", 98,
            Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), false),
        new CuratedSecret("Encrypted Private Key", "Private Keys", "High", 90,
            Pattern.compile("-----BEGIN ENCRYPTED PRIVATE KEY-----"), false)
    );

    private static final List<CuratedSecret> ALL_PATTERNS = new ArrayList<>();

    static {
        ALL_PATTERNS.addAll(CURATED_PATTERNS);
        loadResourceSignatures();
    }

    private static void loadResourceSignatures() {
        try (InputStream is = SecretAndEndpointMiner.class.getResourceAsStream("/com/littlespidy/jssourcemapexplorer/signatures.tsv")) {
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
                        ALL_PATTERNS.add(new CuratedSecret(name, category, "High", confidence, p, needsEntropy, kws));
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {}
    }

    // ── Variable Assignment Regex (JS-Miner) ──
    private static final Pattern VARIABLE_SECRETS_REGEX = Pattern.compile(
        "['\"`]?(?:\\w*\\s*)" +
        "(secret|token|password|passwd|authorization|bearer|aws_access_key_id|aws_secret_access_key|" +
        "secret[_-]?(?:key|token)|api[_-]?(?:key|token)|access[_-]?(?:key|token)|auth[_-]?(?:key|token)|" +
        "session[_-]?(?:key|token)|client[_-]?(?:id|token|key)|ssh[_-]?key|github[_-]?token|slack[_-]?token)" +
        "(?:\\w*\\s*)['\"`]?\\s*[:=]+[:=>]?\\s*['\"`]\\s*([\\w\\-/~!@#$%^&*+]{8,})\\s*['\"`]",
        Pattern.CASE_INSENSITIVE
    );

    // ── HTTP Basic Auth ──
    private static final Pattern HTTP_BASIC_AUTH_REGEX = Pattern.compile(
        "Authorization.{0,5}Basic\\s*([A-Za-z0-9+/=]{8,})",
        Pattern.CASE_INSENSITIVE
    );

    public static List<SecretSignatureInfo> getCuratedSignatures() {
        List<SecretSignatureInfo> list = new ArrayList<>();
        for (CuratedSecret cs : ALL_PATTERNS) {
            list.add(new SecretSignatureInfo(cs.name(), cs.category(), cs.pattern().pattern(), cs.confidence(), cs.needsEntropy()));
        }
        list.add(new SecretSignatureInfo("Variable Entropy Scan", "Variable Assignment", VARIABLE_SECRETS_REGEX.pattern(), 80, true));
        list.add(new SecretSignatureInfo("HTTP Basic Auth", "HTTP Basic Auth", HTTP_BASIC_AUTH_REGEX.pattern(), 95, false));
        return Collections.unmodifiableList(list);
    }

    public static List<String> getAllCategories() {
        Set<String> cats = new LinkedHashSet<>();
        cats.add("All Categories");
        for (CuratedSecret cs : ALL_PATTERNS) {
            cats.add(cs.category());
        }
        cats.add("Variable Assignment");
        cats.add("HTTP Basic Auth");
        return new ArrayList<>(cats);
    }

    public static List<String> getAllSignatureNames() {
        List<String> names = new ArrayList<>();
        names.add("All Signatures");
        for (CuratedSecret cs : ALL_PATTERNS) {
            names.add(cs.name());
        }
        names.add("Variable Entropy Scan");
        names.add("HTTP Basic Auth");
        return names;
    }

    // ── Cloud Services Regex ──
    private static final Pattern CLOUD_URLS_REGEX = Pattern.compile(
        "([\\w.-]+[.])" +
        "(s3\\.amazonaws\\.com|rds\\.amazonaws\\.com|cache\\.amazonaws\\.com|" +
        "blob\\.core\\.windows\\.net|onedrive\\.live\\.com|1drv\\.com|" +
        "storage\\.googleapis\\.com|storage\\.cloud\\.google\\.com|" +
        "cloudfront\\.net|digitaloceanspaces\\.com|oraclecloud\\.com|" +
        "aliyuncs\\.com|firebaseio\\.com|rackcdn\\.com|dream\\.io)",
        Pattern.CASE_INSENSITIVE
    );

    // ── Dependencies ──
    private static final Pattern DEPENDENCIES_BLOCK_REGEX = Pattern.compile(
        "\"dependencies[a-zA-Z0-9_-]*\"\\s*:\\s*\\{([^}]+)\\}", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern NODE_MODULES_PATH_REGEX = Pattern.compile(
        "/node_modules/(@?[a-zA-Z0-9._-]+)/?"
    );
    private static final Pattern DEPENDENCY_KEY_VALUE_REGEX = Pattern.compile(
        "\"([@a-zA-Z0-9._-]+)\"\\s*:\\s*\"([^\"]+)\""
    );

    // ── Method-Specific HTTP Client Calls ──
    private static final Pattern METHOD_CALL_REGEX = Pattern.compile(
        "\\.[$]?(get|post|put|delete|patch)\\(['\"`]([^'\"`\\r\\n]+)['\"`]"
    );

    // ── LinkFinder 5-Arm Pattern ──
    private static final Pattern LINKFINDER_PATTERN = Pattern.compile(
        "(?:\"|')(" +
        "(?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,}" +
        "|(?:/|\\.\\./|\\./)+[^\"'><,;| *()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,}" +
        "|[a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/.]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[?#][^\"']{0,}|)" +
        "|[a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{3,}(?:[?#][^\"']{0,}|)" +
        "|[a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[?#][^\"']{0,}|)" +
        ")(?:\"|')"
    );

    // ── Next.js / React Router client-side path pattern ──
    private static final Pattern CLIENT_SIDE_HREF_PATTERN = Pattern.compile(
        "(?:href|to|route|path)\\s*[:=]\\s*[\"'](/[a-zA-Z0-9_\\-/{}.?&=#]+)[\"']"
    );

    private static final List<Pattern> NOISE_FILTERS = List.of(
        Pattern.compile("^[0-9./]+$"),
        Pattern.compile("(?i)^[a-z]{1,2}\\.[a-z]{1,4}$"),
        Pattern.compile("(?i)\\.(?:png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|css|map)(?:[?#].*)?$"),
        Pattern.compile("(?i)^(?:e\\.g|i\\.e|etc|null|undefined|true|false)\\."),
        Pattern.compile("^//[\\s*#]")
    );

    public record MiningResult(
        List<DiscoveredSecret> secrets,
        List<DiscoveredEndpoint> endpoints,
        List<DiscoveredCloudUrl> cloudUrls,
        List<DiscoveredDependency> dependencies
    ) {}

    /**
     * Primary mining entry point. Analyzes raw source code with size ceilings and execution budgets.
     */
    public static MiningResult mine(String sourceLocation, String sourceType, String sourceCode) {
        if (sourceCode == null || sourceCode.trim().isEmpty()) {
            return new MiningResult(Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
        }

        // Cap analysis to 5MB to prevent memory exhaustion / OOM
        String scannable = sourceCode.length() > 5_000_000 ? sourceCode.substring(0, 5_000_000) : sourceCode;
        long deadline = System.nanoTime() + 2_500_000_000L; // 2.5 second budget

        List<DiscoveredSecret> secrets = new ArrayList<>();
        List<DiscoveredEndpoint> endpoints = new ArrayList<>();
        List<DiscoveredCloudUrl> cloudUrls = new ArrayList<>();
        List<DiscoveredDependency> dependencies = new ArrayList<>();

        Set<String> seenEndpoints = new HashSet<>();
        Set<String> seenSecrets = new HashSet<>();
        Set<String> seenCloudUrls = new HashSet<>();
        Set<String> seenDependencies = new HashSet<>();

        // 1. Dependency Confusion Blocks
        Matcher depBlockMatcher = DEPENDENCIES_BLOCK_REGEX.matcher(scannable);
        while (depBlockMatcher.find()) {
            if (System.nanoTime() > deadline) break;
            String block = depBlockMatcher.group(1);
            Matcher entryMatcher = DEPENDENCY_KEY_VALUE_REGEX.matcher(block);
            while (entryMatcher.find()) {
                String pkgName = entryMatcher.group(1).trim();
                String version = entryMatcher.group(2).trim();
                if (isValidPackageName(pkgName) && seenDependencies.add(pkgName)) {
                    int start = depBlockMatcher.start();
                    int end = depBlockMatcher.end();
                    dependencies.add(new DiscoveredDependency(
                        sourceLocation, sourceType, pkgName, version,
                        "package.json dependencies", "Unverified", "-",
                        getLineNumber(scannable, start), start, end,
                        "\"" + pkgName + "\": \"" + version + "\""
                    ));
                }
            }
        }

        // 2. Node Modules path disclosure
        Matcher nodeModMatcher = NODE_MODULES_PATH_REGEX.matcher(scannable);
        while (nodeModMatcher.find()) {
            if (System.nanoTime() > deadline) break;
            String pkgName = nodeModMatcher.group(1).trim();
            if (isValidPackageName(pkgName) && seenDependencies.add(pkgName)) {
                int start = nodeModMatcher.start();
                int end = nodeModMatcher.end();
                dependencies.add(new DiscoveredDependency(
                    sourceLocation, sourceType, pkgName, "-",
                    "node_modules path", "Unverified", "-",
                    getLineNumber(scannable, start), start, end,
                    getSnippet(scannable, start, end)
                ));
            }
        }

        // 3. Ghost-Js & TruffleHog Curated Secret Scanning with Entropy Engine & Keyword Pre-Filter
        String scannableLower = scannable.toLowerCase(Locale.ROOT);
        for (CuratedSecret cs : ALL_PATTERNS) {
            if (System.nanoTime() > deadline) break;
            if (cs.keywords() != null && !cs.keywords().isEmpty()) {
                boolean matchedKw = false;
                for (String kw : cs.keywords()) {
                    if (scannableLower.contains(kw)) {
                        matchedKw = true;
                        break;
                    }
                }
                if (!matchedKw) continue;
            }
            try {
                Matcher m = cs.pattern().matcher(scannable);
                int guard = 0;
                while (m.find() && guard < 100) {
                    guard++;
                    String secretVal = m.group(m.groupCount() >= 1 && m.group(1) != null ? 1 : 0);
                    if (secretVal == null || secretVal.isBlank()) continue;

                    // Suppress false positives via Entropy heuristics
                    if (Entropy.isLikelyFalsePositive(secretVal, cs.name(), cs.needsEntropy())) continue;
                    if (!seenSecrets.add(secretVal)) continue;

                    double entropy = Entropy.shannon(secretVal);
                    String confidence = cs.confidence() >= 85 ? "High [Firm]" : "Low [Tentative]";
                    int start = m.start();
                    int end = m.end();

                    secrets.add(new DiscoveredSecret(
                        sourceLocation, sourceType, cs.category(), secretVal.strip(),
                        cs.severity(), entropy, confidence, cs.name(),
                        getLineNumber(scannable, start), start, end,
                        getSnippet(scannable, start, end)
                    ));
                }
            } catch (Exception ignored) {}
        }

        // 4. Variable Assignment Entropy Scan
        if (System.nanoTime() <= deadline) {
            try {
                Matcher varMatcher = VARIABLE_SECRETS_REGEX.matcher(scannable);
                int guard = 0;
                while (varMatcher.find() && guard < 80) {
                    guard++;
                    String varName = varMatcher.group(1);
                    String secretVal = varMatcher.group(2);
                    if (secretVal != null && !Entropy.isLikelyFalsePositive(secretVal, varName, true) && seenSecrets.add(secretVal)) {
                        double entropy = Entropy.shannon(secretVal);
                        int start = varMatcher.start();
                        int end = varMatcher.end();
                        secrets.add(new DiscoveredSecret(
                            sourceLocation, sourceType, "Variable: " + varName, secretVal.strip(),
                            "High", entropy, entropy >= 3.5 ? "High [Firm]" : "Low [Tentative]",
                            "Variable Entropy Scan", getLineNumber(scannable, start), start, end,
                            getSnippet(scannable, start, end)
                        ));
                    }
                }
            } catch (Exception ignored) {}
        }

        // 5. HTTP Basic Auth
        if (System.nanoTime() <= deadline) {
            Matcher basicAuthMatcher = HTTP_BASIC_AUTH_REGEX.matcher(scannable);
            while (basicAuthMatcher.find()) {
                String b64 = basicAuthMatcher.group(1);
                if (b64 != null && isValidBase64(b64)) {
                    String decoded = b64Decode(b64);
                    if (decoded != null && !Entropy.isLikelyFalsePositive(decoded, "Basic Auth", false) && seenSecrets.add(b64)) {
                        int start = basicAuthMatcher.start();
                        int end = basicAuthMatcher.end();
                        secrets.add(new DiscoveredSecret(
                            sourceLocation, sourceType, "HTTP Basic Auth", b64 + " (" + decoded + ")",
                            "Critical", Entropy.shannon(decoded), "High [Firm]",
                            "HTTP Basic Auth", getLineNumber(scannable, start), start, end,
                            getSnippet(scannable, start, end)
                        ));
                    }
                }
            }
        }

        // 6. Cloud URLs & Buckets
        if (System.nanoTime() <= deadline) {
            Matcher cloudMatcher = CLOUD_URLS_REGEX.matcher(scannable);
            while (cloudMatcher.find()) {
                String url = cloudMatcher.group(0);
                if (url != null && seenCloudUrls.add(url)) {
                    int start = cloudMatcher.start();
                    int end = cloudMatcher.end();
                    cloudUrls.add(new DiscoveredCloudUrl(
                        sourceLocation, sourceType, classifyCloudProvider(url), url,
                        getLineNumber(scannable, start), start, end,
                        getSnippet(scannable, start, end)
                    ));
                }
            }
        }

        // 7. Method-Specific HTTP Client Calls (.get, .post, etc.)
        if (System.nanoTime() <= deadline) {
            Matcher mcm = METHOD_CALL_REGEX.matcher(scannable);
            while (mcm.find()) {
                String method = mcm.group(1).toUpperCase();
                String rawTarget = mcm.group(2).trim();
                if (isValidEndpointPath(rawTarget) && seenEndpoints.add(rawTarget)) {
                    int start = mcm.start();
                    int end = mcm.end();
                    endpoints.add(new DiscoveredEndpoint(
                        sourceLocation, sourceType, rawTarget, method,
                        getLineNumber(scannable, start), start, end,
                        getSnippet(scannable, start, end), "HTTP Verb Call"
                    ));
                }
            }
        }

        // 8. Next.js / React Router Client-Side Routes
        if (System.nanoTime() <= deadline) {
            Matcher hrefMatcher = CLIENT_SIDE_HREF_PATTERN.matcher(scannable);
            while (hrefMatcher.find()) {
                String route = hrefMatcher.group(1).trim();
                if (isValidEndpointPath(route) && seenEndpoints.add(route)) {
                    int start = hrefMatcher.start();
                    int end = hrefMatcher.end();
                    endpoints.add(new DiscoveredEndpoint(
                        sourceLocation, sourceType, route, "ROUTE",
                        getLineNumber(scannable, start), start, end,
                        getSnippet(scannable, start, end), "Client Route"
                    ));
                }
            }
        }

        // 9. LinkFinder 5-Arm Engine
        if (System.nanoTime() <= deadline) {
            Matcher lfMatcher = LINKFINDER_PATTERN.matcher(scannable);
            int count = 0;
            while (lfMatcher.find() && count < 300) {
                count++;
                String path = lfMatcher.group(1);
                if (path == null || path.length() < 3) continue;
                if (isNoise(path)) continue;
                if (!seenEndpoints.add(path)) continue;

                int start = lfMatcher.start();
                int end = lfMatcher.end();
                endpoints.add(new DiscoveredEndpoint(
                    sourceLocation, sourceType, path, "GET",
                    getLineNumber(scannable, start), start, end,
                    getSnippet(scannable, start, end), classifyLinkFinderArm(path)
                ));
            }
        }

        // 10. Webpack Lazy-Loaded Chunk Extraction (js-recon)
        try {
            Set<String> chunks = WebpackChunkExtractor.extractChunkUrls(sourceLocation, scannable);
            for (String chunk : chunks) {
                if (seenEndpoints.add(chunk)) {
                    endpoints.add(new DiscoveredEndpoint(
                        sourceLocation, sourceType, chunk, "GET",
                        1, 0, 0, "Lazy-loaded Webpack Chunk: " + chunk, "Webpack Chunk"
                    ));
                }
            }
        } catch (Exception ignored) {}

        return new MiningResult(secrets, endpoints, cloudUrls, dependencies);
    }

    private static String classifyCloudProvider(String url) {
        String lower = url.toLowerCase();
        if (lower.contains("amazonaws.com") || lower.contains("cloudfront.net")) return "AWS";
        if (lower.contains("windows.net") || lower.contains("live.com") || lower.contains("1drv.com")) return "Azure";
        if (lower.contains("googleapis.com")) return "Google Cloud";
        if (lower.contains("firebaseio.com")) return "Firebase";
        if (lower.contains("digitaloceanspaces.com")) return "DigitalOcean";
        if (lower.contains("oraclecloud.com")) return "Oracle Cloud";
        if (lower.contains("aliyuncs.com")) return "Alibaba Cloud";
        if (lower.contains("rackcdn.com")) return "Rackspace";
        if (lower.contains("dream.io")) return "DreamHost";
        return "Cloud Resource";
    }

    private static String classifyLinkFinderArm(String path) {
        if (path.startsWith("http://") || path.startsWith("https://") || path.startsWith("//")) return "Absolute URL";
        if (path.startsWith("/") || path.startsWith("./") || path.startsWith("../")) return "Relative Path";
        if (path.contains("/") && !path.contains("?")) return "REST Endpoint";
        if (path.contains(".")) return "File Extension";
        return "Relative Path";
    }

    private static boolean isValidEndpointPath(String path) {
        if (path == null || path.length() < 2) return false;
        if (path.contains("<") || path.contains(">") || path.contains(";") || path.contains("{")) return false;
        return path.contains("/");
    }

    private static boolean isValidPackageName(String name) {
        if (name == null || name.isEmpty() || name.length() > 214) return false;
        if (name.startsWith(".") || name.startsWith("_")) return false;
        if ("node_modules".equalsIgnoreCase(name) || "favicon.ico".equalsIgnoreCase(name)) return false;
        return true;
    }

    private static boolean isValidBase64(String s) {
        try {
            Base64.getDecoder().decode(s.trim());
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static String b64Decode(String s) {
        try {
            byte[] decoded = Base64.getDecoder().decode(s.trim());
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isNoise(String path) {
        for (Pattern noise : NOISE_FILTERS) {
            if (noise.matcher(path).find()) return true;
        }
        return false;
    }

    private static int getLineNumber(String text, int offset) {
        int line = 1;
        int limit = Math.min(offset, text.length());
        for (int i = 0; i < limit; i++) {
            if (text.charAt(i) == '\n') line++;
        }
        return line;
    }

    private static String getSnippet(String text, int start, int end) {
        int s = Math.max(0, start - 30);
        int e = Math.min(text.length(), end + 30);
        String sub = text.substring(s, e).replaceAll("\\s+", " ").strip();
        return sub.length() > 140 ? sub.substring(0, 137) + "..." : sub;
    }
}
