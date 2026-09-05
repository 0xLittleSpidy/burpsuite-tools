// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * High-performance, zero-dependency intelligence miner for JavaScript source files
 * and unpacked Source Maps.
 *
 * <p>Mines four distinct recon facets:
 * <ol>
 *   <li><b>Secrets & Credentials:</b> Specific key signatures, variable assignment entropy scanning,
 *       and HTTP Basic Auth decoded token analysis with Shannon entropy scoring.</li>
 *   <li><b>API Endpoints & Routes:</b> Method-specific HTTP client calls (.get, .post, .put, .delete, .patch),
 *       API namespace routes, relative paths, REST endpoints, and absolute URLs.</li>
 *   <li><b>Cloud URLs & Buckets:</b> Multi-cloud storage buckets, databases, and CDNs across AWS,
 *       Azure, Google Cloud, Firebase, DigitalOcean, Oracle, Alibaba, and DreamHost.</li>
 *   <li><b>Dependencies & Packages:</b> package.json dependency blocks and node_modules path disclosures
 *       for Dependency Confusion auditing.</li>
 * </ol>
 *
 * @author littlespidy
 */
public class SecretAndEndpointMiner {

    // ── 1. Specific High-Confidence Secret Signatures ────────────────────────

    private static final List<SecretPattern> SECRET_PATTERNS = List.of(
        new SecretPattern("JSON Web Token (JWT)",
            Pattern.compile("eyJ[A-Za-z0-9-_]{10,}\\.eyJ[A-Za-z0-9-_]{10,}\\.[A-Za-z0-9-_]{10,}")),
        new SecretPattern("Google API Key",
            Pattern.compile("AIza[0-9A-Za-z-_]{35}")),
        new SecretPattern("Stripe Secret Key",
            Pattern.compile("(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}")),
        new SecretPattern("GitHub Token",
            Pattern.compile("(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}")),
        new SecretPattern("AWS Access Key ID",
            Pattern.compile("(?:AKIA|ASIA)[0-9A-Z]{16}")),
        new SecretPattern("Private Key Header",
            Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
        new SecretPattern("Authorization Header",
            Pattern.compile("(?i)['\"](?:Authorization|Bearer)\\s*[:=]\\s*['\"]?(Bearer\\s+[a-zA-Z0-9_\\-\\.]{20,})['\"]?")),
        new SecretPattern("Generic API Secret Key",
            Pattern.compile("(?i)['\"](?:api[_-]?key|auth[_-]?token|access[_-]?token|secret[_-]?key|client[_-]?secret)['\"]\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-]{16,})['\"]")),
        new SecretPattern("Firebase API Key",
            Pattern.compile("(?i)['\"](?:apiKey|appId)['\"]\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-]{20,})['\"]")),
        new SecretPattern("Developer Flag / Comment",
            Pattern.compile("(?i)(?:TODO|FIXME|BUG|HACK|DEBUG|DEPRECATED):?\\s*(.{5,80})"))
    );

    // ── 2. Variable Assignment Entropy Scan (from JS-Miner) ───────────────────

    private static final Pattern VARIABLE_SECRETS_REGEX = Pattern.compile(
        "['\"`]?(?:\\w*\\s*)" +
        "(secret|token|password|passwd|authorization|bearer|aws_access_key_id|aws_secret_access_key|irc_pass|SLACK_BOT_TOKEN|id_dsa|" +
        "secret[_-]?(?:key|token|secret)|" +
        "api[_-]?(?:key|token|secret)|" +
        "access[_-]?(?:key|token|secret)|" +
        "auth[_-]?(?:key|token|secret)|" +
        "session[_-]?(?:key|token|secret)|" +
        "consumer[_-]?(?:key|token|secret)|" +
        "public[_-]?(?:key|token|secret)|" +
        "client[_-]?(?:id|token|key)|" +
        "ssh[_-]?key|" +
        "encrypt[_-]?(?:secret|key)|" +
        "decrypt[_-]?(?:secret|key)|" +
        "github[_-]?(?:key|token|secret)|" +
        "slack[_-]?token)" +
        "(?:\\w*\\s*)" +
        "['\"`]?" +
        "\\s*[:=]+[:=>]?\\s*" +
        "['\"`]" +
        "\\s*([\\w\\-/~!@#$%^&*+]{5,})" +
        "\\s*['\"`]",
        Pattern.CASE_INSENSITIVE
    );

    // ── 3. HTTP Basic Auth Pattern ───────────────────────────────────────────

    private static final Pattern HTTP_BASIC_AUTH_REGEX = Pattern.compile(
        "Authorization.{0,5}Basic\\s*([A-Za-z0-9+/=]{8,})",
        Pattern.CASE_INSENSITIVE
    );

    // ── 4. Cloud Storage & Services Regex ────────────────────────────────────

    private static final Pattern CLOUD_URLS_REGEX = Pattern.compile(
        "([\\w.-]+[.])" +
        "(s3\\.amazonaws\\.com|rds\\.amazonaws\\.com|cache\\.amazonaws\\.com|" +
        "blob\\.core\\.windows\\.net|onedrive\\.live\\.com|1drv\\.com|" +
        "storage\\.googleapis\\.com|storage\\.cloud\\.google\\.com|storage-download\\.googleapis\\.com|content-storage-upload\\.googleapis\\.com|content-storage-download\\.googleapis\\.com|" +
        "cloudfront\\.net|" +
        "digitaloceanspaces\\.com|" +
        "oraclecloud\\.com|" +
        "aliyuncs\\.com|" +
        "firebaseio\\.com|" +
        "rackcdn\\.com|" +
        "objects\\.cdn\\.dream\\.io|objects-us-west-1\\.dream\\.io)",
        Pattern.CASE_INSENSITIVE
    );

    // ── 5. Dependency Patterns ───────────────────────────────────────────────

    private static final Pattern DEPENDENCIES_BLOCK_REGEX = Pattern.compile(
        "\"dependencies[a-zA-Z0-9_-]*\"\\s*:\\s*\\{([^}]+)\\}",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern NODE_MODULES_PATH_REGEX = Pattern.compile(
        "/node_modules/(@?[a-zA-Z0-9._-]+)/?"
    );

    private static final Pattern DEPENDENCY_KEY_VALUE_REGEX = Pattern.compile(
        "\"([@a-zA-Z0-9._-]+)\"\\s*:\\s*\"([^\"]+)\""
    );

    // ── 6. Method-Specific HTTP Client Call Patterns ─────────────────────────

    private static final List<MethodCallPattern> METHOD_CALL_PATTERNS = List.of(
        new MethodCallPattern("GET", Pattern.compile("\\.[$]?get\\(['\"`]([^'\"`\\r\\n]+)['\"`]")),
        new MethodCallPattern("POST", Pattern.compile("\\.[$]?post\\(['\"`]([^'\"`\\r\\n]+)['\"`]")),
        new MethodCallPattern("PUT", Pattern.compile("\\.[$]?put\\(['\"`]([^'\"`\\r\\n]+)['\"`]")),
        new MethodCallPattern("DELETE", Pattern.compile("\\.[$]?delete\\(['\"`]([^'\"`\\r\\n]+)['\"`]")),
        new MethodCallPattern("PATCH", Pattern.compile("\\.[$]?patch\\(['\"`]([^'\"`\\r\\n]+)['\"`]"))
    );

    // ── 7. Namespace & Absolute URL Patterns ─────────────────────────────────

    private static final Pattern ENDPOINT_PATTERN = Pattern.compile(
        "['\"](/(?:api|v[0-9]|graphql|admin|internal|user|auth|oauth|webhook|rest|service|v1|v2|v3)" +
        "/[a-zA-Z0-9_\\-/{}/?\\u0026=%#.]*)['\"]"
    );

    private static final Pattern HTTP_URL_PATTERN = Pattern.compile(
        "['\"]" +
        "(https?://[a-zA-Z0-9_\\-\\.]+(?::\\d+)?(?:/[a-zA-Z0-9_\\-/{}/?\\u0026=%#.]*)?)" +
        "['\"]"
    );

    // ── 8. LinkFinder 5-Arm Engine ────────────────────────────────────────────

    private static final Pattern LINKFINDER_PATTERN = Pattern.compile(
        "(?:\"|')" +
        "(" +
            // Arm 1: absolute URL with a scheme
            "(?:[a-zA-Z]{1,10}://|//)" +
            "[^\"'/]{1,}\\." +
            "[a-zA-Z]{2,}[^\"']{0,}" +
        "|" +
            // Arm 2: relative path starting with /, ../, ./
            "(?:/|\\.\\./|\\./)+" +
            "[^\"'><,;| *()(%%$^/\\\\\\[\\]]" +
            "[^\"'><,;|()]{1,}" +
        "|" +
            // Arm 3: relative segment with a file extension
            "[a-zA-Z0-9_\\-/]{1,}/" +
            "[a-zA-Z0-9_\\-/.]{1,}" +
            "\\.(?:[a-zA-Z]{1,4}|action)" +
            "(?:[?#][^\"']{0,}|)" +
        "|" +
            // Arm 4: REST-style path without extension (3+ char resource)
            "[a-zA-Z0-9_\\-/]{1,}/" +
            "[a-zA-Z0-9_\\-/]{3,}" +
            "(?:[?#][^\"']{0,}|)" +
        "|" +
            // Arm 5: bare filename with known extension
            "[a-zA-Z0-9_\\-]{1,}" +
            "\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)" +
            "(?:[?#][^\"']{0,}|)" +
        ")" +
        "(?:\"|')"
    );

    private static final List<Pattern> LINKFINDER_NOISE_FILTERS = List.of(
        Pattern.compile("^[0-9./]+$"),
        Pattern.compile("(?i)^[a-z]{1,2}\\.[a-z]{1,4}$"),
        Pattern.compile("(?i)\\.(?:png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|css|map)(?:[?#].*)?$"),
        Pattern.compile("(?i)^(?:e\\.g|i\\.e|etc|null|undefined|true|false)\\."),
        Pattern.compile("^//[\\s*#]")
    );

    private record SecretPattern(String category, Pattern pattern) {}
    private record MethodCallPattern(String method, Pattern pattern) {}

    // ── Main Mining Entry Point ──────────────────────────────────────────────

    public static MiningResult mine(String sourceLocation, String sourceType, String sourceCode) {
        if (sourceCode == null || sourceCode.trim().isEmpty()) {
            return new MiningResult(
                Collections.emptyList(), Collections.emptyList(),
                Collections.emptyList(), Collections.emptyList()
            );
        }

        List<DiscoveredSecret> secrets = new ArrayList<>();
        List<DiscoveredEndpoint> endpoints = new ArrayList<>();
        List<DiscoveredCloudUrl> cloudUrls = new ArrayList<>();
        List<DiscoveredDependency> dependencies = new ArrayList<>();

        Set<String> seenEndpoints = new HashSet<>();
        Set<String> seenSecrets = new HashSet<>();
        Set<String> seenCloudUrls = new HashSet<>();
        Set<String> seenDependencies = new HashSet<>();

        // Handle minified single-line JS by inserting soft newlines after ; and ,
        String scannable = prepareScannable(sourceCode);
        String[] lines = scannable.split("\r?\n", -1);

        // ── A. Whole-file / Block Scanners ───────────────────────────────────

        // 1. Dependency Confusion Blocks: "dependencies": { ... }
        Matcher depBlockMatcher = DEPENDENCIES_BLOCK_REGEX.matcher(sourceCode);
        while (depBlockMatcher.find()) {
            String blockContent = depBlockMatcher.group(1);
            Matcher entryMatcher = DEPENDENCY_KEY_VALUE_REGEX.matcher(blockContent);
            while (entryMatcher.find()) {
                String pkgName = entryMatcher.group(1).trim();
                String version = entryMatcher.group(2).trim();
                if (isValidPackageName(pkgName) && seenDependencies.add(pkgName)) {
                    dependencies.add(new DiscoveredDependency(
                        sourceLocation, sourceType, pkgName, version,
                        "package.json dependencies", "Unverified", "-",
                        1, "\"" + pkgName + "\": \"" + version + "\""
                    ));
                }
            }
        }

        // ── B. Line-by-Line Scanners ─────────────────────────────────────────

        for (int i = 0; i < lines.length; i++) {
            int lineNum = i + 1;
            String line = lines[i];

            // 1. Secrets: Specific Signature Patterns
            for (SecretPattern sp : SECRET_PATTERNS) {
                Matcher sm = sp.pattern().matcher(line);
                while (sm.find()) {
                    String matchVal = sm.group(sm.groupCount() >= 1 && sm.group(1) != null ? 1 : 0);
                    if (matchVal != null && !matchVal.trim().isEmpty() && seenSecrets.add(matchVal)) {
                        double entropy = getShannonEntropy(matchVal);
                        String confidence = entropy >= 3.5 ? "High [Firm]" : "Low [Tentative]";
                        secrets.add(new DiscoveredSecret(
                            sourceLocation, sourceType, sp.category(), matchVal,
                            entropy, confidence, "Pattern Signature", lineNum, getSnippet(line)
                        ));
                    }
                }
            }

            // 2. Secrets: Variable Assignment Entropy Scan (JS-Miner)
            Matcher varSecMatcher = VARIABLE_SECRETS_REGEX.matcher(line);
            while (varSecMatcher.find()) {
                String varName = varSecMatcher.group(1);
                String secretVal = varSecMatcher.group(2);
                if (secretVal != null && isNotFalsePositive(secretVal) && seenSecrets.add(secretVal)) {
                    double entropy = getShannonEntropy(secretVal);
                    String confidence = entropy >= 3.5 ? "High [Firm]" : "Low [Tentative]";
                    String category = "Variable: " + varName;
                    secrets.add(new DiscoveredSecret(
                        sourceLocation, sourceType, category, secretVal,
                        entropy, confidence, "Variable Entropy Scan", lineNum, getSnippet(line)
                    ));
                }
            }

            // 3. Secrets: HTTP Basic Auth Secrets
            Matcher basicAuthMatcher = HTTP_BASIC_AUTH_REGEX.matcher(line);
            while (basicAuthMatcher.find()) {
                String b64 = basicAuthMatcher.group(1);
                if (b64 != null && isValidBase64(b64)) {
                    String decoded = b64Decode(b64);
                    if (decoded != null && isNotFalsePositive(decoded) && seenSecrets.add(b64)) {
                        double entropy = getShannonEntropy(decoded);
                        String confidence = entropy >= 3.5 ? "High [Firm]" : "Low [Tentative]";
                        secrets.add(new DiscoveredSecret(
                            sourceLocation, sourceType, "HTTP Basic Auth", b64 + " (" + decoded + ")",
                            entropy, confidence, "HTTP Basic Auth", lineNum, getSnippet(line)
                        ));
                    }
                }
            }

            // 4. Cloud URLs & Buckets (AWS, Azure, GCP, Firebase, DigitalOcean, etc.)
            Matcher cloudMatcher = CLOUD_URLS_REGEX.matcher(line);
            while (cloudMatcher.find()) {
                String cloudUrl = cloudMatcher.group(0);
                if (cloudUrl != null && !cloudUrl.trim().isEmpty() && seenCloudUrls.add(cloudUrl)) {
                    String provider = classifyCloudProvider(cloudUrl);
                    cloudUrls.add(new DiscoveredCloudUrl(
                        sourceLocation, sourceType, provider, cloudUrl,
                        lineNum, getSnippet(line)
                    ));
                }
            }

            // 5. Node Modules Disclosed Dependency Paths
            Matcher nodeModMatcher = NODE_MODULES_PATH_REGEX.matcher(line);
            while (nodeModMatcher.find()) {
                String pkgName = nodeModMatcher.group(1).trim();
                if (isValidPackageName(pkgName) && seenDependencies.add(pkgName)) {
                    dependencies.add(new DiscoveredDependency(
                        sourceLocation, sourceType, pkgName, "-",
                        "node_modules path", "Unverified", "-",
                        lineNum, getSnippet(line)
                    ));
                }
            }

            // 6. Endpoints: Method-Specific HTTP Client Calls (.get, .post, .put, .delete, .patch)
            for (MethodCallPattern mcp : METHOD_CALL_PATTERNS) {
                Matcher mcm = mcp.pattern().matcher(line);
                while (mcm.find()) {
                    String rawTarget = mcm.group(1).trim();
                    if (isValidEndpointPath(rawTarget) && seenEndpoints.add(rawTarget)) {
                        endpoints.add(new DiscoveredEndpoint(
                            sourceLocation, sourceType, rawTarget,
                            mcp.method(), lineNum, getSnippet(line),
                            "HTTP Verb Call"
                        ));
                    }
                }
            }

            // 7. Endpoints: API Namespace Patterns
            Matcher epMatcher = ENDPOINT_PATTERN.matcher(line);
            while (epMatcher.find()) {
                String ep = epMatcher.group(1);
                if (ep != null && ep.length() > 3 && seenEndpoints.add(ep)) {
                    endpoints.add(new DiscoveredEndpoint(
                        sourceLocation, sourceType, ep,
                        guessMethod(line), lineNum, getSnippet(line),
                        "API Namespace"
                    ));
                }
            }

            // 8. Endpoints: Absolute URLs
            Matcher urlMatcher = HTTP_URL_PATTERN.matcher(line);
            while (urlMatcher.find()) {
                String url = urlMatcher.group(1);
                if (url != null && seenEndpoints.add(url)) {
                    endpoints.add(new DiscoveredEndpoint(
                        sourceLocation, sourceType, url,
                        guessMethod(line), lineNum, getSnippet(line),
                        "Absolute URL"
                    ));
                }
            }

            // 9. Endpoints: LinkFinder 5-Arm Engine
            Matcher lfMatcher = LINKFINDER_PATTERN.matcher(line);
            while (lfMatcher.find()) {
                String path = lfMatcher.group(1);
                if (path == null || path.length() < 3) continue;
                if (isNoise(path)) continue;
                if (!seenEndpoints.add(path)) continue;

                String technique = classifyLinkFinderArm(path);
                endpoints.add(new DiscoveredEndpoint(
                    sourceLocation, sourceType, path,
                    guessMethod(line), lineNum, getSnippet(line),
                    technique
                ));
            }
        }

        return new MiningResult(secrets, endpoints, cloudUrls, dependencies);
    }

    // ── Classification & Validation Helpers ──────────────────────────────────

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
        if (path.startsWith("http://") || path.startsWith("https://") || path.startsWith("//")) {
            return "Absolute URL";
        }
        if (path.startsWith("/") || path.startsWith("./") || path.startsWith("../")) {
            return "Relative Path";
        }
        if (path.contains("/") && !path.contains("?")) {
            return "REST Endpoint";
        }
        if (path.contains(".")) {
            return "File Extension";
        }
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

    // ── Shannon Entropy Calculation ──────────────────────────────────────────

    public static double getShannonEntropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        int n = s.length();
        Map<Character, Integer> occ = new HashMap<>();
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            occ.put(c, occ.getOrDefault(c, 0) + 1);
        }
        double entropy = 0.0;
        for (int count : occ.values()) {
            double p = (double) count / n;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return Math.round(entropy * 100.0) / 100.0;
    }

    public static boolean isHighEntropy(String s) {
        return getShannonEntropy(s) >= 3.5;
    }

    public static boolean isNotFalsePositive(String secret) {
        if (secret == null) return false;
        String cleaned = secret.replaceAll("\\s", "")
            .replace("\t", "").replace("\r", "").replace("\n", "").replace("*", "");
        if (cleaned.length() <= 4) return false;
        String[] falsePositives = {"basic", "bearer", "token", "password", "secret", "true", "false", "null", "undefined"};
        for (String fp : falsePositives) {
            if (cleaned.equalsIgnoreCase(fp)) return false;
        }
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

    private static String prepareScannable(String source) {
        long newlineCount = source.chars().filter(c -> c == '\n').count();
        long ratio = source.length() / Math.max(newlineCount + 1, 1);
        if (ratio > 500) {
            return source.replace(";", ";\n").replace(",", ",\n");
        }
        return source;
    }

    private static boolean isNoise(String path) {
        for (Pattern noise : LINKFINDER_NOISE_FILTERS) {
            if (noise.matcher(path).find()) return true;
        }
        return false;
    }

    private static String guessMethod(String line) {
        String lower = line.toLowerCase();
        if (lower.contains("post(") || lower.contains("method: 'post'") || lower.contains("method: \"post\"")) return "POST";
        if (lower.contains("get(") || lower.contains("method: 'get'") || lower.contains("method: \"get\"")) return "GET";
        if (lower.contains("put(") || lower.contains("method: 'put'") || lower.contains("method: \"put\"")) return "PUT";
        if (lower.contains("delete(") || lower.contains("method: 'delete'") || lower.contains("method: \"delete\"")) return "DELETE";
        if (lower.contains("patch(") || lower.contains("method: 'patch'") || lower.contains("method: \"patch\"")) return "PATCH";
        return "ROUTE";
    }

    private static String getSnippet(String line) {
        String trimmed = line.trim();
        return trimmed.length() > 140 ? trimmed.substring(0, 137) + "..." : trimmed;
    }

    // ── Result Container ─────────────────────────────────────────────────────

    public record MiningResult(
        List<DiscoveredSecret> secrets,
        List<DiscoveredEndpoint> endpoints,
        List<DiscoveredCloudUrl> cloudUrls,
        List<DiscoveredDependency> dependencies
    ) {}
}
