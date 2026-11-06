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

    private static class JsonSecretPattern {
        String name;
        String category;
        String severity;
        int confidence;
        String pattern;
        boolean needsEntropy;
        List<String> keywords;
    }

    private static final List<CuratedSecret> ALL_PATTERNS = new ArrayList<>();

    static {
        loadJsonPatterns();
    }

    private static void loadJsonPatterns() {
        try (InputStream is = SecretAndEndpointMiner.class.getResourceAsStream("/com/littlespidy/jssourcemapexplorer/secrets_patterns_littlespidy.json")) {
            if (is != null) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
                JsonSecretPattern[] patterns = new com.google.gson.Gson().fromJson(reader, JsonSecretPattern[].class);
                if (patterns != null) {
                    for (JsonSecretPattern p : patterns) {
                        try {
                            Pattern compiled = Pattern.compile(p.pattern);
                            List<String> kwList = p.keywords != null ? p.keywords : List.of();
                            ALL_PATTERNS.add(new CuratedSecret(p.name, p.category, p.severity != null ? p.severity : "High", p.confidence, compiled, p.needsEntropy, kwList));
                        } catch (Exception ignored) {}
                    }
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
        boolean hasVar = false;
        boolean hasAuth = false;
        for (CuratedSecret cs : ALL_PATTERNS) {
            if ("Variable Entropy Scan".equalsIgnoreCase(cs.name())) hasVar = true;
            if ("HTTP Basic Auth".equalsIgnoreCase(cs.name())) hasAuth = true;
            list.add(new SecretSignatureInfo(cs.name(), cs.category(), cs.pattern().pattern(), cs.confidence(), cs.needsEntropy()));
        }
        if (!hasVar) {
            list.add(new SecretSignatureInfo("Variable Entropy Scan", "Variable Assignment", VARIABLE_SECRETS_REGEX.pattern(), 80, true));
        }
        if (!hasAuth) {
            list.add(new SecretSignatureInfo("HTTP Basic Auth", "HTTP Basic Auth", HTTP_BASIC_AUTH_REGEX.pattern(), 95, false));
        }
        return Collections.unmodifiableList(list);
    }

    public static List<String> getAllCategories() {
        Set<String> cats = new LinkedHashSet<>();
        cats.add("All Categories");
        for (CuratedSecret cs : ALL_PATTERNS) {
            cats.add(cs.category());
        }
        return new ArrayList<>(cats);
    }

    public static List<String> getAllSignatureNames() {
        List<String> names = new ArrayList<>();
        names.add("All Signatures");
        for (CuratedSecret cs : ALL_PATTERNS) {
            names.add(cs.name());
        }
        return names;
    }

    // ── Cloud Services Regex (All major cloud providers) ──
    private static final Pattern CLOUD_URLS_REGEX = Pattern.compile(
        "(?:https?://)?(?:[\\w.-]+[.])?" +
        "(" +
        // AWS
        "s3(?:\\.[a-z0-9-]+|-accelerate)?\\.amazonaws\\.com|execute-api\\.[a-z0-9-]+\\.amazonaws\\.com|" +
        "lambda\\.[a-z0-9-]+\\.amazonaws\\.com|appsync-api\\.[a-z0-9-]+\\.amazonaws\\.com|" +
        "cognito-idp\\.[a-z0-9-]+\\.amazonaws\\.com|elasticbeanstalk\\.com|cloudfront\\.net|" +
        "rds\\.amazonaws\\.com|cache\\.amazonaws\\.com|" +
        // Azure
        "blob\\.core\\.windows\\.net|file\\.core\\.windows\\.net|queue\\.core\\.windows\\.net|" +
        "table\\.core\\.windows\\.net|azurewebsites\\.net|azureedge\\.net|azure-api\\.net|" +
        "database\\.windows\\.net|vault\\.azure\\.net|cloudapp\\.azure\\.com|azurecontainer\\.io|" +
        "onedrive\\.live\\.com|1drv\\.com|" +
        // Google Cloud / Firebase
        "storage\\.googleapis\\.com|storage\\.cloud\\.google\\.com|appspot\\.com|" +
        "cloudfunctions\\.net|run\\.app|firestore\\.googleapis\\.com|" +
        "firebaseio\\.com|firebaseapp\\.com|web\\.app|" +
        // Cloudflare
        "workers\\.dev|pages\\.dev|r2\\.cloudflarestorage\\.com|" +
        // DigitalOcean
        "digitaloceanspaces\\.com|ondigitalocean\\.app|" +
        // Supabase
        "supabase\\.co|supabase\\.in|" +
        // PaaS / Serverless
        "vercel\\.app|netlify\\.app|herokuapp\\.com|onrender\\.com|fly\\.dev|" +
        // Object Storage / Other
        "oraclecloud\\.com|aliyuncs\\.com|oss-[a-z0-9-]+\\.aliyuncs\\.com|" +
        "cloud-object-storage\\.appdomain\\.cloud|linodeobjects\\.com|wasabisys\\.com|" +
        "backblazeb2\\.com|b2\\.fslb\\.net|rackcdn\\.com|dream\\.io" +
        ")",
        Pattern.CASE_INSENSITIVE
    );

    // ── Internal IP Addresses (RFC 1918, Loopback, Link-Local, IPv6 Unique Local) ──
    private static final Pattern IPV4_RFC1918_10 = Pattern.compile(
        "\\b10\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b"
    );
    private static final Pattern IPV4_RFC1918_172 = Pattern.compile(
        "\\b172\\.(?:1[6-9]|2\\d|3[01])\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b"
    );
    private static final Pattern IPV4_RFC1918_192 = Pattern.compile(
        "\\b192\\.168\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b"
    );
    private static final Pattern IPV4_LOOPBACK = Pattern.compile(
        "\\b127\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b"
    );
    private static final Pattern IPV4_LINK_LOCAL = Pattern.compile(
        "\\b(?:169\\.254|100\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7]))\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b"
    );
    private static final Pattern IPV6_ULA = Pattern.compile(
        "\\b[fF][cCdD][0-9a-fA-F]{2}(?::[0-9a-fA-F]{1,4}){3,7}\\b"
    );

    // ── Social Security Number (SSN) ──
    private static final Pattern SSN_STANDARD = Pattern.compile(
        "\\b(?!000|666|9\\d{2})([0-8]\\d{2})-(?!00)(\\d{2})-(?!0000)(\\d{4})\\b"
    );
    private static final Pattern SSN_KEY_VALUE = Pattern.compile(
        "(?i)[\"']?\\b(?:ssn|social[-_ ]?security(?:[-_ ]?number)?)\\b[\"']?\\s*[:=]\\s*[\"']?((?!000|666|9\\d{2})[0-8]\\d{2}[- ]?(?!00)\\d{2}[- ]?(?!0000)\\d{4})[\"']?"
    );

    // ── Dependencies & License Banners ──
    private static final Pattern DEPENDENCIES_BLOCK_REGEX = Pattern.compile(
        "\"dependencies[a-zA-Z0-9_-]*\"\\s*:\\s*\\{([^}]+)\\}", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern NODE_MODULES_PATH_REGEX = Pattern.compile(
        "/node_modules/(@?[a-zA-Z0-9._-]+)/?"
    );
    private static final Pattern DEPENDENCY_KEY_VALUE_REGEX = Pattern.compile(
        "\"([@a-zA-Z0-9._-]+)\"\\s*:\\s*\"([^\"]+)\""
    );
    private static final Pattern LICENSE_BANNER_REGEX = Pattern.compile(
        "(?i)@licen[sc]e\\s+([A-Za-z0-9_.-]+(?:\\s+[A-Za-z0-9_.-]+)?)\\s+v?([0-9]+(?:\\.[0-9]+)+(?:-[a-zA-Z0-9.]+)?)"
    );

    // ── Method-Specific HTTP Client Calls ──
    private static final Pattern METHOD_CALL_REGEX = Pattern.compile(
        "\\.[$]?(get|post|put|delete|patch)\\(['\"`]([^'\"`\\r\\n]+)['\"`]"
    );

    // ── LinkFinder 5-Arm Pattern (Absolute URLs strictly require https?://) ──
    private static final Pattern LINKFINDER_PATTERN = Pattern.compile(
        "(?:\"|')(" +
        "https?://[^\"'/]{1,}\\.[a-zA-Z]{2,}(?::[0-9]+)?(?:/[^\"']*)?" +
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
        Pattern.compile("^//:?\\d*$"), // Suppress invalid protocol or //:0
        Pattern.compile("^//[\\s*#]"),
        Pattern.compile("(?i)^\\s*(?:import|export)\\s+"), // Direct import or export string
        Pattern.compile("(?i)^\\s*require\\s*\\("), // Direct require invocation
        Pattern.compile("(?i)^(?:application|text|image|audio|video|multipart|font|model)/[a-zA-Z0-9.+_-]+(?:;.*)?$"), // All MIME Content-Types
        Pattern.compile("^(?:\\d{1,2}/\\d{1,2}/\\d{2,4}|\\d{4}/\\d{1,2}/\\d{1,2})$") // m/d/y, mm/dd/yy, yyyy/mm/dd
    );

    // Module import and export syntax detection for preceding code context
    private static final Pattern MODULE_IMPORT_PRE_PATTERN = Pattern.compile(
        "(?s)(?:\\b(?:import|export)\\b[^;()]*?\\bfrom\\s*|\\bimport\\s*\\(\\s*|\\bimport\\s+|\\brequire\\s*\\()\\s*$"
    );

    private static boolean isModuleImportContext(String text, int matchStart) {
        if (text == null || matchStart <= 0) return false;
        int s = Math.max(0, matchStart - 150);
        String pre = text.substring(s, matchStart);
        return MODULE_IMPORT_PRE_PATTERN.matcher(pre).find();
    }

    private static final Pattern COMMENT_SCAN_PATTERN = Pattern.compile(
        "(/\\*[\\s\\S]*?\\*/)|(<!--[\\s\\S]*?-->)|((?<!:)\\/\\/(?![\\/\\*])[^\\r\\n]*)"
    );
    private static final Pattern COMMENT_TODO_PATTERN = Pattern.compile("(?i)\\b(todo|fixme|hack|xxx|bug|temp|workaround|revisit|cleanup)\\b");
    private static final Pattern COMMENT_CRED_PATTERN = Pattern.compile("(?i)\\b(password|passwd|secret|token|apikey|api_key|auth|bearer|credential|admin|root|private_key)\\b");
    private static final Pattern COMMENT_DEBUG_PATTERN = Pattern.compile("(?i)\\b(debug|test|dev|staging|localhost|internal|mock|deprecated|danger|security)\\b");

    public record SecurityBypassRule(
        String framework,
        String method,
        String risk,
        String confidence,
        Pattern pattern,
        String description
    ) {}

    private static final List<SecurityBypassRule> SECURITY_BYPASS_RULES = List.of(
        // ── Angular DomSanitizer ──
        new SecurityBypassRule(
            "Angular", "bypassSecurityTrustHtml", "Critical", "High [Firm]",
            Pattern.compile("(?i)\\b(bypassSecurityTrustHtml)\\s*\\(([^)]*)\\)"),
            "Angular DomSanitizer HTML bypass: renders untrusted content as trusted HTML, leading to direct XSS"
        ),
        new SecurityBypassRule(
            "Angular", "bypassSecurityTrustScript", "Critical", "High [Firm]",
            Pattern.compile("(?i)\\b(bypassSecurityTrustScript)\\s*\\(([^)]*)\\)"),
            "Angular DomSanitizer Script bypass: directly executes untrusted content as trusted JavaScript"
        ),
        new SecurityBypassRule(
            "Angular", "bypassSecurityTrustStyle", "High", "High [Firm]",
            Pattern.compile("(?i)\\b(bypassSecurityTrustStyle)\\s*\\(([^)]*)\\)"),
            "Angular DomSanitizer Style bypass: allows arbitrary CSS injection and potential data exfiltration"
        ),
        new SecurityBypassRule(
            "Angular", "bypassSecurityTrustUrl", "High", "High [Firm]",
            Pattern.compile("(?i)\\b(bypassSecurityTrustUrl)\\s*\\(([^)]*)\\)"),
            "Angular DomSanitizer URL bypass: permits javascript: or untrusted navigation URIs"
        ),
        new SecurityBypassRule(
            "Angular", "bypassSecurityTrustResourceUrl", "Critical", "High [Firm]",
            Pattern.compile("(?i)\\b(bypassSecurityTrustResourceUrl)\\s*\\(([^)]*)\\)"),
            "Angular DomSanitizer ResourceUrl bypass: allows untrusted script or iframe sources"
        ),
        new SecurityBypassRule(
            "Angular", "ɵɵtrustConstantHtml", "High", "High [Firm]",
            Pattern.compile("\\b(ɵɵtrustConstant(?:Html|ResourceUrl))\\s*\\(([^)]*)\\)"),
            "Angular Ivy compiled template internal trust bypass method"
        ),
        new SecurityBypassRule(
            "Angular", "$sce.trustAsHtml", "Critical", "High [Firm]",
            Pattern.compile("(?i)\\$(?:sce|sceDelegate)\\.(trustAsHtml)\\s*\\(([^)]*)\\)"),
            "AngularJS $sce trust bypass: disables Strict Contextual Escaping on untrusted HTML"
        ),
        new SecurityBypassRule(
            "Angular", "$sce.trustAsJs", "Critical", "High [Firm]",
            Pattern.compile("(?i)\\$(?:sce|sceDelegate)\\.(trustAsJs)\\s*\\(([^)]*)\\)"),
            "AngularJS $sce trust bypass: executes untrusted string as trusted JavaScript"
        ),
        new SecurityBypassRule(
            "Angular", "$sce.trustAsResourceUrl", "Critical", "High [Firm]",
            Pattern.compile("(?i)\\$(?:sce|sceDelegate)\\.(trustAsResourceUrl|trustAsUrl)\\s*\\(([^)]*)\\)"),
            "AngularJS $sce trust bypass: loads untrusted resource URL or script"
        ),

        // ── React / Preact ──
        new SecurityBypassRule(
            "React", "dangerouslySetInnerHTML", "Critical", "High [Firm]",
            Pattern.compile("(?i)\\b(dangerouslySetInnerHTML)\\s*=\\s*\\{\\s*(?:\\{\\s*__html\\s*:|\\w+)"),
            "React dangerouslySetInnerHTML: injects raw unescaped HTML directly into the DOM"
        ),
        new SecurityBypassRule(
            "React", "dangerouslySetInnerHTML (prop)", "Critical", "High [Firm]",
            Pattern.compile("(?i)\\b(dangerouslySetInnerHTML)\\b"),
            "React dangerouslySetInnerHTML property detected"
        ),

        // ── Vue.js ──
        new SecurityBypassRule(
            "Vue", "v-html", "High", "High [Firm]",
            Pattern.compile("(?i)\\b(v-html)\\s*=\\s*[\"']([^\"']+)[\"']"),
            "Vue.js v-html directive: updates element innerHTML with raw HTML, leading to XSS on untrusted data"
        ),
        new SecurityBypassRule(
            "Vue", "domProps.innerHTML", "High", "High [Firm]",
            Pattern.compile("(?i)domProps\\s*:\\s*\\{[^}]*\\b(innerHTML)\\s*:\\s*([^},]+)"),
            "Vue compiled render function binding unescaped innerHTML"
        ),
        new SecurityBypassRule(
            "Vue", "{{{ ... }}}", "High", "Medium",
            Pattern.compile("(\\{\\{\\{[^{}]+\\}\\}\\})"),
            "Vue raw unescaped HTML interpolation syntax (triple-mustache)"
        ),

        // ── Svelte ──
        new SecurityBypassRule(
            "Svelte", "{@html ...}", "High", "High [Firm]",
            Pattern.compile("\\{(@html)\\s+([^}]+)\\}"),
            "Svelte @html tag: renders raw unescaped HTML directly into document without sanitization"
        ),

        // ── Sanitizer / Policy Bypasses (DOMPurify, Trusted Types) ──
        new SecurityBypassRule(
            "Sanitizer / Policy Bypass", "DOMPurify.sanitize (loose config)", "High", "High [Firm]",
            Pattern.compile("(?i)DOMPurify\\.sanitize\\s*\\([^,)]+,\\s*\\{[^}]*\\b(ADD_TAGS|ADD_ATTR|WHOLE_DOCUMENT|RETURN_DOM_FRAGMENT|CUSTOM_ELEMENT_HANDLING)\\b"),
            "DOMPurify configured with loose sanitization options or custom allowed tags/attributes"
        ),
        new SecurityBypassRule(
            "Sanitizer / Policy Bypass", "trustedTypes.createPolicy (passthrough)", "Critical", "High [Firm]",
            Pattern.compile("(?i)trustedTypes\\.createPolicy\\s*\\(\\s*['\"][^'\"]+['\"]\\s*,\\s*\\{[^}]*\\b(createHTML|createScript|createScriptURL)\\s*:\\s*(?:function\\s*\\([^)]*\\)|\\([^)]*\\)\\s*=>|[a-zA-Z0-9_$]+\\s*=>)"),
            "Trusted Types policy configured with custom passthrough function bypassing browser enforcement"
        ),

        // ── Direct Dangerous DOM Sinks ──
        new SecurityBypassRule(
            "Vanilla DOM Sink", "innerHTML assignment", "High", "High [Firm]",
            Pattern.compile("\\.innerHTML\\s*=\\s*([^;\\n]+)"),
            "Direct innerHTML property assignment: parses and inserts untrusted markup into DOM"
        ),
        new SecurityBypassRule(
            "Vanilla DOM Sink", "outerHTML assignment", "High", "High [Firm]",
            Pattern.compile("\\.outerHTML\\s*=\\s*([^;\\n]+)"),
            "Direct outerHTML property assignment replaces element with unescaped HTML"
        ),
        new SecurityBypassRule(
            "Vanilla DOM Sink", "document.write", "High", "High [Firm]",
            Pattern.compile("\\bdocument\\.(write(?:ln)?)\\s*\\(([^)]*)\\)"),
            "document.write: dynamically writes raw HTML strings into open document stream"
        ),
        new SecurityBypassRule(
            "Vanilla DOM Sink", "insertAdjacentHTML", "High", "High [Firm]",
            Pattern.compile("\\b(insertAdjacentHTML)\\s*\\(([^)]*)\\)"),
            "insertAdjacentHTML: parses text as HTML and inserts into DOM at specified position"
        ),
        new SecurityBypassRule(
            "Vanilla DOM Sink", "eval()", "Critical", "High [Firm]",
            Pattern.compile("(?<![a-zA-Z0-9_$.])eval\\s*\\(([^)]+)\\)"),
            "eval(): directly executes string as JavaScript code, critical code injection sink"
        ),
        new SecurityBypassRule(
            "Vanilla DOM Sink", "new Function()", "Critical", "High [Firm]",
            Pattern.compile("\\bnew\\s+Function\\s*\\(([^)]+)\\)"),
            "new Function(): dynamically constructs executable code from string arguments"
        ),
        new SecurityBypassRule(
            "jQuery", "$.html()", "High", "High [Firm]",
            Pattern.compile("\\$\\([^)]*\\)\\.(html)\\s*\\(([^)]+)\\)"),
            "jQuery .html(content): dynamically sets inner HTML with untrusted string argument"
        )
    );

    public record MiningResult(
        List<DiscoveredSecret> secrets,
        List<DiscoveredEndpoint> endpoints,
        List<DiscoveredCloudUrl> cloudUrls,
        List<DiscoveredDependency> dependencies,
        List<DiscoveredComment> comments,
        List<DiscoveredSecurityBypass> securityBypasses,
        List<DiscoveredGraphQLOperation> graphQLOperations,
        List<DiscoveredInternalIpAndSsn_littlespidy> internalIpsAndSsns
    ) {
        public MiningResult(
            List<DiscoveredSecret> secrets,
            List<DiscoveredEndpoint> endpoints,
            List<DiscoveredCloudUrl> cloudUrls,
            List<DiscoveredDependency> dependencies,
            List<DiscoveredComment> comments,
            List<DiscoveredSecurityBypass> securityBypasses,
            List<DiscoveredGraphQLOperation> graphQLOperations
        ) {
            this(secrets, endpoints, cloudUrls, dependencies, comments, securityBypasses, graphQLOperations, Collections.emptyList());
        }

        public MiningResult(
            List<DiscoveredSecret> secrets,
            List<DiscoveredEndpoint> endpoints,
            List<DiscoveredCloudUrl> cloudUrls,
            List<DiscoveredDependency> dependencies,
            List<DiscoveredComment> comments,
            List<DiscoveredSecurityBypass> securityBypasses
        ) {
            this(secrets, endpoints, cloudUrls, dependencies, comments, securityBypasses, Collections.emptyList(), Collections.emptyList());
        }

        public MiningResult(
            List<DiscoveredSecret> secrets,
            List<DiscoveredEndpoint> endpoints,
            List<DiscoveredCloudUrl> cloudUrls,
            List<DiscoveredDependency> dependencies,
            List<DiscoveredComment> comments
        ) {
            this(secrets, endpoints, cloudUrls, dependencies, comments, Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
        }

        public MiningResult(
            List<DiscoveredSecret> secrets,
            List<DiscoveredEndpoint> endpoints,
            List<DiscoveredCloudUrl> cloudUrls,
            List<DiscoveredDependency> dependencies
        ) {
            this(secrets, endpoints, cloudUrls, dependencies, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
        }
    }

    /**
     * Primary mining entry point. Analyzes raw source code with size ceilings and execution budgets.
     */
    public static MiningResult mine(String sourceLocation, String sourceType, String sourceCode) {
        if (sourceCode == null || sourceCode.trim().isEmpty()) {
            return new MiningResult(Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
        }

        // Cap analysis to 5MB to prevent memory exhaustion / OOM
        String scannable = sourceCode.length() > 5_000_000 ? sourceCode.substring(0, 5_000_000) : sourceCode;
        long deadline = System.nanoTime() + 2_500_000_000L; // 2.5 second budget

        List<DiscoveredSecret> secrets = new ArrayList<>();
        List<DiscoveredEndpoint> endpoints = new ArrayList<>();
        List<DiscoveredCloudUrl> cloudUrls = new ArrayList<>();
        List<DiscoveredDependency> dependencies = new ArrayList<>();
        List<DiscoveredComment> comments = new ArrayList<>();
        List<DiscoveredSecurityBypass> securityBypasses = new ArrayList<>();
        List<DiscoveredGraphQLOperation> graphQLOperations = new ArrayList<>();
        List<DiscoveredInternalIpAndSsn_littlespidy> internalIpsAndSsns = new ArrayList<>();

        Set<String> seenEndpoints = new HashSet<>();
        Set<String> seenSecrets = new HashSet<>();
        Set<String> seenCloudUrls = new HashSet<>();
        Set<String> seenDependencies = new HashSet<>();
        Set<String> seenComments = new HashSet<>();
        Set<String> seenBypasses = new HashSet<>();
        Set<String> seenInternalIpsAndSsns = new HashSet<>();

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

        // 2b. License Banner Extraction (e.g. @license Angular v20.2.30, @licence, React, Vue, jQuery)
        Matcher licMatcher = LICENSE_BANNER_REGEX.matcher(scannable);
        while (licMatcher.find()) {
            if (System.nanoTime() > deadline) break;
            String pkgName = licMatcher.group(1).trim();
            String version = licMatcher.group(2).trim();
            if (isValidPackageName(pkgName) && seenDependencies.add(pkgName + "@" + version)) {
                int start = licMatcher.start();
                int end = licMatcher.end();
                dependencies.add(new DiscoveredDependency(
                    sourceLocation, sourceType, pkgName, version,
                    "@license banner", "Unverified", "-",
                    getLineNumber(scannable, start), start, end,
                    licMatcher.group(0)
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
                int start = lfMatcher.start();
                int end = lfMatcher.end();
                if (isModuleImportContext(scannable, start)) continue;
                if (!seenEndpoints.add(path)) continue;

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

        // 11. Developer Comments Mining (single-line //, multi-line /* */, HTML <!-- -->)
        Matcher commentMatcher = COMMENT_SCAN_PATTERN.matcher(scannable);
        while (commentMatcher.find()) {
            if (System.nanoTime() > deadline || comments.size() >= 2500) break;
            String rawComment = commentMatcher.group();
            if (rawComment == null || rawComment.contains("sourceMappingURL=")) continue;

            String cleanText = rawComment.replaceAll("^(/\\*+|<!--|//+)", "")
                                         .replaceAll("(\\*/|-->)$", "")
                                         .trim();
            if (cleanText.isEmpty() || cleanText.length() < 3 || cleanText.matches("^[=\\-_*#~\\s]+$")) {
                continue;
            }

            if (seenComments.add(cleanText)) {
                int start = commentMatcher.start();
                int end = commentMatcher.end();
                int line = getLineNumber(scannable, start);

                String type = rawComment.startsWith("//") ? "Single-Line (//)"
                    : rawComment.startsWith("/*") ? "Multi-Line (/* */)"
                    : "HTML (<!-- -->)";

                String category = COMMENT_TODO_PATTERN.matcher(cleanText).find() ? "TODO / FIXME"
                    : COMMENT_CRED_PATTERN.matcher(cleanText).find() ? "Credentials / Auth"
                    : COMMENT_DEBUG_PATTERN.matcher(cleanText).find() ? "Debug / Config"
                    : "General";

                String snippet = cleanText.length() > 140 ? cleanText.substring(0, 140) + "..." : cleanText;
                comments.add(new DiscoveredComment(
                    sourceLocation, sourceType, type, category, cleanText, line, start, end, snippet
                ));
            }
        }

        // 12. Security Bypass Methods & Dangerous DOM Sinks (Angular, React, Vue, Svelte, Sanitizers, Vanilla)
        for (SecurityBypassRule rule : SECURITY_BYPASS_RULES) {
            if (System.nanoTime() > deadline || securityBypasses.size() >= 1000) break;
            Matcher m = rule.pattern().matcher(scannable);
            while (m.find()) {
                if (System.nanoTime() > deadline || securityBypasses.size() >= 1000) break;

                // False-positive suppression for innerHTML/outerHTML empty assignments
                if ("innerHTML assignment".equals(rule.method()) || "outerHTML assignment".equals(rule.method())) {
                    String assigned = m.groupCount() >= 1 ? m.group(1).trim() : "";
                    if (assigned.equals("\"\"") || assigned.equals("''") || assigned.equals("``")
                        || assigned.equals("null") || assigned.equals("undefined") || assigned.isEmpty()) {
                        continue;
                    }
                }

                int start = m.start();
                int end = m.end();
                int line = getLineNumber(scannable, start);
                String dedupeKey = line + ":" + rule.method() + ":" + (start / 40);

                if (seenBypasses.add(dedupeKey)) {
                    // Extract surrounding context line
                    int snippetStart = Math.max(0, start - 40);
                    int snippetEnd = Math.min(scannable.length(), end + 60);
                    int prevNewline = scannable.lastIndexOf('\n', start);
                    if (prevNewline >= 0 && prevNewline >= start - 80) snippetStart = prevNewline + 1;
                    int nextNewline = scannable.indexOf('\n', end);
                    if (nextNewline >= 0 && nextNewline <= end + 100) snippetEnd = nextNewline;

                    String snippet = scannable.substring(snippetStart, snippetEnd).trim();
                    if (snippet.length() > 200) snippet = snippet.substring(0, 200) + "...";

                    securityBypasses.add(new DiscoveredSecurityBypass(
                        sourceLocation, sourceType, rule.framework(), rule.method(),
                        rule.risk(), rule.confidence(), line, start, end, snippet, rule.description()
                    ));
                }
            }
        }

        // 13. Native GraphQL Operation Mining
        if (System.nanoTime() <= deadline) {
            try {
                graphQLOperations.addAll(GraphQLMiner_littlespidy.mine(sourceLocation, sourceType, scannable));
            } catch (Exception ignored) {}
        }

        // 14. Internal IP Address Mining (RFC 1918, Loopback, Link-Local, IPv6 Unique Local)
        if (System.nanoTime() <= deadline) {
            mineInternalIps(scannable, sourceLocation, sourceType, deadline, internalIpsAndSsns, seenInternalIpsAndSsns);
        }

        // 15. Social Security Number (SSN) Mining
        if (System.nanoTime() <= deadline) {
            mineSsns(scannable, sourceLocation, sourceType, deadline, internalIpsAndSsns, seenInternalIpsAndSsns);
        }

        return new MiningResult(secrets, endpoints, cloudUrls, dependencies, comments, securityBypasses, graphQLOperations, internalIpsAndSsns);
    }

    private static void mineInternalIps(
        String scannable, String sourceLocation, String sourceType, long deadline,
        List<DiscoveredInternalIpAndSsn_littlespidy> results, Set<String> seen
    ) {
        checkIpPattern(scannable, sourceLocation, sourceType, IPV4_RFC1918_10, "RFC 1918 (10.x)", deadline, results, seen);
        checkIpPattern(scannable, sourceLocation, sourceType, IPV4_RFC1918_172, "RFC 1918 (172.16-31.x)", deadline, results, seen);
        checkIpPattern(scannable, sourceLocation, sourceType, IPV4_RFC1918_192, "RFC 1918 (192.168.x)", deadline, results, seen);
        checkIpPattern(scannable, sourceLocation, sourceType, IPV4_LOOPBACK, "Loopback (127.x)", deadline, results, seen);
        checkIpPattern(scannable, sourceLocation, sourceType, IPV4_LINK_LOCAL, "Link-Local / Carrier NAT", deadline, results, seen);
        checkIpPattern(scannable, sourceLocation, sourceType, IPV6_ULA, "IPv6 Unique Local", deadline, results, seen);
    }

    private static void checkIpPattern(
        String text, String sourceLoc, String srcType, Pattern pattern, String subtype,
        long deadline, List<DiscoveredInternalIpAndSsn_littlespidy> results, Set<String> seen
    ) {
        if (System.nanoTime() > deadline || results.size() >= 1500) return;
        Matcher m = pattern.matcher(text);
        while (m.find()) {
            if (System.nanoTime() > deadline || results.size() >= 1500) break;
            String ip = m.group();
            int start = m.start();
            int end = m.end();

            // Guard against version numbers like "v10.0.1.2" or "version 10.0.0.1" or decimal fractions
            if (start > 0) {
                char prev = text.charAt(start - 1);
                if (prev == 'v' || prev == 'V' || prev == '.' || prev == '-' || prev == '_') continue;
            }
            if (end < text.length()) {
                char next = text.charAt(end);
                if (next == '.' || next == '-' || next == '_') continue;
            }

            if (seen.add("IP:" + ip)) {
                results.add(new DiscoveredInternalIpAndSsn_littlespidy(
                    sourceLoc, srcType, "Internal IP Address", ip, subtype,
                    getLineNumber(text, start), start, end, getSnippet(text, start, end)
                ));
            }
        }
    }

    private static void mineSsns(
        String scannable, String sourceLocation, String sourceType, long deadline,
        List<DiscoveredInternalIpAndSsn_littlespidy> results, Set<String> seen
    ) {
        if (System.nanoTime() > deadline || results.size() >= 1500) return;

        // 1. Standard formatted XXX-XX-XXXX
        Matcher mStd = SSN_STANDARD.matcher(scannable);
        while (mStd.find()) {
            if (System.nanoTime() > deadline || results.size() >= 1500) break;
            String ssn = mStd.group();
            int start = mStd.start();
            int end = mStd.end();

            if (isFalsePositiveSsn(ssn)) continue;

            if (seen.add("SSN:" + ssn)) {
                results.add(new DiscoveredInternalIpAndSsn_littlespidy(
                    sourceLocation, sourceType, "Social Security Number (SSN)", ssn, "SSN (Standard Formatted)",
                    getLineNumber(scannable, start), start, end, getSnippet(scannable, start, end)
                ));
            }
        }

        // 2. Key-value SSN declarations (e.g. ssn: "123456789")
        Matcher mKv = SSN_KEY_VALUE.matcher(scannable);
        while (mKv.find()) {
            if (System.nanoTime() > deadline || results.size() >= 1500) break;
            String raw = mKv.group(1);
            if (raw == null) continue;
            String ssn = raw.trim();
            int start = mKv.start(1);
            int end = mKv.end(1);

            if (isFalsePositiveSsn(ssn)) continue;

            if (seen.add("SSN:" + ssn)) {
                results.add(new DiscoveredInternalIpAndSsn_littlespidy(
                    sourceLocation, sourceType, "Social Security Number (SSN)", ssn, "SSN (Key-Value)",
                    getLineNumber(scannable, start), start, end, getSnippet(scannable, start, end)
                ));
            }
        }
    }

    private static boolean isFalsePositiveSsn(String ssn) {
        String digits = ssn.replaceAll("[^0-9]", "");
        if (digits.length() != 9) return true;
        // All same digit e.g. 111111111
        if (digits.chars().distinct().count() <= 1) return true;
        // Sequential numbers
        if ("123456789".equals(digits) || "987654321".equals(digits) || "012345678".equals(digits)) return true;
        // Common mock SSN prefixes
        if (digits.startsWith("000") || digits.startsWith("666") || digits.startsWith("9")) return true;
        return false;
    }

    private static String classifyCloudProvider(String url) {
        String lower = url.toLowerCase();
        if (lower.contains("amazonaws.com") || lower.contains("cloudfront.net") || lower.contains("elasticbeanstalk.com")) return "AWS";
        if (lower.contains("windows.net") || lower.contains("azurewebsites.net") || lower.contains("azureedge.net") || lower.contains("azure-api.net") || lower.contains("vault.azure.net") || lower.contains("cloudapp.azure.com") || lower.contains("azurecontainer.io") || lower.contains("live.com") || lower.contains("1drv.com")) return "Azure";
        if (lower.contains("firebaseio.com") || lower.contains("firebaseapp.com") || lower.contains("web.app")) return "Firebase";
        if (lower.contains("googleapis.com") || lower.contains("appspot.com") || lower.contains("cloudfunctions.net") || lower.contains("run.app")) return "Google Cloud";
        if (lower.contains("workers.dev") || lower.contains("pages.dev") || lower.contains("r2.cloudflarestorage.com")) return "Cloudflare";
        if (lower.contains("digitaloceanspaces.com") || lower.contains("ondigitalocean.app")) return "DigitalOcean";
        if (lower.contains("supabase.co") || lower.contains("supabase.in")) return "Supabase";
        if (lower.contains("vercel.app") || lower.contains("netlify.app") || lower.contains("herokuapp.com") || lower.contains("onrender.com") || lower.contains("fly.dev")) return "PaaS / Serverless";
        if (lower.contains("oraclecloud.com")) return "Oracle Cloud";
        if (lower.contains("aliyuncs.com")) return "Alibaba Cloud";
        if (lower.contains("cloud-object-storage.appdomain.cloud") || lower.contains("linodeobjects.com") || lower.contains("wasabisys.com") || lower.contains("backblazeb2.com") || lower.contains("b2.fslb.net")) return "Object Storage";
        if (lower.contains("rackcdn.com")) return "Rackspace";
        if (lower.contains("dream.io")) return "DreamHost";
        return "Cloud Resource";
    }

    private static String classifyLinkFinderArm(String path) {
        if (path.startsWith("http://") || path.startsWith("https://")) return "Absolute URL";
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
