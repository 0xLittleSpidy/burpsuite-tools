// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.evaluator;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Full port of Google's CSP Evaluator engine (evaluator.ts, security_checks.ts,
 * strictcsp_checks.ts, parser_checks.ts).
 *
 * @author littlespidy
 */
public class GoogleCspEvaluator {

    public static final List<String> DIRECTIVES_CAUSING_XSS = List.of(
        CspModel.DIRECTIVE_SCRIPT_SRC,
        CspModel.DIRECTIVE_SCRIPT_SRC_ATTR,
        CspModel.DIRECTIVE_SCRIPT_SRC_ELEM,
        CspModel.DIRECTIVE_OBJECT_SRC,
        CspModel.DIRECTIVE_BASE_URI
    );

    public static final List<String> URL_SCHEMES_CAUSING_XSS = List.of("data:", "http:", "https:");

    private static final Pattern IPV4_PATTERN = Pattern.compile("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$");
    private static final Pattern NONCE_REGEX = Pattern.compile("^'nonce-(.+)'$");

    private final CspModel csp;
    private final int version;

    public GoogleCspEvaluator(CspModel parsedCsp, int version) {
        this.csp = parsedCsp;
        this.version = version;
    }

    public GoogleCspEvaluator(CspModel parsedCsp) {
        this(parsedCsp, CspModel.VERSION_CSP3);
    }

    /**
     * Evaluates a raw CSP string using Google's full default suite.
     */
    public static List<CspFinding> evaluate(String rawCsp) {
        if (rawCsp == null || rawCsp.trim().isEmpty() || rawCsp.equalsIgnoreCase("(missing CSP)")) {
            return List.of(new CspFinding(
                CspFindingType.MISSING_DIRECTIVES,
                "Content Security Policy is completely missing. Allows unrestricted script execution and Clickjacking.",
                CspSeverity.HIGH,
                "default-src",
                ""
            ));
        }

        CspModel model = CspModel.parse(rawCsp);
        GoogleCspEvaluator evaluator = new GoogleCspEvaluator(model, CspModel.VERSION_CSP3);
        return evaluator.evaluateAll();
    }

    public List<CspFinding> evaluateAll() {
        List<CspFinding> findings = new ArrayList<>();

        // 1. Effective CSP (version-dependent normalization)
        CspModel effectiveCsp = csp.getEffectiveCsp(version, findings);

        // 2. Parser checks (syntax mistakes, missing semicolons, unquoted keywords)
        findings.addAll(checkUnknownDirective(csp));
        findings.addAll(checkMissingSemicolon(csp));
        findings.addAll(checkInvalidKeyword(csp));

        // 3. Security checks
        findings.addAll(checkScriptUnsafeInline(effectiveCsp));
        findings.addAll(checkScriptUnsafeEval(csp));
        findings.addAll(checkPlainUrlSchemes(csp));
        findings.addAll(checkWildcards(csp));
        findings.addAll(checkMissingDirectives(csp));
        findings.addAll(checkScriptAllowlistBypass(csp));
        findings.addAll(checkFlashObjectAllowlistBypass(csp));
        findings.addAll(checkIpSource(csp));
        findings.addAll(checkNonceLength(csp));
        findings.addAll(checkSrcHttp(csp));
        findings.addAll(checkDeprecatedDirective(csp));
        findings.addAll(checkHasConfiguredReporting(csp));

        // 4. Strict CSP checks
        findings.addAll(checkStrictDynamic(csp));
        findings.addAll(checkStrictDynamicNotStandalone(csp));
        findings.addAll(checkUnsafeInlineFallback(csp));
        findings.addAll(checkAllowlistFallback(csp));

        Collections.sort(findings);
        return findings;
    }

    // ── Security Checks ────────────────────────────────────────────────────────

    public static List<CspFinding> checkScriptUnsafeInline(CspModel effectiveCsp) {
        List<CspFinding> violations = new ArrayList<>();
        List<String> directivesToCheck = effectiveCsp.getEffectiveDirectives(List.of(
            CspModel.DIRECTIVE_SCRIPT_SRC, CspModel.DIRECTIVE_SCRIPT_SRC_ATTR, CspModel.DIRECTIVE_SCRIPT_SRC_ELEM
        ));

        for (String directive : directivesToCheck) {
            List<String> values = effectiveCsp.getDirectiveValues(directive);
            if (values.contains(CspModel.KEYWORD_UNSAFE_INLINE)) {
                violations.add(new CspFinding(
                    CspFindingType.SCRIPT_UNSAFE_INLINE,
                    "'unsafe-inline' allows the execution of unsafe in-page scripts and event handlers.",
                    CspSeverity.HIGH,
                    directive,
                    CspModel.KEYWORD_UNSAFE_INLINE
                ));
            }
            if (values.contains(CspModel.KEYWORD_UNSAFE_HASHES)) {
                violations.add(new CspFinding(
                    CspFindingType.SCRIPT_UNSAFE_HASHES,
                    "'unsafe-hashes', while safer than 'unsafe-inline', allows the execution of unsafe in-page scripts and event handlers as long as their hashes appear in the CSP. Please refactor them to no longer use inline scripts if possible.",
                    CspSeverity.MEDIUM_MAYBE,
                    directive,
                    CspModel.KEYWORD_UNSAFE_HASHES
                ));
            }
        }
        return violations;
    }

    public static List<CspFinding> checkScriptUnsafeEval(CspModel parsedCsp) {
        List<CspFinding> violations = new ArrayList<>();
        List<String> directivesToCheck = parsedCsp.getEffectiveDirectives(List.of(
            CspModel.DIRECTIVE_SCRIPT_SRC, CspModel.DIRECTIVE_SCRIPT_SRC_ATTR, CspModel.DIRECTIVE_SCRIPT_SRC_ELEM
        ));

        for (String directive : directivesToCheck) {
            List<String> values = parsedCsp.getDirectiveValues(directive);
            if (values.contains(CspModel.KEYWORD_UNSAFE_EVAL)) {
                violations.add(new CspFinding(
                    CspFindingType.SCRIPT_UNSAFE_EVAL,
                    "'unsafe-eval' allows the execution of code injected into DOM APIs such as eval().",
                    CspSeverity.MEDIUM_MAYBE,
                    directive,
                    CspModel.KEYWORD_UNSAFE_EVAL
                ));
            }
        }
        return violations;
    }

    public static List<CspFinding> checkPlainUrlSchemes(CspModel parsedCsp) {
        List<CspFinding> violations = new ArrayList<>();
        List<String> directivesToCheck = parsedCsp.getEffectiveDirectives(DIRECTIVES_CAUSING_XSS);

        for (String directive : directivesToCheck) {
            List<String> values = parsedCsp.getDirectiveValues(directive);
            for (String value : values) {
                if (URL_SCHEMES_CAUSING_XSS.contains(value.toLowerCase())) {
                    violations.add(new CspFinding(
                        CspFindingType.PLAIN_URL_SCHEMES,
                        value + " URI in " + directive + " allows the execution of unsafe scripts.",
                        CspSeverity.HIGH,
                        directive,
                        value
                    ));
                }
            }
        }
        return violations;
    }

    public static List<CspFinding> checkWildcards(CspModel parsedCsp) {
        List<CspFinding> violations = new ArrayList<>();
        List<String> directivesToCheck = parsedCsp.getEffectiveDirectives(DIRECTIVES_CAUSING_XSS);

        for (String directive : directivesToCheck) {
            List<String> values = parsedCsp.getDirectiveValues(directive);
            for (String value : values) {
                String url = AllowlistBypasses.getSchemeFreeUrl(value);
                if ("*".equals(url)) {
                    violations.add(new CspFinding(
                        CspFindingType.PLAIN_WILDCARD,
                        directive + " should not allow '*' as source.",
                        CspSeverity.HIGH,
                        directive,
                        value
                    ));
                }
            }
        }
        return violations;
    }

    public static List<CspFinding> checkMissingDirectives(CspModel parsedCsp) {
        List<CspFinding> violations = new ArrayList<>();

        // checkMissingObjectSrcDirective
        List<String> objectRestrictions = null;
        if (parsedCsp.hasDirective(CspModel.DIRECTIVE_OBJECT_SRC)) {
            objectRestrictions = parsedCsp.getDirectiveValues(CspModel.DIRECTIVE_OBJECT_SRC);
        } else if (parsedCsp.hasDirective(CspModel.DIRECTIVE_DEFAULT_SRC)) {
            objectRestrictions = parsedCsp.getDirectiveValues(CspModel.DIRECTIVE_DEFAULT_SRC);
        }
        if (objectRestrictions == null || objectRestrictions.isEmpty()) {
            violations.add(new CspFinding(
                CspFindingType.MISSING_DIRECTIVES,
                "Missing object-src allows the injection of plugins which can execute JavaScript. Can you set it to 'none'?",
                CspSeverity.HIGH,
                CspModel.DIRECTIVE_OBJECT_SRC,
                ""
            ));
        }

        // checkMissingScriptSrcDirective
        if (!parsedCsp.hasDirective(CspModel.DIRECTIVE_SCRIPT_SRC) && !parsedCsp.hasDirective(CspModel.DIRECTIVE_DEFAULT_SRC)) {
            violations.add(new CspFinding(
                CspFindingType.MISSING_DIRECTIVES,
                "script-src directive is missing.",
                CspSeverity.HIGH,
                CspModel.DIRECTIVE_SCRIPT_SRC,
                ""
            ));
        }

        // checkMissingBaseUriDirective
        boolean needsBaseUri = parsedCsp.policyHasScriptNonces() ||
                (parsedCsp.policyHasScriptHashes() && parsedCsp.policyHasStrictDynamic());
        if (needsBaseUri && !parsedCsp.hasDirective(CspModel.DIRECTIVE_BASE_URI)) {
            violations.add(new CspFinding(
                CspFindingType.MISSING_DIRECTIVES,
                "Missing base-uri allows the injection of base tags. They can be used to set the base URL for all relative (script) URLs to an attacker controlled domain. Can you set it to 'none' or 'self'?",
                CspSeverity.HIGH,
                CspModel.DIRECTIVE_BASE_URI,
                ""
            ));
        }

        return violations;
    }

    public static List<CspFinding> checkScriptAllowlistBypass(CspModel parsedCsp) {
        List<CspFinding> violations = new ArrayList<>();
        List<String> targetDirectives = parsedCsp.getEffectiveDirectives(List.of(
            CspModel.DIRECTIVE_SCRIPT_SRC, CspModel.DIRECTIVE_SCRIPT_SRC_ELEM
        ));

        for (String effectiveDirective : targetDirectives) {
            List<String> values = parsedCsp.getDirectiveValues(effectiveDirective);
            if (values.contains(CspModel.KEYWORD_NONE)) {
                continue;
            }

            for (String value : values) {
                if (CspModel.KEYWORD_SELF.equals(value)) {
                    violations.add(new CspFinding(
                        CspFindingType.SCRIPT_ALLOWLIST_BYPASS,
                        "'self' can be problematic if you host JSONP, AngularJS or user uploaded files.",
                        CspSeverity.MEDIUM_MAYBE,
                        effectiveDirective,
                        value
                    ));
                    continue;
                }

                // Ignore keywords, nonces, hashes
                if (value.startsWith("'")) {
                    continue;
                }

                // Ignore standalone schemes and items without dot
                if (CspModel.isUrlScheme(value) || !value.contains(".")) {
                    continue;
                }

                String url = "//" + AllowlistBypasses.getSchemeFreeUrl(value);

                AllowlistBypasses.BypassMatch angularBypass =
                    AllowlistBypasses.matchWildcardUrls(url, AllowlistBypasses.ANGULAR_URLS);

                AllowlistBypasses.BypassMatch jsonpBypass =
                    AllowlistBypasses.matchWildcardUrls(url, AllowlistBypasses.JSONP_URLS);

                // Some JSONP bypasses only work in presence of unsafe-eval
                if (jsonpBypass != null) {
                    boolean evalRequired = AllowlistBypasses.NEEDS_EVAL.contains(jsonpBypass.hostname().toLowerCase());
                    boolean evalPresent = values.contains(CspModel.KEYWORD_UNSAFE_EVAL);
                    if (evalRequired && !evalPresent) {
                        jsonpBypass = null;
                    }
                }

                if (jsonpBypass != null || angularBypass != null) {
                    String bypassDomain = (jsonpBypass != null) ? jsonpBypass.hostname() : angularBypass.hostname();
                    StringBuilder bypassTxt = new StringBuilder();
                    if (jsonpBypass != null) bypassTxt.append(" JSONP endpoints");
                    if (angularBypass != null) {
                        if (bypassTxt.length() > 0) bypassTxt.append(" and");
                        bypassTxt.append(" Angular libraries");
                    }

                    violations.add(new CspFinding(
                        CspFindingType.SCRIPT_ALLOWLIST_BYPASS,
                        bypassDomain + " is known to host" + bypassTxt + " which allow to bypass this CSP.",
                        CspSeverity.HIGH,
                        effectiveDirective,
                        value
                    ));
                } else {
                    violations.add(new CspFinding(
                        CspFindingType.SCRIPT_ALLOWLIST_BYPASS,
                        "No bypass found; make sure that this URL doesn't serve JSONP replies or Angular libraries.",
                        CspSeverity.MEDIUM_MAYBE,
                        effectiveDirective,
                        value
                    ));
                }
            }
        }

        return violations;
    }

    public static List<CspFinding> checkFlashObjectAllowlistBypass(CspModel parsedCsp) {
        List<CspFinding> violations = new ArrayList<>();
        String effectiveObjectSrc = parsedCsp.getEffectiveDirective(CspModel.DIRECTIVE_OBJECT_SRC);
        List<String> values = parsedCsp.getDirectiveValues(effectiveObjectSrc);

        List<String> pluginTypes = parsedCsp.getDirectiveValues(CspModel.DIRECTIVE_PLUGIN_TYPES);
        if (pluginTypes != null && !pluginTypes.isEmpty() && !pluginTypes.contains("application/x-shockwave-flash")) {
            return violations;
        }

        for (String value : values) {
            if (CspModel.KEYWORD_NONE.equals(value)) {
                continue;
            }

            String url = "//" + AllowlistBypasses.getSchemeFreeUrl(value);
            AllowlistBypasses.BypassMatch flashBypass =
                AllowlistBypasses.matchWildcardUrls(url, AllowlistBypasses.FLASH_URLS);

            if (flashBypass != null) {
                violations.add(new CspFinding(
                    CspFindingType.OBJECT_ALLOWLIST_BYPASS,
                    flashBypass.hostname() + " is known to host Flash files which allow to bypass this CSP.",
                    CspSeverity.HIGH,
                    effectiveObjectSrc,
                    value
                ));
            } else if (CspModel.DIRECTIVE_OBJECT_SRC.equals(effectiveObjectSrc)) {
                violations.add(new CspFinding(
                    CspFindingType.OBJECT_ALLOWLIST_BYPASS,
                    "Can you restrict object-src to 'none' only?",
                    CspSeverity.MEDIUM_MAYBE,
                    effectiveObjectSrc,
                    value
                ));
            }
        }

        return violations;
    }

    public static List<CspFinding> checkIpSource(CspModel parsedCsp) {
        List<CspFinding> violations = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : parsedCsp.getDirectives().entrySet()) {
            String directive = entry.getKey();
            for (String value : entry.getValue()) {
                String host = AllowlistBypasses.getHostname(value);
                if (looksLikeIpAddress(host)) {
                    if ("127.0.0.1".equals(host)) {
                        violations.add(new CspFinding(
                            CspFindingType.IP_SOURCE,
                            directive + " directive allows localhost as source. Please make sure to remove this in production environments.",
                            CspSeverity.INFO,
                            directive,
                            value
                        ));
                    } else {
                        violations.add(new CspFinding(
                            CspFindingType.IP_SOURCE,
                            directive + " directive has an IP address as source: " + host + " (will be ignored by browsers!).",
                            CspSeverity.INFO,
                            directive,
                            value
                        ));
                    }
                }
            }
        }
        return violations;
    }

    private static boolean looksLikeIpAddress(String maybeIp) {
        if (maybeIp == null) return false;
        if (maybeIp.startsWith("[") && maybeIp.endsWith("]")) return true;
        return IPV4_PATTERN.matcher(maybeIp).matches();
    }

    public static List<CspFinding> checkNonceLength(CspModel parsedCsp) {
        List<CspFinding> violations = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : parsedCsp.getDirectives().entrySet()) {
            String directive = entry.getKey();
            for (String value : entry.getValue()) {
                Matcher m = NONCE_REGEX.matcher(value);
                if (m.matches()) {
                    String nonceValue = m.group(1);
                    if (nonceValue.length() < 8) {
                        violations.add(new CspFinding(
                            CspFindingType.NONCE_LENGTH,
                            "Nonces should be at least 8 characters long.",
                            CspSeverity.MEDIUM,
                            directive,
                            value
                        ));
                    }
                    if (!CspModel.isNonce(value, true)) {
                        violations.add(new CspFinding(
                            CspFindingType.NONCE_CHARSET,
                            "Nonces should only use the base64 charset.",
                            CspSeverity.INFO,
                            directive,
                            value
                        ));
                    }
                }
            }
        }
        return violations;
    }

    public static List<CspFinding> checkSrcHttp(CspModel parsedCsp) {
        List<CspFinding> violations = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : parsedCsp.getDirectives().entrySet()) {
            String directive = entry.getKey();
            for (String value : entry.getValue()) {
                if (value.toLowerCase().startsWith("http://")) {
                    String desc = CspModel.DIRECTIVE_REPORT_URI.equals(directive)
                        ? "Use HTTPS to send violation reports securely."
                        : "Allow only resources downloaded over HTTPS.";
                    violations.add(new CspFinding(
                        CspFindingType.SRC_HTTP,
                        desc,
                        CspSeverity.MEDIUM,
                        directive,
                        value
                    ));
                }
            }
        }
        return violations;
    }

    public static List<CspFinding> checkDeprecatedDirective(CspModel parsedCsp) {
        List<CspFinding> violations = new ArrayList<>();
        if (parsedCsp.hasDirective(CspModel.DIRECTIVE_REFLECTED_XSS)) {
            violations.add(new CspFinding(
                CspFindingType.DEPRECATED_DIRECTIVE,
                "reflected-xss is deprecated since CSP2. Please use the X-XSS-Protection header instead.",
                CspSeverity.INFO,
                CspModel.DIRECTIVE_REFLECTED_XSS,
                ""
            ));
        }
        if (parsedCsp.hasDirective(CspModel.DIRECTIVE_REFERRER)) {
            violations.add(new CspFinding(
                CspFindingType.DEPRECATED_DIRECTIVE,
                "referrer is deprecated since CSP2. Please use the Referrer-Policy header instead.",
                CspSeverity.INFO,
                CspModel.DIRECTIVE_REFERRER,
                ""
            ));
        }
        if (parsedCsp.hasDirective(CspModel.DIRECTIVE_DISOWN_OPENER)) {
            violations.add(new CspFinding(
                CspFindingType.DEPRECATED_DIRECTIVE,
                "disown-opener is deprecated since CSP3. Please use the Cross Origin Opener Policy header instead.",
                CspSeverity.INFO,
                CspModel.DIRECTIVE_DISOWN_OPENER,
                ""
            ));
        }
        if (parsedCsp.hasDirective(CspModel.DIRECTIVE_PREFETCH_SRC)) {
            violations.add(new CspFinding(
                CspFindingType.DEPRECATED_DIRECTIVE,
                "prefetch-src is deprecated since CSP3. Be aware that this feature may cease to work at any time.",
                CspSeverity.INFO,
                CspModel.DIRECTIVE_PREFETCH_SRC,
                ""
            ));
        }
        return violations;
    }

    public static List<CspFinding> checkHasConfiguredReporting(CspModel parsedCsp) {
        List<String> reportUri = parsedCsp.getDirectiveValues(CspModel.DIRECTIVE_REPORT_URI);
        if (!reportUri.isEmpty()) {
            return Collections.emptyList();
        }

        List<String> reportTo = parsedCsp.getDirectiveValues(CspModel.DIRECTIVE_REPORT_TO);
        if (!reportTo.isEmpty()) {
            return List.of(new CspFinding(
                CspFindingType.REPORT_TO_ONLY,
                "This CSP policy only provides a reporting destination via the 'report-to' directive. This directive is only supported in Chromium-based browsers so it is recommended to also use a 'report-uri' directive.",
                CspSeverity.INFO,
                CspModel.DIRECTIVE_REPORT_TO,
                ""
            ));
        }

        return List.of(new CspFinding(
            CspFindingType.REPORTING_DESTINATION_MISSING,
            "This CSP policy does not configure a reporting destination. This makes it difficult to maintain the CSP policy over time and monitor for any breakages.",
            CspSeverity.INFO,
            CspModel.DIRECTIVE_REPORT_URI,
            ""
        ));
    }

    // ── Parser Checks ──────────────────────────────────────────────────────────

    public static List<CspFinding> checkUnknownDirective(CspModel parsedCsp) {
        List<CspFinding> findings = new ArrayList<>();
        for (String directive : parsedCsp.getDirectives().keySet()) {
            if (CspModel.isDirective(directive)) {
                continue;
            }
            if (directive.endsWith(":")) {
                findings.add(new CspFinding(
                    CspFindingType.UNKNOWN_DIRECTIVE,
                    "CSP directives don't end with a colon.",
                    CspSeverity.SYNTAX,
                    directive,
                    ""
                ));
            } else {
                findings.add(new CspFinding(
                    CspFindingType.UNKNOWN_DIRECTIVE,
                    "Directive \"" + directive + "\" is not a known CSP directive.",
                    CspSeverity.SYNTAX,
                    directive,
                    ""
                ));
            }
        }
        return findings;
    }

    public static List<CspFinding> checkMissingSemicolon(CspModel parsedCsp) {
        List<CspFinding> findings = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : parsedCsp.getDirectives().entrySet()) {
            String directive = entry.getKey();
            for (String val : entry.getValue()) {
                if (CspModel.isDirective(val)) {
                    findings.add(new CspFinding(
                        CspFindingType.MISSING_SEMICOLON,
                        "Did you forget the semicolon? \"" + val + "\" seems to be a directive, not a value.",
                        CspSeverity.SYNTAX,
                        directive,
                        val
                    ));
                }
            }
        }
        return findings;
    }

    public static List<CspFinding> checkInvalidKeyword(CspModel parsedCsp) {
        List<CspFinding> findings = new ArrayList<>();
        List<String> keywordsNoTicks = CspModel.ALL_KEYWORDS.stream()
                .map(k -> k.replace("'", ""))
                .toList();

        for (Map.Entry<String, List<String>> entry : parsedCsp.getDirectives().entrySet()) {
            String directive = entry.getKey();
            for (String value : entry.getValue()) {
                if (keywordsNoTicks.contains(value) || value.startsWith("nonce-") ||
                        value.startsWith("sha256-") || value.startsWith("sha384-") || value.startsWith("sha512-")) {
                    findings.add(new CspFinding(
                        CspFindingType.INVALID_KEYWORD,
                        "Did you forget to surround \"" + value + "\" with single-ticks?",
                        CspSeverity.SYNTAX,
                        directive,
                        value
                    ));
                    continue;
                }

                if (!value.startsWith("'")) {
                    continue;
                }

                if (CspModel.DIRECTIVE_REQUIRE_TRUSTED_TYPES_FOR.equals(directive)) {
                    if ("'script'".equals(value)) continue;
                } else if (CspModel.DIRECTIVE_TRUSTED_TYPES.equals(directive)) {
                    if ("'allow-duplicates'".equals(value) || "'none'".equals(value)) continue;
                } else {
                    if (CspModel.isKeyword(value) || CspModel.isHash(value, true) || CspModel.isNonce(value, true)) {
                        continue;
                    }
                }

                findings.add(new CspFinding(
                    CspFindingType.INVALID_KEYWORD,
                    value + " seems to be an invalid CSP keyword.",
                    CspSeverity.SYNTAX,
                    directive,
                    value
                ));
            }
        }
        return findings;
    }

    // ── Strict CSP Checks ──────────────────────────────────────────────────────

    public static List<CspFinding> checkStrictDynamic(CspModel parsedCsp) {
        String directiveName = parsedCsp.getEffectiveDirective(CspModel.DIRECTIVE_SCRIPT_SRC);
        List<String> values = parsedCsp.getDirectiveValues(directiveName);

        boolean schemeOrHostPresent = values.stream().anyMatch(v -> !v.startsWith("'"));
        if (schemeOrHostPresent && !values.contains(CspModel.KEYWORD_STRICT_DYNAMIC)) {
            return List.of(new CspFinding(
                CspFindingType.STRICT_DYNAMIC,
                "Host allowlists can frequently be bypassed. Consider using 'strict-dynamic' in combination with CSP nonces or hashes.",
                CspSeverity.STRICT_CSP,
                directiveName,
                ""
            ));
        }
        return Collections.emptyList();
    }

    public static List<CspFinding> checkStrictDynamicNotStandalone(CspModel parsedCsp) {
        String directiveName = parsedCsp.getEffectiveDirective(CspModel.DIRECTIVE_SCRIPT_SRC);
        List<String> values = parsedCsp.getDirectiveValues(directiveName);

        if (values.contains(CspModel.KEYWORD_STRICT_DYNAMIC) && !parsedCsp.policyHasScriptNonces() && !parsedCsp.policyHasScriptHashes()) {
            return List.of(new CspFinding(
                CspFindingType.STRICT_DYNAMIC_NOT_STANDALONE,
                "'strict-dynamic' without a CSP nonce/hash will block all scripts.",
                CspSeverity.INFO,
                directiveName,
                ""
            ));
        }
        return Collections.emptyList();
    }

    public static List<CspFinding> checkUnsafeInlineFallback(CspModel parsedCsp) {
        if (!parsedCsp.policyHasScriptNonces() && !parsedCsp.policyHasScriptHashes()) {
            return Collections.emptyList();
        }

        String directiveName = parsedCsp.getEffectiveDirective(CspModel.DIRECTIVE_SCRIPT_SRC);
        List<String> values = parsedCsp.getDirectiveValues(directiveName);

        if (!values.contains(CspModel.KEYWORD_UNSAFE_INLINE)) {
            return List.of(new CspFinding(
                CspFindingType.UNSAFE_INLINE_FALLBACK,
                "Consider adding 'unsafe-inline' (ignored by browsers supporting nonces/hashes) to be backward compatible with older browsers.",
                CspSeverity.STRICT_CSP,
                directiveName,
                ""
            ));
        }
        return Collections.emptyList();
    }

    public static List<CspFinding> checkAllowlistFallback(CspModel parsedCsp) {
        String directiveName = parsedCsp.getEffectiveDirective(CspModel.DIRECTIVE_SCRIPT_SRC);
        List<String> values = parsedCsp.getDirectiveValues(directiveName);

        if (!values.contains(CspModel.KEYWORD_STRICT_DYNAMIC)) {
            return Collections.emptyList();
        }

        boolean hasSchemeFallback = values.stream().anyMatch(v -> v.equalsIgnoreCase("https:") || v.equalsIgnoreCase("http:"));
        boolean hasWildcardFallback = values.contains("*");

        if (!hasSchemeFallback && !hasWildcardFallback) {
            return List.of(new CspFinding(
                CspFindingType.ALLOWLIST_FALLBACK,
                "Consider adding https: and http: url schemes (ignored by browsers supporting 'strict-dynamic') to be backward compatible with older browsers.",
                CspSeverity.STRICT_CSP,
                directiveName,
                ""
            ));
        }
        return Collections.emptyList();
    }
}
