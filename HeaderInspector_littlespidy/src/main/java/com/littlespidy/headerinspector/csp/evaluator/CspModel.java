// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.evaluator;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Content Security Policy model and parser ported directly from Google's CSP Evaluator (csp.ts, parser.ts).
 *
 * @author littlespidy
 */
public class CspModel {

    public static final int VERSION_CSP1 = 1;
    public static final int VERSION_CSP2 = 2;
    public static final int VERSION_CSP3 = 3;

    // Common directive constants
    public static final String DIRECTIVE_DEFAULT_SRC = "default-src";
    public static final String DIRECTIVE_SCRIPT_SRC = "script-src";
    public static final String DIRECTIVE_SCRIPT_SRC_ATTR = "script-src-attr";
    public static final String DIRECTIVE_SCRIPT_SRC_ELEM = "script-src-elem";
    public static final String DIRECTIVE_STYLE_SRC = "style-src";
    public static final String DIRECTIVE_STYLE_SRC_ATTR = "style-src-attr";
    public static final String DIRECTIVE_STYLE_SRC_ELEM = "style-src-elem";
    public static final String DIRECTIVE_OBJECT_SRC = "object-src";
    public static final String DIRECTIVE_BASE_URI = "base-uri";
    public static final String DIRECTIVE_FRAME_SRC = "frame-src";
    public static final String DIRECTIVE_CHILD_SRC = "child-src";
    public static final String DIRECTIVE_FRAME_ANCESTORS = "frame-ancestors";
    public static final String DIRECTIVE_CONNECT_SRC = "connect-src";
    public static final String DIRECTIVE_FONT_SRC = "font-src";
    public static final String DIRECTIVE_IMG_SRC = "img-src";
    public static final String DIRECTIVE_MEDIA_SRC = "media-src";
    public static final String DIRECTIVE_MANIFEST_SRC = "manifest-src";
    public static final String DIRECTIVE_WORKER_SRC = "worker-src";
    public static final String DIRECTIVE_PREFETCH_SRC = "prefetch-src";
    public static final String DIRECTIVE_PLUGIN_TYPES = "plugin-types";
    public static final String DIRECTIVE_SANDBOX = "sandbox";
    public static final String DIRECTIVE_DISOWN_OPENER = "disown-opener";
    public static final String DIRECTIVE_FORM_ACTION = "form-action";
    public static final String DIRECTIVE_NAVIGATE_TO = "navigate-to";
    public static final String DIRECTIVE_REPORT_TO = "report-to";
    public static final String DIRECTIVE_REPORT_URI = "report-uri";
    public static final String DIRECTIVE_BLOCK_ALL_MIXED_CONTENT = "block-all-mixed-content";
    public static final String DIRECTIVE_UPGRADE_INSECURE_REQUESTS = "upgrade-insecure-requests";
    public static final String DIRECTIVE_REFLECTED_XSS = "reflected-xss";
    public static final String DIRECTIVE_REFERRER = "referrer";
    public static final String DIRECTIVE_REQUIRE_SRI_FOR = "require-sri-for";
    public static final String DIRECTIVE_TRUSTED_TYPES = "trusted-types";
    public static final String DIRECTIVE_REQUIRE_TRUSTED_TYPES_FOR = "require-trusted-types-for";
    public static final String DIRECTIVE_WEBRTC = "webrtc";

    // Keywords
    public static final String KEYWORD_SELF = "'self'";
    public static final String KEYWORD_NONE = "'none'";
    public static final String KEYWORD_UNSAFE_INLINE = "'unsafe-inline'";
    public static final String KEYWORD_UNSAFE_EVAL = "'unsafe-eval'";
    public static final String KEYWORD_WASM_EVAL = "'wasm-eval'";
    public static final String KEYWORD_WASM_UNSAFE_EVAL = "'wasm-unsafe-eval'";
    public static final String KEYWORD_STRICT_DYNAMIC = "'strict-dynamic'";
    public static final String KEYWORD_UNSAFE_HASHED_ATTRIBUTES = "'unsafe-hashed-attributes'";
    public static final String KEYWORD_UNSAFE_HASHES = "'unsafe-hashes'";
    public static final String KEYWORD_REPORT_SAMPLE = "'report-sample'";
    public static final String KEYWORD_BLOCK = "'block'";
    public static final String KEYWORD_ALLOW = "'allow'";
    public static final String KEYWORD_INLINE_SPECULATION_RULES = "'inline-speculation-rules'";

    public static final Set<String> ALL_DIRECTIVES = Set.of(
        DIRECTIVE_CHILD_SRC, DIRECTIVE_CONNECT_SRC, DIRECTIVE_DEFAULT_SRC,
        DIRECTIVE_FONT_SRC, DIRECTIVE_FRAME_SRC, DIRECTIVE_IMG_SRC,
        DIRECTIVE_MEDIA_SRC, DIRECTIVE_OBJECT_SRC, DIRECTIVE_SCRIPT_SRC,
        DIRECTIVE_SCRIPT_SRC_ATTR, DIRECTIVE_SCRIPT_SRC_ELEM, DIRECTIVE_STYLE_SRC,
        DIRECTIVE_STYLE_SRC_ATTR, DIRECTIVE_STYLE_SRC_ELEM, DIRECTIVE_PREFETCH_SRC,
        DIRECTIVE_MANIFEST_SRC, DIRECTIVE_WORKER_SRC, DIRECTIVE_BASE_URI,
        DIRECTIVE_PLUGIN_TYPES, DIRECTIVE_SANDBOX, DIRECTIVE_DISOWN_OPENER,
        DIRECTIVE_FORM_ACTION, DIRECTIVE_FRAME_ANCESTORS, DIRECTIVE_NAVIGATE_TO,
        DIRECTIVE_REPORT_TO, DIRECTIVE_REPORT_URI, DIRECTIVE_BLOCK_ALL_MIXED_CONTENT,
        DIRECTIVE_UPGRADE_INSECURE_REQUESTS, DIRECTIVE_REFLECTED_XSS, DIRECTIVE_REFERRER,
        DIRECTIVE_REQUIRE_SRI_FOR, DIRECTIVE_TRUSTED_TYPES, DIRECTIVE_REQUIRE_TRUSTED_TYPES_FOR,
        DIRECTIVE_WEBRTC
    );

    public static final Set<String> FETCH_DIRECTIVES = Set.of(
        DIRECTIVE_CHILD_SRC, DIRECTIVE_CONNECT_SRC, DIRECTIVE_DEFAULT_SRC,
        DIRECTIVE_FONT_SRC, DIRECTIVE_FRAME_SRC, DIRECTIVE_IMG_SRC,
        DIRECTIVE_MANIFEST_SRC, DIRECTIVE_MEDIA_SRC, DIRECTIVE_OBJECT_SRC,
        DIRECTIVE_SCRIPT_SRC, DIRECTIVE_SCRIPT_SRC_ATTR, DIRECTIVE_SCRIPT_SRC_ELEM,
        DIRECTIVE_STYLE_SRC, DIRECTIVE_STYLE_SRC_ATTR, DIRECTIVE_STYLE_SRC_ELEM,
        DIRECTIVE_WORKER_SRC
    );

    public static final Set<String> ALL_KEYWORDS = Set.of(
        KEYWORD_SELF, KEYWORD_NONE, KEYWORD_UNSAFE_INLINE, KEYWORD_UNSAFE_EVAL,
        KEYWORD_WASM_EVAL, KEYWORD_WASM_UNSAFE_EVAL, KEYWORD_STRICT_DYNAMIC,
        KEYWORD_UNSAFE_HASHED_ATTRIBUTES, KEYWORD_UNSAFE_HASHES, KEYWORD_REPORT_SAMPLE,
        KEYWORD_BLOCK, KEYWORD_ALLOW, KEYWORD_INLINE_SPECULATION_RULES
    );

    private static final Pattern URL_SCHEME_PATTERN = Pattern.compile("^[a-zA-Z][+a-zA-Z0-9.-]*:$");
    private static final Pattern NONCE_PATTERN = Pattern.compile("^'nonce-(.+)'$");
    private static final Pattern STRICT_NONCE_PATTERN = Pattern.compile("^'nonce-[a-zA-Z0-9+/_-]+[=]{0,2}'$");
    private static final Pattern HASH_PATTERN = Pattern.compile("^'(sha256|sha384|sha512)-(.+)'$");
    private static final Pattern STRICT_HASH_PATTERN = Pattern.compile("^'(sha256|sha384|sha512)-[a-zA-Z0-9+/_-]+[=]{0,2}'$");

    private final Map<String, List<String>> directives = new LinkedHashMap<>();

    public CspModel() {}

    public CspModel(Map<String, List<String>> initialDirectives) {
        if (initialDirectives != null) {
            for (Map.Entry<String, List<String>> entry : initialDirectives.entrySet()) {
                if (entry.getValue() != null) {
                    this.directives.put(entry.getKey(), new ArrayList<>(entry.getValue()));
                }
            }
        }
    }

    public Map<String, List<String>> getDirectives() {
        return directives;
    }

    public List<String> getDirectiveValues(String directive) {
        return directives.getOrDefault(directive.toLowerCase().trim(), Collections.emptyList());
    }

    public boolean hasDirective(String directive) {
        return directives.containsKey(directive.toLowerCase().trim());
    }

    public CspModel cloneModel() {
        return new CspModel(this.directives);
    }

    /**
     * Parses a raw CSP header string into this model matching Google CspParser logic.
     */
    public static CspModel parse(String unparsedCsp) {
        CspModel model = new CspModel();
        if (unparsedCsp == null || unparsedCsp.trim().isEmpty()) {
            return model;
        }

        String[] tokens = unparsedCsp.split(";");
        for (String rawToken : tokens) {
            String trimmed = rawToken.trim();
            if (trimmed.isEmpty()) continue;

            String[] parts = trimmed.split("\\s+");
            if (parts.length == 0) continue;

            String directiveName = parts[0].toLowerCase().trim();
            if (model.directives.containsKey(directiveName)) {
                // If the set of directives already contains a directive whose name is a
                // case-insensitive match, ignore this instance and continue.
                continue;
            }

            List<String> values = new ArrayList<>();
            for (int i = 1; i < parts.length; i++) {
                String val = normalizeDirectiveValue(parts[i]);
                if (!values.contains(val)) {
                    values.add(val);
                }
            }
            model.directives.put(directiveName, values);
        }

        return model;
    }

    private static String normalizeDirectiveValue(String directiveValue) {
        String val = directiveValue.trim();
        String lower = val.toLowerCase();
        if (isKeyword(lower) || isUrlScheme(val)) {
            return lower;
        }
        return val;
    }

    public static boolean isDirective(String directive) {
        return ALL_DIRECTIVES.contains(directive.toLowerCase().trim());
    }

    public static boolean isKeyword(String keyword) {
        return ALL_KEYWORDS.contains(keyword.toLowerCase().trim());
    }

    public static boolean isUrlScheme(String urlScheme) {
        return URL_SCHEME_PATTERN.matcher(urlScheme.trim()).matches();
    }

    public static boolean isNonce(String nonce, boolean strictCheck) {
        if (nonce == null) return false;
        return strictCheck ? STRICT_NONCE_PATTERN.matcher(nonce).matches()
                           : NONCE_PATTERN.matcher(nonce).matches();
    }

    public static boolean isHash(String hash, boolean strictCheck) {
        if (hash == null) return false;
        return strictCheck ? STRICT_HASH_PATTERN.matcher(hash).matches()
                           : HASH_PATTERN.matcher(hash).matches();
    }

    public String getEffectiveDirective(String directive) {
        String lower = directive.toLowerCase().trim();
        if (directives.containsKey(lower)) {
            return lower;
        }

        if ((DIRECTIVE_SCRIPT_SRC_ATTR.equals(lower) || DIRECTIVE_SCRIPT_SRC_ELEM.equals(lower))
                && directives.containsKey(DIRECTIVE_SCRIPT_SRC)) {
            return DIRECTIVE_SCRIPT_SRC;
        }

        if ((DIRECTIVE_STYLE_SRC_ATTR.equals(lower) || DIRECTIVE_STYLE_SRC_ELEM.equals(lower))
                && directives.containsKey(DIRECTIVE_STYLE_SRC)) {
            return DIRECTIVE_STYLE_SRC;
        }

        if (FETCH_DIRECTIVES.contains(lower)) {
            return DIRECTIVE_DEFAULT_SRC;
        }

        return lower;
    }

    public List<String> getEffectiveDirectives(Collection<String> targetDirectives) {
        Set<String> effective = new LinkedHashSet<>();
        for (String d : targetDirectives) {
            effective.add(getEffectiveDirective(d));
        }
        return new ArrayList<>(effective);
    }

    public boolean policyHasScriptNonces(String directive) {
        String eff = getEffectiveDirective(directive == null ? DIRECTIVE_SCRIPT_SRC : directive);
        List<String> values = directives.getOrDefault(eff, Collections.emptyList());
        return values.stream().anyMatch(v -> isNonce(v, true));
    }

    public boolean policyHasScriptNonces() {
        return policyHasScriptNonces(DIRECTIVE_SCRIPT_SRC);
    }

    public boolean policyHasScriptHashes(String directive) {
        String eff = getEffectiveDirective(directive == null ? DIRECTIVE_SCRIPT_SRC : directive);
        List<String> values = directives.getOrDefault(eff, Collections.emptyList());
        return values.stream().anyMatch(v -> isHash(v, true));
    }

    public boolean policyHasScriptHashes() {
        return policyHasScriptHashes(DIRECTIVE_SCRIPT_SRC);
    }

    public boolean policyHasStrictDynamic(String directive) {
        String eff = getEffectiveDirective(directive == null ? DIRECTIVE_SCRIPT_SRC : directive);
        List<String> values = directives.getOrDefault(eff, Collections.emptyList());
        return values.contains(KEYWORD_STRICT_DYNAMIC);
    }

    public boolean policyHasStrictDynamic() {
        return policyHasStrictDynamic(DIRECTIVE_SCRIPT_SRC);
    }

    /**
     * Returns CSP as it would be seen by a UA supporting a specific CSP version (CSP1, CSP2, CSP3).
     */
    public CspModel getEffectiveCsp(int cspVersion, List<CspFinding> optFindings) {
        CspModel effective = this.cloneModel();
        List<String> scriptDirectives = List.of(DIRECTIVE_SCRIPT_SRC, DIRECTIVE_SCRIPT_SRC_ATTR, DIRECTIVE_SCRIPT_SRC_ELEM);

        for (String dirToNormalize : scriptDirectives) {
            String directive = effective.getEffectiveDirective(dirToNormalize);
            List<String> values = this.directives.getOrDefault(directive, Collections.emptyList());
            List<String> effectiveValues = effective.directives.get(directive);

            if (effectiveValues != null && (effective.policyHasScriptNonces(directive) || effective.policyHasScriptHashes(directive))) {
                if (cspVersion >= VERSION_CSP2) {
                    if (values.contains(KEYWORD_UNSAFE_INLINE)) {
                        effectiveValues.remove(KEYWORD_UNSAFE_INLINE);
                        if (optFindings != null) {
                            optFindings.add(new CspFinding(
                                CspFindingType.IGNORED,
                                "'unsafe-inline' is ignored if a nonce or a hash is present (CSP2 and above).",
                                CspSeverity.NONE, directive, KEYWORD_UNSAFE_INLINE
                            ));
                        }
                    }
                } else {
                    effectiveValues.removeIf(v -> v.startsWith("'nonce-") || v.startsWith("'sha"));
                }
            }

            if (effectiveValues != null && this.policyHasStrictDynamic(directive)) {
                if (cspVersion >= VERSION_CSP3) {
                    List<String> toRemove = new ArrayList<>();
                    for (String val : values) {
                        if (!val.startsWith("'") || KEYWORD_SELF.equals(val) || KEYWORD_UNSAFE_INLINE.equals(val)) {
                            toRemove.add(val);
                            if (optFindings != null) {
                                optFindings.add(new CspFinding(
                                    CspFindingType.IGNORED,
                                    "Because of 'strict-dynamic' this entry is ignored in CSP3 and above.",
                                    CspSeverity.NONE, directive, val
                                ));
                            }
                        }
                    }
                    effectiveValues.removeAll(toRemove);
                } else {
                    effectiveValues.remove(KEYWORD_STRICT_DYNAMIC);
                }
            }
        }

        if (cspVersion < VERSION_CSP3) {
            effective.directives.remove(DIRECTIVE_REPORT_TO);
            effective.directives.remove(DIRECTIVE_WORKER_SRC);
            effective.directives.remove(DIRECTIVE_MANIFEST_SRC);
            effective.directives.remove(DIRECTIVE_TRUSTED_TYPES);
            effective.directives.remove(DIRECTIVE_REQUIRE_TRUSTED_TYPES_FOR);
            effective.directives.remove(DIRECTIVE_SCRIPT_SRC_ATTR);
            effective.directives.remove(DIRECTIVE_SCRIPT_SRC_ELEM);
            effective.directives.remove(DIRECTIVE_STYLE_SRC_ATTR);
            effective.directives.remove(DIRECTIVE_STYLE_SRC_ELEM);
        }

        return effective;
    }
}
