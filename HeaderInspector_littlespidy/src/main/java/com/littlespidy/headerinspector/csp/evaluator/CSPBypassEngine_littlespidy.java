// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.evaluator;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * CSPBypass Engine porting techniques and data from renniepak/CSPBypass.
 * Evaluates Content-Security-Policy directives (script-src and default-src)
 * against a curated database of 370+ known CSP bypasses, JSONP gadgets,
 * and script execution endpoints.
 *
 * @author littlespidy
 */
public class CSPBypassEngine_littlespidy {

    private static final String TSV_RESOURCE = "/com/littlespidy/headerinspector/csp/csp_bypass_data.tsv";

    public record BypassEntry(String domain, String code) {}

    public record ParsedCspSource(
            String rawToken,
            String scheme,
            String host,
            boolean wildcardSubdomain,
            String pathPrefix
    ) {}

    public record BypassFinding_littlespidy(
            String domain,
            String directive,
            String sourceToken,
            String code,
            String description
    ) {}

    public record BypassEvaluationResult_littlespidy(
            String rawPolicy,
            String effectiveDirective,
            List<BypassFinding_littlespidy> findings,
            boolean hasUnsafeInline,
            boolean hasNonceOrHash
    ) {
        public int count() {
            return findings != null ? findings.size() : 0;
        }
    }

    private static final Set<String> IGNORED_KEYWORDS = Set.of(
            "'self'", "'unsafe-inline'", "'unsafe-eval'", "'none'",
            "'strict-dynamic'", "'wasm-unsafe-eval'", "'report-sample'"
    );

    private static final Pattern NONCE_OR_HASH_PATTERN = Pattern.compile(
            "^'(nonce|sha(256|384|512))-[a-zA-Z0-9+/=]+'", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern URL_EXTRACTION_PATTERN = Pattern.compile(
            "(?:src|href)=[\"']?([^\"' >]+)", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern URL_PARSER_PATTERN = Pattern.compile(
            "^([a-zA-Z][a-zA-Z0-9+.-]*):\\/\\/([^/?#]+)(\\/[^?#]*)?", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern BARE_SCHEME_PATTERN = Pattern.compile(
            "^[a-zA-Z][a-zA-Z0-9+.-]*:$", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern SCHEME_PREFIX_PATTERN = Pattern.compile(
            "^([a-zA-Z][a-zA-Z0-9+.-]*):\\/\\/", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern NONCE_OR_HASH_IN_STR = Pattern.compile(
            "(^|\\s)'(nonce|sha(256|384|512))-[^\\s']+'", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern UNSAFE_INLINE_IN_STR = Pattern.compile(
            "(^|\\s)'unsafe-inline'", Pattern.CASE_INSENSITIVE
    );

    private static final List<BypassEntry> DATABASE = new ArrayList<>();
    private static volatile boolean loaded = false;

    static {
        loadDatabase();
    }

    public static synchronized void loadDatabase() {
        if (loaded && !DATABASE.isEmpty()) return;
        DATABASE.clear();
        try (InputStream in = CSPBypassEngine_littlespidy.class.getResourceAsStream(TSV_RESOURCE)) {
            if (in == null) {
                return;
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                boolean firstLine = true;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    if (firstLine) {
                        firstLine = false;
                        if (line.toLowerCase(Locale.ROOT).startsWith("domain")) {
                            continue;
                        }
                    }
                    int splitIdx = line.indexOf('\t');
                    if (splitIdx == -1) {
                        splitIdx = line.indexOf(' ');
                    }
                    if (splitIdx > 0 && splitIdx < line.length() - 1) {
                        String domain = line.substring(0, splitIdx).trim();
                        String code = line.substring(splitIdx + 1).trim();
                        if (!domain.isEmpty() && !code.isEmpty()) {
                            DATABASE.add(new BypassEntry(domain, code));
                        }
                    }
                }
            }
            loaded = true;
        } catch (Exception ignored) {
        }
    }

    public static List<BypassEntry> getAllDatabaseEntries() {
        if (!loaded) loadDatabase();
        return Collections.unmodifiableList(DATABASE);
    }

    public static int getDatabaseSize() {
        if (!loaded) loadDatabase();
        return DATABASE.size();
    }

    public static ParsedCspSource parseCSPSource(String token) {
        if (token == null) return null;
        token = token.trim();
        if (token.isEmpty()) return null;

        if (BARE_SCHEME_PATTERN.matcher(token).matches()) {
            return new ParsedCspSource(
                    token,
                    token.substring(0, token.length() - 1).toLowerCase(Locale.ROOT),
                    "*",
                    false,
                    null
            );
        }

        String scheme = null;
        String rest = token;
        Matcher sm = SCHEME_PREFIX_PATTERN.matcher(token);
        if (sm.find()) {
            scheme = sm.group(1).toLowerCase(Locale.ROOT);
            rest = token.substring(sm.end());
        }

        int slashIdx = rest.indexOf('/');
        String host = (slashIdx == -1) ? rest : rest.substring(0, slashIdx);
        String pathPrefix = (slashIdx == -1) ? null : rest.substring(slashIdx);

        if (host.contains(":")) {
            host = host.split(":")[0];
        }
        host = host.toLowerCase(Locale.ROOT);

        boolean wildcardSubdomain = host.startsWith("*.");
        if (wildcardSubdomain) {
            host = host.substring(2);
        }

        return new ParsedCspSource(token, scheme, host, wildcardSubdomain, pathPrefix);
    }

    public static boolean matchesCspSource(String entryDomain, String entryCode, ParsedCspSource cspSource) {
        if (cspSource == null) return false;

        Matcher m = URL_EXTRACTION_PATTERN.matcher(entryCode);
        List<String> candidates = new ArrayList<>();
        if (m.find()) {
            candidates.add(m.group(1));
        } else {
            candidates.add("https://" + entryDomain);
        }

        for (String candidate : candidates) {
            Matcher um = URL_PARSER_PATTERN.matcher(candidate);
            if (!um.find()) continue;

            String urlScheme = um.group(1).toLowerCase(Locale.ROOT);
            String urlHost = um.group(2).split(":")[0].toLowerCase(Locale.ROOT);
            String urlPath = (um.group(3) != null) ? um.group(3) : "/";

            // 1. Scheme check
            if (cspSource.scheme() != null && !cspSource.scheme().equalsIgnoreCase(urlScheme)) {
                continue;
            }

            // 2. Host check
            if (!cspSource.host().equals("*")) {
                if (cspSource.wildcardSubdomain()) {
                    if (!urlHost.endsWith("." + cspSource.host())) {
                        continue;
                    }
                } else {
                    if (!urlHost.equalsIgnoreCase(cspSource.host())) {
                        continue;
                    }
                }
            }

            // 3. Path prefix check
            if (cspSource.pathPrefix() != null && !cspSource.pathPrefix().equals("/")) {
                String prefixWithSlash = cspSource.pathPrefix().endsWith("/")
                        ? cspSource.pathPrefix
                        : cspSource.pathPrefix() + "/";
                if (!urlPath.equals(cspSource.pathPrefix()) && !urlPath.startsWith(prefixWithSlash)) {
                    continue;
                }
            }

            return true;
        }
        return false;
    }

    public static Map<String, String> parseCspDirectives(String rawCsp) {
        Map<String, String> result = new LinkedHashMap<>();
        if (rawCsp == null || rawCsp.isBlank()) return result;

        String normalized = rawCsp.replaceAll("\\s+", " ").trim();
        String[] parts = normalized.split(";");
        for (String part : parts) {
            part = part.trim();
            if (part.isEmpty()) continue;
            int spaceIdx = part.indexOf(' ');
            if (spaceIdx == -1) {
                result.put(part.toLowerCase(Locale.ROOT), "");
            } else {
                String name = part.substring(0, spaceIdx).trim().toLowerCase(Locale.ROOT);
                String value = part.substring(spaceIdx + 1).trim();
                result.put(name, value);
            }
        }
        return result;
    }

    public static List<ParsedCspSource> processCspDirective(String directiveValue) {
        List<ParsedCspSource> sources = new ArrayList<>();
        if (directiveValue == null || directiveValue.isBlank()) return sources;

        String[] tokens = directiveValue.trim().split("\\s+");
        for (String token : tokens) {
            token = token.trim();
            if (token.isEmpty()) continue;
            String lower = token.toLowerCase(Locale.ROOT);
            if (IGNORED_KEYWORDS.contains(lower)) continue;
            if (NONCE_OR_HASH_PATTERN.matcher(token).find()) continue;

            ParsedCspSource parsed = parseCSPSource(token);
            if (parsed != null) {
                sources.add(parsed);
            }
        }
        return sources;
    }

    public static BypassEvaluationResult_littlespidy evaluatePolicy(String rawCsp) {
        if (!loaded) loadDatabase();
        if (rawCsp == null || rawCsp.isBlank()) {
            return new BypassEvaluationResult_littlespidy(
                    "", "", Collections.emptyList(), false, false
            );
        }

        Map<String, String> directives = parseCspDirectives(rawCsp);
        String effectiveDirective = "";
        String directiveValue = "";

        if (directives.containsKey("script-src")) {
            effectiveDirective = "script-src";
            directiveValue = directives.get("script-src");
        } else if (directives.containsKey("default-src")) {
            effectiveDirective = "default-src";
            directiveValue = directives.get("default-src");
        }

        boolean hasNonceOrHash = NONCE_OR_HASH_IN_STR.matcher(directiveValue).find();
        boolean hasUnsafeInline = UNSAFE_INLINE_IN_STR.matcher(directiveValue).find() && !hasNonceOrHash;

        List<BypassFinding_littlespidy> findings = new ArrayList<>();
        if (!effectiveDirective.isEmpty() && !directiveValue.isEmpty()) {
            List<ParsedCspSource> parsedSources = processCspDirective(directiveValue);

            for (BypassEntry entry : DATABASE) {
                for (ParsedCspSource src : parsedSources) {
                    if (matchesCspSource(entry.domain(), entry.code(), src)) {
                        String desc = "Domain '" + entry.domain() + "' allowed by CSP token '" + src.rawToken()
                                + "' in " + effectiveDirective + " has a known CSPBypass technique.";
                        findings.add(new BypassFinding_littlespidy(
                                entry.domain(),
                                effectiveDirective,
                                src.rawToken(),
                                entry.code(),
                                desc
                        ));
                        break;
                    }
                }
            }
        }

        return new BypassEvaluationResult_littlespidy(
                rawCsp, effectiveDirective, findings, hasUnsafeInline, hasNonceOrHash
        );
    }

    public static List<BypassFinding_littlespidy> searchDatabase(String query) {
        if (!loaded) loadDatabase();
        List<BypassFinding_littlespidy> results = new ArrayList<>();
        if (query == null || query.isBlank()) {
            for (BypassEntry entry : DATABASE) {
                results.add(new BypassFinding_littlespidy(
                        entry.domain(), "-", "-", entry.code(), "Database technique"
                ));
            }
            return results;
        }

        String lower = query.trim().toLowerCase(Locale.ROOT);
        for (BypassEntry entry : DATABASE) {
            if (entry.domain().toLowerCase(Locale.ROOT).contains(lower)
                    || entry.code().toLowerCase(Locale.ROOT).contains(lower)) {
                results.add(new BypassFinding_littlespidy(
                        entry.domain(), "-", "-", entry.code(), "Matched keyword search: " + query
                ));
            }
        }
        return results;
    }
}
