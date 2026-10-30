// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Representation of a CORS bypass technique including the 29 PortSwigger techniques.
 */
public class CorsTechnique_littlespidy {

    private static final String DEFAULT_RESOURCE_PATH = "/com/littlespidy/apiinspector/payloads/cors_techniques_littlespidy.json";

    private final String id;
    private final String name;
    private final String description;
    private final String browserNote;
    private final String originTemplate;
    private boolean enabled;

    public CorsTechnique_littlespidy(String id, String name, String description, String browserNote, boolean enabled, String originTemplate) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.browserNote = browserNote;
        this.enabled = enabled;
        this.originTemplate = originTemplate;
    }

    public CorsTechnique_littlespidy(String id, String name, String description, String browserNote, boolean enabled) {
        this(id, name, description, browserNote, enabled, null);
    }

    public CorsTechnique_littlespidy(String id, String name, String description, String browserNote) {
        this(id, name, description, browserNote, true, null);
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getBrowserNote() {
        return browserNote;
    }

    public String getOriginTemplate() {
        return originTemplate;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Resolves the Origin header value to inject for a given base target URL and attacker domain.
     */
    public String resolveOrigin(String targetBaseUrl, String attackerDomain) {
        String base = cleanBaseUrl(targetBaseUrl);
        String attacker = cleanAttackerUrl(attackerDomain);

        if (originTemplate != null && !originTemplate.trim().isEmpty()) {
            return originTemplate.replace("{base}", base).replace("{attacker}", attacker);
        }

        switch (id) {
            case "arbitrary_origin":
                return "https://" + attacker;
            case "trusted_null":
                return "null";
            case "dot_underscore_dot":
                return "https://" + base + "._." + attacker;
            case "dot_hyphen_dot":
                return "https://" + base + ".-." + attacker;
            case "safari_comma":
                return "https://" + base + ".,." + attacker;
            case "safari_semicolon":
                return "https://" + base + ".;." + attacker;
            case "safari_exclamation":
                return "https://" + base + ".!." + attacker;
            case "safari_single_quote":
                return "https://" + base + ".'." + attacker;
            case "safari_open_paren":
                return "https://" + base + ".(." + attacker;
            case "safari_close_paren":
                return "https://" + base + ".)." + attacker;
            case "safari_open_brace":
                return "https://" + base + ".{." + attacker;
            case "safari_close_brace":
                return "https://" + base + ".}." + attacker;
            case "safari_asterisk":
                return "https://" + base + ".*." + attacker;
            case "safari_ampersand":
                return "https://" + base + ".&." + attacker;
            case "safari_backtick":
                return "https://" + base + ".`." + attacker;
            case "firefox_safari_plus":
                return "https://" + base + ".+." + attacker;
            case "prefix_match":
                return "https://" + base + "." + attacker;
            case "safari_equals":
                return "https://" + base + ".=." + attacker;
            case "safari_tilde":
                return "https://" + base + ".~." + attacker;
            case "firefox_safari_dollar":
                return "https://" + base + ".$.+" + attacker;
            case "suffix_match":
                return "https://" + base + attacker;
            case "trust_subdomain":
                return "https://" + attacker + "." + base;
            case "ends_with":
                return "https://anything" + base;
            case "localhost_edge":
                return "https://localhost." + attacker;
            case "unencrypted_ends_with":
                return "http://s" + base;
            case "ipv6_unspecified":
                return "http://[::]";
            case "ipv6_loopback":
                return "http://[::1]";
            case "ipv4_mapped_ipv6":
                return "http://[::ffff:7f00:1]";
            case "ipv6_expanded":
                return "http://[0000:0000:0000:0000:0000:0000:0000:0000]";
            case "localhost_local":
                return "http://" + base + ".localhost";
            default:
                return "https://" + attacker;
        }
    }

    private String cleanBaseUrl(String baseUrl) {
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            return "example.com";
        }
        String s = baseUrl.trim();
        if (s.startsWith("http://")) {
            s = s.substring(7);
        } else if (s.startsWith("https://")) {
            s = s.substring(8);
        }
        if (s.contains("/")) {
            s = s.substring(0, s.indexOf('/'));
        }
        if (s.contains(":")) {
            s = s.substring(0, s.indexOf(':'));
        }
        return s;
    }

    private String cleanAttackerUrl(String attackerUrl) {
        if (attackerUrl == null || attackerUrl.trim().isEmpty()) {
            return "evil.com";
        }
        String s = attackerUrl.trim();
        if (s.startsWith("http://")) {
            s = s.substring(7);
        } else if (s.startsWith("https://")) {
            s = s.substring(8);
        }
        if (s.contains("/")) {
            s = s.substring(0, s.indexOf('/'));
        }
        if (s.contains(":")) {
            s = s.substring(0, s.indexOf(':'));
        }
        return s;
    }

    /**
     * Returns list of all 29 PortSwigger techniques plus arbitrary origin loaded from JSON.
     */
    public static List<CorsTechnique_littlespidy> getDefaultTechniques() {
        InputStream is = CorsTechnique_littlespidy.class.getResourceAsStream(DEFAULT_RESOURCE_PATH);
        if (is == null) {
            File f = new File("src/main/resources/com/littlespidy/apiinspector/payloads/cors_techniques_littlespidy.json");
            if (!f.exists()) {
                f = new File("APIInspector_littlespidy/src/main/resources/com/littlespidy/apiinspector/payloads/cors_techniques_littlespidy.json");
            }
            if (f.exists()) {
                try {
                    is = new FileInputStream(f);
                } catch (Exception ignored) {
                }
            }
        }

        if (is != null) {
            try (InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
                Gson gson = new Gson();
                Type type = new TypeToken<List<CorsTechnique_littlespidy>>() {}.getType();
                List<CorsTechnique_littlespidy> loaded = gson.fromJson(reader, type);
                if (loaded != null && !loaded.isEmpty()) {
                    return loaded;
                }
            } catch (Exception ignored) {
            }
        }

        return getFallbackTechniques();
    }

    public static List<CorsTechnique_littlespidy> getFallbackTechniques() {
        List<CorsTechnique_littlespidy> list = new ArrayList<>();
        list.add(new CorsTechnique_littlespidy("arbitrary_origin", "Arbitrary Attacker Origin", "Reflects arbitrary untrusted origin", "Universal bypass test", true, "https://{attacker}"));
        list.add(new CorsTechnique_littlespidy("trusted_null", "Trusted Null Origin", "CORS vulnerability with trusted null origin", "Sandboxed iframe / data URI", true, "null"));
        list.add(new CorsTechnique_littlespidy("dot_underscore_dot", "Dot-Underscore-Dot Subdomain", "Underscore subdomain bypass", "Bypasses naive domain regex matching", true, "https://{base}._.{attacker}"));
        list.add(new CorsTechnique_littlespidy("dot_hyphen_dot", "Dot-Hyphen-Dot Subdomain", "Hyphen subdomain bypass", "Bypasses subdomain regex", true, "https://{base}.-.{attacker}"));
        list.add(new CorsTechnique_littlespidy("safari_comma", "Safari Comma Subdomain", "Safari allows comma in subdomain", "Safari browser specific", true, "https://{base}.,.{attacker}"));
        list.add(new CorsTechnique_littlespidy("safari_semicolon", "Safari Semicolon Subdomain", "Safari allows semicolon in subdomain", "Safari browser specific", true, "https://{base}.;.{attacker}"));
        list.add(new CorsTechnique_littlespidy("safari_exclamation", "Safari Exclamation Subdomain", "Safari allows exclamation mark in subdomain", "Safari browser specific", true, "https://{base}.!.{attacker}"));
        list.add(new CorsTechnique_littlespidy("safari_single_quote", "Safari Single Quote Subdomain", "Safari allows single quote in subdomain", "Safari browser specific", true, "https://{base}.'.{attacker}"));
        list.add(new CorsTechnique_littlespidy("safari_open_paren", "Safari Open Parenthesis", "Safari allows open parenthesis in subdomain", "Safari browser specific", true, "https://{base}.(.{attacker}"));
        list.add(new CorsTechnique_littlespidy("safari_close_paren", "Safari Close Parenthesis", "Safari allows close parenthesis in subdomain", "Safari browser specific", true, "https://{base}.).{attacker}"));
        list.add(new CorsTechnique_littlespidy("safari_open_brace", "Safari Open Brace", "Safari allows open brace in subdomain", "Safari browser specific", true, "https://{base}.{.{attacker}"));
        list.add(new CorsTechnique_littlespidy("safari_close_brace", "Safari Close Brace", "Safari allows close brace in subdomain", "Safari browser specific", true, "https://{base}.}.{attacker}"));
        list.add(new CorsTechnique_littlespidy("safari_asterisk", "Safari Asterisk Subdomain", "Safari allows asterisk in subdomain", "Safari browser specific", true, "https://{base}.*.{attacker}"));
        list.add(new CorsTechnique_littlespidy("safari_ampersand", "Safari Ampersand Subdomain", "Safari allows ampersand in subdomain", "Safari browser specific", true, "https://{base}.&.{attacker}"));
        list.add(new CorsTechnique_littlespidy("safari_backtick", "Safari Backtick Subdomain", "Safari allows backtick in subdomain", "Safari browser specific", true, "https://{base}.`.{attacker}"));
        list.add(new CorsTechnique_littlespidy("firefox_safari_plus", "Firefox & Safari Plus Subdomain", "Firefox and Safari allow plus in subdomain", "Firefox & Safari browser specific", true, "https://{base}.+.{attacker}"));
        list.add(new CorsTechnique_littlespidy("prefix_match", "Prefix Match / Attacker Subdomain", "Regex prefix match without dot anchor", "Common regex error", true, "https://{base}.{attacker}"));
        list.add(new CorsTechnique_littlespidy("safari_equals", "Safari Equals Subdomain", "Safari allows equals in subdomain", "Safari browser specific", true, "https://{base}.=.{attacker}"));
        list.add(new CorsTechnique_littlespidy("safari_tilde", "Safari Tilde Subdomain", "Safari allows tilde in subdomain", "Safari browser specific", true, "https://{base}.~.{attacker}"));
        list.add(new CorsTechnique_littlespidy("firefox_safari_dollar", "Firefox & Safari Dollar Subdomain", "Firefox and Safari allow dollar in subdomain", "Firefox & Safari browser specific", true, "https://{base}.$.+{attacker}"));
        list.add(new CorsTechnique_littlespidy("suffix_match", "Suffix Match (Domain Registration)", "Attacker registers domain ending with allowed domain", "Regex suffix match without boundary", true, "https://{base}{attacker}"));
        list.add(new CorsTechnique_littlespidy("trust_subdomain", "Trust Arbitrary Subdomain", "Insecure wildcard subdomain trust", "Subdomain takeover risk", true, "https://{attacker}.{base}"));
        list.add(new CorsTechnique_littlespidy("ends_with", "Domain Ends With", "Unanchored regex matching end of string", "Unanchored regex", true, "https://anything{base}"));
        list.add(new CorsTechnique_littlespidy("localhost_edge", "Localhost Regex Edge Case", "Localhost regex implementation edge case", "Regex matches localhost without anchor", true, "https://localhost.{attacker}"));
        list.add(new CorsTechnique_littlespidy("unencrypted_ends_with", "Unencrypted Domain Ends With", "Unencrypted domain ends with http://s<allowed>", "Insecure HTTP scheme bypass", true, "http://s{base}"));
        list.add(new CorsTechnique_littlespidy("ipv6_unspecified", "IPv6 Localhost Loopback", "IPv6 unspecified address loopback", "Server trusts loopback origin", true, "http://[::]"));
        list.add(new CorsTechnique_littlespidy("ipv6_loopback", "IPv6 Loopback", "Standard IPv6 loopback", "Server trusts loopback origin", true, "http://[::1]"));
        list.add(new CorsTechnique_littlespidy("ipv4_mapped_ipv6", "IPv4-Mapped IPv6 Loopback", "IPv4-mapped 127.0.0.1 loopback", "Server trusts loopback origin", true, "http://[::ffff:7f00:1]"));
        list.add(new CorsTechnique_littlespidy("ipv6_expanded", "Fully-Expanded IPv6 Loopback", "Fully-expanded IPv6 loopback", "Server trusts expanded IPv6", true, "http://[0000:0000:0000:0000:0000:0000:0000:0000]"));
        list.add(new CorsTechnique_littlespidy("localhost_local", "Localhost Allowed Domain Bypass", "Localhost allowed domain bypass", "Internal domain resolution bypass", true, "http://{base}.localhost"));
        return list;
    }
}
