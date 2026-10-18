// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.model;

import burp.api.montoya.MontoyaApi;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Registry of all parameter-based payload categories and their corresponding JSON files.
 * Provides unified loading for all JSON payload categories across the extension.
 *
 * @author littlespidy
 */
public class PayloadCategoryRegistry_littlespidy {

    /**
     * Category definition pairing a human-readable tab/menu display title with its JSON file name.
     */
    public record CategoryInfo_littlespidy(String displayName, String jsonFileName) {}

    /**
     * Ordered list of all supported parameter payload categories.
     */
    public static final CategoryInfo_littlespidy[] ALL_CATEGORIES = new CategoryInfo_littlespidy[] {
            // Core original categories
            new CategoryInfo_littlespidy("XSS", "xss_payloads.json"),
            new CategoryInfo_littlespidy("CSTI", "csti_payloads.json"),
            new CategoryInfo_littlespidy("SQL", "sql_payloads.json"),

            // OWASP-Hunting categories
            new CategoryInfo_littlespidy("Authentication Bypass", "authentication_bypass_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Business Logic", "business_logic_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Cache Poisoning", "cache_poisoning_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Command Injection", "command_injection_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("CORS Misconfiguration", "cors_misconfiguration_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("CSV Injection", "csv_injection_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Deserialization", "deserialization_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("File Upload", "file_upload_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("IDOR", "idor_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("JWT Vulnerabilities", "jwt_vulnerabilities_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("LDAP Injection", "ldap_injection_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Log Injection", "log_injection_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("NoSQL Injection", "nosql_injection_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Open Redirect", "open_redirect_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Password Reset", "password_reset_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Path Traversal", "path_traversal_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Prompt Injection", "prompt_injection_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Prototype Pollution", "prototype_pollution_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Security Misconfiguration", "security_misconfiguration_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("SSJI", "ssji_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("SSRF", "ssrf_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Symbolic Link Attacks", "symbolic_link_attacks_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Timing Attacks", "timing_attacks_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Tor-Based Attacks", "tor_based_attacks_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Vulnerable Components", "vulnerable_components_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Weak Cryptography", "weak_cryptography_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("Weak Passwords", "weak_passwords_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("XML Injection", "xml_injection_payloads_littlespidy.json"),

            // PayloadsAllTheThings dedicated categories
            new CategoryInfo_littlespidy("CRLF Injection", "crlf_injection_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("File Inclusion", "file_inclusion_payloads_littlespidy.json"),
            new CategoryInfo_littlespidy("XXE Injection", "xxe_injection_payloads_littlespidy.json")
    };

    /**
     * Instantiates dedicated ParamPayloadStore instances for all categories.
     *
     * @param api Montoya API instance
     * @return Ordered Map of Category Display Name to ParamPayloadStore
     */
    public static Map<String, ParamPayloadStore> createAllParamStores(MontoyaApi api) {
        Map<String, ParamPayloadStore> stores = new LinkedHashMap<>();
        for (CategoryInfo_littlespidy info : ALL_CATEGORIES) {
            stores.put(info.displayName(), new ParamPayloadStore(api, info.jsonFileName()));
        }
        return Collections.unmodifiableMap(stores);
    }
}
