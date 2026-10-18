# Payload Injector (littlespidy)

> Created with the help of an AI Agent and littlespidy.

A Burp Suite Java extension (Montoya API) combining parameterized security payload injection across requests and HTTP Request Smuggling into a single, clean workspace extension with four independent tabs and dedicated JSON storage.

---

## Features

The extension introduces a unified Suite Tab named **Payload Injector** containing 32 dedicated, independent tabs for all JSON payload categories. The tabs use Swing `WRAP_TAB_LAYOUT`, wrapping cleanly across multiple rows down below without any scroll bars:

### Core Attack Vector Tabs
1. **XSS** (`xss_payloads.json` - 550 payloads): Parameter-attributed XSS templates ({param} placeholder), event handlers, SVG/HTML5, breakout probes, and WAF bypasses.
2. **CSTI** (`csti_payloads.json` - 146 payloads): Client-side and server-side template injection (Angular, Vue, Jinja2, Twig, Freemarker, Velocity).
3. **SQL** (`sql_payloads.json` - 163 payloads): SQL injection syntax probes, boolean blind, time-based delays, UNION attacks, and DB-specific syntax.
4. **HTTP Request Smuggling** (`http_request_smuggling_payloads.json` - 37 payloads): HTTP desync headers and chunked body injections with 3-column overview and discrepancy detail inspector.

### OWASP-Hunting Category Tabs
Dedicated tabs for each of the 28 additional vulnerability categories, each with full search filtering, table sorting, enable/disable toggling, in-place edit/delete/add dialogs, .txt file import, deduplication with safe backups, clipboard copy, and independent JSON storage:
- **Authentication Bypass** (`authentication_bypass_payloads_littlespidy.json` - 297 payloads)
- **Business Logic** (`business_logic_payloads_littlespidy.json` - 27 payloads)
- **Cache Poisoning** (`cache_poisoning_payloads_littlespidy.json` - 21 payloads)
- **Command Injection** (`command_injection_payloads_littlespidy.json` - 290 payloads)
- **CORS Misconfiguration** (`cors_misconfiguration_payloads_littlespidy.json` - 142 payloads)
- **CSV Injection** (`csv_injection_payloads_littlespidy.json` - 137 payloads)
- **Deserialization** (`deserialization_payloads_littlespidy.json` - 127 payloads)
- **File Upload** (`file_upload_payloads_littlespidy.json` - 300 payloads)
- **IDOR** (`idor_payloads_littlespidy.json` - 139 payloads)
- **JWT Vulnerabilities** (`jwt_vulnerabilities_payloads_littlespidy.json` - 86 payloads)
- **LDAP Injection** (`ldap_injection_payloads_littlespidy.json` - 122 payloads)
- **Log Injection** (`log_injection_payloads_littlespidy.json` - 130 payloads)
- **NoSQL Injection** (`nosql_injection_payloads_littlespidy.json` - 170 payloads)
- **Open Redirect** (`open_redirect_payloads_littlespidy.json` - 707 payloads)
- **Password Reset** (`password_reset_payloads_littlespidy.json` - 271 payloads)
- **Path Traversal** (`path_traversal_payloads_littlespidy.json` - 22,815 payloads)
- **Prompt Injection** (`prompt_injection_payloads_littlespidy.json` - 182 payloads)
- **Prototype Pollution** (`prototype_pollution_payloads_littlespidy.json` - 79 payloads)
- **Security Misconfiguration** (`security_misconfiguration_payloads_littlespidy.json` - 5,113 payloads)
- **SSJI** (`ssji_payloads_littlespidy.json` - 268 payloads)
- **SSRF** (`ssrf_payloads_littlespidy.json` - 64 payloads)
- **Symbolic Link Attacks** (`symbolic_link_attacks_payloads_littlespidy.json` - 136 payloads)
- **Timing Attacks** (`timing_attacks_payloads_littlespidy.json` - 167 payloads)
- **Tor-Based Attacks** (`tor_based_attacks_payloads_littlespidy.json` - 132 payloads)
- **Vulnerable Components** (`vulnerable_components_payloads_littlespidy.json` - 30 payloads)
- **Weak Cryptography** (`weak_cryptography_payloads_littlespidy.json` - 134 payloads)
- **Weak Passwords** (`weak_passwords_payloads_littlespidy.json` - 32 payloads)
- **XML Injection** (`xml_injection_payloads_littlespidy.json` - 61 payloads)

### PayloadsAllTheThings Dedicated Category Tabs
- **CRLF Injection** (`crlf_injection_payloads_littlespidy.json` - 17 payloads)
- **File Inclusion** (`file_inclusion_payloads_littlespidy.json` - 4,796 payloads)
- **XXE Injection** (`xxe_injection_payloads_littlespidy.json` - 110 payloads)

---

## Right-Click Context Menu

Right-click in Repeater or any Message Editor to dispatch armed payloads or inject in-place across all 34 parameter categories and HTTP Request Smuggling.

---

## Storage, JSON Files, and Source Reflection

All payloads are saved and loaded strictly through independent JSON files located alongside the extension JAR.

### Multi-Source Reflection Tracking
When a payload appears across multiple intelligence sources (e.g. both OWASP and PayloadsAllTheThings):
- The `Source Type` column displays all reflecting sources (e.g. `OWASP, PayloadsAllTheThings`).
- The `Source File` column displays the originating source files (e.g. `xss-payloads.txt, IntrudersXSS.txt`).
- Deduplicating at runtime merges the sources into the retained entry so you always know every collection that includes the vector.

### Primary Suite Tab Payloads
Enriched with curated payloads from both OWASP and PayloadsAllTheThings:

| Tab | JSON File | Count | Purpose |
|---|---|---|---|
| XSS | xss_payloads.json | 2,518 | Parameter-attributed XSS templates, bypasses, DOM, polyglots, and modern vectors |
| CSTI | csti_payloads.json | 239 | Client-side and server-side template injection (Angular, Vue, Jinja2, Twig, Freemarker, Velocity) |
| SQL | sql_payloads.json | 1,524 | SQL injection error probes, UNION attacks, boolean blind, time-based, and DB-specific |
| HTTP Request Smuggling | http_request_smuggling_payloads.json | 40 | HTTP desync headers, chunked bodies, timing probes, obfuscations, and protocol downgrades |

Modifying, adding, or deleting payloads in one tab has zero side effects on the other tabs.

---

## Build

### Prerequisites
- Java 21+
- Gradle (wrapper included)

### Compile
```bash
cd payload_injector_littlespidy
./gradlew clean build
```

The compiled JAR and all JSON files are output together to `build/libs/`.

Important: The JSON files must remain in the same directory as the JAR file for the extension to load and save payloads.

---

## Installation in Burp Suite

1. Copy the JAR and JSON files from build/libs/ into a folder on your system.
2. In Burp Suite, navigate to Extensions -> Installed -> Add.
3. Choose Extension type: Java.
4. Select payload-injector-littlespidy-1.0.0.jar.
5. Check the Output tab to verify:
   ```
   [PayloadInjector] Loaded 2518 payloads from .../xss_payloads.json
   [PayloadInjector] Loaded 239 payloads from .../csti_payloads.json
   [PayloadInjector] Loaded 1524 payloads from .../sql_payloads.json
   [PayloadInjector] Loaded 40 smuggling payloads from .../http_request_smuggling_payloads.json
   Payload Injector (littlespidy) loaded successfully with 35 tabs!
   ```

