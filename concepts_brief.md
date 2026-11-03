# Dedicated Internal IPs and SSNs Finding Tabs with Azure Insights URL Detection

* **Author:** 0xLittleSpidy
* **Date:** 2026-11-04

## Overview

This feature adds two dedicated finding tabs ("Internal IPs" and "SSNs") to JavaScriptInspector_littlespidy and expands Cloud URLs detection to capture Azure Application Insights and Azure Monitor telemetry ingestion endpoints. The goal is to provide direct, un-filtered triage of high-risk network topology and Personally Identifiable Information (PII) disclosures found within JavaScript source files and unpacked source maps during web security assessments.

## Analysis

### 1. UI Density and Tab Management
JavaScriptInspector_littlespidy already hosts nine tabs: JS and Source Map, Paths, Secrets, Comments, Security Bypasses, Cloud URLs, Dependencies, GraphQL, and AI Security Analyst. Adding two more top-level tabs raises the total to eleven. In standard Swing JTabbedPane layouts, this causes tab header wrapping or horizontal compression on standard screen resolutions (such as 1080p split view). To maintain usability, the tab container must use JTabbedPane.SCROLL_TAB_LAYOUT to allow horizontal scrolling rather than multi-row vertical stacking. Finding counts must also be appended to tab titles (for example, "Internal IPs (4)") to avoid requiring manual tab switching when scanning empty categories.

### 2. Signal Quality vs. False Positives
* **Internal IPv4:** Using RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) with strict lookahead and lookbehind boundaries prevents matching within semantic version numbers (such as 1.10.1.2) or public IPs. Loopback (127.0.0.0/8) and link-local (169.254.0.0/16) are excluded. However, minified JavaScript files frequently contain network defaults, subnet masks (such as 255.255.255.0), or documentation boundaries (such as 10.0.0.0 or 192.168.1.255) that should be tagged or filtered to avoid false alarms.
* **Structural SSNs:** Evaluating code against the raw structural format (AAA-GG-SSSS) without contextual keyword gates introduces false positive risks from product serial numbers, date formats, math ranges, or hyphenated component IDs. While SSA rules eliminate obvious invalid area numbers (000, 666, 900-999), group numbers (00), and serial numbers (0000), common sample fixtures (such as 078-05-1120 or 123-45-6789) occur frequently in frontend test suites and require classification as test fixtures rather than active leaks.
* **Sensitive Data Exposure in UI:** Displaying raw SSNs unmasked in table views poses exposure hazards during live demonstrations, screen sharing, or client walkthroughs. An optional presentation mask toggle ("Mask Display") provides visual safety while preserving raw copying functionality.

### 3. Confinement to JavaScript and Source Maps
Scanning is strictly limited to JavaScript response bodies (application/javascript, text/javascript) and extracted source map contents (sourcesContent arrays). General HTML responses, backend API JSON responses, and CSS files are excluded from this mining pass to prevent excessive processing overhead and noise.

### 4. Azure Application Insights Endpoints
Frontend monitoring agents send telemetry to Azure App Insights and Azure Monitor ingestion domains:
* applicationinsights.azure.com (including dc.applicationinsights.azure.com and regional ingestion subdomains)
* monitor.azure.com (Azure Monitor Data Collection Endpoints)
* services.visualstudio.com (classic telemetry endpoints)
Adding these domains to the cloud URL regex catalog enables detection of exposed instrumentation keys and monitoring topologies.

### 5. Execution Performance and Thread Safety
Mining multi-megabyte minified scripts with multiple complex regex passes cannot run on the Swing Event Dispatch Thread (EDT). Scanning must be dispatched asynchronously through the existing background worker pool with per-script result caps (such as 500 findings per category) to prevent UI freezes and memory exhaustion.

## Goals vs. Non-Goals

* **In-Scope Goals:**
  * Implement two dedicated Swing finding tabs extending BaseFindingPanel_littlespidy: "Internal IPs" and "SSNs".
  * Implement strict RFC 1918 IPv4 detection excluding loopback (127.0.0.0/8) and link-local (169.254.0.0/16).
  * Implement structural US SSN matching adhering to SSA area, group, and serial rules, with support for unmasked display.
  * Update Cloud URLs regex to detect Azure Application Insights and Azure Monitor endpoints.
  * Restrict mining strictly to JavaScript scripts and unpacked source map sources.
  * Integrate finding deep-linking into Burp message editors and the source map code viewer.
  * Persist findings in session storage (JsSessionDTO_littlespidy).
  * Provide an interactive HTML preview (js_inspector_ui_preview_littlespidy.html) prior to Java build.

* **Out-of-Scope Non-Goals:**
  * Passive scanning of general HTTP responses, HTML documents, or API JSON endpoints.
  * Support for unhyphenated (9-digit continuous) SSNs due to prohibitive false positive rates in minified code.
  * IPv6 private address (ULA/link-local) detection in the initial release.
  * Automated active network probing or ping sweeps against discovered internal IP addresses.

## Alternatives Weighed

* **Consolidating IPs and SSNs into the Existing Secrets Tab:** Rejected by author: The user requires separate, dedicated tabs to allow direct triage without needing category dropdown filters.
* **Requiring Contextual Keywords for SSNs (e.g., "ssn", "tax_id"):** Rejected by author: The user requires raw structural matching to identify hardcoded SSNs in raw arrays or unkeyed tuples without requiring field names.
* **Enforcing Default SSN UI Masking:** Rejected by author: The user requires unmasked display by default for immediate verification. A visual-only masking toggle can be provided as a non-intrusive presentation utility.
* **Scanning Full Burp Proxy HTTP History Payloads:** Rejected by author: Confining mining strictly to JS and source maps matches the core mandate of JavaScriptInspector and avoids severe performance bottlenecks.

## Key Decisions & Staging for Next Steps

1. **Tab Layout:** Create InternalIpsPanel_littlespidy and SsnsPanel_littlespidy extending BaseFindingPanel_littlespidy. Use JTabbedPane.SCROLL_TAB_LAYOUT on the root tabbed pane to prevent UI layout degradation.
2. **Regex Implementation:**
   * Internal IPv4: `(?<![0-9.])(?:10\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2}|192\.168(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2})(?![0-9.])`
   * Structural SSN: `\b(?!000|666|9\d{2})(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})\b`
   * Azure Insights: Update CLOUD_URLS_REGEX to include `applicationinsights\.azure\.com|monitor\.azure\.com|services\.visualstudio\.com`.
3. **Data Model & Storage:** Introduce DiscoveredInternalIp and DiscoveredSsn models, update MiningResult, JsDataStore, and JsSessionDTO_littlespidy to ensure persistent session save/restore.
4. **Interactive HTML Mockup:** Update `js_inspector_ui_preview_littlespidy.html` to demonstrate the new tabs and sample data, verify with `xdg-open`.
5. **Next Step:** Proceed to `/egm:egm-draft` to formalize the technical design document.
