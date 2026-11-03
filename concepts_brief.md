# Dedicated Internal IPs and SSNs Tabs with Two-Tier Cloud Engine

* **Author:** 0xLittleSpidy
* **Date:** 2026-11-04

## Overview

This feature introduces two dedicated finding tabs ("Internal IPs" and "SSNs") to JavaScriptInspector_littlespidy and upgrades the cloud resource mining pipeline to a comprehensive Two-Tier Cloud Engine. The engine captures 100% of cloud services across Amazon Web Services (AWS), Microsoft Azure, Google Cloud Platform (GCP), and Firebase without regex backtracking, and introduces a dedicated "Service" column and multi-select service filter dropdown in the Cloud URLs panel.

## Analysis

### 1. Dedicated Tabs and UI Density
* **Tab Layout Management:** JavaScriptInspector_littlespidy currently contains nine tabs. Adding "Internal IPs" and "SSNs" expands the suite to 11 tabs. In standard Swing, multi-row wrapping consumes excessive vertical space. The tab container must be configured with `JTabbedPane.SCROLL_TAB_LAYOUT` to provide horizontal arrow navigation, and tab titles must include dynamic finding counters (e.g., `Internal IPs (4)`) to avoid blind tab switching.
* **BaseFindingPanel Integration:** Both new panels (`InternalIpsPanel_littlespidy` and `SsnsPanel_littlespidy`) extend `BaseFindingPanel_littlespidy`, inheriting standard 50/50 split Montoya Request/Response viewers, occurrence navigators, TSV clipboard export, search filtering, and user classification marking ("Investigating", "False Positive", "Confirmed").

### 2. Mining Precision & Signal Quality
* **RFC 1918 Internal IPv4:** Uses strict boundary matching `(?<![0-9.])(?:10\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2}|192\.168(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2})(?![0-9.])`. Loopback addresses (`127.0.0.0/8`) and link-local addresses (`169.254.0.0/16`) are strictly excluded. Boundaries suppress partial matches inside public IPs and semantic version strings.
* **Structural US SSN:** Evaluates hyphenated syntax `\b(?!000|666|9\d{2})(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})\b` enforcing SSA area, group, and serial rules. Unmasked display is standard in the table and persistent storage. An optional toolbar toggle (`[ ] Mask SSNs`) provides presentation safety during live demos or screen sharing without altering copied values.
* **Confinement to Client-Side Assets:** Scanning is strictly confined to JavaScript source files and extracted source map files (`sourcesContent`). General HTML responses, backend API JSON endpoints, and CSS stylesheets are excluded.

### 3. Two-Tier Cloud Engine Architecture
Capturing all services across AWS, Azure, and GCP requires moving away from single-pattern subdomain matching:
* **Tier 1 (Root Domain Anchor Engine):** Fast root regex matching authoritative cloud zones without backtracking:
  * AWS: `*.amazonaws.com`, `*.on.aws`, `*.amazoncognito.com`, `*.elasticbeanstalk.com`, `*.amplifyapp.com`, `*.cloudfront.net`
  * Azure: `*.windows.net`, `*.azure.com`, `*.azurewebsites.net`, `*.azure-api.net`, `*.azurefd.net`, `*.azureedge.net`, `*.azurecontainerapps.io`, `*.applicationinsights.azure.com`, `*.monitor.azure.com`, `*.services.visualstudio.com`, `*.azurestaticapps.net`, `*.cloudapp.net`
  * Google Cloud & Firebase: `*.googleapis.com`, `*.run.app`, `*.cloudfunctions.net`, `*.appspot.com`, `*.web.app`, `*.firebaseapp.com`, `*.firebaseio.com`, `*.firebasedatabase.app`
* **Tier 2 (Dynamic Service Taxonomy Classifier):** In-memory domain parser that resolves the specific cloud service (e.g., S3, Lambda, API Gateway, CloudFront, Azure Blob Storage, Azure Functions, Cosmos DB, Application Insights, Azure Key Vault, Cloud Storage, BigQuery, Cloud Run, Firebase Realtime DB). Unlisted subdomains dynamically resolve to their prefix (e.g., `bedrock.us-east-1.amazonaws.com` -> "AWS Bedrock"), ensuring 100% service coverage.
* **Cloud URLs Panel Upgrades:**
  * Expanded 8-column table: `#`, `Occurrences`, `Cloud Provider`, `Service`, `Discovered Cloud URL`, `Source Type`, `Source Location`, `Line`.
  * Dedicated multi-select filter dropdown for `Service` alongside `Provider`.
  * Grouping key updated to `url + "||" + provider + "||" + service`.

### 4. Performance & Memory Ceilings
* Mining operations execute exclusively in background worker threads off the Swing Event Dispatch Thread (EDT).
* Scannable content is capped at 5MB per file with a strict 2.5-second execution budget deadline per script.
* Stored discoveries are capped at 500 findings per category per script to protect the JVM heap.

## Goals vs. Non-Goals

* **In-Scope Goals:**
  * Create dedicated `InternalIpsPanel_littlespidy` and `SsnsPanel_littlespidy` extending `BaseFindingPanel_littlespidy`.
  * Implement strict RFC 1918 regex excluding loopback and link-local.
  * Implement structural US SSN matching adhering to SSA validation rules with unmasked default display.
  * Implement the Two-Tier Cloud Engine covering all AWS, Azure, GCP, and Firebase services.
  * Add the `Service` column and multi-select filter dropdown to `CloudUrlsPanel_littlespidy`.
  * Confine mining strictly to JavaScript source files and unpacked source maps.
  * Serialize new finding models (`DiscoveredInternalIp`, `DiscoveredSsn`, updated `DiscoveredCloudUrl`) in `JsSessionDTO_littlespidy` for persistent session management.
  * Build interactive HTML preview (`js_inspector_ui_preview_littlespidy.html`) and verify with `xdg-open` prior to compilation.

* **Out-of-Scope Non-Goals:**
  * Passive scanning of general HTTP responses, HTML documents, or API JSON endpoints.
  * Detection of unhyphenated (continuous 9-digit) SSNs due to prohibitive false positive rates.
  * IPv6 private address (ULA/link-local) detection in this release.
  * Active network port scanning or automated SSRF verification against discovered IP addresses.

## Alternatives Weighed

* **Monolithic 300+ Service Regex:** Rejected by author: Compiling every individual service name into one regex introduces catastrophic backtracking (ReDoS) risks and maintenance overhead. The Two-Tier architecture guarantees O(N) linear performance while capturing all services.
* **Combining Internal IPs and SSNs into the Secrets Tab:** Rejected by author: Dedicated tabs allow direct, single-click triage without requiring category filter manipulation.
* **Requiring Contextual Keywords for SSNs:** Rejected by author: Structural matching is necessary to catch hardcoded array elements and raw mock objects that lack field name identifiers.
* **Forced Default UI Masking of SSNs:** Rejected by author: Default unmasked display enables instant verification, with an optional toolbar toggle provided for presentation safety.

## Key Decisions & Staging for Next Steps

1. **Tab Structure:** Add `InternalIpsPanel_littlespidy` and `SsnsPanel_littlespidy` to `JSSourceMapExplorerTab.java`. Switch root tabbed pane to `JTabbedPane.SCROLL_TAB_LAYOUT`.
2. **Data Models:** Create `DiscoveredInternalIp` and `DiscoveredSsn` records. Add `service` field to `DiscoveredCloudUrl` with backward-compatible constructors.
3. **Mining Engine:** Update `SecretAndEndpointMiner.java` with RFC 1918 pattern, SSA SSN pattern, Tier 1 root cloud anchor regex, and Tier 2 `classifyCloudService()` taxonomy method. Expand `MiningResult` to include `internalIps` and `ssns`.
4. **Cloud URLs UI:** Update `CloudUrlsPanel_littlespidy.java` to support 8 columns, `Service` filter dropdown, and 3-part grouping key.
5. **Session Persistence:** Update `JsSessionDTO_littlespidy` and `JsDataStore` to serialize and restore internal IPs and SSNs across Burp restarts.
6. **GUI Mockup & Build:** Update `js_inspector_ui_preview_littlespidy.html`, verify with `xdg-open`, run Gradle tests, compile fat-JAR, stage, commit, and push.
