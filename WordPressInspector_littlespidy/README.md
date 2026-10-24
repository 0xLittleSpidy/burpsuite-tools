# WordPress Inspector (littlespidy)

<!-- Created with the help of an AI Agent and littlespidy. -->

A modern Burp Suite Montoya API extension designed for WordPress reconnaissance, passive traffic detection, vulnerability identification, and security posture assessment.

Ported and enhanced from BurpWpsScan, WordPress Inspector introduces a clean multi-domain tab architecture, persistent credential management, smart plugin vulnerability analysis via the WPScan API v3, WordPress.org version update tracking, XML-RPC and REST API probing, user account enumeration, and exportable security reports in standard Markdown and JSON formats.

## Key Features

### 1. Dedicated Configuration Tab
- Secure WPScan API Token input stored directly in Burp preferences.
- Real-time API connection testing and validation with wpscan.com.
- Daily API usage tracker and counter reset tool.
- Passive live traffic detection toggle.
- 24-hour result caching to avoid redundant API credit consumption.
- Burp Proxy HTTP history scanner to detect WordPress targets from previous browsing.
- Quick-add domain utility to spin up new target tabs on demand.

### 2. Multi-Domain Parent Tab Workflow
- Each target domain has its own dedicated parent tab with an editable target URL bar.
- Custom subpaths and protocols can be edited on the fly before scanning.
- Closeable tab headers using clean ASCII controls `[X]`.

### 3. Comprehensive Domain Sub-Tabs
- **Overview & Core**: Displays detected WordPress version, core vulnerabilities from the WPScan database, XML-RPC pingback and multicall vectors, accessible REST endpoints, and security hardening analysis.
- **Plugins**: Filterable table of all detected plugins, high-risk classification indicators (80+ known high-risk plugins), public version comparison against WordPress.org API, and an interactive vulnerability detail drill-down pane.
- **Theme Detection**: Discovered active and installed themes, paths, and vulnerability assessment via WPScan API.
- **Users & Recon**: Enumerated WordPress accounts collected via REST API (`/wp-json/wp/v2/users`) and author redirect queries (`/?author=N`).
- **Scan Logs**: Real-time monospaced ASCII scan log window with clear and clipboard copy controls.

### 4. Practitioner Report Exports
- Clean Markdown (`.md`) reports formatted for technical documentation and client presentations.
- Structured JSON (`.json`) exports for automated pipeline integration and tracking.
- Excludes AI-ready report generation to maintain clean practitioner reporting standards.

## Project Architecture

```
WordPressInspector_littlespidy/
|-- build.gradle.kts
|-- settings.gradle.kts
|-- gradlew
|-- gradlew.bat
|-- README.md
|-- wordpress_inspector_ui_preview_littlespidy.html
|-- build/libs/
|   `-- wordpress-inspector-littlespidy-1.0.0.jar
`-- src/
    |-- main/java/com/littlespidy/wordpressinspector/
    |   |-- WordPressInspectorExtension_littlespidy.java
    |   |-- engine/
    |   |   |-- RestApiProber_littlespidy.java
    |   |   |-- SecurityHardeningAnalyzer_littlespidy.java
    |   |   |-- UserEnumerator_littlespidy.java
    |   |   |-- WPScanApiClient_littlespidy.java
    |   |   |-- WordPressDetectionEngine_littlespidy.java
    |   |   |-- WordPressOrgClient_littlespidy.java
    |   |   |-- WordPressPassiveHandler_littlespidy.java
    |   |   |-- WordPressReportExporter_littlespidy.java
    |   |   `-- XmlRpcProber_littlespidy.java
    |   |-- model/
    |   |   |-- PluginFinding_littlespidy.java
    |   |   |-- RestApiResult_littlespidy.java
    |   |   |-- ScanConfig_littlespidy.java
    |   |   |-- ThemeFinding_littlespidy.java
    |   |   |-- UserFinding_littlespidy.java
    |   |   |-- VulnerabilityEntry_littlespidy.java
    |   |   |-- WordPressDataStore_littlespidy.java
    |   |   |-- WordPressTarget_littlespidy.java
    |   |   `-- XmlRpcResult_littlespidy.java
    |   |-- storage/
    |   |   `-- WordPressPreferencesManager_littlespidy.java
    |   `-- ui/
    |       |-- CloseableTabHeader_littlespidy.java
    |       |-- ConfigurationTab_littlespidy.java
    |       |-- DomainParentTab_littlespidy.java
    |       |-- ExportReportDialog_littlespidy.java
    |       `-- WordPressInspectorSuiteTab_littlespidy.java
    `-- test/java/com/littlespidy/wordpressinspector/
        |-- engine/
        |   |-- WordPressDetectionEngineTest_littlespidy.java
        |   `-- WordPressReportExporterTest_littlespidy.java
        `-- model/
            `-- WordPressDataStoreTest_littlespidy.java
```

## Building the Extension

Ensure OpenJDK 17 or later is installed, then build the release fat-JAR:

```bash
cd WordPressInspector_littlespidy
./gradlew clean test build jar
```

The compiled release fat-JAR will be located at:
```
build/libs/wordpress-inspector-littlespidy-1.0.0.jar
```

## Installing in Burp Suite

1. Open Burp Suite.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. Select **Extension type**: Java.
5. Choose `WordPressInspector_littlespidy/build/libs/wordpress-inspector-littlespidy-1.0.0.jar`.
6. Click **Next** to load the extension.
7. Navigate to the newly added **WordPress Inspector** suite tab.
