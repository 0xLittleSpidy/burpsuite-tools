# Input Validation Fuzzer (Burp Suite Extension)

*Created with the help of an AI Agent and littlespidy.*

A Montoya API Burp Suite extension providing both an interactive multi-session UI fuzzer and an active scanner check for discovering improper input handling, verbose error disclosures, reflection flaws, and boundary handling anomalies across HTTP request parameters.

---

## Features

- **Interactive Multi-Session Fuzzing Tab**: Send any request from Proxy, Repeater, Logger, or Sitemap directly to the fuzzer. Each request opens an isolated, closeable session tab.
- **Full Parameter Scope Support**: Target URL Query, Body (Form), Cookie, JSON, XML, XML Attributes, and Multipart parameters.
- **Multi-Signal Anomaly Detection**:
  - **5xx Server Errors**: Catches unhandled server crashes and exceptions.
  - **30+ Error Signatures**: Detects SQL syntax errors, PHP notices/warnings, Java stack traces, Python tracebacks, and database driver errors.
  - **Payload Reflection**: Flags unencoded payload reflection in response bodies.
  - **Status & Body Size Shifts**: Flags unexpected status changes and response size shifts $\ge 300\%$.
- **Collapsible Filter Sidebar**: Smart pattern auto-detection (first $N$ signature suppression) and manual filters (status codes, length bounds, regex, and severity).
- **Montoya Built-in Editors**: Native Pretty, Raw, and Hex editors for fuzzed and baseline requests/responses.
- **Burp Scanner Integration**: Registers as an active `ScanCheck` (`activeAudit()`) so tests run automatically with Burp's audit engine.

---

## Building the Extension

To compile and package the extension into a standalone JAR:

```bash
cd /home/littlespidy/myextra/burpsuite/InputValidationFuzzer_littlespidy
./gradlew jar
```

The compiled JAR file will be located at:
`build/libs/input-validation-fuzzer-littlespidy-1.0.0.jar`

---

## Installation in Burp Suite

1. Open **Burp Suite**.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. Choose **Extension type**: `Java`.
5. Select the **Extension file (.jar)**: `build/libs/input-validation-fuzzer-littlespidy-1.0.0.jar`.
6. Click **Next**. The **"Input Validation Fuzzer"** tab will appear in the main suite bar.

---

## Usage

1. Right-click any HTTP request in **Proxy history**, **Repeater**, **Sitemap**, or **Logger**.
2. Select **Extensions** -> **Input Validation Fuzzer** -> **Send to Input Validation Fuzzer**.
3. In the newly opened session tab, click **Start Fuzzing**.
4. Review anomalies color-coded in the results table, inspect evidence details in the **Evidence & Findings** tab, and toggle the filter sidebar as needed.
