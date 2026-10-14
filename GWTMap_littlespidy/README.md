<!-- Created with the help of an AI Agent and littlespidy. -->
# GWTMap - GWT RPC Analyzer (Burp Suite Montoya Extension)

A powerful, high-performance Burp Suite extension that fully ports and enhances [gwtmap](https://github.com/reverseclabs/gwtmap) (by Oliver Simonnet / F-Secure Labs), [GWT-Penetration-Testing-Toolset](https://github.com/GDSSecurity/GWT-Penetration-Testing-Toolset) (by GDS Security: gwtparse, gwtfuzzer, gwtenum), and [GWTab](https://github.com/thehackerish/GWTab) (by thehackerish) into a unified, native Burp Suite workflow using the modern **Montoya API**.

GWTMap reverse engineers obfuscated client-side Google Web Toolkit (GWT) JavaScript applications, discovers permutations and deferred fragments, extracts RPC service endpoints and methods, resolves parameter types, synthesizes valid GWT-RPC Version 7 wire request payloads with Intruder markers (`§...§`), provides deep request deserialization (including XSRF token handling), embeds a fast Base64 Long encoder/decoder, performs automated parameter injection testing and numeric ID sweeps, and provides a native Burp Suite HTTP Request Editor tab captioned **"GWT"**.

---

## Unified Feature Parity & Capabilities

GWTMap unifies the capabilities of three premier GWT security tools into one cohesive Burp Suite extension with zero external dependencies:

| Tool Source | Feature Component | Capabilities & Implementation |
| :--- | :--- | :--- |
| **gwtmap** | **Permutation & Fragment Discovery** | Extracts permutations from `.nocache.js` (`unflattenKeylistIntoAnswers` & `selectingPermutation`), provides an active permutation switcher, and crawls deferred fragments (`deferredjs/{permutation}/{i}.cache.js`). |
| **gwtmap** | **RPC Method & Service Extraction** | Discovers service interfaces, endpoints, serialization policy strong names, and methods from obfuscated `.cache.js` files; resolves parameter signatures and complex object warnings. |
| **gwtmap** | **Wire Payload Generation & Probing** | Synthesizes GWT-RPC Version 7 wire format requests with string tables and parameter maps; supports single and batch live HTTP POST probing with latency and response metrics. |
| **gwtmap** | **Code Cleaner & Local Backup** | Decodes unicode escape sequences (`\uXXXX`), beautifies JavaScript code, and provides one-click export to local disk. |
| **GDS gwtparse** | **GWT-RPC Wire Deserializer** | Pure Java AST parser for raw GWT requests; handles string tables, index streams, complex objects, arrays, and XSRF token flags (`FLAG_RPC_TOKEN_INCLUDED = 0x2`). |
| **GDS gwtparse** | **Payload Arming & Delimiters** | Automatically wraps fuzzable parameter tokens with Burp Intruder markers (`§...§`), custom surround markers (`-s`), or replacement strings (`-r`). |
| **GDS gwtfuzzer** | **Parameter Fuzzer & Exception Tester** | Injects security test payloads into string parameters (with automatic `\|` to `\!` escaping) and performs numeric ID sweeps (+/- N); automatically detects serialized GWT exceptions (`//EX[`). |
| **GWTab** | **Native Burp Request Editor Tab** | Registers a native "GWT" HTTP Request Editor tab across Burp Suite (Proxy, Repeater, Logger, etc.) showing deserialized AST calls, armed Intruder requests, and Base64 Long codec. |
| **GWTab** | **GWT Base64 Long Codec** | Fast two-way converter for GWT 64-bit integer tokens using GWT custom alphabet (`[A-Za-z0-9$_]`) and RFC 4648 Base64. |

---

## Extension Interface & Architecture

### 1. Main Suite Tab: GWTMap
The main Suite Tab comprises seven functional tabs with a unified target input header:

- **Target Header Controls**:
  - **Bootstrap URL (-u)**: Target GWT application URL or `.nocache.js` bootstrap script.
  - **Permutation URL (-b)**: Base directory URL or direct `.cache.js` permutation script URL.
  - **Permutations Selector**: Dropdown listing all discovered permutation hashes with instant switching.
  - **Analyze Target**: High-speed multi-stage reverse engineering engine with O(1) variable map indexing and 80-line lookahead bound.
  - **Permutation Local File**: Offline file selection for analyzing saved `.cache.js` scripts directly from disk.

1. **Methods & Payloads**:
   - Filter Toolbar: Real-time debounced search bar (`-f`), multi-select filter buttons for Services and Status (`200 OK`, `4xx`, `5xx`, `Probed`, `Unprobed`), and `In-Scope Only` gating.
   - Methods Table: Lists discovered methods, service categories, parameter signatures, full endpoint URLs, status codes, latencies, and response lengths.
   - Right-Click Context Menu: Fast workflow actions available directly on selected rows (`Send Probe`, `Probe All Visible`, `Send to Repeater`, `Send to Intruder`, `Copy RPC Payload`, `Copy HTTP Request`, `Send to Deserializer`, and `Send to Fuzzer`).
   - Integrated Montoya Editors: Maximized full-height split-view Request and Response editors displaying live probe transactions, raw wire format payloads, and type analysis evidence without bottom button clutter.
2. **HTTP History**:
   - Live Traffic Streaming: Displays all network activity initiated during "Analyze Target" in real time (Bootstrap fetch, Permutation script download, deferred JavaScript fragments, and single/batch RPC probes).
   - History Table: Columns for ID, Time, Type (`BOOTSTRAP`, `PERMUTATION`, `FRAGMENT`, `PROBE`), Method, URL, Status Code, Response Length, and Round-Trip Duration (ms).
   - Integrated Split Editors: Embedded native Montoya HTTP Request and Response editors with automatic search term synchronization and syntax formatting.
   - Toolbar & Context Actions: `Clear History`, `Send to Repeater`, `Send to Intruder`, `Copy URL`, `Copy Request`, and `Copy Response`.
3. **Services & Policies**:
   - Enumerates discovered service paths, serialization policy strong names (`.gwt.rpc`), and associated method counts (`--svc` mode).
4. **Module Info**:
   - Summary card displaying GWT Version, Content-Type, Base URL, Active Permutation Hash, RPC Version, RPC Flags, all discovered permutations, and deferred JS fragments.
5. **Deobfuscated Code**:
   - Monospace viewer displaying retabbed, beautified, and unicode-decoded JavaScript with a `Save / Backup Code to Disk...` export button.
6. **RPC Deserializer**:
   - Accepts raw GWT-RPC wire requests, parses them into typed AST representations, identifies all fuzzable parameter offsets, and generates Intruder-armed (`§...§`) or custom-delimited payloads with one-click `Send to Repeater` dispatch.
   - Built-in GWT Base64 Long Codec for instant conversion between GWT Base64 strings and 64-bit decimal integers.
7. **RPC Fuzzer & Tester**:
   - Automated testing console for GWT endpoints.
   - Detects fuzzable string parameters and numeric ID tokens from baseline requests.
   - Configurable string payload lists (SQL, XSS, format strings, path traversal) and numeric ID delta sweeps (+/- N).
   - Real-time results table tracking status codes, response lengths, response times, and highlights serialized GWT server exceptions (`//EX[`).
   - Integrated Request and Response viewers for every executed test probe.

### 2. Native Burp HTTP Request Editor Tab: "GWT"
- Appears automatically in Burp Proxy, Repeater, Logger, and Intruder whenever viewing GWT-RPC traffic (`text/x-gwt-rpc` or payload starting with stream version `[0-9]+\|[0-9]+\|...`).
- Sub-tab 1: **Parsed Call** -> Formatted AST breakdown of the method call, service interface, parameter types, values, and string table.
- Sub-tab 2: **Armed Payload (§)** -> The request body pre-armed with Burp Intruder markers (`§...§`) for one-click copying.
- Sub-tab 3: **Base64 Long Codec** -> Quick-access encoder and decoder for GWT 64-bit integers.
- Action Buttons: `Copy Armed Payload` and `Send to GWTMap Deserializer`.

### 3. Context Menu Integration
Right-clicking any HTTP request or response across Burp Suite provides:
- **Send to GWTMap (Scan / Enumerate)**: Dispatches the URL of a `.nocache.js` or `.cache.js` file directly into GWTMap for full permutation and method analysis.
- **Send to GWTMap Deserializer**: Extracts the GWT request body and loads it into the Deserializer tab for deep AST inspection and arming.
- **Send to GWTMap Fuzzer**: Extracts the target URL and request body and loads them into the automated Fuzzer tab.

### 4. Passive Background Monitor
- Passively detects `.nocache.js` and `.cache.js` responses passing through Burp Proxy.
- Automatically populates the target URL for immediate analysis if GWTMap is currently empty.

---

## Building from Source

### Prerequisites
- Java Development Kit (JDK) 17 or higher
- Linux, macOS, or Windows

### Build Command
Run the included Gradle wrapper from the extension directory:

```bash
cd /home/littlespidy/myextra/burpsuite-extensions/GWTMap_littlespidy
./gradlew build
```

The compiled extension JAR will be generated at:
```
build/libs/gwtmap-littlespidy-1.0.0.jar
```

---

## Installing into Burp Suite

1. Open **Burp Suite**.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. In the *Load Burp Extension* dialog:
   - **Extension type**: `Java`
   - **Extension file (.jar)**: Browse to `build/libs/gwtmap-littlespidy-1.0.0.jar`
5. Click **Next**.
6. The extension will initialize, log startup confirmation to Output, and register the **GWTMap** Suite Tab, the native **GWT** message editor tab, and the context menu items.

---

## Testing & Verification

Run the automated test suite using:

```bash
./gradlew test
```

Includes unit tests for:
- GWT code classification and permutation extraction
- Unicode escape decoding
- Serialization policy strong name and service mapping
- GWT Base64 Long codec round-trip and custom alphabet verification
- GWT-RPC wire request deserialization, XSRF token handling, and Intruder arming
- GWT server exception (`//EX[`) detection and error auditing
- Strict zero-emoji codebase enforcement
