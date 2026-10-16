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
The main Suite Tab is organized into four dedicated top-level tabs with a unified target input header and cross-platform persistence:

- **Target Header Controls & Persistence**:
  - **Bootstrap URL (-u)**: Target GWT application URL or `.nocache.js` bootstrap script.
  - **Permutation URL (-b)**: Base directory URL or direct `.cache.js` permutation script URL.
  - **Permutations Selector**: Dropdown listing all discovered permutation hashes with instant switching.
  - **Analyze Target**: High-speed multi-stage reverse engineering engine with real-time percentage progress bar.
  - **Permutation Local File**: Offline file selection for analyzing saved `.cache.js` scripts directly from disk.
  - **Storage Folder...**: View or configure the cross-platform session persistence directory (`gwtmap_session.json`). Data is auto-saved in the Burp project file directory (or prompts via folder chooser for temporary projects) and restored on launch.

#### Tab 1: GWT Analysis
Combines all core analysis tools into a structured multi-tab workspace:

1. **HTTP History** (First Tab):
   - Live Traffic Streaming: Displays all network activity initiated during "Analyze Target" in real time (Bootstrap fetch, Permutation script download, deferred JavaScript fragments, and single/batch RPC probes).
   - History Table: Columns for ID, Time, Type (`BOOTSTRAP`, `PERMUTATION`, `FRAGMENT`, `PROBE`), Method, Method Name (GWT RPC method), URL, Status Code, Response Length, and Round-Trip Duration (ms).
   - Integrated Split Editors: Embedded native Montoya HTTP Request and Response editors with automatic search term synchronization and syntax formatting.
   - Toolbar & Context Actions: `Clear History`, `Send to Intruder`, `Copy URL`, `Copy Request`, and `Copy Response`.
2. **Module Info**:
   - Summary card displaying GWT Version, Content-Type, Base URL, Active Permutation Hash, RPC Version, RPC Flags, all discovered permutations, and deferred JS fragments.
3. **Methods & Payloads**:
   - Filter Toolbar: Real-time debounced search bar (`Search Methods:`), service selector, and method dropdown selector.
   - Action Buttons: **Send Request** (dispatches HTTP request for the selected method/payload) and **Send All Requests** (batch sends requests for all methods with live progress tracking).
   - Methods Table: Lists discovered methods, service categories, parameter signatures, full endpoint URLs, status codes, latencies, and response lengths.
   - Right-Click Context Menu: Fast workflow actions (`Send Probe`, `Probe All Visible`, `Send to Repeater`, `Send to Intruder`, `Copy RPC Payload`, `Copy HTTP Request`, `Send to Deserializer`, and `Send to Fuzzer`).
   - Integrated Montoya Editors: Split-view Request and Response editors displaying live probe transactions and raw wire format payloads.
4. **Services & Policies**:
   - Enumerates discovered service paths, serialization policy strong names (`.gwt.rpc`), and associated method counts (`--svc` mode).
5. **Deobfuscated Code**:
   - Monospace viewer displaying retabbed, beautified, and unicode-decoded JavaScript.
   - **Interactive Code Search**: Search bar with `< Prev` and `Next >` navigation buttons, `Match Case` toggle, match position counter (e.g. `3 / 15`), and dual-color occurrence highlighting that auto-scrolls to the active match.
   - One-click `Save / Backup Code to Disk...` export button.

#### Tab 2: HTTP Proxy History
- Ingests all past and live proxy traffic via Montoya API (`api.proxy().history()` & `registerResponseHandler`).
- Enriches every request with extracted GWT RPC metadata: Method Name, Service Interface, and GWT-RPC classification.
- Multi-Criteria Filtering Toolbar:
  - **Search**: Debounced real-time filter across URLs, method names, services, and payload bodies.
  - **Method Name Filter**: Dynamic dropdown populated with all unique GWT methods observed in proxy history.
  - **Service Filter**: Dynamic dropdown populated with all unique GWT services observed.
  - **Status Filter**: Fast filter for 2xx, 3xx, 4xx, and 5xx response codes.
  - **Only GWT-RPC Traffic Toggle**: Instant filter focusing exclusively on GWT transactions.
- Split-Screen Inspection: Embedded Request, Response, Structured GWT Response, and GWT Request AST editors.
- Context Menu: `Send to Repeater`, `Send to Intruder`, `Send to GWTMap Deserializer`, `Send to GWTMap Fuzzer`, `Copy URL`, `Copy GWT Method Name`, `Copy RPC Payload`.

#### Tab 3: RPC Deserializer
- Accepts raw GWT-RPC wire requests, parses them into typed AST representations, resolves field types, decodes RPC flags, and identifies all fuzzable parameter offsets.
- Built-in GWT Base64 Long Codec for instant conversion between GWT Base64 strings and 64-bit decimal integers.

#### Tab 4: RPC Fuzzer & Tester
- Automated testing console for GWT endpoints.
- **Burp Cookie Store Integration**: Automatically extracts and includes relevant session cookies from Burp's `CookieJar` matching the target domain/path, merged with any custom headers.
- **File Upload Options**: `Load Body from File...` for base requests and `Load Payloads from File...` for wordlists.
- Detects fuzzable string parameters and numeric ID tokens from baseline requests.
- Configurable string payload lists (SQL, XSS, format strings, path traversal) and numeric ID delta sweeps (+/- N).
- Real-time results table tracking status codes, response lengths, response times, and serialized GWT server exceptions (`//EX[`).
- Determinate percentage progress bar (`progressBar.setValue(...)` / `X / Y (Z%)`).

---

### 2. Native Burp Message Editor Tabs: "GWT" & "GWT Response"
- **"GWT" (Request Editor Tab)**:
  - Appears automatically across Burp Proxy, Repeater, Logger, and Intruder whenever viewing GWT-RPC traffic (`text/x-gwt-rpc` or payload starting with stream version `[0-9]+\|[0-9]+\|...`).
  - Sub-tab 1: **Parsed Call** -> Formatted AST breakdown of the method call, service interface, parameter types, values, and string table.
  - Sub-tab 2: **Armed Payload (§)** -> The request body pre-armed with Burp Intruder markers (`§...§`).
  - Sub-tab 3: **Base64 Long Codec** -> Quick-access encoder and decoder for GWT 64-bit integers.
  - Action Buttons: **Send to Intruder** and **Send to GWTMap Deserializer**.
- **"GWT Response" (Response Editor Tab)**:
  - Appears automatically across Burp Proxy, Repeater, Logger, and GWTMap whenever viewing GWT-RPC responses (`//OK[...]` success payloads or `//EX[...]` server exceptions).
  - Top Status Banner: Green success badge for `//OK` returns and red exception badge for `//EX` server errors (with exception class and error message).
  - Sub-tab 1: **Structured View** -> Human-readable breakdown of return values, types, and flags.
  - Sub-tab 2: **String Table** -> Sortable table mapping indices to string values and type signatures.
  - Sub-tab 3: **Raw Response** -> Preserved raw response with one-click copy actions.

---

### 3. Context Menu Integration
Right-clicking any HTTP request or response across Burp Suite provides:
- **Send to GWTMap (Scan / Enumerate)**: Dispatches the URL of a `.nocache.js` or `.cache.js` file directly into GWTMap for full permutation and method analysis.
- **Send to GWTMap Deserializer**: Extracts the GWT request body and loads it into the Deserializer tab for deep AST inspection.
- **Send to GWTMap Fuzzer**: Extracts the target URL and request body and loads them into the automated Fuzzer tab.

---

### 4. Passive Background Monitor & Session Persistence
- Passively detects `.nocache.js` and `.cache.js` responses passing through Burp Proxy.
- Automatically populates the target URL for immediate analysis if GWTMap is currently empty.
- **Session Persistence**: Sessions auto-save on extension unloading to `gwtmap_session.json` and restore on startup across Windows, Linux, and macOS.

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
