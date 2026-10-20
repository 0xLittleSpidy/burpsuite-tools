# Request Smuggling Inspector (littlespidy)

> Created with the help of an AI Agent and littlespidy.

A Burp Suite Java extension (Montoya API) for injecting HTTP request-smuggling payloads directly into the Repeater request editor via the right-click context menu, and for managing payloads through a dedicated **Smuggling Payloads** tab.

---

## Features

### Smuggling Payloads Tab

A dedicated read-only Burp Suite tab that displays all loaded payloads in a 2-column table:

| Column | Content |
|---|---|
| **Name** | Payload label (e.g. `CL.TE`, `TE.CL Timing (Detect)`) |
| **Payload Value** | Raw body string stored in the JSON file |

Clicking any row shows a **detail pane** with Description, Headers, and Body.

**[Reload from JSON]** - re-reads `smuggling-payloads.json` from disk instantly, without restarting Burp.

---

### Context Menu: Dynamic Payload Injection

Right-click inside the **Repeater request panel** -> **Request Smuggling Inspector (littlespidy)** -> select a payload.

All entries are loaded dynamically from `smuggling-payloads.json`. No hardcoded payloads exist in the extension code - add, remove, or edit payloads by editing the JSON file.

---

## Built-in Payloads

### CL.TE

| Header | Value |
|---|---|
| `Content-Length` | `10` |
| `Transfer-Encoding` | `chunked` |

**Body:** `0\r\n\r\nHELLO`

Front-end reads `Content-Length: 10`, forwarding the entire body. Back-end reads `Transfer-Encoding: chunked`, processes `0\r\n\r\n` as end-of-chunk, then treats `HELLO` as the beginning of the *next* request - potentially prepending it to another user's request.

---

### CL.TE Timing (Detect)

| Header | Value |
|---|---|
| `Content-Length` | `4` |
| `Transfer-Encoding` | `chunked` |

**Body:** `1\r\nA\r\nX`

**How it works:** The front-end reads `Content-Length: 4` and forwards only `1\r\nA\r\n` (4 bytes). The back-end reads `Transfer-Encoding: chunked`, processes chunk `1` (data = `A`), then sees `X` as the start of the *next* chunk header - but no size is given, so it **hangs waiting**. A measurable response delay confirms a CL.TE desync condition.

---

### TE.CL Timing (Detect)

| Header | Value |
|---|---|
| `Content-Length` | `6` |
| `Transfer-Encoding` | `chunked` |

**Body:** `0\r\n\r\nX`

**How it works:** The front-end reads `Transfer-Encoding: chunked`, processes `0\r\n\r\n` as end-of-stream, and stops forwarding. The back-end reads `Content-Length: 6`, receives only 5 bytes (`0\r\n\r\n`), then **hangs waiting for the 6th byte**. A measurable response delay confirms a TE.CL desync condition.

---

## Adding Custom Payloads

Edit `smuggling-payloads.json` (placed next to the JAR) and append a new object:

```json
{
  "name": "My Custom Payload",
  "description": "Optional tooltip / notes",
  "headers": {
    "Transfer-Encoding": "chunked",
    "Content-Length": "42"
  },
  "body": "0\\r\\n\\r\\nSMUGGLED"
}
```

> **Tip:** Use `\\r\\n` in the body string. The extension converts these to actual CR+LF bytes before injection.

Click **[Reload from JSON]** in the Smuggling Payloads tab - the new entry appears immediately in both the table and the context menu without restarting Burp.

---

## JSON File Format

```json
[
  {
    "name":        "string (required) - display label",
    "description": "string (optional) - tooltip / notes",
    "headers": {
      "Header-Name": "Header-Value"
    },
    "body":        "string (required) - use \\r\\n for CR+LF"
  }
]
```

---

## Build

### Prerequisites
- Java 21+
- Gradle (wrapper included)

### Compile

```bash
cd RequestSmugglingInspector_littlespidy
./gradlew clean build
```

The compiled JAR and JSON file are output together to:
```
build/libs/
+-- request-smuggling-inspector-littlespidy-1.0.0.jar
+-- smuggling-payloads.json
```

> **Important:** Both files must remain in the **same directory** for the extension to load payloads correctly.

---

## Installation in Burp Suite

1. Copy **both** files from `build/libs/` to the same folder.
2. Open Burp Suite -> **Extensions** tab -> **Add**.
3. Extension type: **Java**.
4. Select: `request-smuggling-inspector-littlespidy-1.0.0.jar`.
5. Click **Next** - check the Output tab for:
   ```
   [RSI] Loaded 3 payload(s) from .../smuggling-payloads.json
   Request Smuggling Inspector (littlespidy) loaded!
   ```

---

## Usage

### Using the Context Menu

1. Send a request to **Repeater**.
2. Right-click anywhere in the **request** panel.
3. Navigate: **Request Smuggling Inspector (littlespidy)** -> choose a payload.
4. The headers and body are updated in-place - ready to send.

### Using the Payloads Tab

1. Open the **Smuggling Payloads** tab in the Burp top navigation bar.
2. Browse the 2-column table (Name | Payload Value).
3. Click a row to see the full payload detail (description, headers, body) in the lower pane.
4. Edit `smuggling-payloads.json`, then click **[Reload from JSON]** to refresh.

---

## Roadmap

- [x] CL.TE variant
- [x] CL.TE Timing (Detect) - timing-based CL.TE detection
- [x] TE.CL Timing (Detect) - timing-based TE.CL detection
- [x] JSON-driven payload manager tab (Name | Payload Value)
- [x] Dynamic context menu populated from JSON
- [ ] TE.TE variant (obfuscated Transfer-Encoding)
