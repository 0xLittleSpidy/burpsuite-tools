# Param Payload Injector (Burp Suite Extension)

*Created with the help of an AI Agent and littlespidy.*

A modern Montoya API Burp Suite extension that dynamically binds parameter names into security test payloads (such as Cross-Site Scripting (XSS) and AngularJS / Angular Client-Side Template Injection (CSTI)). 

When testing applications with dozens of parameters, generic payloads like `<script>alert(1)</script>` or `{{7*7}}` make it nearly impossible to determine which parameter reflected or executed in the DOM or response. **Param Payload Injector** solves this attribution problem by dynamically generating parameter-attributed payloads (e.g., `alert('username')`, `"><img src=x onerror=alert('redirect_url')>`, or `{{constructor.constructor('alert(\'param_name\')')()}}`) directly inside your Burp testing workflow.

---

## Key Features

### 1. Context Menu Integration (Editor & Traffic)
Right-click inside any HTTP request (Repeater, Proxy History, Logger, Target):
- **Send to Repeater with Armed Payloads**:
  - Clones the target request directly to a new Repeater tab with all parameters pre-populated with your chosen payload template.
  - Submenus categorized by **XSS Payloads**, **Angular CSTI Payloads**, and **Custom Payloads**.
- **Inject into All Parameters (In-Place)**:
  - Modifies the active request in the message editor in-place across all URL Query, Form Body, and JSON parameters.
- **Inject into Selected Text / Range**:
  - Replaces highlighted text or parameters with the chosen parameterized template.

### 2. Built-in Parameter-Attributed Templates
Ships with out-of-the-box templates supporting `{param}`, `{value}`, and `{rand}` token placeholders:

* **XSS Payloads**:
  - `Script Tag (Direct)`: `<script>alert('{param}')</script>`
  - `Script Tag (Breakout)`: `"><script>alert('{param}')</script>`
  - `IMG OnError`: `"><img src=x onerror=alert('{param}')>`
  - `SVG OnLoad`: `'"><svg/onload=alert('{param}')>`
  - `JavaScript URI`: `javascript:alert('{param}')`
  - `Details OnToggle`: `"><details open ontoggle=alert('{param}')>`
* **Angular / AngularJS CSTI Payloads**:
  - `String Interpolation Canary`: `{{'{param}'}}`
  - `Math Expression + Param`: `{{7*7}} /* {param} */`
  - `Constructor Sandbox Escape`: `{{constructor.constructor('alert(\'{param}\')')()}}`
  - `Angular 1.6+ $on Escape`: `{{$on.constructor('alert(\'{param}\')')()}}`
  - `AngularJS 1.5.8 Escape`: `{{x={'a':1};constructor.constructor('alert(\'{param}\')')()}}`
  - `AngularJS 1.4 $eval Escape`: `{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(\'{param}\');//');}}`

### 3. Dedicated Suite Tab: "Param Injector"
- **Reflection Monitor Tab**:
  - Live inspection table capturing reflections of injected parameter payloads in HTTP responses.
  - Automatically classifies reflection context: `HTML Tag Body`, `HTML Attribute`, `Script Block`, `Angular Template`, or `Raw Body`.
  - Filters: Scope filter (`In-Scope Only`), Category filter (`XSS`, `Angular CSTI`), and live search bar.
  - Native Montoya side-by-side HTTP Request and Response editors with automatic search expression highlighting of the reflecting parameter.
- **Payload Templates & Settings Tab**:
  - Value insertion modes: **Replace**, **Append**, or **Prepend**.
  - Context encoding modes: **Auto** (URL-encodes query/body parameters, escapes JSON strings to keep JSON syntax valid), **Always URL Encode**, or **Raw**.
  - Target parameter scopes: URL Query, Form Body, JSON, Cookies.
  - Passive reflection detection & Burp History annotation toggles.
  - Full template CRUD: Add custom templates, edit existing ones, toggle active status, and reset to defaults.

### 4. Passive Reflection Annotations
When active, responses containing reflected parameter payloads automatically receive:
- **Burp Suite Notes**: Safe-appended notes in the format `Reflected: param '<name>' (<category>)`.
- **Burp Suite Highlights**: Color-coded in **Red** for high-risk contexts (HTML tags, script blocks) and **Yellow** for attribute or template contexts.

---

## Building the Extension

To compile and package the extension into a standalone JAR:

```bash
cd /home/littlespidy/myextra/burpsuite/ParamPayloadInjector_littlespidy
./gradlew jar
```

The compiled JAR file is located at:
`build/libs/param-payload-injector-littlespidy-1.0.0.jar`

---

## Installation in Burp Suite

1. Open **Burp Suite**.
2. Navigate to **Extensions** $\to$ **Installed**.
3. Click **Add**.
4. Choose **Extension type**: `Java`.
5. Select the **Extension file (.jar)**:
   `/home/littlespidy/myextra/burpsuite/ParamPayloadInjector_littlespidy/build/libs/param-payload-injector-littlespidy-1.0.0.jar`
6. Click **Next**. The **"Param Injector"** tab will appear in the main suite bar.

---

## Usage Workflow

1. Open **Repeater** or **Proxy HTTP History**.
2. Right-click on any HTTP request:
   - Choose **Param Payload Injector (littlespidy)** $\to$ **Send to Repeater with Armed Payloads** $\to$ select **XSS** or **Angular CSTI**.
   - A new Repeater tab will open with all parameters automatically tagged with their respective parameter names.
3. Send the request.
4. Check the **Param Injector** $\to$ **Reflection Monitor** tab or the Proxy/Repeater notes to instantly see which parameter reflected in the response!
