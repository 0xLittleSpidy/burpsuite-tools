# Burp Suite – Custom Scan Checks Reference

> Source pages (PortSwigger official documentation):
> - https://portswigger.net/burp/documentation/desktop/extend-burp/custom-scan-checks
> - https://portswigger.net/burp/documentation/desktop/extend-burp/custom-scan-checks/managing
> - https://portswigger.net/burp/documentation/desktop/extend-burp/custom-scan-checks/importing
> - https://portswigger.net/burp/documentation/desktop/extend-burp/custom-scan-checks/creating
> - https://portswigger.net/burp/documentation/desktop/extend-burp/custom-scan-checks/creating/writing-guide
> - https://portswigger.net/burp/documentation/desktop/extend-burp/custom-scan-checks/creating/passive-worked-example
> - https://portswigger.net/burp/documentation/desktop/extend-burp/custom-scan-checks/creating/active-worked-example
> - https://portswigger.net/burp/documentation/desktop/extend-burp/custom-scan-checks/testing
> - https://portswigger.net/burp/documentation/scanner/bchecks
> - https://portswigger.net/burp/documentation/scanner/bchecks/contribute-bchecks
> - https://portswigger.net/burp/documentation/desktop/extend-burp/bambdas/creating/contribute-scripts

---

## Overview

Custom scan checks enable you to extend Burp Scanner with your own vulnerability detection logic. Use them to tailor scans to meet your testing requirements and react quickly to new vulnerabilities.

You can store checks in your **custom scan checks library** and reuse them across scans and projects.

There are two ways to add custom scan checks to your library:

- **Import checks** – Import existing checks shared by others or downloaded from the [Bambda scripts repository](https://github.com/PortSwigger/bambdas) or [BChecks repository](https://github.com/PortSwigger/BChecks).
- **Create checks** – Write your own checks in Java or the custom BChecks language to target issues specific to your application.

---

## Managing Custom Scan Checks

Navigate to **Extensions > Custom scan checks** to store and manage checks.

The library table shows:
| Column | Description |
|--------|-------------|
| **Name** | The name of the check |
| **Author** | The author of the check (BChecks only) |
| **Tags** | Tags applied to the check (BChecks only) |

> **Note:** Tags and Author are only populated for BCheck-based checks. They are automatically populated from the definition. To modify them, edit the definition directly.

### Importing Checks

You can import `.bcheck` files, `.bambda` scan check files, or a folder containing either.

**Steps:**
1. Go to **Extensions > Custom scan checks**.
2. Click **Import**.
3. Select `.bcheck` files, `.bambda` files, or a folder.
4. Click **Open**.

> **Warning:** Custom scan checks can run arbitrary code. Be cautious when importing from unverified sources.

**Importing full GitHub repositories:**
1. Download the Bambda scripts or BChecks repository as a ZIP.
2. Extract the ZIP.
3. Import the extracted folder via **Extensions > Custom scan checks > Import**.

#### Updating Checks

If checks have been modified outside Burp, re-import them. Burp will offer to replace existing checks.

**Script-based checks** – Matched by unique ID embedded in `.bambda` metadata. If IDs match, Burp offers to overwrite. If no match, treated as new.

**BCheck-based checks** – Matched by filename. Importing a `.bcheck` with the same name appends a number to the new file name, keeping both as separate entries.

### Exporting Checks

1. Select the checks to export.
2. Click **Export**.
3. Select a directory.
4. Save:
   - Single check: Enter a filename and click **Save**.
   - Multiple checks: Click **Save** to export all into a folder.

File extensions:
- `.bcheck` – BCheck-based checks
- `.bambda` – Script-based checks (includes unique ID metadata)

### Library Actions

| Action | How |
|--------|-----|
| **Edit** | Select check → click Edit |
| **Copy** | Select check → click Copy |
| **Delete** | Select check → click Delete |

---

## Creating Custom Scan Checks

Two types of custom scan checks are supported:

| Type | Language | Best For |
|------|----------|----------|
| **Scripts** | Java (Montoya API) | Complex checks requiring full API access |
| **BChecks** | BCheck DSL | Quick, lightweight checks |

### Creating Script-Based Checks (Java)

1. Go to **Extensions > Custom scan checks**.
2. Click **New** → select **Blank script** or **From template**.
3. If using a template, select the **Script mode** tab, choose a template, click **Create using this template**.
4. Select the script **Type**: Active or Passive.
5. Select **when the script runs**: Per insertion point, Per request, or Per host.
6. *(Optional)* Enable **Use Collaborator** for out-of-band testing.
7. Write the script in Java.
8. Click **Validate** – resolve any errors shown in the Errors panel.
9. *(Optional)* Test against real HTTP messages.
10. Click **Save & close**.

### Creating BCheck-Based Checks

1. Go to **Extensions > Custom scan checks**.
2. Click **New** → select **Blank BCheck** or **From template**.
3. If using a template, select the **BCheck mode** tab, choose a template, click **Create using this template**.
4. Write the BCheck definition.
5. Click **Validate**.
6. *(Optional)* Right-click editor → **Format BCheck** to normalize indentation.
7. *(Optional)* Test against real HTTP messages.
8. Click **Save & close**.

---

## Custom Scan Checks Writing Guide (Java)

### Choosing the Right Check Type

**Decision factors:**
- **Type:** Active or Passive
- **When it runs:** Per host, Per request, or Per insertion point
- **Collaborator:** Whether out-of-band interaction testing is needed

#### Active vs Passive

| Type | Description | Example Use Cases |
|------|-------------|-------------------|
| **Passive** | Analyzes existing traffic without sending new requests | Missing security headers, leaked server info, insecure cookies |
| **Active** | Sends additional modified requests to probe for vulnerabilities | SQL injection, SSTI, command injection |

#### When Checks Run

| Check Type | Runs | When to Use | Examples |
|------------|------|-------------|---------|
| **Host check** | Once per unique host | Host-level information only | `robots.txt`, security headers |
| **Request check** | Once per request | Full request/response analysis | Exposed API keys, insecure redirects |
| **Insertion-point check** *(active only)* | Once per insertion point | Payload injection into parameters/headers | SQL injection, XSS |

### Structure of a Custom Scan Check

Every check follows this pattern:
1. Validate a response exists
2. Perform the check
3. Report issues

#### 1. Validating Response Exists

**Passive checks:**
```java
if (!requestResponse.hasResponse()) {
    return AuditResult.auditResult();
}
```

**Active checks:**
```java
var rr = http.sendRequest(requestResponse.request());
if (!rr.hasResponse()) {
    return AuditResult.auditResult();
}
```

> **Warning:** Each check runs for a maximum of **two minutes**. Burp automatically interrupts it if exceeded. Write efficient checks to minimize performance impact.

---

### Modifying Requests (Active Checks)

#### Request or Host Checks

```java
// Build a modified request
var modifiedRequest = requestResponse.request()
    .withAddedParameters("test", "canary123")
    .withBody("modified body content");

// Send the request
var rr = http.sendRequest(modifiedRequest);

if (!rr.hasResponse()) return AuditResult.auditResult();
```

#### Insertion Point Checks

Payloads must be **value-only** – Burp handles context-aware encoding. Each payload is a `ByteArray`.

```java
var reqWithPayload = insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
var rr = http.sendRequest(reqWithPayload);
if (!rr.hasResponse()) return AuditResult.auditResult();
```

#### Insertion Point Checks – Multiple Payloads

```java
var payloads = List.of("canary123", "<script>alert(1)</script>");

for (var payload : payloads) {
    var reqWithPayload = insertionPoint.buildHttpRequestWithPayload(
        ByteArray.byteArray(payload, StandardCharsets.UTF_8)
    );
    var rr = http.sendRequest(reqWithPayload);
    if (!rr.hasResponse()) continue;
    // Process results
}
```

---

### Inspecting Traffic

#### Detect Payload Reflections

```java
var marker = "canary123";
var modifiedRequest = requestResponse.request()
    .withAddedHeader("X-Test", marker);

var rr = http.sendRequest(modifiedRequest);

if (rr.hasResponse() && rr.response().body().indexOf(marker, false) > -1) {
    // Reflected input detected
}
```

#### Check Specific Response Elements

```java
var response = requestResponse.response();

var hasXfo = response.hasHeader("X-Frame-Options");
if (!hasXfo || response.headerValue("X-Frame-Options").isEmpty()) {
    // Expected header is missing or empty
}
```

#### Compare Responses

```java
var baseline = http.sendRequest(requestResponse.request().withMethod("GET"));
var variant  = http.sendRequest(requestResponse.request().withMethod("POST"));

var attributeTypes = new AttributeType[]{
    AttributeType.STATUS_CODE,
    AttributeType.CONTENT_LENGTH,
    AttributeType.BODY_CONTENT
};

if (baseline.hasResponse() && variant.hasResponse()) {
    var baselineAttributes = baseline.response().attributes(attributeTypes);
    var variantAttributes  = variant.response().attributes(attributeTypes);

    for (int i = 0; i < 3; i++) {
        var baselineAttribute = baselineAttributes.get(i);
        var variantAttribute  = variantAttributes.get(i);

        if (baselineAttribute.type() == AttributeType.STATUS_CODE) {
            if (baselineAttribute.value() != variantAttribute.value()) {
                api().logging().logToOutput("Status codes are different");
            }
        }
        if (baselineAttribute.type() == AttributeType.CONTENT_LENGTH) {
            if (baselineAttribute.value() != variantAttribute.value()) {
                api().logging().logToOutput("Content length is different");
            }
        }
        if (baselineAttribute.type() == AttributeType.BODY_CONTENT) {
            if (baselineAttribute.value() != variantAttribute.value()) {
                api().logging().logToOutput("Content is different");
            }
        }
    }
}

return AuditResult.auditResult();
```

#### Identify Timing Differences

```java
var baseline = http.sendRequest(requestResponse.request());
var variant  = http.sendRequest(
    requestResponse.request().withAddedHeader("Cookie", "TrackingId=x'||pg_sleep(5)--")
);

if (baseline.hasResponse() && variant.hasResponse()) {
    var baseTiming    = baseline.timingData();
    var variantTiming = variant.timingData();

    if (baseTiming.isPresent() && variantTiming.isPresent()) {
        var baseMs            = baseTiming.get().timeBetweenRequestSentAndStartOfResponse();
        var varMs             = variantTiming.get().timeBetweenRequestSentAndStartOfResponse();
        var timingThresholdMs = 4000;

        if (varMs.toMillis() - baseMs.toMillis() >= timingThresholdMs) {
            // Significant timing difference detected
        }
    }
}

return AuditResult.auditResult();
```

---

### Reporting Results

Every check must return an `AuditResult`:
- **Issue found** → `AuditResult` containing one or more `AuditIssue` objects.
- **No issue** → `AuditResult.auditResult()` (empty).

#### AuditIssue Structure

```java
return AuditResult.auditResult(
    AuditIssue.auditIssue(
        "TITLE_HERE",
        "DETAIL_HERE",
        "REMEDIATION_HERE",
        "URL_HERE",
        AuditIssueSeverity.SEVERITY_HERE,    // INFORMATION / LOW / MEDIUM / HIGH
        AuditIssueConfidence.CONFIDENCE_HERE, // TENTATIVE / FIRM / CERTAIN
        "ISSUE_BACKGROUND_HERE",
        "REMEDIATION_BACKGROUND_HERE",
        AuditIssueSeverity.OVERALL_SEVERITY_HERE,
        REQUEST_RESPONSE_HERE                // HttpRequestResponse object(s)
    )
);
```

> **Notes:**
> - All string fields can include HTML. Always encode untrusted values first.
> - Pass `""` for unused string fields or `null` for other unused fields.
> - Always include a URL – without it the issue won't appear in results.

#### AuditIssue Field Reference

| Field | Description |
|-------|-------------|
| **Title** | Short, clear issue name |
| **Detail** | Detailed vulnerability description |
| **Remediation** | Practical fix steps |
| **URL** | Endpoint where the issue was identified |
| **Severity** | INFORMATION / LOW / MEDIUM / HIGH (this finding) |
| **Confidence** | TENTATIVE / FIRM / CERTAIN |
| **Issue background** | Extra context about this issue type |
| **Remediation background** | Extra remediation guidance |
| **Overall severity** | Typical severity for this issue type |
| **HTTP messages** | `HttpRequestResponse` object(s) to display |

#### Setting the URL

| Scenario | Code |
|----------|------|
| Issue visible in unmodified response | `requestResponse.request().url()` |
| Host-level check | `requestResponse.request().httpService().toString()` |
| Modified request demonstrates the issue | `rr.request().url()` |

#### Reporting Multiple Issues

```java
var issue1 = AuditIssue.auditIssue(...);
var issue2 = AuditIssue.auditIssue(...);
return AuditResult.auditResult(issue1, issue2);
```

#### Empty Result

```java
return AuditResult.auditResult();
```

---

### Using Collaborator in Checks

Enable the **Use Collaborator** toggle to detect out-of-band vulnerabilities. Burp polls Collaborator in the background and passes interactions to your handler.

> **Note:** The scan check remains active as long as it exists in your project – delayed interactions are still detected after a scan completes.

**Code tab example (email-splitting detection):**

```java
var spoofServer = "target.domain";

var techniques = new String[]{
    "=?x?q?$COLLABORATOR_PAYLOAD=40$COLLABORATOR_SERVER=3e=00?=foo@$SPOOF_SERVER"
};

for (var technique : techniques) {
    var payload = collaboratorClient.generatePayload();
    technique = technique.replaceAll("[$]COLLABORATOR_SERVER", payload.server().get().address());
    technique = technique.replaceAll("[$]COLLABORATOR_PAYLOAD", payload.id().toString());
    technique = technique.replaceAll("[$]SPOOF_SERVER", spoofServer);

    HttpRequestResponse reqResp = http.sendRequest(
        insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(technique))
    );
}

// Return no issue here – interactions handled via the Collaborator tab
return AuditResult.auditResult();
```

**Collaborator tab handler example:**

```java
if (!interaction.smtpDetails().isPresent()) return AuditResult.auditResult();

var technique = "=?x?q?$COLLABORATOR_PAYLOAD=40$COLLABORATOR_SERVER=3e=00?=foo@$SPOOF_SERVER";
HttpRequest req = insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(technique));
HttpRequestResponse reqRes = HttpRequestResponse.httpRequestResponse(req, requestResponse.response());

Function<String, String> newLinesToBr = s -> s.replaceAll("\\r?\\n", "<br>");

var id           = interaction.id().toString();
var conversation = interaction.smtpDetails().get().conversation().substring(0, 500) + "...";
var title        = "Email address parser discrepancy";
var detail       = "This site is vulnerable to an email splitting attack. SMTP conversation: "
    + utilities().htmlUtils().encode(conversation);

return AuditResult.auditResult(AuditIssue.auditIssue(
    title,
    newLinesToBr.apply(detail),
    newLinesToBr.apply("Reject encoded-word patterns, disable legacy address parsing, verify ownership via one-time link."),
    reqRes.request().url(),
    AuditIssueSeverity.MEDIUM,
    AuditIssueConfidence.FIRM,
    newLinesToBr.apply("Email syntax allows embedded control characters that survive initial validation but are re-interpreted by deeper libraries."),
    newLinesToBr.apply("Disable 'encoded-word' in user registration flows. Sanitize addresses before HTML/SQL insertion."),
    AuditIssueSeverity.MEDIUM,
    reqRes
));
```

---

## Worked Examples

### Passive Check – Missing Content-Security-Policy Header

```java
if (!requestResponse.hasResponse()) {
    return AuditResult.auditResult();
}

if (!requestResponse.response().hasHeader("Content-Security-Policy")) {
    var issueTitle   = "Content Security Policy header missing";
    var issueDetail  = "The response does not include a Content-Security-Policy header. Without this header the browser cannot enforce a restrictive policy for scripts, styles, images and other resources, increasing exposure to XSS, click-jacking and content-injection attacks.";
    var remediation  = "Add a suitable Content-Security-Policy header, for example: Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none';";
    var background   = "Content Security Policy (CSP) is an HTTP response header that tells the browser which sources are permitted for each resource type. A correctly configured CSP helps mitigate XSS and other code-injection flaws by limiting the origins from which content can be loaded.";
    var remBg        = "Create a baseline policy in report-only mode, review violation reports, then switch to enforcement. Start with default-src 'self' and add only the sources that the application legitimately requires.";

    return AuditResult.auditResult(
        AuditIssue.auditIssue(
            issueTitle,
            issueDetail,
            remediation,
            requestResponse.request().url(),
            AuditIssueSeverity.LOW,
            AuditIssueConfidence.FIRM,
            background,
            remBg,
            AuditIssueSeverity.LOW,
            requestResponse
        )
    );
}

return AuditResult.auditResult();
```

**Step-by-step breakdown:**

1. **Exit if no response** – `hasResponse()` prevents null errors.
2. **Check for header** – `hasHeader("Content-Security-Policy")` (case-insensitive).
3. **Build issue variables** – title, detail, remediation, background strings.
4. **Return issue** – wrap in `AuditIssue` → `AuditResult`.
5. **Return empty result** – if header is present or early exit triggered.

---

### Active Check – CORS Arbitrary Origin Reflection

```java
if (!requestResponse.hasResponse()) {
    return AuditResult.auditResult();
}

var evilHttps = "https://"
    + api().utilities().randomUtils().randomString(6) + "."
    + api().utilities().randomUtils().randomString(3);
var evilHttp = "http://"
    + api().utilities().randomUtils().randomString(6) + "."
    + api().utilities().randomUtils().randomString(3);

for (var origin : new String[]{evilHttps, evilHttp}) {
    var rr = http.sendRequest(
        requestResponse.request()
            .withRemovedHeader("Origin")
            .withAddedHeader("Origin", origin)
    );

    if (!rr.hasResponse()) {
        continue;
    }

    var headers = rr.response().headers().toString().toLowerCase();
    var creds   = headers.contains("access-control-allow-credentials: true");
    var reflect = headers.contains("access-control-allow-origin: " + origin.toLowerCase());
    var vary    = headers.contains("vary: origin");

    if (reflect) {
        var severity = creds ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;
        var note     = vary ? "" : " (missing Vary: Origin)";
        return AuditResult.auditResult(
            AuditIssue.auditIssue(
                "CORS: arbitrary origin reflection" + note,
                "Reflected Origin: " + origin + "; credentials=" + creds,
                "Use strict allowlist; include Vary: Origin.",
                rr.request().url(),
                severity,
                AuditIssueConfidence.FIRM,
                "",
                "",
                severity,
                rr
            )
        );
    }
}

return AuditResult.auditResult();
```

**Step-by-step breakdown:**

1. **Exit if no response** – guards against null.
2. **Create random origins** – avoids caching artefacts; ensures origins can't be allowlisted.
3. **Loop through origins** – tests both `https://` and `http://` variants.
4. **Send modified requests** – replaces existing `Origin` header with forged value.
5. **Inspect response headers** – checks `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, and `Vary: Origin`.
6. **Return issue if reflected** – severity is HIGH when credentials allowed, MEDIUM otherwise; adds note if `Vary: Origin` is absent.
7. **Return empty result** – if no reflection detected.

---

## Testing Custom Scan Checks

### Testing in the Editor

1. Go to **Extensions > Custom scan checks**.
2. Open an existing or new check.
3. From anywhere in Burp, select HTTP messages to test.
4. Right-click → **Send to Custom scan checks editor**.
5. In the editor, select the **Scan check** tab.
6. Check the messages to use in the **Select custom scan check test cases** panel.
7. Click **Run test**.

**Results panels:**
| Tab | Shows |
|-----|-------|
| **Audit items** | Individual HTTP requests flagged as audit items |
| **Issues** | All security vulnerabilities found |
| **Event log** | Key events during the task |
| **Logger** | All HTTP traffic generated |

**Test case actions:**
| Action | How |
|--------|-----|
| Enable/Disable | Checkbox in the panel |
| Duplicate | Right-click → Duplicate |
| Remove | Right-click → Remove |
| Edit | Select + modify in Request/Response tabs |

### Running a Test Scan

To test multiple checks at once using a controlled scan:

1. Open the scan launcher → **Scan configuration** tab.
2. Under **Audit configuration**, click **Scan checks**.
3. In **Built-in** tab, disable all built-in checks (top toggle).
4. In **Extensions** tab, disable all extension-provided checks.
5. In **Custom** tab, enable only the checks you want to test.

---

## BChecks

BChecks are custom scan checks written in PortSwigger's custom **BCheck definition language**. Each BCheck is a plain text `.bcheck` file.

- **Manage in Burp Suite Professional** – Extensions > Custom scan checks (see Managing Custom Scan Checks above).
- **Community repository** – [PortSwigger BChecks on GitHub](https://github.com/PortSwigger/BChecks)
- **Full language reference** – BCheck definition reference (in Burp Suite documentation).

### Submitting BChecks to the Community

1. **Check submission guidelines** – Review the repository's contributing guidelines first.
2. **Export your BCheck** from Burp (see Exporting Checks above).
3. **Fork** the [PortSwigger BChecks repository](https://github.com/PortSwigger/BChecks) on GitHub.
4. Clone your fork and create a new branch.
5. Add your `.bcheck` file, then commit and push.
6. Open a **pull request** against the PortSwigger BChecks repository.
7. PortSwigger reviews it (automated + manual), adds feedback to the PR, then merges.

> **Note:** The BChecks repository is for `.bcheck` files only. For Java-based scan check scripts (`.bambda`), use the [Bambda scripts repository](https://github.com/PortSwigger/bambdas).

### Submitting Script-Based Checks to GitHub

For Java `.bambda` scan check files, submit to the **Bambda scripts repository** following a similar pull request process. See [Submitting scripts to GitHub](https://portswigger.net/burp/documentation/desktop/extend-burp/bambdas/creating/contribute-scripts).
