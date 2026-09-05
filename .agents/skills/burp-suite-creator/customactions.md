# Custom Actions - Burp Suite Knowledge Reference

Custom actions are scripts that run directly from Burp Repeater to extract, analyze, and transform data. You can use custom actions to:

**Analyze responses** - Extract data, count elements, decode and encode messages, and check for specific content.

**Retrieve additional data** - Perform lookups, resolve hostnames, fetch external data, and use this data to modify the request or response.

**Resend requests** - Modify headers, parameters, or body content and resend the request.

**Use AI features** - Analyze messages, generate payloads based on context, or transform data using AI.

To try custom actions, open the Custom actions side panel in Repeater and click **Add samples** to load some ready-to-use examples.

You can also import community-created scripts from the [Bambdas GitHub repository](https://github.com/PortSwigger/bambdas) into your Bambda library. This is your personal collection of reusable scripts. These scripts can be loaded into the Custom actions side panel whenever you need them, making it easy to use and adapt scripts created by others.

---

## Creating Custom Actions

_Last updated: August 3, 2026 | Read time: 3 Minutes_

Custom actions are scripts that run directly from Burp Repeater to extract, transform, and analyze data. You can write your own custom actions to tailor Burp Repeater to your specific testing requirements.

Custom actions are built with **Java** and can be simple to write, even for beginners. Useful scripts may be as simple as a few lines of code. To help you get started, PortSwigger provides:

- Built-in starter templates in the editor.
- Inline suggestions and error highlighting in the editor.
- A range of community and reference resources.

### Related Pages

- **Custom action worked example** - Write your first custom action.
- **Custom actions writing guide** - Useful code snippets and building block examples of custom actions.
- **Developing AI features in custom actions** - Add AI-features to your custom actions.
- **Bambdas GitHub repository** - Examples of custom actions created by the community.

### Steps to Create a New Custom Action

1. **[Optional]** Make sure the Repeater tab contains a request/response pair that you've sent and want to test the custom action against.
2. In Repeater, click **Custom actions**. The Custom actions side panel opens.
3. Click **New** and select either **Blank** or **From template**. The Custom actions editor dialog opens.
4. If you selected **From template**, select a Custom action template from the list, then click **Create using this template**.
5. Write your custom action script using Java.
6. Test the custom action using the built-in test function.
7. **[Optional]** Click **Save to library > Save**. The custom action is saved to your Bambda library for future use across Burp.
8. Click **OK**.

If the custom action is error-free, it's added to the Custom actions side panel. If errors exist, they appear in the **Compilation errors** panel.

> **Note:** Keyboard shortcuts for saving to the Bambda library:
> - **Save to library** - `Ctrl + S` or `Cmd + S`
> - **Save copy to library** - `Ctrl + Shift + S` or `Cmd + Shift + S`

> **Warning:** Using slow running or resource-intensive custom action scripts can slow down Burp. Write your custom action carefully to minimize performance impact.

### Testing Custom Actions

When adding or editing a custom action, you can test its behavior using the built-in test function.

1. Review the sample message under **Request**. Optionally, replace it with the specific request you'd like to test against.
2. Click **Test**. Burp runs the custom action on the sample message.
3. Review any output in the **Console** tab.
4. Adjust the custom action as necessary.

#### How Burp Selects Test Data

The test function automatically uses the open request, response, and HTTP service from the current Repeater tab when you open the Custom actions editor.

The HTTP service is the destination host, port, and protocol (e.g., `https://example.com:443`). If this information isn't available, Burp uses a **null HTTP service** instead. This can impact how your custom action behaves during testing, especially if it:

- Makes follow-up requests.
- Logs information about the target service.
- Processes messages based on host or protocol.

---

## Custom Action Worked Example

_Last updated: August 3, 2026 | Read time: 2 Minutes_

The following example uses Java to write a custom action that **extracts a CSRF token from the response body**, modifies it, then logs the modified CSRF token.

### Complete Script

```java
var resp = requestResponse.response().bodyToString();
if (resp.contains("csrf=")){
    var csrfIndex = resp.lastIndexOf("csrf=")+5;
    var csrf = resp.substring(csrfIndex, csrfIndex+16);
    csrf = csrf.replace("a", "b").replace("c", "d");
    logging.logToOutput(csrf);
}
else{
    logging.logToOutput("No CSRF token");
}
```

### Step-by-Step Breakdown

**Step 1: Get the response body**
```java
var response = requestResponse.response().bodyToString();
```
- `requestResponse` represents the request/response pair the action is applied to.
- `response().bodyToString()` gets the response object and converts the body to a string.

**Step 2: Check the response body for the CSRF token**
```java
if (response.contains("csrf=")) {
```
Checks whether the response body contains the string `csrf=`.

**Step 3: Extract and process the token**
```java
var csrfIndex = response.lastIndexOf("csrf=") + 5;
var csrf = response.substring(csrfIndex, csrfIndex + 16);
csrf = csrf.replace("a", "b").replace("c", "d");
```
- `lastIndexOf("csrf=")` returns the index of the last occurrence of `csrf=`.
- `+5` moves the index to the start of the actual token (just after `csrf=`).
- `substring(csrfIndex, csrfIndex + 16)` extracts the 16-character token.
- `replace()` replaces characters `a` with `b`, and `c` with `d`.

**Step 4: Log the result**
```java
logging.logToOutput(csrf);
```
Logs the modified CSRF token to the Output panel in the Custom actions side panel.

**Step 5: Handle the situation where no token is found**
```java
else{
    logging.logToOutput("No CSRF token");
}
```
If `csrf=` is not found, logs the message `No CSRF token`.

---

## Custom Actions Writing Guide

_Last updated: August 3, 2026 | Read time: 11 Minutes_

This section provides useful code snippets and building block examples of custom actions.

### API Access

Seven objects of the Montoya API are available for custom action scripts:

| Object | Description |
|--------|-------------|
| `HttpRequestResponse` | Represents the full HTTP request and response. |
| `RequestResponseSelection` | Represents selected portions of a request or response. |
| `HttpEditor` | Provides access to editable HTTP message components in Repeater. |
| `MontoyaApi` | Provides access to Burp features. |
| `Utilities` | Provides access to the Montoya API helper functions. |
| `Logging` | Enables logging output to the Output panel. |
| `Ai` | Enables custom actions to send prompts to a Large Language Model (LLM). |

---

### Step 1: Accessing Request and Response Data

**Retrieving the full request or response**
```java
// Get the full HTTP request
var request = requestResponse.request();

// Get the full HTTP response
var response = requestResponse.response();
```

**Extracting specific parts of the message**
```java
// Get response body as a string
var responseBody = requestResponse.response().bodyToString();

// Get the value of a specific request header
var userAgent = requestResponse.request().headerValue("User-Agent");
```

**Extracting user-selected content**
```java
// Get selected text from the response as a string
var selectedText = selection.responseSelection().contents().toString();

// Get selected text from the request if available, or from the response, as a string
var messageSelection = selection.hasRequestSelection() ? selection.requestSelection() : selection.responseSelection();
var selectedText = messageSelection.contents().toString();
```

**Extracting the HTTP service**
```java
// Get the HTTP service from the request
var service = requestResponse.request().httpService();

// Always check that the HttpService is not null before using it
if (service == null) {
    return;
}
```

**Handling empty or missing content**
```java
// Check for an empty or missing response
if (requestResponse.response() == null || requestResponse.response().toString().isEmpty()) {
    return;
}

// Check for an empty user selection in the response
if (!selection.hasResponseSelection()) {
    return;
}
```

---

### Step 2: Processing Data

**Modifying editor content**
```java
// Set plain text in the request editor
httpEditor.requestPane().set("example");

// Set binary content using a ByteArray
httpEditor.requestPane().set(ByteArray.byteArray("example"));

// Replace all instances of a placeholder string in the response
httpEditor.responsePane().replace("replace_all_occurances_of_this", "with_this");
```

> **Note:** `EditorPane.set()` doesn't update the underlying message object. Store the new content in a variable before calling `set()` if you need to log or reuse it.

**Replacing selected content in the editor**
```java
// Get start and end positions of the selection
int start = selection.requestSelection().offsets().startIndexInclusive();
int end = selection.requestSelection().offsets().endIndexExclusive();

// Get the complete request as a string
var requestStr = requestResponse.request().toString();

// Insert new content at the selection location
var updatedRequest = requestStr.substring(0, start) + "NEW_VALUE" + requestStr.substring(end);

// Set the updated request in the request editor
httpEditor.requestPane().set(updatedRequest);
```

---

### Step 3: Logging and Using Data

**Logging to output**
```java
// Log a simple message
logging.logToOutput("Custom action triggered");

// Log the length of the response body
var responseBody = requestResponse.response().bodyToString();
logging.logToOutput("Response body length: " + responseBody.length());
```

**Sending data to other Burp tools**
```java
// Send the original request to a new Organizer tab
api.organizer().sendToOrganizer(requestResponse.request());

// Add a custom header and send the request to a new Repeater tab
var updatedRequest = requestResponse.request().withUpdatedHeader("X-Debug", "true");
api.repeater().sendToRepeater(updatedRequest);
```

**Logging data to a file**
```java
var filePath = System.getProperty("user.home") + File.separator + "output.txt";
var line = requestResponse.httpService().toString();
try (FileWriter writer = new FileWriter(filePath, true)) {
    writer.write(line + "\n");
    logging.logToOutput("HTTP service recorded.");
} catch (IOException e) {
    logging.logToError("Could not write to " + filePath, e);
}
```

---

### Example Use Cases

#### Decoding Data (Unicode Escape Sequences)

```java
// Check for an empty user selection in the response
if (!selection.hasResponseSelection()) {
    return;
}
var selectedResponseText = selection.responseSelection().contents().toString();
var pattern = Pattern.compile("\\\\u([0-9a-fA-F]{4})");
var decodedText = pattern.matcher(selectedResponseText).replaceAll(match -> String.valueOf((char) Integer.parseInt(match.group(1), 16)));
logging.logToOutput(decodedText);
var responseStr = requestResponse.response().toString();
int start = selection.responseSelection().offsets().startIndexInclusive();
int end = selection.responseSelection().offsets().endIndexExclusive();
var updatedResponse = responseStr.substring(0, start) + decodedText + responseStr.substring(end);
httpEditor.responsePane().set(updatedResponse);
```

#### Encoding Data (MIME Encoded-Word / Base64)

```java
if (!selection.hasRequestSelection()) {
    return;
}
var input = selection.requestSelection().contents().toString();
var charset = "iso-8859-1";
var encodedWord = api.utilities().base64Utils().encode(input);
var encodedWordPlusMeta = "=?"+charset+"?b?"+encodedWord+"?=";
var requestStr = requestResponse.request().toString();
int start = selection.requestSelection().offsets().startIndexInclusive();
int end = selection.requestSelection().offsets().endIndexExclusive();
var updatedRequest = requestStr.substring(0, start) + encodedWordPlusMeta + requestStr.substring(end);
httpEditor.requestPane().set(updatedRequest);
```

#### Sending Modified Requests (Remove Auth Headers)

```java
var request = requestResponse.request();
var modifiedRequest = request.withRemovedHeader("Authorization").withRemovedHeader("Cookie");
httpEditor.requestPane().set(modifiedRequest);
var response = api().http().sendRequest(modifiedRequest).response();
httpEditor.responsePane().set(response);
```

#### Sending Modified Requests (Path Traversal Test)

```java
var modifiedRequest = requestResponse.request().withPath("/../../");
var response = api().http().sendRequest(modifiedRequest).response();
httpEditor.responsePane().set(response);
```

#### Sending Repeated Requests (Race Condition Testing)

```java
int NUMBER_OF_REQUESTS = 10;
var reqs = new ArrayList<HttpRequest>();
for (int i = 0; i < NUMBER_OF_REQUESTS; i++) {
    reqs.add(requestResponse.request());
}
var responses = api().http().sendRequests(reqs);
var codes = responses.stream()
    .map(HttpRequestResponse::response)
    .map(HttpResponse::statusCode)
    .toList();
logging.logToOutput(codes);
```
> Uses single-packet attack for HTTP/2 and last-byte synchronization for HTTP/1.

#### Fetching External Data

```java
var apiURL = "https://portswigger.net/research/rss";
var responseBody = api().http().sendRequest(HttpRequest.httpRequestFromUrl(apiURL)).response().bodyToString();
var extractedData = responseBody.split(">item<")[1].split(">link<")[1].split("<")[0];
logging.logToOutput(extractedData);
```

#### Running Shell Commands (Traceroute)

```java
HttpService service = requestResponse.request().httpService();
if (service == null) {
    return;
}
String output = utilities().shellUtils().execute(
    executeOptions()
        .withTimeout(Duration.ofSeconds(15))
        .withTimeoutBehavior(TimeoutBehavior.ALLOW_TIMEOUT)
        .withStderrBehavior(StderrBehavior.MERGE)
        .withExitCodeBehavior(ExitCodeBehavior.ALLOW_NON_ZERO),
    "traceroute", service.host()
);
logging().logToOutput(output);
```

#### Running Shell Commands (AWS CLI)

```java
String output = utilities().shellUtils().execute(
    executeOptions()
        .withEnvironmentVariable("AWS_ACCESS_KEY_ID", "AKIAEXAMPLEKEY123")
        .withEnvironmentVariable("AWS_SECRET_ACCESS_KEY", "supersecretkeyvalue")
        .withEnvironmentVariable("AWS_DEFAULT_REGION", "us-west-2"),
    "aws", "sts", "get-caller-identity"
);
logging().logToOutput(output);
```

> **Warning:** Avoid using `dangerouslyExecute()` with user-controlled input. Use `execute()` with separate arguments instead to prevent command injection.

---

## Developing AI Features in Custom Actions

_Last updated: August 3, 2026 | Read time: 3 Minutes_

You can add AI-powered features to your custom actions using the Montoya API. Examples include:

- Analyzing requests or responses for vulnerabilities automatically.
- Generating payloads based on context.
- Transforming or optimizing data.

### Sending Prompts and Handling Responses

The `Prompt` interface sends structured prompts to the AI. A prompt consists of one or more `Message` objects:

- **System messages**: Set the AI's behavior or role.
- **User messages**: Represent request/response data or user queries.

**Steps to construct a prompt:**
1. Get the request or response data to analyze.
2. Construct a system message defining the AI's role.
3. Create a user message with the data to analyze.
4. Send the prompt using `ai().prompt().execute()`, which returns a `PromptResponse` object.
5. Retrieve the AI's response as a string using `content()`.
6. Output or use the result.

**Single-shot prompt example (WAF bypass payload generation):**
```java
var selectedText = selection.requestSelection().contents().toString();
if (selectedText.isEmpty()) {
    return;
}
var systemMessage = "You are a web security expert. Be creative. Just output vectors separated by new lines. Do not output markdown. Do not prefix with a number. Do not quote with backticks. Work out what is being tested then create 10 variants separated by new lines. The variants you create should be useful for bypassing a WAF for security testing purposes. Create 10 variants of this:";
var aiOutput = ai().prompt().execute(Message.systemMessage(systemMessage), Message.userMessage(selectedText)).content();
logging.logToOutput(aiOutput);
```

### Setting the Temperature

Temperature is a numeric value between `0` and `2`:

| Range | Behavior | Best For |
|-------|----------|----------|
| 0.0 – 0.8 | Predictable, deterministic | Technical / factual tasks |
| 0.8 – 2.0 | Creative, diverse | Exploratory tasks |

Default temperature: **0.5**

```java
var selectedText = selection.requestSelection().contents().toString();
if (selectedText.isEmpty()) {
    return;
}
var temperature = 1.0;
var prompt = "Guess possible meanings of this web identifier, concisely: " + selectedText;
var aiOutput = api.ai().prompt().execute(PromptOptions.promptOptions().withTemperature(temperature), Message.userMessage(prompt)).content();
logging.logToOutput(aiOutput);
```

### Handling Exceptions

Wrap calls to AI methods in a `try-catch` block to handle errors cleanly. When an error occurs, a `PromptException` is thrown.

```java
try {
    var requestBody = requestResponse.request().toString();
    var systemMessage = "You are a web security expert. Analyze the request and identify anything that may indicate a vulnerability.";
    var aiOutput = ai().prompt().execute(Message.systemMessage(systemMessage), Message.userMessage(requestBody)).content();
    logging.logToOutput(aiOutput);
} catch (PromptException e) {
    logging.logToError("An error occurred while processing the prompt: " + e.getMessage());
}
```

---

## Loading Custom Actions from Your Library

_Last updated: August 3, 2026 | Read time: 1 Minute_

Your **Bambda library** is your personal collection of reusable scripts. You can load custom action scripts from it into the Custom actions side panel.

> **Note:** If your library doesn't contain any custom actions yet, you can download community-created scripts from the GitHub repository, then import them.

### Steps to Load a Custom Action

1. In Repeater, click **Custom actions** to open the Custom actions side panel.
2. Click **Load**.
3. Select a recent custom action script from the list. If the script isn't listed, click **View all**.
4. Select a custom action script.
5. Click **Load**.

If the custom action is error-free, it's added to the Custom actions side panel, ready for use.

---

## Managing Custom Actions

_Last updated: August 3, 2026 | Read time: 1 Minute_

Once you've created or loaded a custom action, it's added to the Custom actions side panel. Custom actions are available from **any Repeater tab**.

| Action | How To |
|--------|--------|
| **Run** | Run manually or configure to run automatically after a response is received. |
| **Edit** | Click the edit icon beside the custom action. |
| **Rename** | Right-click > **Rename**. |
| **Save to library** | Right-click > **Save to library**. |
| **Save copy to library** | Right-click > **Save copy to library**. |
| **Remove from list** | Right-click > **Remove from list** (remains in library). |
| **Delete** | Right-click > **Delete** (permanently removes if not in library). |

---

## Community and Resources

- Share your custom action on the **PortSwigger Discord #bambdas channel** for feedback and collaboration.
- Submit your custom actions to the **[Bambdas GitHub repository](https://github.com/PortSwigger/bambdas)**.
- Reference the **[Montoya API JavaDoc](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/)** for full API documentation.
