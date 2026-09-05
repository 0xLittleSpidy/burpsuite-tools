---
name: burp-extension
description: >
  Comprehensive guide and reference for developing, debugging, installing, managing, and publishing Burp Suite extensions using the Montoya API, Java, Kotlin, Python/Jython, and AI capabilities. Use this skill whenever developing Burp extensions, integrating with Montoya API interfaces, setting up build configurations (Gradle/Maven), adding UI/Settings/Hotkeys, troubleshooting extension execution, or adhering to BApp Store acceptance criteria.
---

# Burp Extension Development & Management Skill

A comprehensive reference and practical implementation guide for creating, building, debugging, installing, managing, and publishing extensions for PortSwigger Burp Suite using the modern **Montoya API**.

---

## 1. Overview & Architecture

Burp extensions allow developers to customize and extend Burp Suite's core behavior, including:
- Intercepting and modifying HTTP/WebSocket requests and responses.
- Adding custom checks and insertion points to Burp Scanner (Professional).
- Injecting custom UI tabs, context menu items, hotkeys, and settings panels.
- Sending out-of-band requests using Burp Collaborator or standard Burp networking.
- Integrating LLM-driven AI capabilities natively into pentesting workflows via Burp AI.

### Choosing the Right Extensibility Model

| Model | Best Used For | Language / Framework | Setup Requirement |
| :--- | :--- | :--- | :--- |
| **Bambdas** | Quick on-the-fly table filtering, custom columns, match-and-replace rules. | Java snippet | None (Runs directly in Burp) |
| **BChecks** | Custom scan checks, vulnerability pattern matching, simple active/passive scans. | BCheck DSL | None (Burp Scanner tab) |
| **Extensions** | Full features, custom UI, background tasks, complex multi-step attacks, third-party integrations, AI workflows. | Java / Kotlin (Montoya API) or Python / Ruby (Legacy Extender) | Project / Build setup (`.jar`, `.py`) |

> [!IMPORTANT]
> Always use the modern **Montoya API** (`net.portswigger.burp.extensions:montoya-api`) for new extensions. The legacy `IBurpExtender` API is deprecated and unmaintained.

---

## 2. Development Environment Setup

Burp Suite supports Java 21 or lower for compiled extensions.

### Gradle Setup

#### `build.gradle.kts` (Kotlin DSL)
```kotlin
plugins {
    java
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2023.12.1") // Use latest release
    // Third-party dependencies:
    // implementation("com.google.code.gson:gson:2.10.1")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

// Bundle third-party dependencies into a Fat JAR
tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
}
```

#### `build.gradle` (Groovy DSL)
```groovy
plugins {
    id 'java'
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly 'net.portswigger.burp.extensions:montoya-api:2023.12.1'
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

tasks.named('jar') {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from configurations.runtimeClasspath.findAll { it.isDirectory() }
    from configurations.runtimeClasspath.findAll { !it.isDirectory() }.collect { zipTree(it) }
}
```

### Maven Setup (`pom.xml`)
```xml
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>burp-extension</artifactId>
    <version>1.0.0</version>

    <properties>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <dependency>
            <groupId>net.portswigger.burp.extensions</groupId>
            <artifactId>montoya-api</artifactId>
            <version>2023.12.1</version>
            <scope>provided</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-shade-plugin</artifactId>
                <version>3.5.1</version>
                <executions>
                    <execution>
                        <phase>package</phase>
                        <goals><goal>shade</goal></goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
```

---

## 3. Core Montoya API Reference

When Burp loads an extension, it calls `BurpExtension.initialize(MontoyaApi api)`. `MontoyaApi` exposes the following subsystems:

| Method | Subsystem | Description |
| :--- | :--- | :--- |
| `api.extension()` | Extension | Manage extension name, metadata, and unload handlers. |
| `api.userInterface()` | UI | Register tabs, context menus, hotkeys, editors, and settings panels. |
| `api.http()` | HTTP | Register HTTP request/response handlers, issue HTTP requests, cookie/parameter utilities. |
| `api.proxy()` | Proxy | Access and hook into Burp Proxy traffic (`ProxyHttpRequestHandler`, `ProxyHttpResponseHandler`). |
| `api.siteMap()` | Site Map | Query and update the target site map. |
| `api.scanner()` | Scanner (Pro) | Register custom scan checks (`ScanCheck`), insertion points, and audit issues. |
| `api.collaborator()` | Collaborator (Pro) | Generate out-of-band payloads and poll Collaborator interactions. |
| `api.ai()` | AI (Pro) | Interact with LLM models using prompt templates, system messages, and chat history. |
| `api.logging()` | Logging | Output info/error logs to Burp's extension Output/Error tabs or system console. |
| `api.repeater()` | Repeater | Send requests programmatically to Repeater tabs. |
| `api.intruder()` | Intruder | Register custom Intruder payload generators and processors. |
| `api.websockets()` | WebSockets | Register WebSocket creation and message handlers. |
| `api.persistence()` | Persistence | Manage temporary file contexts and preferences. |
| `api.project()` | Project | Access project-level data and metadata. |
| `api.scope()` | Scope | Evaluate if URLs/requests are in Burp's Target Scope. |
| `api.bambda()` | Bambda | Execute or evaluate Bambdas programmatically. |
| `api.utilities()` | Utilities | Byte, HTML, URL, Base64, and compression helper utilities. |

---

## 4. Extension Implementation Templates

### A. Minimal Montoya Extension Starter
```java
package com.example.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class MyExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        // Set extension name in Extensions > Installed
        api.extension().setName("My Extension");

        // Log initialization
        api.logging().logToOutput("Extension loaded successfully.");
    }
}
```

---

### B. Custom Context Menu & Suite Tab
```java
package com.example.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class UIContextMenuExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("UI & Context Menu Extension");

        // 1. Register Context Menu Item
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                JMenuItem item = new JMenuItem("Send to Custom Extension Processor");
                item.addActionListener(e -> {
                    event.selectedRequestResponses().forEach(reqResp -> {
                        api.logging().logToOutput("Processing request to: " + reqResp.request().url());
                    });
                });
                return List.of(item);
            }
        });

        // 2. Register Custom Suite Tab
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JLabel("Welcome to Custom Extension UI", SwingConstants.CENTER), BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("Custom Tab", panel);
    }
}
```

---

### C. Settings Panel Integration
```java
package com.example.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelPersistence;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;

import java.util.List;

public class SettingsExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Extension with Custom Settings");

        SettingsPanelWithData panel = SettingsPanelBuilder.settingsPanel()
            .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
            .withTitle("My Custom Settings")
            .withDescription("Configure target host and scan options.")
            .withKeywords("Custom", "Fuzzer", "Settings")
            .withSettings(
                SettingsPanelSetting.stringSetting("Target host", "example.com"),
                SettingsPanelSetting.integerSetting("Max concurrency", 10),
                SettingsPanelSetting.booleanSetting("Follow redirects", true),
                SettingsPanelSetting.listSetting("Scan Mode", List.of("Passive", "Active", "Aggressive"), "Passive")
            )
            .build();

        api.userInterface().registerSettingsPanel(panel);

        // Accessing values:
        String targetHost = panel.getString("Target host");
        int maxConcurrency = panel.getInteger("Max concurrency");
        boolean followRedirects = panel.getBoolean("Follow redirects");
        String scanMode = panel.getString("Scan Mode");

        api.logging().logToOutput("Configured Host: " + targetHost + ", Mode: " + scanMode);
    }
}
```

---

### D. Hotkey Registration
```java
package com.example.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext;
import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.api.montoya.ui.hotkey.HotKeyHandler;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.List;
import java.util.stream.Collectors;

public class HotKeyExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Header Copier Hotkey");

        HotKey hotKey = HotKey.hotKey("Copy Header Names", "Ctrl+Alt+H");

        HotKeyHandler handler = event -> event.messageEditorRequestResponse().ifPresent(editor -> {
            SelectionContext selection = editor.selectionContext();
            HttpRequestResponse reqResp = editor.requestResponse();

            List<HttpHeader> headers = (selection == SelectionContext.REQUEST)
                ? reqResp.request().headers()
                : reqResp.response().headers();

            String joined = headers.stream().map(HttpHeader::name).collect(Collectors.joining(", "));

            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(new StringSelection(joined), null);
            api.logging().logToOutput("Copied headers: " + joined);
        });

        api.userInterface().registerHotKeyHandler(
            HotKeyContext.HTTP_MESSAGE_EDITOR,
            hotKey,
            handler
        );
    }
}
```

---

### E. AI-Powered Extension (Burp AI Integration)
```java
package com.example.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ai.Ai;
import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.Prompt;
import burp.api.montoya.ai.chat.PromptException;
import burp.api.montoya.ai.chat.PromptOptions;
import burp.api.montoya.ai.chat.PromptResponse;

import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AiSecurityAssistant implements BurpExtension {
    private final ExecutorService executor = Executors.newFixedThreadPool(4);

    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        // Required for "Use AI" checkbox to appear in Extensions tab
        return Set.of(EnhancedCapability.AI_FEATURES);
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("AI Security Assistant");

        api.extension().registerUnloadingHandler(executor::shutdownNow);

        if (!api.ai().isEnabled()) {
            api.logging().logToOutput("AI features are disabled. Please check 'Use AI' in Extensions > Installed.");
            return;
        }

        // Example asynchronous AI analysis call
        executor.submit(() -> analyzeVulnerability(api, "Explain potential risks of SQL injection in JSON endpoints."));
    }

    private void analyzeVulnerability(MontoyaApi api, String userQuery) {
        try {
            Prompt prompt = api.ai().prompt();
            PromptOptions options = PromptOptions.promptOptions().withTemperature(0.2); // Low temp for deterministic output

            Message systemMsg = Message.systemMessage("You are a professional application security penetration tester.");
            Message userMsg = Message.userMessage(userQuery);

            PromptResponse response = prompt.execute(options, systemMsg, userMsg);
            api.logging().logToOutput("AI Analysis:\n" + response.content());
        } catch (PromptException pe) {
            api.logging().logToError("AI Execution failed: " + pe.getMessage());
        } catch (Exception e) {
            api.logging().logToError("Unexpected error during AI call: " + e.getMessage());
        }
    }
}
```

---

## 5. BApp Store Acceptance Criteria & Best Practices

To ensure extensions pass PortSwigger review and operate reliably:

1. **Unique Purpose**: Do not duplicate existing BApp functionality unless providing substantial architectural or usability improvements.
2. **Fat JAR Packaging**: Include all external dependencies inside the final `.jar` using Gradle `duplicatesStrategy = DuplicatesStrategy.EXCLUDE` or Maven Shade Plugin.
3. **Threading & Responsiveness**:
   - **NEVER** perform network I/O, heavy parsing, or LLM calls in the Swing Event Dispatch Thread (EDT).
   - Avoid slow operations in `ProxyHttpRequestHandler`, `ProxyHttpResponseHandler`, and `HttpHandler`.
   - Use background `ExecutorService` pools and catch unhandled thread exceptions to write to `api.logging().logToError(...)`.
4. **Clean Unload**: Always register `api.extension().registerUnloadingHandler(...)` to shutdown thread pools, close file handles, and release background listeners.
5. **Burp Networking**: Use `api.http().sendRequest(...)` or `api.http().issueHttpRequest(...)` instead of `java.net.HttpURLConnection` or third-party HTTP clients so that upstream proxies, TLS certificates, and session rules are respected.
6. **Large Project Scalability**: Avoid keeping static long-term in-memory collections of `HttpRequestResponse`. Use `api.persistence().temporaryFileContext()` for large payload buffers.
7. **GUI Parent Window**: Ensure any custom popups/dialogs use `SwingUtils.suiteFrame()` or the main Burp Frame as parent to prevent multi-monitor detachment.
8. **AI Providers**: Extensions leveraging LLMs must use Burp AI (`api.ai()`) as the default provider and declare `EnhancedCapability.AI_FEATURES`.

---

## 6. Building, Loading, and Debugging

### Compiling & Building
- **Gradle**: `./gradlew jar` -> Outputs to `build/libs/<name>.jar`
- **Maven**: `mvn clean package` -> Outputs to `target/<name>-<version>.jar`

### Loading in Burp Suite
1. Navigate to **Extensions** > **Installed**.
2. Click **Add** -> Choose **Java** (or Python/Ruby).
3. Select the built `.jar` file.
4. Check **Auto-reload** so Burp automatically refreshes the extension when the JAR is recompiled.
5. Review logs under the **Output** and **Errors** tabs.

### Remote Debugging Setup
1. Launch Burp Suite from command line with JVM debug flags:
   ```bash
   java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 -jar burpsuite_pro.jar
   ```
2. In IntelliJ IDEA / Eclipse:
   - Create a **Remote JVM Debug** configuration targeting `localhost:5005`.
   - Set breakpoints in `initialize()` or request handlers.
   - Attach debugger and trigger extension actions in Burp.

---

## 7. Troubleshooting Common Extension Issues

| Issue | Root Cause | Solution |
| :--- | :--- | :--- |
| **Install button greyed out** | Burp version mismatch, missing Jython/JRuby, or Pro-only requirement. | Update Burp to latest, configure Jython standalone JAR in Settings > Extensions, or verify Pro license. |
| **`OutOfMemoryError: Metaspace`** | Frequent reload of Python/Ruby extensions or large class caches. | Launch Burp with `-XX:MaxMetaspaceSize=1G`. |
| **Network calls blocked / failing** | Upstream proxy or SSL intercepting proxy (e.g. Zscaler). | Add upstream proxy in **Settings > Network > Connections** and import CA cert under **Settings > Network > TLS**. |
| **UI Freeze / Hangs** | Synchronous HTTP or heavy computation on Swing EDT. | Offload task to an `ExecutorService` background worker thread. |
| **Requests missing from HTTP History** | Extension traffic does not appear in Proxy HTTP history. | Open **Logger** tab and filter by **Tool: Extensions** and **Tool: Scanner**. |
| **AI prompt fails** | AI features disabled, insufficient credits, or missing capability flag. | Check `api.ai().isEnabled()`, override `enhancedCapabilities()`, and verify AI credits in bottom-right corner. |

---

## 8. Reference Links & Resources

- [PortSwigger Montoya API Documentation](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions)
- [Montoya API JavaDoc Reference](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html)
- [Montoya API Official GitHub Examples](https://github.com/PortSwigger/burp-extensions-montoya-api-examples)
- [BApp Store Extension Portal Issues & Submissions](https://github.com/PortSwigger/extension-portal)
