# Agent Guidelines and Project Rules

## Core Directives

### 1. Emoji Prohibition Rule
Never use emojis anywhere in this project. This applies strictly to:
- Source code (Java, Python, Kotlin, Rust, JavaScript, TypeScript, etc.)
- User interface components, Swing controls, button text, labels, dialog titles, tooltips
- Log messages, console output, and exception strings
- Markdown documentation, README files, walkthroughs, artifacts
- Code comments and docstrings
- Commit messages and version control tags
- Agent chat responses and user communication

Always use plain, professional ASCII text only. Do not use unicode decorative icons or emoji symbols (e.g. plus signs as unicode symbols, checkmarks, arrows, smiley faces). Use standard words such as "Add", "Edit", "Delete", "Reload", "Enabled", "Error", "Warning", etc.

### 2. Montoya API Standard
All Burp Suite extensions must use the modern Montoya API (net.portswigger.burp.extensions:montoya-api). Do not use the legacy Extender API.

### 3. File Naming and Author Markers
- Every generated file must include the distinct marker `_littlespidy` at the end of the filename/project name where applicable.
- Every generated source file must include the comment at the top:
  `// Created with the help of an AI Agent and littlespidy.`

### 4. Code Preservation
Preserve all existing comments, docstrings, and unrelated code functionality unless explicitly instructed otherwise.

### 5. Extension JAR Artifact Requirement
- Every Burp Suite extension project must include and track its compiled release fat-JAR under `<ExtensionFolder>/build/libs/<name>.jar`.
- Whenever an extension project is created, modified, or refactored:
  1. Build the release fat-JAR (`./gradlew clean test build` or `./gradlew jar`).
  2. Verify that `.gitignore` does not ignore `build/libs/*.jar`.
  3. Always stage, commit, and push the newly compiled JAR file to the remote repository alongside source code changes.
  4. Never omit the compiled JAR file from commits.

### 6. Mandatory HTML GUI Preview Before Building
Every time a Burp Suite extension user interface, suite tab, sub-tab, dialog, toolbar, or interactive feature is created, redesigned, or modified:
1. Always build a standalone, interactive HTML mockup preview file (`<feature>_ui_preview_littlespidy.html`) in the extension directory before building the Java extension artifact.
2. The HTML mockup must mirror Burp Suite aesthetics (dark and light themes), display realistic sample data, and include interactive tab and table behaviors.
3. Automatically launch the HTML preview in the user's default web browser using `xdg-open <feature>_ui_preview_littlespidy.html`.
4. The HTML file must adhere to all project directives (ASCII text only, no emojis, author markers).
5. Always stage, commit, and push the HTML preview file to the remote repository.

