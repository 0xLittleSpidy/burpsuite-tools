# Mandatory HTML GUI Preview Before Building Rule

## Core Directive
Whenever any Burp Suite extension user interface, suite tab, sub-tab, dialog, toolbar, or interactive feature is created, redesigned, or modified:
1. Always build a standalone, interactive HTML mockup preview file representing the complete user interface before building or compiling the Java extension release artifact.
2. Automatically launch the generated HTML preview in the user's default web browser using the command: `xdg-open <feature>_ui_preview_littlespidy.html`.
3. The HTML preview must be verified and approved by the user before compiling the release fat-JAR (`./gradlew clean test build` or `./gradlew jar`).

## File Naming and Placement Standard
- The preview file must be placed in the corresponding extension folder.
- The filename must follow the pattern: `<feature_name>_ui_preview_littlespidy.html`.
- The HTML file must include the author marker comment at the top:
  `<!-- Created with the help of an AI Agent and littlespidy. -->`

## Aesthetic and Functional Requirements
1. Burp Suite Look and Feel:
   - Must mirror the Burp Suite UI design (Dark theme by default, matching Burp colors like `#1e1e1e`, `#252526`, `#e56b1f` Burp Orange, etc.).
   - Must include a Dark / Light theme toggle.
2. Realistic Data & Layout:
   - Must contain realistic security datasets (e.g. real URLs, headers, vulnerabilities, CVEs, or findings).
   - Must represent all tables, columns, badges, buttons, toolbars, and split panes accurately.
3. Interactive Controls:
   - Must support interactive row selection, tab switching, and simulated filtering in pure JavaScript within the HTML.
4. Emoji Prohibition:
   - Must strictly adhere to the project-wide No Emojis Rule. Only plain ASCII text is permitted everywhere.

## Version Control Requirement
- The generated `<feature>_ui_preview_littlespidy.html` must be tracked by git.
- Always stage, commit, and push the HTML preview file to the remote repository alongside project changes.
