---
trigger: always_on
---

# Auto Commit and Push Rule

## Core Directive
Whenever code, documentation, configuration, or any repository files are created, modified, refactored, or deleted:
1. Always stage all modified and newly created files using `git add`.
2. Commit the staged changes immediately with a clear, concise, and descriptive commit message that accurately reflects the modifications made.
3. Push the commit immediately to the remote repository on the active working branch (e.g. `git push origin <branch>`).

## Execution Guidelines
- Stage and commit all relevant changes once a modification or task step is complete.
- Do not leave dirty working directory states or uncommitted code changes behind at the end of a turn or task.
- Commit messages must follow project guidelines: use plain ASCII text only, and strictly avoid emojis or decorative unicode symbols.
- Verify git status and ensure remote push succeeds. If conflicts or errors occur during push, resolve them promptly.

## Extension JAR Artifact Requirement
- Whenever an extension project is created, modified, or refactored:
  1. Build the release fat-JAR (e.g. using `./gradlew clean test build` or `./gradlew jar`).
  2. Ensure the compiled JAR file under `<ExtensionFolder>/build/libs/<extension-name>-<version>.jar` is not blocked by `.gitignore`.
  3. Always stage, commit, and push the newly compiled JAR file to the remote repository alongside source code changes.
  4. Never omit the compiled JAR file from commits.
