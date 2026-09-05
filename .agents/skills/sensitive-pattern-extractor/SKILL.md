---
name: sensitive-pattern-extractor
description: >
  Generates and configures secret, API key, token, and cloud URL detection for Burp Suite tools (Extensions, Bambdas, BChecks). References patterns.md for all regular expressions, two-stage refiners, and extraction rules.
---

# Sensitive Pattern Extractor

Use this skill whenever creating or modifying secret scanning tools in Burp Suite (Extensions, Bambdas, BChecks).

All regular expressions, two-stage refiner rules, and keywords are stored in **[`patterns.md`](file:///home/littlespidy/myextra/burpsuite/.agents/skills/sensitive-pattern-extractor/patterns.md)**.

## Quick Workflow

1. **Read Patterns**: Open [`patterns.md`](file:///home/littlespidy/myextra/burpsuite/.agents/skills/sensitive-pattern-extractor/patterns.md) and pick the required regexes (Tokens, Cloud Storage, Keywords, PII, Errors).
2. **Apply Two-Stage Refiner for Cloud Buckets**:
   - Match the domain anchor suffix first (e.g. `s3.amazonaws.com`, `blob.core.windows.net`).
   - Scan backward 64 chars with the refiner regex (`[a-z\d\-]{3,63}\.$`) to grab bucket/account prefixes without ReDoS or greedy delimiter bleed.
3. **Choose Output Tool**:
   - **Bambda (Java)**: Quick filter for Burp Proxy HTTP history table. Append notes (`setNotes`) without overwriting.
   - **BCheck**: Passive or active scan check for Burp Scanner.
   - **Extension (Java Montoya)**: Full UI tab with table findings, multi-select filters, deep-linking, and TSV export.
