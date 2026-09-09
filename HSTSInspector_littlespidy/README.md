# HSTS Inspector (Burp Suite Extension)

**Author**: littlespidy  
*Created with the help of an AI Agent and littlespidy.*

---

## Overview

**HSTS Inspector** is a Burp Suite extension built on the modern **Montoya API** to audit, group, and analyze **HTTP Strict Transport Security (HSTS)** implementation across web applications.

It empowers penetration testers and security researchers to rapidly identify:
- Endpoints completely **missing HSTS** headers.
- Weak or opt-out configurations (`max-age=0`).
- Insufficient header duration (`max-age < 1 year` or `max-age < 30 days`).
- Missing `includeSubDomains` directives allowing subdomain hijacking/MITM.
- Missing `preload` readiness flags.

---

## Features & UI

1. **HSTS Value Overview & Assessment (Summary Table)**:
   - **Value**: Displays the actual raw Strict-Transport-Security header value (e.g. `max-age=31536000; includeSubDomains; preload`, `(missing HSTS)`).
   - **Domains**: Comma-separated list of all distinct hostnames sharing each HSTS value. Hover tooltip shows all matching domains.
   - **Count**: Number of endpoints associated with the value.
   - **Assessment**: Color-coded security posture (`CRITICAL`, `HIGH`, `MEDIUM`, `GOOD`).

2. **Endpoint Detailed View**:
   - Master-detail table displaying `#`, `Status`, `Method`, `Host`, `URL`, `Content-Type`, `max-age`, `includeSubDomains`, `preload`, `Assessment`, and `Raw HSTS Header`.
   - Embedded native Montoya Request/Response editors for deep inspection.

3. **Multi-Faceted Triage Filtering**:
   - Multi-select popups for HTTP Method, Status Code, and Content-Type.
   - Freeform keyword search and In-Scope only filtering.

4. **Export Capabilities**:
   - One-click `Export TSV` to copy displayed records to clipboard.

---

## Building the Extension

```bash
cd /home/littlespidy/myextra/burpsuite/HSTSInspector_littlespidy
./gradlew jar
```

Compiled JAR output: `build/libs/hsts-inspector-littlespidy-1.0.0.jar`.
