# 📤 Upload Scanner (Montoya Edition)

<!-- Created with the help of an AI Agent and littlespidy. -->

A modern, high-performance Burp Suite extension written in **Java** using PortSwigger's **Montoya API** (`burp.api.montoya.*`). 

This project is a modernized, standalone rewrite and enhancement of the legacy *Upload Scanner* extension, featuring:
- **Integrated Side-by-Side Split Workspace**: Results view and Montoya detail viewers integrated directly into the right side of each request session tab, providing real-time triage without switching tabs.
- **SecLists Content-Type Validation**: Complete integration with the SecLists `web-all-content-types.txt` wordlist (2,387 MIME types) alongside MIME spoofing (e.g. PHP/JSP scripts with image MIME types) and header tampering checks.
- **File Size Limit Checking**: Stepped boundary probe suite (0-byte empty file, 1KB, 10KB, 100KB, 500KB, 1MB, 2MB, 5MB, 10MB, 20MB) with valid image structure and configurable max size.
- **EXIF Metadata Upload & Leakage Testing**: 100% native Java in-memory JPEG APP1 (EXIF) and PNG tEXt chunk generation with GPS/PII canaries, automated ReDownloader stripping verification, and stored EXIF XSS testing (zero `exiftool` dependencies).
- **Simplified ReDownloader** with 1-click magic auto-detection, highlight marker derivation, custom directory preset patterns, and automated cookie/auth header propagation.
- **Allowed Extensions Probe & Matrix** for probing accepted file formats across Images, Documents, Web/Data, Archives, Media, and custom extensions with authentic magic bytes & MIME types.
- **Complete Attack Matrix** across 7 categories (Server RCE, Image Libraries, XML/Documents, Client-Side/Polyglots, Archives/Quirks/DoS, Allowed Extensions, Validation & EXIF).
- **Integrated Burp Collaborator** for automated Out-Of-Band (OOB) blind interaction tracking.
- **Interactive Triage Activity Log** with multi-select filtering (`Stage`, `Status`, `Method`), live search, and synchronized editor marker highlighting.

---

## 🌟 Key Features

### 1. 🖥️ Integrated Side-by-Side Split Workspace
Instead of burying scan results in a separate tab, each upload request session features an integrated horizontal split view:
- **Left Panel (Configuration & Baseline Reference)**:
  - ReDownloader wizard banner and 4 intuitive extraction modes.
  - 7 categorized attack module tabs with 1-click "Select All" / "Clear" buttons.
  - Action toolbar with dedicated 1-click probe buttons (`🧪 Probe Extensions`, `🧪 Probe Content-Types`, `📏 Test File Sizes`, `📷 Test EXIF Leakage`, `▶ Start Scan`).
  - Intruder-style baseline request editor (with `§ Add Marker` / `§ Clear Markers`) and upload response editor.
- **Right Panel (Live Activity Log & Detail Inspector)**:
  - Real-time streaming log table displaying `#`, `Stage`, `Method`, `Status`, `Filename / Payload`, `Length`, `URL`.
  - Multi-select filter buttons (`Stage`, `Status`, `Method`) and instant text search.
  - Embedded Montoya HTTP Request and Response editors with automatic search/marker synchronization upon row selection.
  - `🗑️ Clear Log` and `💾 Export TSV` controls.

---

### 2. 📑 SecLists Content-Type Validation & MIME Spoofing
- **Full SecLists Wordlist**: Bundles Daniel Miessler's SecLists `web-all-content-types.txt` (2,387 MIME types) directly inside the extension jar.
- **MIME Spoofing Probes**: Tests whether the server allows executable scripts when disguised with harmless MIME types:
  - `.php` web shell with `Content-Type: image/jpeg`, `image/png`, `application/octet-stream`, `text/plain`
  - `.jsp` scriptlet with `Content-Type: image/png`
  - `.asp` script with `Content-Type: image/jpeg`
  - `.html` stored XSS with `Content-Type: image/gif`
  - `.svg` vector with `Content-Type: image/png`
- **MIME Mismatch Probes**: Tests whether static files (`.jpg`, `.png`, `.pdf`) are handled dangerously when sent with executable MIME types (`application/x-php`, `text/html`).
- **Header Tampering & Mutations**:
  - Empty Content-Type (`Content-Type: `)
  - Semicolon parameter injection (`Content-Type: image/jpeg; evil=application/x-php`)
  - Mixed-case tampering (`Content-Type: ImAgE/jPeG`)
  - Binary charset parameter (`Content-Type: image/jpeg; charset=binary`)
- **1-Click Probe**: Click **`🧪 Probe Content-Types`** to test MIME acceptance and spoofing against the target endpoint.

---

### 3. 📏 File Size Limit Checking
- **Stepped Boundary Probes**:
  - `0 Bytes`: Empty file upload to test for unhandled `NullPointerException` or division-by-zero crashes.
  - `1 KB (1,024 B)`
  - `10 KB (10,240 B)`
  - `100 KB (102,400 B)`
  - `500 KB (512,000 B)`
  - `1 MB (1,048,576 B)`
  - `2 MB (2,097,152 B)`
  - `5 MB (5,242,880 B)`
  - `10 MB (10,485,760 B)`
  - `20 MB (20,971,520 B)` (configurable max size up to 500 MB)
- **Authentic Magic Envelope**: Padded files begin with valid image magic bytes and end with valid image termination markers (e.g. JPEG `FF D8 ... FF D9`), ensuring pure file-size rejection is evaluated rather than premature magic-byte rejections.
- **1-Click Probe**: Click **`📏 Test File Sizes`** to map the application's file size acceptance boundary.

---

### 4. 📷 EXIF Metadata Upload & Leakage Testing (100% Native Java)
- **Zero External Dependencies**: Generates valid JPEG images with embedded `APP1` (EXIF) segments and TIFF structures, as well as PNG images with `tEXt` chunks entirely in memory (no Perl or `exiftool` required).
- **GPS & PII Canary Leakage**:
  - Embeds authentic GPS coordinates (`37.7749° N, 122.4194° W` / San Francisco), Camera Make (`LittleSpidy Phone 1.0`), Model (`AuditProbe 1.0`), Artist (`LittleSpidy Security Canary`), and unique canary timestamp tokens into EXIF tags.
  - **Automated ReDownloader Stripping Verification**: Re-downloads the uploaded image and checks whether GPS/PII canaries remain intact.
    - If canaries are preserved: Flags `⚠️ VULNERABILITY: EXIF PII Leakage (GPS / Metadata Preserved on Server!)`.
    - If stripped: Flags `✔ EXIF Stripped: Server sanitized metadata`.
- **Stored EXIF Injections**:
  - Embeds Stored XSS vectors (`"><script>alert('EXIF_XSS')</script>`) inside Artist and ImageDescription tags.
  - Embeds Command Injection vectors (`$(whoami);id`) and SQL Injection vectors (`' OR '1'='1'`) inside EXIF metadata.
  - Automatically flags if XSS payloads reflect unencoded in upload or download HTTP responses.
- **1-Click Probe**: Click **`📷 Test EXIF Leakage`** to run the complete EXIF security assessment.

---

### 5. 🎯 Effortless ReDownloader (4 Intuitive Modes)
The ReDownloader verifies whether uploaded files are stored, publicly accessible, or executed by automatically redownloading them after upload:

1. **✨ Magic Auto-Detect (1-Click)**:
   - Automatically inspects the upload HTTP response to discover download links without manual configuration.
   - Discovers links from `Location:` / `Content-Location:` redirect headers, filename reflections in the response body, JSON keys (`url`, `path`, `file`, `download`, `src`, `href`), and HTML media tags (`<img src>`, `<a href>`, `<source>`).
   - Automatically strips escaped JSON backslashes (`\/` → `/`).
2. **🎯 1-Click Highlight Selection**:
   - Simply select/highlight the file URL or path in Burp's native response viewer.
   - Click **🎯 Use Highlighted Selection** — the engine instantly derives the exact start and end markers around your selection with zero regex math.
3. **📁 Directory Preset**:
   - Easily provide any target directory or static URL pattern (e.g. `/uploads/${FILENAME}`, `/storage/${FILENAME}`, `/media/${FILENAME_NO_EXT}/${FILENAME}`) with live automatic synchronization.
4. **⚙️ Advanced Custom Markers & Templates**:
   - Custom Start/End markers with full placeholder support:
     - `${FILENAME}`: Injected filename (e.g. `shell.php`)
     - `${ENCODED_FILENAME}`: URL-encoded filename (`%20`, `%2e`, etc.)
     - `${FILENAME_NO_EXT}`: Filename without extension (e.g. `shell`)
     - `${ORIG_EXT}`: File extension (e.g. `php`)
     - `${RANDOMIZE}`: Unique 12-digit random number for cache busting
5. **🔐 Cookie & Auth Header Propagation**:
   - Automatically forwards `Cookie`, `Authorization`, `Proxy-Authorization`, and custom session/token headers (`X-Auth-Token`, `X-API-Key`, `Bearer`, etc.) from the upload request onto all ReDownloader verification requests.
6. **🧪 Live ReDownloader Verification**:
   - Click **🧪 Test ReDownloader Now** to test parsing and dispatch a live background GET request to verify download headers and content in real-time.

---

## ⚔️ Complete Attack Matrix (7 Categories)

| Category | Module | Description | Detection / OOB |
| :--- | :--- | :--- | :--- |
| **Server RCE** | PHP Web Shells | PHP info & system shells (`.php`, `.phtml`, `.php5`, `.phar`, double ext, null-byte) | Token reflection |
| | JSP / JSPX Shells | Java scriptlet runtime execution, EL expression `${7*7}`, XML JSPX | Token reflection |
| | Classic ASP & ASPX | IIS Classic ASP (`VBScript`), ASPX `.NET`, IIS semicolon execution (`.asp;.jpg`) | Token reflection |
| | Apache `.htaccess` | Overrides `AddType application/x-httpd-php .png` to execute images as PHP | Token reflection |
| | IIS `web.config` | Custom IIS script-map handler executing static files as PHP / ASP | Token reflection |
| | CGI Scripts | Perl (`#!/usr/bin/perl`), Python, Ruby, and Bash Unix shell CGI scripts | Token reflection |
| | SSI & ESI Injection | Server-Side Includes (`<!--#exec cmd="..." -->`) & Edge Side Includes (`<esi:include>`) | Token reflection |
| **Image Libraries** | ImageTragick (CVE-2016-3714) | MVG `fill 'url(https://...)'` RCE, SVG `xlink:href` SSRF | Collaborator OOB |
| | Bad Manners (CVE-2018-16323) | ImageMagick XBM memory disclosure / information leak | Token reflection |
| | ImageMagick Delegates | MSL (`.msl`) Magick Scripting Language XML delegate injection | Collaborator OOB |
| | Ghostscript SAFER Bypasses | CVE-2016-7977 (`/etc/passwd` LFI) & CVE-2017-8291 (`%pipe%` RCE) | LFI / Collab OOB |
| | LibAVFormat / FFmpeg SSRF | AVI / HLS (`.m3u8`) playlist remote segment injection (`#EXT-X-TARGET`) | Collaborator OOB |
| **XML & Documents** | SVG XXE Injection | XML external entity injection in SVG image processing | Collaborator OOB |
| | Standard XML XXE | Generic XML external entity payload reading `/etc/passwd` | LFI / Collab OOB |
| | Office OpenXML (DOCX) | In-memory ZIP package with `word/document.xml` XXE | Collaborator OOB |
| | XMP Packet Metadata XXE | Adobe XMP metadata packet embedded XXE | Collaborator OOB |
| | PDF Action & SSRF | PDF OpenAction JavaScript (`app.alert`) & URI callback SSRF/NTLM | Script / Collab |
| | CSV Formula Injection | Spreadsheet execution payloads (`=cmd\|' /C calc'`, `-2+3+cmd\|' /C nslookup'`) | Token / Collab |
| **Client & Polyglots**| HTML Stored XSS | HTML upload with JavaScript execution (`<script>alert(...)</script>`) | Token reflection |
| | SVG Stored XSS | Valid SVG vector containing embedded JavaScript event handlers | Token reflection |
| | Adobe Flash SWF XSS | Binary SWF Flash applet triggering ActionScript `getURL(javascript:)` | Token reflection |
| | PortSwigger JPEG+JS Polyglot | Authentic valid JPEG header with embedded JavaScript CSP bypass | Token reflection |
| | ThinkFu GIF89a+JS Polyglot | Authentic valid GIF89a graphic with embedded JavaScript CSP bypass | Token reflection |
| **Archives & DoS** | Zip Slip Archive Traversal | In-memory ZIP archive containing `../../../../traversal_shell.php` | Directory Traversal |
| | TAR Symlink Archive | In-memory TAR archive containing a symlink (`Typeflag 2`) to `/etc/passwd` | LFI `/etc/passwd` |
| | Upload Quirks & Bypasses | Trailing dot (`.php.`), trailing space (`.php `), mixed case (`.PhP`) | Token reflection |
| | EICAR AV Test | Industry-standard Anti-Virus test string to evaluate AV scanner controls | Token reflection |
| | Pixel Flood DoS | PNG IHDR dimension bomb modified to 65535×65535 pixels | Resource exhaustion |
| | XML Billion Laughs Bomb | Nested entity expansion XML bomb (`lol1`, `lol2`, ... `lol9`) | Resource exhaustion |
| **Allowed Extensions** | Images, Docs, Data, Archives | Probes accepted extensions (`.jpg`, `.pdf`, `.zip`, etc.) with valid headers | HTTP Status / Code |
| **Validation & EXIF** | SecLists Content-Types | All 2,387 MIME types from `web-all-content-types.txt` | HTTP Status / Code |
| | MIME Spoofing & Mutations | Executable scripts with image MIME types & header tampering | Token reflection |
| | File Size Limits | Stepped boundary probes (0B to 20MB+) with image envelopes | Status 413 / Code |
| | EXIF PII Canary Leakage | JPEG APP1 & PNG tEXt GPS / metadata stripping check | ReDownload Verification |
| | EXIF Stored XSS & Injection | Stored XSS, command injection, and SQLi in EXIF tags | Reflection / OOB |

---

## 🛠️ Build & Installation

### Requirements
- **Java 17+** (or Java 21)
- **Burp Suite Professional / Community** (Montoya API supported)

### Building the JAR
From the `UploadScanner_littlespidy` directory:
```bash
./gradlew clean test build jar
```
The compiled fat JAR will be located at:
```
build/libs/upload-scanner-littlespidy-1.0.0.jar
```

### Loading in Burp Suite
1. Open Burp Suite.
2. Navigate to **Extensions → Installed**.
3. Click **Add**.
4. Choose **Extension type: Java**.
5. Select `build/libs/upload-scanner-littlespidy-1.0.0.jar`.
6. Click **Next**. The `📤 Upload Scanner` suite tab will appear in the top bar.

---

## 📖 Quick Start Walkthrough

1. **Send Request to Extension**: Find a file upload HTTP request in Burp Proxy history or Repeater. Right-click and choose **Send to Upload Scanner**.
2. **Side-by-Side Workspace Opens**: The request configuration and baseline editors appear on the left, while the live activity log table and response viewers are ready on the right.
3. **Setup ReDownloader in Seconds**:
   - **Option A**: Click **✨ Auto-Detect Magic** to automatically discover the download URL from the response.
   - **Option B**: Highlight the returned file path in the response editor and click **🎯 Use Highlighted Selection**.
   - **Option C**: Specify a **Directory Preset** path pattern (e.g. `/uploads/${FILENAME}`).
4. **Verify Download**: Click **🧪 Test ReDownloader Now** to inspect the live response in the test viewer.
5. **Run Focused Probes or Full Scan**:
   - Click **`🧪 Probe Extensions`**: Quick test of accepted file formats.
   - Click **`🧪 Probe Content-Types`**: Test MIME acceptance using the 2,387-type SecLists wordlist & MIME spoofing.
   - Click **`📏 Test File Sizes`**: Map file size limits (0B to 20MB+).
   - Click **`📷 Test EXIF Leakage`**: Upload GPS/PII canaries and test whether the server strips metadata or reflects EXIF XSS.
   - Click **`▶ Start Scan`**: Run selected categories from the attack matrix.
6. **Triage Results on the Right**: Inspect responses in real-time on the right side using multi-select stage/status/method filters and search highlighting.

---

## 📄 License & Attribution
Created with the help of an AI Agent and littlespidy.
