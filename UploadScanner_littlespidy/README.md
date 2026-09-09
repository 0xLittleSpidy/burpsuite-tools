# 📤 Upload Scanner (Montoya Edition)

<!-- Created with the help of an AI Agent and littlespidy. -->

A modern, high-performance Burp Suite extension written in **Java** using PortSwigger's **Montoya API** (`burp.api.montoya.*`). 

This project is a modernized, standalone rewrite of the legacy Python *Upload Scanner* extension, featuring:
- **Simplified ReDownloader** with 1-click magic auto-detection, highlight marker derivation, and common CMS presets.
- **Complete 24-Module Attack Matrix** across 5 categories (Server RCE, Image Libraries, XML/Documents, Client-Side/Polyglots, Archives/Quirks/DoS).
- **Integrated Burp Collaborator** for automated Out-Of-Band (OOB) blind interaction tracking.
- **100% Native Java Engine** (in-memory ZIP and TAR builders, zero Perl or `exiftool` dependencies).
- **Interactive Triage Activity Log** with multi-select filtering, live search, and synchronized editor marker highlighting.

---

## 🌟 Key Features

### 1. 🎯 Effortless ReDownloader (4 Intuitive Modes)
The ReDownloader verifies whether uploaded files are stored, publicly accessible, or executed by automatically redownloading them after upload:

1. **✨ Magic Auto-Detect (1-Click)**:
   - Automatically inspects the upload HTTP response to discover download links without manual configuration.
   - Discovers links from `Location:` / `Content-Location:` redirect headers, filename reflections in the response body, JSON keys (`url`, `path`, `file`, `download`, `src`, `href`), and HTML media tags (`<img src>`, `<a href>`, `<source>`).
   - Automatically strips escaped JSON backslashes (`\/` → `/`).
2. **🎯 1-Click Highlight Selection**:
   - Simply select/highlight the file URL or path in Burp's native response viewer.
   - Click **🎯 Use Highlighted Selection** — the engine instantly derives the exact start and end markers around your selection with zero regex math.
3. **📁 Common Directory Presets**:
   - 1-click buttons for popular frameworks and CMS setups:
     - `📁 /uploads/${FILENAME}`
     - `📁 /wp-content/uploads/${FILENAME}`
     - `📁 /storage/${FILENAME}`
     - `📁 /media/${FILENAME}`
     - `📁 /static/${FILENAME}`
     - `📁 /files/${FILENAME}`
4. **⚙️ Advanced Custom Markers & Templates**:
   - Custom Start/End markers with full placeholder support:
     - `${FILENAME}`: Injected filename (e.g. `shell.php`)
     - `${ENCODED_FILENAME}`: URL-encoded filename (`%20`, `%2e`, etc.)
     - `${FILENAME_NO_EXT}`: Filename without extension (e.g. `shell`)
     - `${ORIG_EXT}`: File extension (e.g. `php`)
     - `${RANDOMIZE}`: Unique 12-digit random number for cache busting
5. **🧪 Live ReDownloader Verification**:
   - Click **🧪 Test ReDownloader Now** to test parsing and dispatch a live background GET request to verify download headers and content in real-time.

---

## ⚔️ Complete 24-Module Attack Matrix

Upload Scanner implements all 24 scanning methods across 5 categories:

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

---

### 3. 🌐 Integrated Burp Collaborator Tracking
- Automatically generates unique collaborator subdomains for each scan.
- Embeds subdomains into blind OOB vectors:
  - ImageTragick MVG / SVG SSRF callbacks
  - Ghostscript command execution callbacks
  - LibAVFormat `.m3u8` playlist SSRF
  - Office DOCX OpenXML XXE entity resolution
  - SVG & XML XXE entity resolution
  - XMP packet metadata XXE
  - PDF NTLM / SMB authentication callbacks
  - CSV formula DNS lookup probes
- Automatically polls Burp Collaborator upon scan completion and flags confirmed out-of-band interactions directly in the UI.

---

### 4. 📋 Enhanced "Done Uploads" Activity Log
- **Multi-Select Triage Toolbars**:
  - **Stage**: Filter by `Upload`, `Preflight`, `ReDownload`, or `Verification`.
  - **Status**: Filter by HTTP status code groups (`2xx`, `3xx`, `4xx`, `5xx`).
  - **Method**: Filter by HTTP method (`POST`, `GET`, `PUT`, `DELETE`).
- **Live Search**: Instant multi-field text search across URLs, filenames, status codes, and stages.
- **Master Table Columns**:
  - `#`: Sequential transaction ID
  - `Stage`: Color-coded phase badge
  - `Method`: HTTP request method
  - `Status`: Color-coded status code (Green for 2xx, Blue for 3xx, Orange for 4xx, Red for 5xx)
  - `Filename / Payload`: Injected test file or payload identifier
  - `Length (B)`: Response body byte size
  - `URL`: Target request URL
- **Master-Detail Split Viewer**: Embedded native Montoya `HttpRequestEditor` and `HttpResponseEditor` with automatic search highlight synchronization.
- **Log Management**:
  - `🗑️ Clear Log`: Resets the log table and editors in one click.
  - `💾 Export TSV`: Export all captured requests and responses to a TSV spreadsheet.

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
2. **Setup ReDownloader in Seconds**:
   - **Option A**: Click **✨ Auto-Detect Magic** to automatically discover the download URL from the response.
   - **Option B**: Highlight the returned file path in the response editor and click **🎯 Use Highlighted Selection**.
   - **Option C**: Click any **Common Directory Preset** (e.g. `/uploads/${FILENAME}`).
3. **Verify Download**: Click **🧪 Test ReDownloader Now** to inspect the live response in the test viewer.
4. **Choose Attack Vectors**: Use the category tabs to select desired modules or click **Select All (24 Modules)**.
5. **Run Scan**: Click **▶ Start Scan**.
6. **Triage Results**: Review uploads and redownloads in the **📋 Done Uploads** log table using the multi-select filters and search bar.

---

## 📄 License & Attribution
Created with the help of an AI Agent and littlespidy.
