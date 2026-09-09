# 📤 Upload Scanner (Montoya Edition)

<!-- Created with the help of an AI Agent and littlespidy. -->

A modern, high-performance Burp Suite extension written in **Java** using PortSwigger's **Montoya API** (`burp.api.montoya.*`). 

This project is a modernized, standalone rewrite of the legacy Python *Upload Scanner* extension, featuring a powerful **ReDownloader** with **visual editor markers**, an **interactive triage activity log**, and native Java attack payload generators (no external Perl/exiftool binaries required).

---

## 🌟 Key Features

### 1. 🎯 ReDownloader with Visual Editor Markers
The ReDownloader allows automated retrieval of uploaded files to detect whether the server executed or exposed them:
- **Dynamic URL Extraction**: Configure **Start** and **End** markers to parse relative or absolute file URLs directly from JSON, HTML, or plain text upload responses.
- **Template Placeholders**: Supports dynamic tokens in delimiters, prefixes, and suffixes:
  - `${FILENAME}`: Injected filename (e.g. `shell.php`)
  - `${ENCODED_FILENAME}`: URL-encoded filename (`%20`, `%2e`, etc.)
  - `${FILENAME_NO_EXT}`: Filename without extension (e.g. `shell`)
  - `${ORIG_EXT}`: File extension (e.g. `php`)
  - `${RANDOMIZE}`: Unique 12-digit random number for cache busting
- **Visual Editor Markers**: 
  - Automatically computes precise character offsets (`Marker.marker(start, end)`) for the parsed URL.
  - Automatically drives Burp's message editors via `HttpResponseEditor.setSearchExpression()` so the extracted URL and reflected payload tokens are highlighted in yellow/orange.
- **Preflight Support**: Supports an intermediate preflight request to discover dynamic storage endpoints (e.g. `/profile/` or `/user/gallery/`).

### 2. 📋 Enhanced "Done Uploads" Activity Log
Overhauls the legacy 2-column log table into a triage command center:
- **Multi-Select Triage Toolbars**: Powered by `MultiSelectFilterButton`:
  - **Stage**: Filter by `UPLOAD`, `PREFLIGHT`, or `REDOWNLOAD`.
  - **Status**: Filter by HTTP status code groups (`2xx`, `3xx`, `4xx`, `5xx`).
  - **Method**: Filter by HTTP method (`POST`, `GET`, `PUT`, `DELETE`).
- **Live Search**: Instant multi-field text search across URLs, filenames, status codes, and stages.
- **Master Table Columns**:
  - `#`: Sequential transaction ID
  - `Stage`: Color-coded phase badge (`Upload`, `Preflight`, `ReDownload`)
  - `Method`: HTTP request method
  - `Status`: Color-coded status code (Green for 2xx, Blue for 3xx, Orange for 4xx, Red for 5xx)
  - `Filename / Payload`: Injected test file or payload identifier
  - `Length (B)`: Response body byte size
  - `URL`: Target request URL
- **Master-Detail Split Viewer**: Embedded native Montoya `HttpRequestEditor` and `HttpResponseEditor` with automatic search highlight synchronization.
- **Log Management**:
  - `🗑️ Clear Log`: Resets the log table and editors in one click.
  - `💾 Export TSV`: Export all captured requests and responses to a TSV spreadsheet.

### 3. ⚡ Native Java Attack Vectors (No External Binaries)
Includes built-in generators for key upload attack techniques:
- **Web Shells**: PHP system/phpinfo shells, PHTML, JSP Runtime execution, and ASPX test files.
- **Image Polyglots**: Valid GIF89a headers and PNG IHDR chunks containing embedded PHP code to bypass strict file magic-byte checks.
- **Path Traversal**: Directory climbing filenames (`../../shell.php`, `%2e%2e%2f`) to escape intended upload folders.
- **Extension Bypasses**: Double extensions (`.php.jpg`), mixed case (`.PhP`), trailing dots/spaces (`.php.`), and null-bytes (`%00`).
- **Client-Side & Anti-Virus**: Stored SVG XSS vectors and the industry-standard EICAR anti-virus test file to evaluate upload filter controls.

### 4. 🚀 Modern Multi-Session UI Architecture
- **Right-Click Integration**: Send any HTTP request from Burp Proxy, Repeater, Logger, or Target to Upload Scanner via **Extensions → Send to Upload Scanner**.
- **Dynamic Session Tabs**: Each test target spawns an independent session tab with its own ReDownloader config, execution controls, and close button (`×`).
- **Safe EDT Threading**: All network operations run off the Event Dispatch Thread via `SwingWorker` with instant pause and cancellation controls.

---

## 🛠️ Build & Installation

### Requirements
- **Java 17+** (or Java 21)
- **Burp Suite Professional / Community** (Montoya API supported)

### Building the JAR
From the `UploadScanner_littlespidy` directory:
```bash
./gradlew clean build jar
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
2. **Configure ReDownloader**:
   - Enter the **Start Marker** (e.g. `{"url":"`) and **End Marker** (e.g. `"}`).
   - Alternatively, supply a **Static URL** (e.g. `/uploads/${FILENAME}`).
3. **Verify Extraction**: Click **🧪 Test ReDownloader**. Check the preview label to confirm the URL and character offsets are parsed correctly and visible in the response viewer.
4. **Run Attack**: Select desired attack modules and click **▶ Start Scan**.
5. **Analyze Results**: Switch to the **📋 Done Uploads** tab to triage all sent uploads and redownloads using the multi-select filters.

---

## 📄 License & Attribution
Created with the help of an AI Agent and littlespidy.
