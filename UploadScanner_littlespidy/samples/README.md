# 📁 Upload Scanner Sample Files Directory

This directory contains a complete library of sample test files and payloads covering all file extensions, categories, and test cases supported by **Upload Scanner (Montoya Edition)**.

Each file has been generated with authentic file magic headers, structural metadata, and standard signatures recognized by web servers, reverse proxies, and operating systems.

---

## 🗂️ Directory Structure

```
samples/
├── allowed-extensions/          # Clean, benign sample files for testing accepted extensions
│   ├── images/                  # JPG, JPEG, PNG, GIF, WebP, BMP, SVG, ICO, TIFF, AVIF
│   ├── documents/               # TXT, PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, CSV, RTF, ODT
│   ├── web-data/                # JSON, XML, HTML, JS, CSS, YAML
│   ├── archives/                # ZIP, TAR, GZ, 7Z, RAR
│   └── media/                   # MP3, WAV, MP4, AVI, MOV, MKV, OGG
├── server-rce/                  # Server-side execution payloads and web shells
│   ├── sample.php               # PHP info & execution shell
│   ├── sample.phtml             # Alternative PHP extension
│   ├── sample.php5              # Legacy PHP5 extension
│   ├── sample.phar              # PHP executable archive
│   ├── sample.jsp               # JSP scriptlet execution shell
│   ├── sample-el.jsp            # JSP Expression Language evaluation (${...})
│   ├── sample.jspx              # JSPX XML execution shell
│   ├── sample.asp               # Classic ASP VBScript shell
│   ├── sample.aspx              # ASP.NET C# inline shell
│   ├── sample.pl                # Perl CGI execution script
│   ├── sample.py                # Python CGI execution script
│   ├── sample.rb                # Ruby CGI execution script
│   ├── sample.sh                # Bash/Shell CGI script
│   ├── sample.shtml             # SSI (Server-Side Includes) directive
│   └── sample.esi               # ESI (Edge-Side Includes) SSRF directive
├── configs/                     # Server configuration overrides
│   ├── .htaccess                # Apache AddType/AddHandler execution override
│   ├── web.config               # IIS FastCGI script-map handler mapping
│   ├── .user.ini                # PHP auto_prepend_file configuration
│   └── .env                     # Sensitive environment configuration probe
├── image-libraries/             # Exploits targeting server-side image processors
│   ├── sample-imagetragick.mvg  # ImageTragick MVG RCE (CVE-2016-3714)
│   ├── sample-imagetragick.svg  # ImageTragick SVG RCE (CVE-2016-3714)
│   ├── sample-badmanners.xbm    # ImageMagick Bad Manners memory leak (CVE-2018-16323)
│   ├── sample-delegate.msl      # ImageMagick MSL delegate SSRF
│   ├── sample-ghostscript-lfi.ps# Ghostscript /etc/passwd LFI (CVE-2016-7977)
│   ├── sample-ghostscript-rce.eps# Ghostscript SAFER pipe RCE (CVE-2017-8291)
│   └── sample-libavformat.m3u8  # LibAVFormat / FFmpeg HLS SSRF
├── xml-documents/               # XML external entity & document-embedded attacks
│   ├── sample-xxe.svg           # SVG XML External Entity injection
│   ├── sample-xxe.xml           # Generic XML XXE injection
│   ├── sample-xxe.docx          # OpenXML DOCX with embedded XXE in document.xml
│   ├── sample-xxe.xmp           # Adobe XMP metadata packet XXE injection
│   ├── sample-javascript.pdf    # PDF OpenAction embedded JavaScript
│   ├── sample-callback.pdf      # PDF Out-Of-Band SSRF / NTLM probe
│   └── sample-formula.csv       # Spreadsheet CSV formula injection (=cmd|...)
├── client-side/                 # Stored XSS and CSP polyglot payloads
│   ├── sample-stored-xss.html   # HTML stored XSS vector
│   ├── sample-stored-xss.svg    # Valid SVG with embedded script
│   ├── sample-flash-xss.swf     # Compiled SWF Flash ActionScript vector
│   ├── sample-csp-polyglot.jpg  # PortSwigger JPEG + JavaScript CSP bypass polyglot
│   ├── sample-csp-polyglot.gif  # ThinkFu GIF89a + JavaScript CSP bypass polyglot
│   ├── sample-php-polyglot.gif  # GIF89a + PHP execution polyglot
│   └── sample-php-polyglot.png  # PNG IHDR header + PHP execution polyglot
├── archives-quirks/             # Path traversal, DoS bombs, and parser quirks
│   ├── sample-zipslip.zip       # Zip Slip traversal archive (../../../../traversal_shell.php)
│   ├── sample-symlink.tar       # TAR archive with symbolic link to /etc/passwd
│   ├── sample-trailing-dot.php. # Windows trailing dot quirk
│   ├── sample-mixed-case.PhP    # Case sensitivity bypass
│   ├── sample-nullbyte.php%00.png# Legacy null-byte injection quirk
│   ├── sample-double-ext.php.jpg# Double extension bypass
│   ├── sample-iis-semicolon.asp;.jpg # IIS semicolon path truncation bypass
│   ├── sample-eicar.txt         # Standard EICAR Anti-Virus test string
│   ├── sample-pixelflood.png    # Pixel flood DoS (65535x65535 dimensions)
│   └── sample-billionlaughs.xml # XML Billion Laughs nested expansion DoS bomb
└── exif-metadata/               # Native JPEG/PNG EXIF and metadata test files
    ├── sample-exif-canary.jpg   # JPEG with GPS coordinates & PII metadata canary
    ├── sample-exif-canary.png   # PNG with tEXt chunks containing PII canary
    ├── sample-exif-xss.jpg      # JPEG with Stored XSS in EXIF Artist/Description tags
    ├── sample-exif-cmd.jpg      # JPEG with command injection vector in EXIF tags
    └── sample-exif-sqli.jpg     # JPEG with SQL injection vector in EXIF tags
```

---

## 📋 Comprehensive File Catalog

### 1. Allowed Extensions: Images
| File | Extension | Content-Type | Format Details |
| :--- | :--- | :--- | :--- |
| `sample.jpg` | `.jpg` | `image/jpeg` | Minimal JFIF 1.01 JPEG (1x1 px, 72 DPI) |
| `sample.jpeg` | `.jpeg` | `image/jpeg` | Minimal JFIF 1.01 JPEG (1x1 px, 72 DPI) |
| `sample.png` | `.png` | `image/png` | Valid 1x1 RGBA PNG with IHDR, IDAT, IEND |
| `sample.gif` | `.gif` | `image/gif` | Valid GIF89a 1x1 image |
| `sample.webp` | `.webp` | `image/webp` | RIFF VP8L lossless 1x1 WebP |
| `sample.bmp` | `.bmp` | `image/bmp` | Windows 3.x 24-bit 1x1 BMP bitmap |
| `sample.svg` | `.svg` | `image/svg+xml` | Valid scalable vector graphic XML |
| `sample.ico` | `.ico` | `image/x-icon` | Windows Icon header wrapping 24-bit BMP |
| `sample.tiff` | `.tiff` | `image/tiff` | Little-endian II* TIFF structure |
| `sample.avif` | `.avif` | `image/avif` | ISO ftyp avif box |

### 2. Allowed Extensions: Documents
| File | Extension | Content-Type | Format Details |
| :--- | :--- | :--- | :--- |
| `sample.txt` | `.txt` | `text/plain` | Plain ASCII text file |
| `sample.pdf` | `.pdf` | `application/pdf` | Valid 1-page PDF 1.4 catalog & xref |
| `sample.doc` | `.doc` | `application/msword` | Microsoft Compound File Binary Format (CFBF) |
| `sample.docx` | `.docx` | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` | OpenXML ZIP package with valid word/document.xml |
| `sample.xls` | `.xls` | `application/vnd.ms-excel` | Microsoft CFBF Excel spreadsheet format |
| `sample.xlsx` | `.xlsx` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | OpenXML ZIP package with xl/workbook.xml |
| `sample.ppt` | `.ppt` | `application/vnd.ms-powerpoint` | Microsoft CFBF PowerPoint presentation format |
| `sample.pptx` | `.pptx` | `application/vnd.openxmlformats-officedocument.presentationml.presentation` | OpenXML ZIP package with ppt/presentation.xml |
| `sample.csv` | `.csv` | `text/csv` | Comma-Separated Values table |
| `sample.rtf` | `.rtf` | `application/rtf` | Rich Text Format standard ANSI header |
| `sample.odt` | `.odt` | `application/vnd.oasis.opendocument.text` | OASIS OpenDocument Text ZIP package |

### 3. Allowed Extensions: Web & Data
| File | Extension | Content-Type | Format Details |
| :--- | :--- | :--- | :--- |
| `sample.json` | `.json` | `application/json` | Formatted valid JSON object |
| `sample.xml` | `.xml` | `application/xml` | Standard XML 1.0 document |
| `sample.html` | `.html` | `text/html` | HTML5 standard document |
| `sample.js` | `.js` | `application/javascript` | JavaScript source |
| `sample.css` | `.css` | `text/css` | Cascading Style Sheet rules |
| `sample.yaml` | `.yaml` | `application/x-yaml` | YAML configuration data |

### 4. Allowed Extensions: Archives
| File | Extension | Content-Type | Format Details |
| :--- | :--- | :--- | :--- |
| `sample.zip` | `.zip` | `application/zip` | Valid ZIP archive containing probe text |
| `sample.tar` | `.tar` | `application/x-tar` | Valid POSIX ustar archive containing file |
| `sample.gz` | `.gz` | `application/gzip` | GZIP compressed stream |
| `sample.7z` | `.7z` | `application/x-7z-compressed` | Authentic 7-Zip signature (`37 7A BC AF 27 1C`) |
| `sample.rar` | `.rar` | `application/vnd.rar` | Authentic RAR signature (`52 61 72 21 1A 07 00`) |

### 5. Allowed Extensions: Media (Audio & Video)
| File | Extension | Content-Type | Format Details |
| :--- | :--- | :--- | :--- |
| `sample.mp3` | `.mp3` | `audio/mpeg` | ID3v2.3 tagged MPEG audio frame |
| `sample.wav` | `.wav` | `audio/wav` | RIFF WAVE PCM 44.1kHz audio stream |
| `sample.mp4` | `.mp4` | `video/mp4` | ISO ftyp isom/mp42 container |
| `sample.avi` | `.avi` | `video/x-msvideo` | RIFF AVI LIST/hdrl container |
| `sample.mov` | `.mov` | `video/quicktime` | Apple QuickTime ftyp container |
| `sample.mkv` | `.mkv` | `video/x-matroska` | EBML Matroska multimedia container |
| `sample.ogg` | `.ogg` | `audio/ogg` | OggS stream header |

### 6. Server-Side Execution (RCE)
| File | Extension | Content-Type | Attack Scenario |
| :--- | :--- | :--- | :--- |
| `sample.php` | `.php` | `application/x-php` | PHP info & system function execution |
| `sample.phtml` | `.phtml` | `application/x-phtml` | PHP execution via alternative extension |
| `sample.php5` | `.php5` | `application/x-php` | Legacy PHP extension bypass |
| `sample.phar` | `.phar` | `application/octet-stream` | PHP Phar stub execution |
| `sample.jsp` | `.jsp` | `application/x-jsp` | Java Servlet runtime scriptlet execution |
| `sample-el.jsp` | `.jsp` | `application/x-jsp` | JSP Expression Language evaluation |
| `sample.jspx` | `.jspx` | `application/xml` | XML JSPX scriptlet execution |
| `sample.asp` | `.asp` | `text/asp` | Classic ASP VBScript response write |
| `sample.aspx` | `.aspx` | `application/x-aspx` | ASP.NET C# inline execution |
| `sample.pl` | `.pl` | `application/x-perl` | Perl CGI script |
| `sample.py` | `.py` | `text/x-python` | Python CGI script |
| `sample.rb` | `.rb` | `application/x-ruby` | Ruby CGI script |
| `sample.sh` | `.sh` | `application/x-sh` | Bash CGI script |
| `sample.shtml` | `.shtml` | `text/html` | Apache SSI directive `#exec cmd` |
| `sample.esi` | `.esi` | `text/html` | Reverse proxy ESI SSRF |

### 7. Configurations & Web Servers
| File | Extension | Target Server | Attack Scenario |
| :--- | :--- | :--- | :--- |
| `.htaccess` | `.htaccess` | Apache | Overrides MIME type mapping (`AddType application/x-httpd-php .jpg`) |
| `web.config` | `.config` | IIS | Maps static extensions to FastCGI handler |
| `.user.ini` | `.ini` | PHP-FPM | Injects `auto_prepend_file` to execute uploaded images |
| `.env` | `.env` | Any | Checks if sensitive environment files can be overwritten |

### 8. Image Libraries & Exploit Formats
| File | Extension | Target Library | CVE / Vulnerability |
| :--- | :--- | :--- | :--- |
| `sample-imagetragick.mvg` | `.mvg` | ImageMagick | CVE-2016-3714 (Command Execution via `url()`) |
| `sample-imagetragick.svg` | `.svg` | ImageMagick | CVE-2016-3714 (SSRF/RCE via `xlink:href`) |
| `sample-badmanners.xbm` | `.xbm` | ImageMagick | CVE-2018-16323 (Uninitialized memory disclosure) |
| `sample-delegate.msl` | `.msl` | ImageMagick | MSL XML delegate file read/write |
| `sample-ghostscript-lfi.ps` | `.ps` | Ghostscript | CVE-2016-7977 (`/etc/passwd` LFI) |
| `sample-ghostscript-rce.eps` | `.eps` | Ghostscript | CVE-2017-8291 (SAFER bypass via `%pipe%`) |
| `sample-libavformat.m3u8` | `.m3u8` | LibAV / FFmpeg | HLS playlist SSRF / arbitrary file read |

### 9. XML & Document Attacks
| File | Extension | Target | Attack Scenario |
| :--- | :--- | :--- | :--- |
| `sample-xxe.svg` | `.svg` | Image / XML Parser | External DTD & `/etc/passwd` entity injection |
| `sample-xxe.xml` | `.xml` | XML Parsers | Generic XML External Entity extraction |
| `sample-xxe.docx` | `.docx` | Office Parser | Embedded XXE in `word/document.xml` |
| `sample-xxe.xmp` | `.xmp` | Metadata Parser | Adobe XMP metadata packet XXE |
| `sample-javascript.pdf` | `.pdf` | PDF Viewer | OpenAction JavaScript execution (`app.alert`) |
| `sample-callback.pdf` | `.pdf` | PDF Viewer | Remote GoToE URI SSRF / NTLM hash theft |
| `sample-formula.csv` | `.csv` | Excel / Calc | Dynamic Data Exchange (`=cmd\|' /C calc'`) |

### 10. Client-Side & Polyglots
| File | Extension | Technique | Attack Scenario |
| :--- | :--- | :--- | :--- |
| `sample-stored-xss.html` | `.html` | Direct Script | Stored Cross-Site Scripting |
| `sample-stored-xss.svg` | `.svg` | Inline Script | SVG XML Stored XSS |
| `sample-flash-xss.swf` | `.swf` | ActionScript | Adobe Flash `getURL("javascript:...")` |
| `sample-csp-polyglot.jpg` | `.jpg` | PortSwigger Polyglot | Valid JPEG header bypassing strict CSP |
| `sample-csp-polyglot.gif` | `.gif` | ThinkFu Polyglot | Valid GIF89a header bypassing strict CSP |
| `sample-php-polyglot.gif` | `.gif` | Header Injection | Valid GIF89a graphic with appended PHP code |
| `sample-php-polyglot.png` | `.png` | Header Injection | Valid PNG signature with appended PHP code |

### 11. Archives, Quirks & DoS
| File | Extension | Technique | Attack Scenario |
| :--- | :--- | :--- | :--- |
| `sample-zipslip.zip` | `.zip` | Zip Slip | Directory traversal extraction (`../../../../traversal_shell.php`) |
| `sample-symlink.tar` | `.tar` | Tar Symlink | Symbolic link pointing to `/etc/passwd` |
| `sample-trailing-dot.php.` | `.php.` | Path Quirks | Windows dot truncation bypass |
| `sample-mixed-case.PhP` | `.PhP` | Blacklist Quirks | Case-sensitive filename filter bypass |
| `sample-nullbyte.php%00.png` | `.php%00.png` | Null Byte | File extension truncation bypass |
| `sample-double-ext.php.jpg` | `.php.jpg` | Apache Quirks | Multi-extension handler execution |
| `sample-iis-semicolon.asp;.jpg` | `.asp;.jpg` | IIS Quirks | IIS semicolon path truncation |
| `sample-eicar.txt` | `.txt` | AV Signature | Standard EICAR Anti-Virus detection test |
| `sample-pixelflood.png` | `.png` | Pixel Flood | 65535×65535 dimension decompression bomb |
| `sample-billionlaughs.xml` | `.xml` | Entity Bomb | Nested XML entity expansion memory bomb |

### 12. EXIF Metadata Testing
| File | Extension | Technique | Attack Scenario |
| :--- | :--- | :--- | :--- |
| `sample-exif-canary.jpg` | `.jpg` | GPS & PII Canary | Tests whether server strips GPS & author EXIF tags |
| `sample-exif-canary.png` | `.png` | tEXt Canary | Tests whether server strips PNG textual chunks |
| `sample-exif-xss.jpg` | `.jpg` | Metadata XSS | Stored XSS inside `Artist` & `ImageDescription` tags |
| `sample-exif-cmd.jpg` | `.jpg` | Metadata Injection | Command injection vector in EXIF metadata |
| `sample-exif-sqli.jpg` | `.jpg` | Metadata Injection | SQL injection vector in EXIF metadata |

---

## 🚀 How to Use These Samples

### Method 1: Manual Upload Testing
1. Select any sample file from `samples/` based on the vulnerability you wish to test.
2. Upload the file via the target application's file upload interface.
3. Review whether the server accepts the extension, processes the content, or executes the payload.

### Method 2: Testing with Burp Suite Repeater
1. Send the file upload request to Burp Repeater.
2. Load the binary or text payload content from the sample file into the request body.
3. Update the `filename` and `Content-Type` headers to match the sample.

### Method 3: Upload Scanner Automated Scanning
The Upload Scanner extension natively generates these payloads in real-time during scans, utilizing unique timestamped execution tokens (`UPLOAD_SCANNER_EXEC_SUCCESS_<timestamp>`) and live Burp Collaborator subdomains for accurate reflection and out-of-band detection.
