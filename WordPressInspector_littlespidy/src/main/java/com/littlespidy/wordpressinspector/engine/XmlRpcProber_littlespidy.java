// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.engine;

import com.littlespidy.wordpressinspector.model.XmlRpcResult_littlespidy;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Probes the target WordPress XML-RPC endpoint for enabled state and risky methods.
 */
public class XmlRpcProber_littlespidy {

    public static XmlRpcResult_littlespidy probeXmlRpc(String baseUrl) {
        XmlRpcResult_littlespidy result = new XmlRpcResult_littlespidy();
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            return result;
        }

        String target = baseUrl.trim().replaceAll("/+$", "") + "/xmlrpc.php";
        try {
            URL url = URI.create(target).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
            conn.setRequestProperty("Content-Type", "text/xml");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(10000);
            conn.setDoOutput(true);

            String body = "<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>";
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            int code = conn.getResponseCode();
            if (code == 200) {
                result.setEnabled(true);
                try (InputStream is = conn.getInputStream();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    String responseText = sb.toString();
                    if (responseText.contains("pingback.ping")) {
                        result.setPingback(true);
                    }
                    if (responseText.contains("system.multicall")) {
                        result.setMulticall(true);
                    }
                    result.setDetails("XML-RPC 200 OK: system.listMethods executed.");
                }
            } else if (code == 405) {
                result.setEnabled(true);
                result.setDetails("XML-RPC enabled (returned HTTP 405 Method Not Allowed).");
            } else if (code == 403) {
                result.setEnabled(false);
                result.setDetails("XML-RPC blocked (HTTP 403 Forbidden).");
            } else {
                result.setEnabled(false);
                result.setDetails("Inaccessible (HTTP " + code + ").");
            }
        } catch (Exception e) {
            result.setEnabled(false);
            result.setDetails("Connection error: " + e.getMessage());
        }

        return result;
    }
}
