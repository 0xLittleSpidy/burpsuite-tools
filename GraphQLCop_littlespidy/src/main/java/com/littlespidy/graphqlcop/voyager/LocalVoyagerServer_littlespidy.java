// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.voyager;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class LocalVoyagerServer_littlespidy {
    private HttpServer server;
    private int port = 8989;
    private volatile String currentSchemaJson = "{\"data\":{\"__schema\":{\"types\":[]}}}";

    public synchronized void start() {
        if (server != null) return;
        try {
            // Try 8989, fallback to port 0 (dynamic port)
            try {
                server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
            } catch (IOException e) {
                server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
                port = server.getAddress().getPort();
            }

            server.createContext("/", new RootHandler());
            server.createContext("/voyager.css", new ResourceHandler("/voyager/voyager.css", "text/css"));
            server.createContext("/voyager.standalone.js", new ResourceHandler("/voyager/voyager.standalone.js", "application/javascript"));
            server.createContext("/schema.json", new SchemaHandler());

            server.setExecutor(null);
            server.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public synchronized void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
    }

    public int getPort() {
        return port;
    }

    public void setSchemaJson(String schemaJson) {
        if (schemaJson != null && !schemaJson.trim().isEmpty()) {
            this.currentSchemaJson = schemaJson;
        }
    }

    public void openInBrowser() {
        start();
        String url = "http://127.0.0.1:" + port + "/";
        try {
            new ProcessBuilder("xdg-open", url).start();
        } catch (Exception e) {
            try {
                java.awt.Desktop.getDesktop().browse(java.net.URI.create(url));
            } catch (Exception ignored) {}
        }
    }

    private class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String html = "<!doctype html>\n" +
                    "<html>\n" +
                    "<head>\n" +
                    "  <meta charset=\"utf-8\" />\n" +
                    "  <title>GraphQL Voyager (Offline Localhost)</title>\n" +
                    "  <link rel=\"stylesheet\" href=\"/voyager.css\" />\n" +
                    "  <style>\n" +
                    "    body { height: 100vh; margin: 0; width: 100vw; overflow: hidden; background: #1e1e1e; font-family: sans-serif; }\n" +
                    "    #voyager { height: 100vh; width: 100vw; }\n" +
                    "    .header-bar { position: absolute; top: 8px; left: 16px; z-index: 100; color: #9cdcfe; font-weight: bold; font-size: 13px; }\n" +
                    "  </style>\n" +
                    "  <script src=\"/voyager.standalone.js\"></script>\n" +
                    "</head>\n" +
                    "<body>\n" +
                    "  <div class=\"header-bar\">GraphQL Voyager (Local Offline Instance - littlespidy)</div>\n" +
                    "  <div id=\"voyager\">Loading Schema...</div>\n" +
                    "  <script>\n" +
                    "    window.addEventListener('load', async () => {\n" +
                    "      try {\n" +
                    "        const resp = await fetch('/schema.json');\n" +
                    "        const json = await resp.json();\n" +
                    "        const introspection = json.data ? json.data : json;\n" +
                    "        GraphQLVoyager.renderVoyager(document.getElementById('voyager'), {\n" +
                    "          introspection: introspection\n" +
                    "        });\n" +
                    "      } catch (err) {\n" +
                    "        document.getElementById('voyager').innerHTML = '<div style=\"padding: 40px; color: #ff6b6b;\">Failed to render schema: ' + err + '</div>';\n" +
                    "      }\n" +
                    "    });\n" +
                    "  </script>\n" +
                    "</body>\n" +
                    "</html>";

            byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }

    private class SchemaHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            byte[] bytes = currentSchemaJson.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }

    private static class ResourceHandler implements HttpHandler {
        private final String resourcePath;
        private final String contentType;

        public ResourceHandler(String resourcePath, String contentType) {
            this.resourcePath = resourcePath;
            this.contentType = contentType;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
                if (is == null) {
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int read;
                while ((read = is.read(buf)) != -1) {
                    baos.write(buf, 0, read);
                }
                byte[] bytes = baos.toByteArray();
                exchange.getResponseHeaders().set("Content-Type", contentType);
                exchange.getResponseHeaders().set("Cache-Control", "public, max-age=3600");
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            }
        }
    }
}
