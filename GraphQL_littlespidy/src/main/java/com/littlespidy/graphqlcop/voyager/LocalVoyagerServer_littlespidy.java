// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.voyager;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LocalVoyagerServer_littlespidy {
    private ServerSocket serverSocket;
    private int port = 8989;
    private volatile boolean running = false;
    private volatile String currentSchemaJson = "{\"data\":{\"__schema\":{\"types\":[]}}}";
    private ExecutorService workerPool;
    private Thread acceptThread;

    public synchronized void start() {
        if (running && serverSocket != null && !serverSocket.isClosed()) {
            return;
        }

        try {
            // Bind to 127.0.0.1 on port 8989, or fallback to ephemeral port 0 if busy
            try {
                serverSocket = new ServerSocket(port, 50, InetAddress.getByName("127.0.0.1"));
            } catch (IOException e) {
                serverSocket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
                port = serverSocket.getLocalPort();
            }

            running = true;
            workerPool = Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "VoyagerClientWorker-littlespidy");
                t.setDaemon(true);
                return t;
            });

            acceptThread = new Thread(this::acceptLoop, "VoyagerAcceptor-littlespidy");
            acceptThread.setDaemon(true);
            acceptThread.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void acceptLoop() {
        while (running && serverSocket != null && !serverSocket.isClosed()) {
            try {
                Socket clientSocket = serverSocket.accept();
                workerPool.submit(() -> handleClient(clientSocket));
            } catch (IOException e) {
                if (!running) {
                    break;
                }
            }
        }
    }

    private void handleClient(Socket socket) {
        try (socket;
             InputStream in = socket.getInputStream();
             OutputStream out = socket.getOutputStream()) {

            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String requestLine = reader.readLine();
            if (requestLine == null || requestLine.isEmpty()) {
                return;
            }

            // Drain headers
            String header;
            while ((header = reader.readLine()) != null && !header.isEmpty()) {
                // Ignore headers
            }

            String[] parts = requestLine.split(" ");
            if (parts.length < 2 || !"GET".equalsIgnoreCase(parts[0])) {
                sendResponse(out, 405, "Method Not Allowed", "text/plain", "Method Not Allowed".getBytes(StandardCharsets.UTF_8), false);
                return;
            }

            String path = parts[1];
            int queryIdx = path.indexOf('?');
            if (queryIdx >= 0) {
                path = path.substring(0, queryIdx);
            }

            if ("/".equals(path) || "/index.html".equals(path)) {
                byte[] html = buildVoyagerHtml().getBytes(StandardCharsets.UTF_8);
                sendResponse(out, 200, "OK", "text/html; charset=UTF-8", html, false);
            } else if ("/schema.json".equals(path)) {
                byte[] schema = currentSchemaJson.getBytes(StandardCharsets.UTF_8);
                sendResponse(out, 200, "OK", "application/json; charset=UTF-8", schema, true);
            } else if ("/voyager.css".equals(path)) {
                byte[] css = loadResourceBytes("/voyager/voyager.css");
                if (css != null) {
                    sendResponse(out, 200, "OK", "text/css; charset=UTF-8", css, false);
                } else {
                    send404(out);
                }
            } else if ("/voyager.standalone.js".equals(path)) {
                byte[] js = loadResourceBytes("/voyager/voyager.standalone.js");
                if (js != null) {
                    sendResponse(out, 200, "OK", "application/javascript; charset=UTF-8", js, false);
                } else {
                    send404(out);
                }
            } else {
                send404(out);
            }
        } catch (Exception ignored) {}
    }

    private void sendResponse(OutputStream out, int statusCode, String statusText,
                              String contentType, byte[] body, boolean cors) throws IOException {
        PrintWriter pw = new PrintWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
        pw.print("HTTP/1.1 " + statusCode + " " + statusText + "\r\n");
        pw.print("Content-Type: " + contentType + "\r\n");
        pw.print("Content-Length: " + body.length + "\r\n");
        pw.print("Connection: close\r\n");
        if (cors) {
            pw.print("Access-Control-Allow-Origin: *\r\n");
        }
        pw.print("\r\n");
        pw.flush();
        out.write(body);
        out.flush();
    }

    private void send404(OutputStream out) throws IOException {
        byte[] body = "404 Not Found".getBytes(StandardCharsets.UTF_8);
        sendResponse(out, 404, "Not Found", "text/plain", body, false);
    }

    private byte[] loadResourceBytes(String resourcePath) {
        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            if (is == null) return null;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int read;
            while ((read = is.read(buf)) != -1) {
                baos.write(buf, 0, read);
            }
            return baos.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private String buildVoyagerHtml() {
        return "<!doctype html>\n" +
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
    }

    public synchronized void stop() {
        running = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (Exception ignored) {}

        if (workerPool != null) {
            workerPool.shutdownNow();
        }
        serverSocket = null;
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
}
