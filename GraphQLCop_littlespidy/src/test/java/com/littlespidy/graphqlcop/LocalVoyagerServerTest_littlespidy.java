// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop;

import com.littlespidy.graphqlcop.voyager.LocalVoyagerServer_littlespidy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class LocalVoyagerServerTest_littlespidy {
    private LocalVoyagerServer_littlespidy server;

    @BeforeEach
    public void setUp() {
        server = new LocalVoyagerServer_littlespidy();
        server.start();
    }

    @AfterEach
    public void tearDown() {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    public void testRootEndpoint() throws Exception {
        int port = server.getPort();
        URL url = URI.create("http://127.0.0.1:" + port + "/").toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);

        int code = conn.getResponseCode();
        assertEquals(200, code);
        assertTrue(conn.getContentType().contains("text/html"));

        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
        }
        assertTrue(sb.toString().contains("GraphQL Voyager"));
    }

    @Test
    public void testSchemaEndpoint() throws Exception {
        int port = server.getPort();
        server.setSchemaJson("{\"data\":{\"testKey\":\"testValue\"}}");

        URL url = URI.create("http://127.0.0.1:" + port + "/schema.json").toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);

        int code = conn.getResponseCode();
        assertEquals(200, code);
        assertTrue(conn.getContentType().contains("application/json"));
        assertEquals("*", conn.getHeaderField("Access-Control-Allow-Origin"));
    }

    @Test
    public void testCssEndpoint() throws Exception {
        int port = server.getPort();
        URL url = URI.create("http://127.0.0.1:" + port + "/voyager.css").toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);

        int code = conn.getResponseCode();
        assertEquals(200, code);
        assertTrue(conn.getContentType().contains("text/css"));
    }

    @Test
    public void testJsEndpoint() throws Exception {
        int port = server.getPort();
        URL url = URI.create("http://127.0.0.1:" + port + "/voyager.standalone.js").toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);

        int code = conn.getResponseCode();
        assertEquals(200, code);
        assertTrue(conn.getContentType().contains("application/javascript"));
    }
}
