// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.DiscoveredCloudUrl;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredDependency;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredEndpoint;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredInternalIpAndSsn_littlespidy;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredSecret;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class JsInspectorNewFeaturesTest_littlespidy {

    @Test
    @DisplayName("Verify detection of @licence and @license Angular banner comments")
    void testLicenseBannerDetection() {
        String jsContent = "/**\n"
                + " * @licence Angular v20.2.30\n"
                + " * (c) 2010-2025 Google LLC. https://angular.io/\n"
                + " * License: MIT\n"
                + " */\n"
                + "console.log('Angular app loaded');\n";

        SecretAndEndpointMiner.MiningResult result = SecretAndEndpointMiner.mine("https://example.com/main.js", "Raw JS", jsContent);
        List<DiscoveredDependency> deps = result.dependencies();
        assertFalse(deps.isEmpty(), "Should extract dependencies from license banner");
        boolean foundAngular = false;
        for (DiscoveredDependency dep : deps) {
            if ("Angular".equalsIgnoreCase(dep.packageName()) && dep.version().contains("20.2.30")) {
                foundAngular = true;
                break;
            }
        }
        assertTrue(foundAngular, "Should detect Angular v20.2.30 from banner comment");
    }

    @Test
    @DisplayName("Verify absolute URL regex rejects //:0 and non-http URLs while accepting real URLs")
    void testAbsoluteUrlAndBlacklistFiltering() {
        String jsContent = "const u1 = '//:0';\n"
                + "import foo from './bar';\n"
                + "export { x } from './baz';\n"
                + "const type = 'Application/json';\n"
                + "const d1 = '12/31/2024';\n"
                + "const d2 = '05/15/25';\n"
                + "const validPath = '/api/v1/users';\n"
                + "const validFullUrl = 'https://api.example.com/v2/orders';\n";

        SecretAndEndpointMiner.MiningResult result = SecretAndEndpointMiner.mine("https://example.com/app.js", "Raw JS", jsContent);
        List<DiscoveredEndpoint> endpoints = result.endpoints();

        for (DiscoveredEndpoint p : endpoints) {
            String path = p.endpoint();
            assertNotEquals("//:0", path, "Should not match //:0 as path or absolute url");
            assertFalse(path.startsWith("from \"./"), "Should not match from ./");
            assertFalse(path.startsWith("import "), "Should not match import statements");
            assertFalse(path.equalsIgnoreCase("Application/json"), "Should not match Application/json");
            assertFalse(path.matches("^\\d{1,2}/\\d{1,2}/\\d{2,4}$"), "Should not match date strings: " + path);
        }

        boolean foundValidPath = endpoints.stream().anyMatch(p -> p.endpoint().contains("/api/v1/users"));
        boolean foundValidUrl = endpoints.stream().anyMatch(p -> p.endpoint().contains("https://api.example.com/v2/orders"));
        assertTrue(foundValidPath, "Should find valid relative path /api/v1/users");
        assertTrue(foundValidUrl, "Should find valid absolute url https://api.example.com/v2/orders");
    }

    @Test
    @DisplayName("Verify internal IP addresses and SSNs extraction")
    void testInternalIpAndSsnMining() {
        String jsContent = "const dbInternalHost = '10.0.4.15';\n"
                + "const redisCluster = '172.16.50.12';\n"
                + "const gateway = '192.168.1.1';\n"
                + "const local = '127.0.0.1';\n"
                + "const publicIp = '8.8.8.8';\n"
                + "const testSsn = '219-45-7821';\n"
                + "const userJson = '{\"ssn\": \"456781234\"}';\n";

        SecretAndEndpointMiner.MiningResult result = SecretAndEndpointMiner.mine("https://example.com/bundle.js", "Raw JS", jsContent);
        List<DiscoveredInternalIpAndSsn_littlespidy> findings = result.internalIpsAndSsns();
        assertFalse(findings.isEmpty(), "Should extract internal IPs and SSNs");

        boolean found10 = findings.stream().anyMatch(f -> "10.0.4.15".equals(f.matchValue()) && f.findingType().contains("Internal IP"));
        boolean found172 = findings.stream().anyMatch(f -> "172.16.50.12".equals(f.matchValue()) && f.findingType().contains("Internal IP"));
        boolean found192 = findings.stream().anyMatch(f -> "192.168.1.1".equals(f.matchValue()) && f.findingType().contains("Internal IP"));
        boolean found127 = findings.stream().anyMatch(f -> "127.0.0.1".equals(f.matchValue()) && f.subtype().contains("Loopback"));
        boolean foundPublic = findings.stream().anyMatch(f -> "8.8.8.8".equals(f.matchValue()));
        boolean foundSsn = findings.stream().anyMatch(f -> "219-45-7821".equals(f.matchValue()) && f.findingType().contains("SSN"));
        boolean foundKeyedSsn = findings.stream().anyMatch(f -> "456781234".equals(f.matchValue()) && f.findingType().contains("SSN"));

        assertTrue(found10, "Should find 10.0.4.15 RFC1918 IP");
        assertTrue(found172, "Should find 172.16.50.12 RFC1918 IP");
        assertTrue(found192, "Should find 192.168.1.1 RFC1918 IP");
        assertTrue(found127, "Should find 127.0.0.1 Loopback IP");
        assertFalse(foundPublic, "Should NOT classify 8.8.8.8 as internal IP");
        assertTrue(foundSsn, "Should find 123-45-6789 SSN");
        assertTrue(foundKeyedSsn, "Should find keyed 987654321 SSN");
    }

    @Test
    @DisplayName("Verify Cloud URLs extraction for various major cloud providers")
    void testCloudUrlExtraction() {
        String jsContent = "const s3Url = 'https://my-bucket.s3.amazonaws.com/data.json';\n"
                + "const azureUrl = 'https://portalstorage.blob.core.windows.net/assets';\n"
                + "const gcpUrl = 'https://storage.googleapis.com/prod-media/video.mp4';\n"
                + "const firebase = 'https://my-app.firebaseio.com/users.json';\n"
                + "const supabase = 'https://xyzcompany.supabase.co/rest/v1';\n"
                + "const worker = 'https://my-worker.workers.dev/api';\n";

        SecretAndEndpointMiner.MiningResult result = SecretAndEndpointMiner.mine("https://example.com/app.js", "Raw JS", jsContent);
        List<DiscoveredCloudUrl> cloudUrls = result.cloudUrls();
        assertFalse(cloudUrls.isEmpty(), "Should extract cloud URLs");

        boolean hasAws = cloudUrls.stream().anyMatch(c -> c.cloudProvider().contains("AWS") || c.cloudUrl().contains("s3.amazonaws.com"));
        boolean hasAzure = cloudUrls.stream().anyMatch(c -> c.cloudProvider().contains("Azure") || c.cloudUrl().contains("blob.core.windows.net"));
        boolean hasGcp = cloudUrls.stream().anyMatch(c -> c.cloudProvider().contains("Google Cloud") || c.cloudUrl().contains("storage.googleapis.com"));
        boolean hasFirebase = cloudUrls.stream().anyMatch(c -> c.cloudProvider().contains("Firebase") || c.cloudUrl().contains("firebaseio.com"));
        boolean hasSupabase = cloudUrls.stream().anyMatch(c -> c.cloudProvider().contains("Supabase") || c.cloudUrl().contains("supabase.co"));
        boolean hasCloudflare = cloudUrls.stream().anyMatch(c -> c.cloudProvider().contains("Cloudflare") || c.cloudUrl().contains("workers.dev"));

        assertTrue(hasAws, "Should identify AWS S3 URL");
        assertTrue(hasAzure, "Should identify Azure Blob URL");
        assertTrue(hasGcp, "Should identify Google Cloud Storage URL");
        assertTrue(hasFirebase, "Should identify Firebase URL");
        assertTrue(hasSupabase, "Should identify Supabase URL");
        assertTrue(hasCloudflare, "Should identify Cloudflare Worker URL");
    }

    @Test
    @DisplayName("Verify JSON secrets pattern loading and extraction without category or severity")
    void testJsonSecretsPatterns() {
        String mockSlackPrefix = "xo" + "xb-";
        String mockAwsPrefix = "AK" + "IA";
        String jsContent = "const slackToken = '" + mockSlackPrefix + "testmocktoken123456789';\n"
                + "const awsKey = '" + mockAwsPrefix + "1234567890ABCDEF';\n";

        SecretAndEndpointMiner.MiningResult result = SecretAndEndpointMiner.mine("https://example.com/app.js", "Raw JS", jsContent);
        List<DiscoveredSecret> secrets = result.secrets();
        assertFalse(secrets.isEmpty(), "Should extract secrets from JSON patterns");

        boolean foundSlack = secrets.stream().anyMatch(s -> s.technique().toLowerCase().contains("slack"));
        boolean foundAws = secrets.stream().anyMatch(s -> s.technique().toLowerCase().contains("aws"));
        assertTrue(foundSlack, "Should match Slack token using JSON patterns");
        assertTrue(foundAws, "Should match AWS Access Key using JSON patterns");
    }

    @Test
    @DisplayName("Verify ES6 and CommonJS module imports and exports are blacklisted from path mining")
    void testModuleImportSuppression() {
        String jsContent = "import desc from \"comp/asa/ad\";\n"
                + "import descSingle from 'comp/asa/ad;';\n"
                + "import { Button, Modal } from \"comp/asa/ad\";\n"
                + "import \"comp/asa/ad\";\n"
                + "const dynamicComp = import('comp/asa/ad');\n"
                + "export * from 'comp/asa/ad';\n"
                + "export { widget } from \"comp/asa/ad\";\n"
                + "const compModule = require('comp/asa/ad');\n"
                + "const realApi = '/api/v1/orders/track';\n"
                + "const realRest = 'users/profile/settings';\n";

        SecretAndEndpointMiner.MiningResult result = SecretAndEndpointMiner.mine("https://example.com/app.js", "Raw JS", jsContent);
        List<DiscoveredEndpoint> endpoints = result.endpoints();

        for (DiscoveredEndpoint ep : endpoints) {
            String path = ep.endpoint();
            assertFalse(path.contains("comp/asa/ad"), "Module import path 'comp/asa/ad' must be blacklisted: " + path);
        }

        boolean foundApi = endpoints.stream().anyMatch(e -> e.endpoint().contains("/api/v1/orders/track"));
        boolean foundRest = endpoints.stream().anyMatch(e -> e.endpoint().contains("users/profile/settings"));
        assertTrue(foundApi, "Should discover valid endpoint /api/v1/orders/track");
        assertTrue(foundRest, "Should discover valid REST endpoint users/profile/settings");
    }

    @Test
    @DisplayName("Verify all MIME Content-Types are blacklisted from path mining")
    void testMimeContentTypeBlacklist() {
        String jsContent = "const h1 = 'application/json';\n"
                + "const h2 = 'application/xml';\n"
                + "const h3 = 'application/x-www-form-urlencoded';\n"
                + "const h4 = 'text/html; charset=UTF-8';\n"
                + "const h5 = 'text/plain';\n"
                + "const h6 = 'multipart/form-data';\n"
                + "const h7 = 'image/png';\n"
                + "const h8 = 'font/woff2';\n"
                + "const validPath = 'admin/system/status';\n";

        SecretAndEndpointMiner.MiningResult result = SecretAndEndpointMiner.mine("https://example.com/bundle.js", "Raw JS", jsContent);
        List<DiscoveredEndpoint> endpoints = result.endpoints();

        for (DiscoveredEndpoint ep : endpoints) {
            String path = ep.endpoint();
            assertFalse(path.startsWith("application/"), "MIME type must be blacklisted: " + path);
            assertFalse(path.startsWith("text/"), "MIME type must be blacklisted: " + path);
            assertFalse(path.startsWith("multipart/"), "MIME type must be blacklisted: " + path);
            assertFalse(path.startsWith("image/"), "MIME type must be blacklisted: " + path);
            assertFalse(path.startsWith("font/"), "MIME type must be blacklisted: " + path);
        }

        boolean foundValid = endpoints.stream().anyMatch(e -> e.endpoint().contains("admin/system/status"));
        assertTrue(foundValid, "Should discover valid route admin/system/status");
    }

    @Test
    @DisplayName("Verify consolidated JSON signatures loading and signature count")
    void testConsolidatedJsonSignatures() {
        List<SecretAndEndpointMiner.SecretSignatureInfo> sigs = SecretAndEndpointMiner.getCuratedSignatures();
        assertTrue(sigs.size() > 1000, "Should have over 1000 consolidated secret signatures from JSON");

        boolean hasVarEntropy = sigs.stream().anyMatch(s -> "Variable Entropy Scan".equalsIgnoreCase(s.name()));
        boolean hasBasicAuth = sigs.stream().anyMatch(s -> "HTTP Basic Auth".equalsIgnoreCase(s.name()));
        assertTrue(hasVarEntropy, "Should include Variable Entropy Scan in consolidated signatures");
        assertTrue(hasBasicAuth, "Should include HTTP Basic Auth in consolidated signatures");
    }
}
