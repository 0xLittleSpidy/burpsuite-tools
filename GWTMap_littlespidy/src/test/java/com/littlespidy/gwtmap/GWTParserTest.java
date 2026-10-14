// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap;

import com.littlespidy.gwtmap.model.GWTDataStore;
import com.littlespidy.gwtmap.model.GWTMethod;
import com.littlespidy.gwtmap.model.GWTModuleInfo;
import com.littlespidy.gwtmap.model.GWTService;
import com.littlespidy.gwtmap.parser.GWTClassifier;
import com.littlespidy.gwtmap.parser.GWTCodeCleaner;
import com.littlespidy.gwtmap.parser.GWTParser;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class GWTParserTest {

    @Test
    public void testClassifier() {
        String bootstrapO = "function test(){ var x = \"bootstrap\"; var y = \"begin\"; }";
        assertEquals(GWTClassifier.CodeType.BOOTSTRAP_OBFUSCATED, GWTClassifier.classify(bootstrapO));

        String permO = "app.onScriptDownloaded(['4DE825BB25A8D7B3950D45A81EA7CD84']);";
        assertEquals(GWTClassifier.CodeType.PERMUTATION_OBFUSCATED, GWTClassifier.classify(permO));
    }

    @Test
    public void testCodeCleanerUnicodeDecodes() {
        String escaped = "function\\u0020hello() { return '\\u0041\\u0042\\u0043'; }";
        String decoded = GWTCodeCleaner.decodeUnicodeEscapes(escaped);
        assertTrue(decoded.contains("function hello()"));
        assertTrue(decoded.contains("'ABC'"));
    }

    @Test
    public void testExtractPermutations() {
        String sampleBootstrap = "var q='selectingPermutation', answers=['4DE825BB25A8D7B3950D45A81EA7CD84', 'C39AB19B83398A76A21E0CD04EC9B14C'];";
        List<String> lines = List.of(sampleBootstrap);
        List<String> perms = GWTParser.extractPermutations(lines, GWTClassifier.CodeType.BOOTSTRAP_OBFUSCATED);

        assertEquals(2, perms.size());
        assertTrue(perms.contains("4DE825BB25A8D7B3950D45A81EA7CD84"));
        assertTrue(perms.contains("C39AB19B83398A76A21E0CD04EC9B14C"));
    }

    @Test
    public void testExtractModuleInfo() {
        List<String> lines = List.of(
                "var $strongName = '4DE825BB25A8D7B3950D45A81EA7CD84';",
                "var $gwt_version = \"2.9.0\";",
                "flagVar = 0;",
                "_.k = 7;"
        );

        GWTModuleInfo info = new GWTModuleInfo();
        GWTParser.extractModuleInfo(lines, info);

        assertEquals("2.9.0", info.getGwtVersion());
        assertEquals("4DE825BB25A8D7B3950D45A81EA7CD84", info.getActivePermutation());
        assertEquals("7", info.getRpcVersion());
        assertEquals("0", info.getRpcFlags());
    }

    @Test
    public void testExtractServiceInfo() {
        List<String> lines = List.of(
                "svc = 'testService';",
                "hash = '67E3923F861223EE4967653A96E43846';",
                "func.call(this, inst(), svc, hash, handler);"
        );

        List<GWTService> services = GWTParser.extractServiceInfo(lines);
        assertEquals(1, services.size());
        assertEquals("testService", services.get(0).getServicePath());
        assertEquals("67E3923F861223EE4967653A96E43846", services.get(0).getStrongName());
    }

    @Test
    public void testDataStoreFiltering() {
        GWTDataStore ds = new GWTDataStore();
        GWTMethod m1 = new GWTMethod(1, "login", "AuthService_Proxy", "com.example.AuthService", "2", List.of("java.lang.String/2004016611", "java.lang.String/2004016611"));
        m1.setFullEndpointUrl("http://target.com/auth");
        m1.setMethodRpcCall("7|0|4|http://target.com/|HASH|com.example.AuthService|login|§param_user§|§param_pass§|");

        GWTMethod m2 = new GWTMethod(2, "getData", "DataService_Proxy", "com.example.DataService", "1", List.of("I"));
        m2.setFullEndpointUrl("http://target.com/data");
        m2.setMethodRpcCall("7|0|3|http://target.com/|HASH|com.example.DataService|getData|§10§|");

        ds.addMethod(m1);
        ds.addMethod(m2);

        // Filter by text
        List<GWTMethod> res = ds.getFilteredEntries("login", null, "All", Collections.emptySet(), null);
        assertEquals(1, res.size());
        assertEquals("login", res.get(0).getMethodName());

        // Filter by service category
        List<GWTMethod> resService = ds.getFilteredEntries("", Collections.singleton("AuthService"), "All", Collections.emptySet(), null);
        assertEquals(1, resService.size());
        assertEquals("AuthService", resService.get(0).getServiceCategory());
    }

    @Test
    public void testGwtLongCodecRoundtrip() {
        long[] testValues = {0L, 1L, 42L, 123456789L, Long.MAX_VALUE, -1L, -999999L, -Long.MAX_VALUE};
        for (long val : testValues) {
            String encoded = com.littlespidy.gwtmap.parser.GwtLongCodec.encode(val);
            assertNotNull(encoded);
            assertFalse(encoded.isEmpty());
            long decoded = com.littlespidy.gwtmap.parser.GwtLongCodec.decode(encoded);
            assertEquals(val, decoded, "Failed roundtrip for value: " + val);
        }
    }

    @Test
    public void testGwtLongCodecCustomGwtAlphabet() {
        // Test custom GWT '$' and '_' alphabet characters
        String encoded63 = com.littlespidy.gwtmap.parser.GwtLongCodec.encode(63);
        assertEquals("_", encoded63);
        assertEquals(63, com.littlespidy.gwtmap.parser.GwtLongCodec.decode("_"));

        String encoded62 = com.littlespidy.gwtmap.parser.GwtLongCodec.encode(62);
        assertEquals("$", encoded62);
        assertEquals(62, com.littlespidy.gwtmap.parser.GwtLongCodec.decode("$"));
    }

    @Test
    public void testRpcDeserializer() {
        // Standard GWT-RPC payload: 7|0|6|http://example.com/|STRONGHASH|com.example.Service|getUser|java.lang.String/2004016611|admin|1|2|3|4|1|5|6|
        String sampleRpc = "7|0|6|http://example.com/|STRONGHASH|com.example.Service|getUser|java.lang.String/2004016611|admin|1|2|3|4|1|5|6|";
        com.littlespidy.gwtmap.model.GWTRpcPayload payload = com.littlespidy.gwtmap.parser.GWTRpcDeserializer.deserialize(sampleRpc);

        assertEquals(7, payload.getStreamVersion());
        assertEquals(0, payload.getFlags());
        assertEquals("http://example.com/", payload.getBaseUrl());
        assertEquals("STRONGHASH", payload.getStrongName());
        assertEquals("com.example.Service", payload.getServiceInterface());
        assertEquals("getUser", payload.getMethodName());
        assertEquals(1, payload.getParameters().size());
        assertEquals("admin", payload.getParameters().get(0).getValues().get(0));

        // Test Arming with Intruder Section Markers
        String armed = com.littlespidy.gwtmap.parser.GWTRpcDeserializer.armWithIntruderMarkers(sampleRpc);
        assertTrue(armed.contains("§admin§"), "Armed payload must contain §admin§: " + armed);

        // Test Surround and Replace
        String surrounded = com.littlespidy.gwtmap.parser.GWTRpcDeserializer.surroundFuzzable(sampleRpc, "[[", "]]");
        assertTrue(surrounded.contains("[[admin]]"));

        String replaced = com.littlespidy.gwtmap.parser.GWTRpcDeserializer.replaceFuzzable(sampleRpc, "MUTATED");
        assertTrue(replaced.contains("MUTATED"));
    }

    @Test
    public void testRpcDeserializerWithXsrfFlag() {
        // Flag 2 = FLAG_RPC_TOKEN_INCLUDED
        String sampleXsrfRpc = "7|2|8|http://example.com/|STRONGHASH|XSRF_TOKEN|secret123|com.example.Service|doAction|java.lang.String/2004016611|data|1|2|3|4|5|6|1|7|8|";
        com.littlespidy.gwtmap.model.GWTRpcPayload payload = com.littlespidy.gwtmap.parser.GWTRpcDeserializer.deserialize(sampleXsrfRpc);

        assertEquals(7, payload.getStreamVersion());
        assertEquals(2, payload.getFlags());
        assertTrue(payload.hasXsrfToken());
        assertEquals("XSRF_TOKEN", payload.getXsrfTokenName());
        assertEquals("secret123", payload.getXsrfTokenValue());
        assertEquals("com.example.Service", payload.getServiceInterface());
        assertEquals("doAction", payload.getMethodName());
    }

    @Test
    public void testGwtFuzzerExceptionDetection() {
        String normalResp = "//OK[1,2,3]";
        assertFalse(com.littlespidy.gwtmap.engine.GWTFuzzerEngine.isGwtException(normalResp));

        String exResp = "//EX[2,1,[\"com.google.gwt.user.client.rpc.SerializationException/2004016611\",\"Invalid character\"],0,7]";
        assertTrue(com.littlespidy.gwtmap.engine.GWTFuzzerEngine.isGwtException(exResp));

        String errorAudit = com.littlespidy.gwtmap.engine.GWTFuzzerEngine.auditErrors(500, exResp);
        assertTrue(errorAudit.contains("GWT Exception"));
        assertTrue(errorAudit.contains("HTTP 500"));
    }

    @Test
    public void testPermutationExtractionFromUrl() {
        String testUrl = "http://example.com/app/4DE825BB25A8D7B3950D45A81EA7CD84.cache.js";
        int lastSlash = testUrl.lastIndexOf('/');
        String baseUrl = testUrl.substring(0, lastSlash + 1);
        String filename = testUrl.substring(lastSlash + 1);
        String forcedPerm = filename.replaceAll("\\.(cache|nocache)\\.(js|html)$", "");

        assertEquals("http://example.com/app/", baseUrl);
        assertEquals("4DE825BB25A8D7B3950D45A81EA7CD84", forcedPerm);
    }

    @Test
    public void testZeroEmojisInCodebase() throws Exception {
        java.nio.file.Path srcDir = java.nio.file.Paths.get("src");
        java.util.regex.Pattern emojiPattern = java.util.regex.Pattern.compile("[\\x{1F300}-\\x{1F9FF}\\x{2600}-\\x{26FF}\\x{2700}-\\x{27BF}]");

        try (java.util.stream.Stream<java.nio.file.Path> stream = java.nio.file.Files.walk(srcDir)) {
            List<java.nio.file.Path> javaFiles = stream.filter(p -> p.toString().endsWith(".java")).toList();
            for (java.nio.file.Path file : javaFiles) {
                String content = java.nio.file.Files.readString(file);
                java.util.regex.Matcher m = emojiPattern.matcher(content);
                assertFalse(m.find(), "Emoji detected in " + file.getFileName() + ": " + (m.hitEnd() ? "" : m.group()));
            }
        }
    }
}
