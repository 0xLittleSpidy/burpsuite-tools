// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.strategy;

import com.littlespidy.apiinspector.TestMockHelper_littlespidy;
import com.littlespidy.apiinspector.engine.BaselineDiffAnalyzer_littlespidy;
import com.littlespidy.apiinspector.model.ProbeMutation_littlespidy;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class StrategyMutationTest_littlespidy {

    @Test
    public void testUriPathReplacement() {
        UriPathStrategy_littlespidy strategy = new UriPathStrategy_littlespidy();
        HttpRequest base = TestMockHelper_littlespidy.createMockRequest("GET", "https://example.com/api/v1/users", "/api/v1/users", null, "");

        List<ProbeMutation_littlespidy> mutations = strategy.generateMutations(base, Arrays.asList("2", "3", "beta"));
        assertNotNull(mutations);
        assertFalse(mutations.isEmpty());

        boolean hasV2 = mutations.stream().anyMatch(m -> m.getRequest().path().contains("/api/v2/users"));
        boolean hasV3 = mutations.stream().anyMatch(m -> m.getRequest().path().contains("/api/v3/users"));
        boolean hasBeta = mutations.stream().anyMatch(m -> m.getRequest().path().contains("/api/vbeta/users") || m.getRequest().path().contains("/api/beta/users"));

        assertTrue(hasV2, "Expected mutation /api/v2/users");
        assertTrue(hasV3, "Expected mutation /api/v3/users");
        assertTrue(hasBeta, "Expected mutation with beta");
    }

    @Test
    public void testUriPathInsertion() {
        UriPathStrategy_littlespidy strategy = new UriPathStrategy_littlespidy();
        HttpRequest base = TestMockHelper_littlespidy.createMockRequest("GET", "https://example.com/api/users", "/api/users", null, "");

        List<ProbeMutation_littlespidy> mutations = strategy.generateMutations(base, Arrays.asList("1", "2"));
        assertNotNull(mutations);

        boolean hasV1 = mutations.stream().anyMatch(m -> m.getRequest().path().contains("/api/v1/users"));
        boolean hasV2 = mutations.stream().anyMatch(m -> m.getRequest().path().contains("/api/v2/users"));

        assertTrue(hasV1, "Expected mutation /api/v1/users");
        assertTrue(hasV2, "Expected mutation /api/v2/users");
    }

    @Test
    public void testHeaderMutations() {
        HeaderStrategy_littlespidy strategy = new HeaderStrategy_littlespidy();
        HttpRequest base = TestMockHelper_littlespidy.createMockRequest("GET", "https://example.com/api/users", "/api/users", null, "");

        List<ProbeMutation_littlespidy> mutations = strategy.generateMutations(base, Arrays.asList("2", "v3"));
        assertNotNull(mutations);
        assertFalse(mutations.isEmpty());

        boolean hasXApiVersion = mutations.stream().anyMatch(m -> "2".equals(m.getRequest().headerValue("X-API-Version")));
        boolean hasAcceptVersion = mutations.stream().anyMatch(m -> m.getRequest().hasHeader("Accept-Version"));

        assertTrue(hasXApiVersion, "Expected X-API-Version header mutation");
        assertTrue(hasAcceptVersion, "Expected Accept-Version header mutation");
    }

    @Test
    public void testQueryParamMutations() {
        QueryParamStrategy_littlespidy strategy = new QueryParamStrategy_littlespidy();
        HttpRequest base = TestMockHelper_littlespidy.createMockRequest("GET", "https://example.com/api/users", "/api/users", null, "");

        List<ProbeMutation_littlespidy> mutations = strategy.generateMutations(base, Arrays.asList("2"));
        assertNotNull(mutations);
        assertFalse(mutations.isEmpty());

        boolean hasVersionParam = mutations.stream().anyMatch(m -> m.getRequest().path().contains("version=2"));
        boolean hasVParam = mutations.stream().anyMatch(m -> m.getRequest().path().contains("v=2"));

        assertTrue(hasVersionParam, "Expected version=2 query parameter");
        assertTrue(hasVParam, "Expected v=2 query parameter");
    }

    @Test
    public void testContentNegotiationMutations() {
        ContentNegotiationStrategy_littlespidy strategy = new ContentNegotiationStrategy_littlespidy();
        HttpRequest base = TestMockHelper_littlespidy.createMockRequest("GET", "https://example.com/api/users", "/api/users", null, "");

        List<ProbeMutation_littlespidy> mutations = strategy.generateMutations(base, Arrays.asList("2"));
        assertNotNull(mutations);
        assertFalse(mutations.isEmpty());

        boolean hasJsonVersion = mutations.stream().anyMatch(m -> {
            String acc = m.getRequest().headerValue("Accept");
            return acc != null && acc.contains("version=2");
        });

        assertTrue(hasJsonVersion, "Expected Accept header with version=2");
    }

    @Test
    public void testBaselineDiffAnalysis() {
        HttpResponse baseResp = TestMockHelper_littlespidy.createMockResponse(200, Map.of("Content-Type", "application/json"), "{\"users\":[]}");
        HttpResponse sameResp = TestMockHelper_littlespidy.createMockResponse(200, Map.of("Content-Type", "application/json"), "{\"users\":[]}");
        HttpResponse diffResp = TestMockHelper_littlespidy.createMockResponse(200, Map.of("Content-Type", "application/json"), "{\"users\":[{\"id\":1}]}");
        HttpResponse notFoundResp = TestMockHelper_littlespidy.createMockResponse(404, null, "Not Found");
        HttpResponse deprecationResp = TestMockHelper_littlespidy.createMockResponse(400, null, "{\"error\":\"API version is deprecated\"}");

        assertEquals("SAME AS BASELINE", BaselineDiffAnalyzer_littlespidy.analyze(baseResp, sameResp));
        assertTrue(BaselineDiffAnalyzer_littlespidy.analyze(baseResp, diffResp).startsWith("ACTIVE ALTERNATIVE"));
        assertEquals("NOT FOUND (404)", BaselineDiffAnalyzer_littlespidy.analyze(baseResp, notFoundResp));
        assertTrue(BaselineDiffAnalyzer_littlespidy.analyze(baseResp, deprecationResp).contains("DEPRECATED"));

        // Status shift 404 -> 200
        HttpResponse base404 = TestMockHelper_littlespidy.createMockResponse(404, null, "Not Found");
        assertTrue(BaselineDiffAnalyzer_littlespidy.analyze(base404, diffResp).contains("STATUS SHIFT: 404 -> 200"));
    }
}
