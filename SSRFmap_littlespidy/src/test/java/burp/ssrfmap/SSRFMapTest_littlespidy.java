// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap;

import burp.ssrfmap.engine.DiffAnalyzer_littlespidy;
import burp.ssrfmap.engine.HttpRequestNormalizer_littlespidy;
import burp.ssrfmap.modules.SSRFPayloadItem_littlespidy;
import burp.ssrfmap.modules.SSRFPayloadManager_littlespidy;
import burp.ssrfmap.ui.MarkerRequestEditor_littlespidy;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SSRFMapTest_littlespidy {

    @Test
    public void testMarkerExtractionAndReplacement() {
        MarkerRequestEditor_littlespidy editor = new MarkerRequestEditor_littlespidy();
        String sampleRequest = "POST /api/v1/import HTTP/1.1\r\n"
                + "Host: example.corp\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                + "target=§https://allowed.internal/file.json§&format=json";

        editor.setRequestText(sampleRequest);

        Assertions.assertTrue(editor.hasMarker());
        Assertions.assertEquals("https://allowed.internal/file.json", editor.getMarkedParameterValue());

        String modified = editor.buildRequestWithPayload("file:///etc/passwd");
        Assertions.assertTrue(modified.contains("target=file:///etc/passwd&format=json"));
        Assertions.assertFalse(modified.contains("§"));

        String baseline = editor.getCleanBaselineRequest();
        Assertions.assertTrue(baseline.contains("target=https://allowed.internal/file.json&format=json"));
        Assertions.assertFalse(baseline.contains("§"));
    }

    @Test
    public void testHttpRequestNormalizerCRLFAndContentLength() {
        String rawWithLfAndOldLength = "POST /submit HTTP/1.1\n"
                + "Host: example.com\n"
                + "Content-Type: application/x-www-form-urlencoded\n"
                + "Content-Length: 10\n\n"
                + "param=very_long_payload_replacement_value_that_is_much_longer";

        String reqString = HttpRequestNormalizer_littlespidy.normalizeRequestText(rawWithLfAndOldLength);

        // Must contain CRLF
        Assertions.assertTrue(reqString.contains("\r\n"), "Request must contain CRLF line endings");
        Assertions.assertFalse(reqString.contains("\n\n"), "Headers must be separated with CRLF CRLF, not bare LF LF");

        // Content-Length must be recalculated to match new body length
        byte[] bodyBytes = "param=very_long_payload_replacement_value_that_is_much_longer".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Assertions.assertTrue(reqString.contains("Content-Length: " + bodyBytes.length),
                "Content-Length must be recalculated to " + bodyBytes.length);
    }

    @Test
    public void testDiffAnalyzerDetection() {
        String baselineBody = "{\"status\": \"ok\", \"content\": \"hello world\"}";
        int baselineStatus = 200;

        String vulnBody = "{\"status\": \"ok\", \"content\": \"root:x:0:0:root:/root:/bin/bash\"}";
        int vulnStatus = 200;

        DiffAnalyzer_littlespidy.AnalysisResult result = DiffAnalyzer_littlespidy.analyze(
                baselineBody,
                baselineStatus,
                vulnBody,
                vulnStatus,
                Arrays.asList("root:x:0:0:", "daemon:")
        );

        Assertions.assertTrue(result.isSignificantDiff());
        Assertions.assertFalse(result.getMatchedIndicators().isEmpty());
        Assertions.assertEquals("root:x:0:0:", result.getMatchedIndicators().get(0));
    }

    @Test
    public void testJsonPayloadManagerLoadsProtocolsIncludingHttpAndHttps() {
        SSRFPayloadManager_littlespidy manager = SSRFPayloadManager_littlespidy.getInstance();
        List<SSRFPayloadItem_littlespidy> protocolPayloads = manager.getAllProtocolPayloads();

        Assertions.assertFalse(protocolPayloads.isEmpty());

        boolean hasHttp = protocolPayloads.stream().anyMatch(p -> p.getModuleName().equalsIgnoreCase("http"));
        boolean hasHttps = protocolPayloads.stream().anyMatch(p -> p.getModuleName().equalsIgnoreCase("https"));
        boolean hasFile = protocolPayloads.stream().anyMatch(p -> p.getModuleName().equalsIgnoreCase("file"));
        boolean hasGopher = protocolPayloads.stream().anyMatch(p -> p.getModuleName().equalsIgnoreCase("gopher"));

        Assertions.assertTrue(hasHttp, "Protocol suite must include http:// payloads");
        Assertions.assertTrue(hasHttps, "Protocol suite must include https:// payloads");
        Assertions.assertTrue(hasFile, "Protocol suite must include file:// payloads");
        Assertions.assertTrue(hasGopher, "Protocol suite must include gopher:// payloads");
    }

    @Test
    public void testJsonPayloadManagerLoadsCloudMetadataUserUrls() {
        SSRFPayloadManager_littlespidy manager = SSRFPayloadManager_littlespidy.getInstance();
        List<SSRFPayloadItem_littlespidy> awsPayloads = manager.getCloudPayloads("aws");
        List<SSRFPayloadItem_littlespidy> gcpPayloads = manager.getCloudPayloads("gcp");
        List<SSRFPayloadItem_littlespidy> azurePayloads = manager.getCloudPayloads("azure");

        Assertions.assertTrue(awsPayloads.size() >= 16, "AWS must have at least 16 payloads");
        Assertions.assertTrue(gcpPayloads.size() >= 6, "GCP must have at least 6 payloads");
        Assertions.assertTrue(azurePayloads.size() >= 3, "Azure must have at least 3 payloads");

        Assertions.assertTrue(awsPayloads.stream().anyMatch(p -> p.getPayloadTemplate().equals("http://instance-data")));
        Assertions.assertTrue(awsPayloads.stream().anyMatch(p -> p.getPayloadTemplate().contains("dynamic/instance-identity/document")));
        Assertions.assertTrue(gcpPayloads.stream().anyMatch(p -> p.getPayloadTemplate().contains("metadata.google.internal")));
        Assertions.assertTrue(azurePayloads.stream().anyMatch(p -> p.getPayloadTemplate().contains("api-version=2017-04-02")));
    }
}
