// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap;

import burp.ssrfmap.engine.DiffAnalyzer_littlespidy;
import burp.ssrfmap.modules.CloudMetadataModules_littlespidy;
import burp.ssrfmap.modules.ProtocolModules_littlespidy;
import burp.ssrfmap.modules.SSRFPayloadItem_littlespidy;
import burp.ssrfmap.modules.ServiceExploitModules_littlespidy;
import burp.ssrfmap.ui.MarkerRequestEditor_littlespidy;
import java.util.Arrays;
import java.util.Collections;
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
        Assertions.assertTrue(result.getLineDiff().contains("root:x:0:0:"));
    }

    @Test
    public void testAllSevenProtocolsPresent() {
        String[] requiredProtocols = {"file", "dict", "sftp", "tftp", "ldap", "smtp", "gopher"};
        for (String proto : requiredProtocols) {
            List<SSRFPayloadItem_littlespidy> payloads = ProtocolModules_littlespidy.getPayloads(proto);
            Assertions.assertFalse(payloads.isEmpty(), "Protocol payloads missing for: " + proto);
            for (SSRFPayloadItem_littlespidy item : payloads) {
                Assertions.assertNotNull(item.getPayloadTemplate());
                Assertions.assertEquals(proto, item.getModuleName());
            }
        }
    }

    @Test
    public void testCloudAndServiceModulesPresent() {
        List<SSRFPayloadItem_littlespidy> cloudPayloads = CloudMetadataModules_littlespidy.getAllCloudPayloads();
        Assertions.assertFalse(cloudPayloads.isEmpty());

        List<SSRFPayloadItem_littlespidy> servicePayloads = ServiceExploitModules_littlespidy.getAllServicePayloads();
        Assertions.assertFalse(servicePayloads.isEmpty());
    }
}
