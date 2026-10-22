// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;
import com.littlespidy.sqlmapanalyzer.runner.ScanRequestSession;
import com.littlespidy.sqlmapanalyzer.ui.runner.RequestConfigPanel;
import com.littlespidy.sqlmapanalyzer.ui.runner.RequestScanTabPanel;
import com.littlespidy.sqlmapanalyzer.util.OSUtils;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class TimeSecAndUrlResolutionTest_littlespidy {

    private HttpService createMockService(String host, int port, boolean secure) {
        return (HttpService) Proxy.newProxyInstance(
                HttpService.class.getClassLoader(),
                new Class<?>[]{HttpService.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("host".equals(name)) return host;
                    if ("port".equals(name)) return port;
                    if ("secure".equals(name)) return secure;
                    if ("ipAddress".equals(name)) return "127.0.0.1";
                    return null;
                }
        );
    }

    private HttpRequest createMockRequest(HttpService service, String url, String path, String hostHeader, byte[] rawBytes) {
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("httpService".equals(name)) return service;
                    if ("url".equals(name)) return url;
                    if ("path".equals(name)) return path;
                    if ("headerValue".equals(name) && args != null && args.length > 0 && "Host".equalsIgnoreCase((String) args[0])) {
                        return hostHeader;
                    }
                    if ("toByteArray".equals(name)) return null;
                    if ("toString".equals(name)) return "MockHttpRequest";
                    return null;
                }
        );
    }

    @Test
    public void testResolveFullUrlFromRawRequest() {
        byte[] rawHttp = ("GET /api/v1/search?q=test HTTP/1.1\r\n" +
                "Host: api.target.local\r\n" +
                "User-Agent: Burp\r\n\r\n").getBytes(StandardCharsets.UTF_8);

        String resolvedHttp = OSUtils.resolveFullUrlFromRaw(rawHttp, null);
        assertEquals("http://api.target.local/api/v1/search?q=test", resolvedHttp);

        byte[] rawHttps = ("POST /login HTTP/1.1\r\n" +
                "Host: secure.target.local:443\r\n" +
                "Content-Type: application/json\r\n\r\n{}").getBytes(StandardCharsets.UTF_8);

        String resolvedHttps = OSUtils.resolveFullUrlFromRaw(rawHttps, null);
        assertEquals("https://secure.target.local:443/login", resolvedHttps);
    }

    @Test
    public void testResolveFullUrlFromHostHeaderWithoutService() {
        HttpRequest req = createMockRequest(null, "/api/v1/search?q=test", "/api/v1/search?q=test", "api.target.local", null);
        String resolved = OSUtils.resolveFullUrl(req, null);
        assertEquals("http://api.target.local/api/v1/search?q=test", resolved);
    }

    @Test
    public void testResolveFullUrlWithHttpServiceCustomPort() {
        HttpService service = createMockService("service.target.local", 8080, false);
        HttpRequest req = createMockRequest(service, "/products/123", "/products/123", "ignored.host", null);

        String resolved = OSUtils.resolveFullUrl(req, null);
        assertEquals("http://service.target.local:8080/products/123", resolved);
    }

    @Test
    public void testResolveFullUrlWithHttpsHttpServiceStandardPort() {
        HttpService service = createMockService("secure.company.org", 443, true);
        HttpRequest req = createMockRequest(service, "/dashboard", "/dashboard", "secure.company.org", null);

        String resolved = OSUtils.resolveFullUrl(req, null);
        assertEquals("https://secure.company.org/dashboard", resolved);
    }

    @Test
    public void testTimeSecDefaultAndCustomCliCommand() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://target.local/vuln.php?id=1");

        // Default timeSec is 5
        assertEquals(5, options.getTimeSec());
        String defaultCli = options.buildCommandLine();
        assertTrue(defaultCli.contains("--time-sec=5"));

        // Custom timeSec set to 10
        options.setTimeSec(10);
        assertEquals(10, options.getTimeSec());
        String customCli = options.buildCommandLine();
        assertTrue(customCli.contains("--time-sec=10"));

        Map<String, Object> map = options.toOptionMap();
        assertEquals(10, map.get("timeSec"));
    }

    @Test
    public void testTimeSecUIConfigPanel() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://target.local/timebased?id=5");
        options.setTimeSec(5);

        byte[] raw = "GET /timebased?id=5 HTTP/1.1\r\nHost: target.local\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        ScanRequestSession session = new ScanRequestSession(1, "GET", "http://target.local/timebased?id=5", raw, options);

        RequestScanTabPanel tabPanel = new RequestScanTabPanel(null, session, null);
        RequestConfigPanel configPanel = tabPanel.getConfigPanelForTest();
        assertNotNull(configPanel);
        assertNotNull(configPanel.getTxtTimeSecForTest());

        // Verify default loaded value
        assertEquals("5", configPanel.getTxtTimeSecForTest().getText().trim());

        // Update value in UI
        configPanel.getTxtTimeSecForTest().setText("12");
        SqlmapTaskOptions updatedOpts = configPanel.applyUiToOptions();

        assertEquals(12, updatedOpts.getTimeSec());
        assertTrue(updatedOpts.buildCommandLine().contains("--time-sec=12"));
        assertEquals(12, updatedOpts.toOptionMap().get("timeSec"));
    }

    @Test
    public void testForceSslOptionAndCliCommand() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://target.local/vuln.php?id=1");
        // forceSsl is true by default
        assertTrue(options.isForceSsl());

        String cli = options.buildCommandLine();
        assertTrue(cli.contains("-u \"https://target.local/vuln.php?id=1\""));
        assertTrue(cli.contains("--force-ssl"));

        Map<String, Object> map = options.toOptionMap();
        assertEquals("true", map.get("forceSSL"));

        // Disable forceSsl
        options.setForceSsl(false);
        assertFalse(options.isForceSsl());
        String cliDisabled = options.buildCommandLine();
        assertTrue(cliDisabled.contains("-u \"http://target.local/vuln.php?id=1\""));
        assertFalse(cliDisabled.contains("--force-ssl"));
    }

    @Test
    public void testTimelessNoCastHexOptions() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("https://target.local/vuln.php?id=1");

        // Defaults are false
        assertFalse(options.isTimeless());
        assertFalse(options.isNoCast());
        assertFalse(options.isHexConvert());

        options.setTimeless(true);
        options.setNoCast(true);
        options.setHexConvert(true);

        assertTrue(options.isTimeless());
        assertTrue(options.isNoCast());
        assertTrue(options.isHexConvert());

        String cli = options.buildCommandLine();
        assertTrue(cli.contains("--timeless"));
        assertTrue(cli.contains("--no-cast"));
        assertTrue(cli.contains("--hex"));

        Map<String, Object> map = options.toOptionMap();
        assertEquals("true", map.get("timeLess"));
        assertEquals("true", map.get("noCast"));
        assertEquals("true", map.get("hexConvert"));
    }

    @Test
    public void testTimelessNoCastHexUIConfigPanel() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("https://target.local/test");
        options.setTimeless(false);
        options.setNoCast(false);
        options.setHexConvert(false);

        byte[] raw = "GET /test HTTP/1.1\r\nHost: target.local\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        ScanRequestSession session = new ScanRequestSession(4, "GET", "https://target.local/test", raw, options);

        RequestScanTabPanel tabPanel = new RequestScanTabPanel(null, session, null);
        RequestConfigPanel configPanel = tabPanel.getConfigPanelForTest();
        assertNotNull(configPanel);
        assertNotNull(configPanel.getChkTimelessForTest());
        assertNotNull(configPanel.getChkNoCastForTest());
        assertNotNull(configPanel.getChkHexForTest());

        assertFalse(configPanel.getChkTimelessForTest().isSelected());
        assertFalse(configPanel.getChkNoCastForTest().isSelected());
        assertFalse(configPanel.getChkHexForTest().isSelected());

        // Check options in UI
        configPanel.getChkTimelessForTest().setSelected(true);
        configPanel.getChkNoCastForTest().setSelected(true);
        configPanel.getChkHexForTest().setSelected(true);

        SqlmapTaskOptions updatedOpts = configPanel.applyUiToOptions();
        assertTrue(updatedOpts.isTimeless());
        assertTrue(updatedOpts.isNoCast());
        assertTrue(updatedOpts.isHexConvert());

        String cli = updatedOpts.buildCommandLine();
        assertTrue(cli.contains("--timeless"));
        assertTrue(cli.contains("--no-cast"));
        assertTrue(cli.contains("--hex"));
    }

    @Test
    public void testForceSslUIConfigPanelToggle() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://target.local/api/search");
        options.setForceSsl(false);

        byte[] raw = "GET /api/search HTTP/1.1\r\nHost: target.local\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        ScanRequestSession session = new ScanRequestSession(2, "GET", "http://target.local/api/search", raw, options);

        RequestScanTabPanel tabPanel = new RequestScanTabPanel(null, session, null);
        RequestConfigPanel configPanel = tabPanel.getConfigPanelForTest();
        assertNotNull(configPanel);
        assertNotNull(configPanel.getChkForceSslForTest());

        // Checkbox starts unchecked for http://
        assertFalse(configPanel.getChkForceSslForTest().isSelected());

        // User checks the HTTPS checkbox
        configPanel.getChkForceSslForTest().setSelected(true);
        for (var al : configPanel.getChkForceSslForTest().getActionListeners()) {
            al.actionPerformed(new java.awt.event.ActionEvent(configPanel.getChkForceSslForTest(), 0, ""));
        }

        // Verify URL updated to https:// in session and options
        assertEquals("https://target.local/api/search", session.getUrl());
        SqlmapTaskOptions activeOpts = session.getActiveExecution().getOptions();
        assertTrue(activeOpts.isForceSsl());
        assertEquals("https://target.local/api/search", activeOpts.getUrl());
        assertTrue(activeOpts.buildCommandLine().contains("--force-ssl"));
        assertTrue(activeOpts.buildCommandLine().contains("-u \"https://target.local/api/search\""));
    }

    @Test
    public void testForceSslPreCheckedForHttpsUrl() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("https://secure.target.local/admin");

        byte[] raw = "GET /admin HTTP/1.1\r\nHost: secure.target.local\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        ScanRequestSession session = new ScanRequestSession(3, "GET", "https://secure.target.local/admin", raw, options);

        RequestScanTabPanel tabPanel = new RequestScanTabPanel(null, session, null);
        RequestConfigPanel configPanel = tabPanel.getConfigPanelForTest();
        assertNotNull(configPanel);

        // Pre-checked because URL starts with https://
        assertTrue(configPanel.getChkForceSslForTest().isSelected());
    }
}
