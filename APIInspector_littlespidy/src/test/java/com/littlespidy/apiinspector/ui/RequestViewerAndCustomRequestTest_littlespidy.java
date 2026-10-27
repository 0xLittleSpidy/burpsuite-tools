// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.apiinspector.engine.AuthTestEngine_littlespidy;
import com.littlespidy.apiinspector.model.*;
import com.littlespidy.apiinspector.persistence.APIInspectorPersistenceManager_littlespidy;
import com.littlespidy.apiinspector.persistence.SessionStateDTO_littlespidy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for editable Request Viewer, custom request persistence,
 * and propagation of user edits to the Auth Testing Engine.
 */
class RequestViewerAndCustomRequestTest_littlespidy {

    @Test
    @DisplayName("Verify customRawRequest setter, getter, and reset on DiscoveredEndpoint")
    void testDiscoveredEndpointCustomRequest() {
        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("POST", "/api/v1/users/{id}", "Create or update user");
        assertFalse(ep.hasCustomRequest(), "Initially endpoint should have no custom request");
        assertNull(ep.getCustomRawRequest());

        String custom = "POST /api/v1/users/42 HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/json\r\n\r\n{\"name\":\"Alice\"}";
        ep.setCustomRawRequest(custom);
        assertTrue(ep.hasCustomRequest(), "Endpoint should report custom request present");
        assertEquals(custom, ep.getCustomRawRequest());

        ep.resetCustomRequest();
        assertFalse(ep.hasCustomRequest(), "Endpoint should reset custom request to null");
        assertNull(ep.getCustomRawRequest());
    }

    @Test
    @DisplayName("Verify persistence manager serializes and deserializes customRawRequest")
    void testPersistenceManagerCustomRequest() {
        ImportedCollection_littlespidy col = new ImportedCollection_littlespidy(
                "Test Collection",
                "OpenAPI 3.0",
                "FILE",
                "/tmp/test.json"
        );
        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("PUT", "/api/v1/items/{itemId}", "Update item");
        String customRaw = "PUT /api/v1/items/99 HTTP/1.1\r\nHost: api.example.com\r\n\r\n{\"quantity\":5}";
        ep.setCustomRawRequest(customRaw);
        col.setEndpoints(List.of(ep));

        SessionStateDTO_littlespidy.ImportedCollectionDTO dto = APIInspectorPersistenceManager_littlespidy.serializeImportedCollection(col);
        assertNotNull(dto);
        assertEquals(1, dto.endpoints.size());
        assertEquals(customRaw, dto.endpoints.get(0).customRawRequest);

        ImportedCollection_littlespidy deserialized = APIInspectorPersistenceManager_littlespidy.deserializeImportedCollection(dto);
        assertNotNull(deserialized);
        assertEquals(1, deserialized.getEndpoints().size());
        DiscoveredEndpoint_littlespidy recoveredEp = deserialized.getEndpoints().get(0);
        assertTrue(recoveredEp.hasCustomRequest());
        assertEquals(customRaw, recoveredEp.getCustomRawRequest());
    }

    @Test
    @DisplayName("Verify AuthTestEngine uses custom request template and reflects user edits")
    void testAuthTestEngineBuildsFromCustomRequest() {
        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("POST", "/api/v1/payments/{paymentId}", "Process payment");
        ep.getPathParams().put("paymentId", "{paymentId}"); // dummy unedited param

        // 1. Baseline without edits has dummy value
        HttpRequest defaultReq = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, null, false);
        assertNotNull(defaultReq);
        assertEquals("POST", defaultReq.method());

        // 2. User edits the request to replace invalid placeholder with real payload
        String customReqStr = "POST /api/v1/payments/pay_12345 HTTP/1.1\r\n" +
                "Host: api.example.com\r\n" +
                "Content-Type: application/json\r\n" +
                "X-Custom-Client: BurpInspector\r\n\r\n" +
                "{\"amount\": 1500, \"currency\": \"USD\"}";
        ep.setCustomRawRequest(customReqStr);

        // 3. Auth test engine with no auth should use the edited path, body, and headers
        HttpRequest editedReq = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, null, false);
        assertNotNull(editedReq);
        assertEquals("POST", editedReq.method());
        assertEquals("/api/v1/payments/pay_12345", editedReq.path());
        assertEquals("{\"amount\": 1500, \"currency\": \"USD\"}", editedReq.bodyToString());
        assertEquals("BurpInspector", editedReq.headerValue("X-Custom-Client"));

        // 4. Auth test engine with Bearer Token auth profile should inject the Bearer token onto the edited request
        AuthProfile_littlespidy bearerProfile = new AuthProfile_littlespidy("User Profile", AuthType_littlespidy.BEARER_TOKEN);
        bearerProfile.setBearerToken("secret_token_abc");

        HttpRequest authReq = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, bearerProfile, true);
        assertNotNull(authReq);
        assertEquals("/api/v1/payments/pay_12345", authReq.path());
        assertEquals("{\"amount\": 1500, \"currency\": \"USD\"}", authReq.bodyToString());
        assertEquals("Bearer secret_token_abc", authReq.headerValue("Authorization"));
        assertEquals("BurpInspector", authReq.headerValue("X-Custom-Client"));

        // 5. Auth test engine with unauthenticated comparison (includeAuth = false) should strip Authorization header
        String customWithAuth = "POST /api/v1/payments/pay_12345 HTTP/1.1\r\n" +
                "Host: api.example.com\r\n" +
                "Authorization: Bearer old_token\r\n\r\n" +
                "{\"amount\": 1500}";
        ep.setCustomRawRequest(customWithAuth);

        HttpRequest unauthReq = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, bearerProfile, false);
        assertNotNull(unauthReq);
        assertFalse(unauthReq.hasHeader("Authorization"), "Unauthenticated request must have Authorization header stripped");
    }

    @Test
    @DisplayName("Verify RequestTableModel displays Status and Edited columns correctly")
    void testRequestTableModelColumns() {
        RequestResponseViewerTab_littlespidy tab = new RequestResponseViewerTab_littlespidy(null);
        ImportedCollection_littlespidy col = new ImportedCollection_littlespidy("Store API", "OpenAPI 3.0", "FILE", "/tmp/store.json");
        DiscoveredEndpoint_littlespidy ep1 = new DiscoveredEndpoint_littlespidy("GET", "/api/v1/items", "List items");
        DiscoveredEndpoint_littlespidy ep2 = new DiscoveredEndpoint_littlespidy("POST", "/api/v1/orders", "Place order");
        ep2.setCustomRawRequest("POST /api/v1/orders HTTP/1.1\r\nHost: store.com\r\n\r\n{\"sku\":\"SKU-1\"}");
        col.setEndpoints(List.of(ep1, ep2));

        tab.updateCollections(List.of(col));
        RequestResponseViewerTab_littlespidy.RequestTableModel model = tab.getTableModel();
        assertNotNull(model);
        assertEquals(8, model.getColumnCount(), "Content Type column removed; total columns should be 8");
        assertEquals("Status", model.getColumnName(3));
        assertEquals("Edited", model.getColumnName(4));

        assertEquals(2, model.getRowCount());

        // ep1 is unedited
        assertEquals("-", model.getValueAt(0, 3)); // Status
        assertEquals("-", model.getValueAt(0, 4)); // Edited

        // ep2 is edited
        assertEquals("-", model.getValueAt(1, 3)); // Status
        assertEquals("Yes", model.getValueAt(1, 4)); // Edited
    }

    @Test
    @DisplayName("Verify SessionStore parses pasted raw headers and strictly replaces existing headers")
    void testSessionStoreRawHeadersParsingAndStrictReplace() {
        SessionStore_littlespidy store = new SessionStore_littlespidy();
        store.setEnabled(true);

        String pastedHeaders = "# Authentication and session headers\n" +
                "Authorization: Bearer my_jwt_token_12345\n" +
                "Cookie: session_id=sess_abcdef; tracking=none\n" +
                "X-Api-Key: api_key_secret\n";

        store.setRawHeaders(pastedHeaders);
        assertEquals(3, store.getParsedHeaders().size());
        assertEquals("Bearer my_jwt_token_12345", store.getParsedHeaders().get("Authorization"));
        assertEquals("session_id=sess_abcdef; tracking=none", store.getParsedHeaders().get("Cookie"));
        assertEquals("api_key_secret", store.getParsedHeaders().get("X-Api-Key"));
        assertEquals("Session Store: Active (3 headers)", store.getStatusSummary());

        // Baseline request with old credentials
        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("GET", "/api/profile", "Profile");
        ep.setRequiresAuth(true);
        HttpRequest baseline = AuthTestEngine_littlespidy.buildRequest("https://api.example.com", ep, null, false);
        baseline = baseline.withHeader("Authorization", "Bearer old_expired_token")
                           .withHeader("Cookie", "session_id=old_expired_cookie");

        assertEquals("Bearer old_expired_token", baseline.headerValue("Authorization"));
        assertEquals("session_id=old_expired_cookie", baseline.headerValue("Cookie"));

        // Applying session store should strictly replace matching headers
        HttpRequest applied = store.applyToRequest(baseline, ep);
        assertNotNull(applied);
        assertEquals("Bearer my_jwt_token_12345", applied.headerValue("Authorization"), "Authorization must be strictly replaced");
        assertEquals("session_id=sess_abcdef; tracking=none", applied.headerValue("Cookie"), "Cookie must be strictly replaced");
        assertEquals("api_key_secret", applied.headerValue("X-Api-Key"), "New header must be injected");
    }

    @Test
    @DisplayName("Verify SessionStore rawHeaders persistence")
    void testSessionStorePersistence() {
        SessionStore_littlespidy store = new SessionStore_littlespidy();
        store.setEnabled(true);
        store.setApplyMode(SessionStore_littlespidy.MODE_ALL_REQUESTS);
        String raw = "Authorization: Bearer token_xyz\nCookie: auth=yes\n";
        store.setRawHeaders(raw);

        SessionStateDTO_littlespidy.SessionStoreDTO dto = APIInspectorPersistenceManager_littlespidy.serializeSessionStore(store);
        assertNotNull(dto);
        assertTrue(dto.enabled);
        assertEquals(SessionStore_littlespidy.MODE_ALL_REQUESTS, dto.applyMode);
        assertEquals(raw, dto.rawHeaders);

        SessionStore_littlespidy recovered = APIInspectorPersistenceManager_littlespidy.deserializeSessionStore(dto);
        assertNotNull(recovered);
        assertTrue(recovered.isEnabled());
        assertEquals(SessionStore_littlespidy.MODE_ALL_REQUESTS, recovered.getApplyMode());
        assertEquals(raw, recovered.getRawHeaders());
        assertEquals(2, recovered.getParsedHeaders().size());
    }

    @Test
    @DisplayName("Verify FillParametersDialog correctly synchronizes parameters and builds modified request")
    void testFillParametersDialogAndRebuildRequest() {
        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("POST", "/api/v1/users/{userId}", "Update user");
        ep.getPathParams().put("userId", "");
        ep.getQueryParams().put("filter", "active");
        ep.getBodyParams().put("role", "admin");

        if (!java.awt.GraphicsEnvironment.isHeadless()) {
            java.util.concurrent.atomic.AtomicReference<HttpRequest> updatedReqRef = new java.util.concurrent.atomic.AtomicReference<>();
            FillParametersDialog_littlespidy dialog = new FillParametersDialog_littlespidy(
                    null,
                    ep,
                    "https://api.example.com",
                    "POST /api/v1/users/{userId}?filter=active HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                    null,
                    updatedReqRef::set
            );
            assertNotNull(dialog);
            dialog.dispose();
        }

        // Simulating parameter updates in endpoint
        ep.getPathParams().put("userId", "user_999");
        ep.getQueryParams().put("filter", "inactive");
        ep.getBodyParams().put("role", "manager");
        ep.setRequestBodySample("{\"role\": \"manager\"}");

        HttpRequest rebuilt = AuthTestEngine_littlespidy.buildDefaultRequest("https://api.example.com", ep);
        assertNotNull(rebuilt);
        assertEquals("POST", rebuilt.method());
        assertTrue(rebuilt.path().contains("/api/v1/users/user_999"));
        assertTrue(rebuilt.path().contains("filter=inactive"));
        assertTrue(rebuilt.bodyToString().contains("manager"));
    }

    @Test
    @DisplayName("Verify in-place parameter mutation preserves custom headers, authorization, and nested JSON fields")
    void testInPlaceMutationPreservesHeadersAndNestedJson() {
        String originalRaw = "POST /api/v1/accounts/{accountId}?region=us-east HTTP/1.1\r\n" +
                "Host: billing.target.com\r\n" +
                "Authorization: Bearer secret_jwt_token_999\r\n" +
                "X-Custom-Tracing: trace_id_abc123\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: 64\r\n\r\n" +
                "{\n" +
                "  \"account\": {\n" +
                "    \"tier\": \"free\"\n" +
                "  },\n" +
                "  \"keepThisField\": 42\n" +
                "}";

        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("POST", "/api/v1/accounts/{accountId}", "Update account");
        ep.setCustomRawRequest(originalRaw);

        // When mutating through buildFromCustomRequest after in-place replacement:
        String mutatedRaw = originalRaw.replace("{accountId}", "acc_777")
                                       .replace("tier\": \"free\"", "tier\": \"enterprise\"");

        HttpRequest req = AuthTestEngine_littlespidy.buildFromCustomRequest("https://billing.target.com", mutatedRaw);
        assertNotNull(req);

        // Verify path substituted
        assertTrue(req.path().contains("/api/v1/accounts/acc_777"));
        assertTrue(req.path().contains("region=us-east"));

        // Verify custom headers preserved
        assertEquals("Bearer secret_jwt_token_999", req.headerValue("Authorization"));
        assertEquals("trace_id_abc123", req.headerValue("X-Custom-Tracing"));

        // Verify untouched JSON fields preserved and modified fields updated
        String body = req.bodyToString();
        assertTrue(body.contains("enterprise"), "Tier must be updated to enterprise");
        assertTrue(body.contains("keepThisField"), "Untouched fields must be preserved");
        assertTrue(body.contains("42"), "Untouched field value must be preserved");
    }

    @Test
    @DisplayName("Verify auto parameter discovery and viewer refresh populate parameters for early imported sessions")
    void testEnsureParametersDiscoveredAndRefreshButton() {
        // Simulating endpoint imported early or loaded from an old session file without pre-populated maps
        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("POST", "/api/v1/orders/{orderId}?status=pending&limit=10", "Create order");
        ep.setRequestBodySample("{\n  \"note\": \"rush\",\n  \"customer\": {\n    \"vip\": true\n  }\n}");

        // Initially maps are empty
        assertTrue(ep.getPathParams().isEmpty());
        assertTrue(ep.getQueryParams().isEmpty());
        assertTrue(ep.getBodyParams().isEmpty());

        // Parameter summary automatically triggers discovery
        String summary = ep.getParametersSummary();
        assertNotNull(summary);
        assertNotEquals("None", summary);
        assertTrue(summary.contains("orderId"), "Must discover orderId from path template");
        assertTrue(summary.contains("status"), "Must discover status from path query string");
        assertTrue(summary.contains("note"), "Must discover note from JSON body");
        assertTrue(summary.contains("customer.vip"), "Must discover nested customer.vip from JSON body");

        // Verify maps are populated
        assertEquals(1, ep.getPathParams().size());
        assertTrue(ep.getPathParams().containsKey("orderId"));
        assertEquals(2, ep.getQueryParams().size());
        assertTrue(ep.getQueryParams().containsKey("status"));
        assertTrue(ep.getQueryParams().containsKey("limit"));
        assertEquals("pending", ep.getQueryParams().get("status"));
        assertEquals("10", ep.getQueryParams().get("limit"));
        assertTrue(ep.getBodyParams().containsKey("note"));
        assertTrue(ep.getBodyParams().containsKey("customer.vip"));

        // Verify Refresh in RequestResponseViewerTab updates the table
        RequestResponseViewerTab_littlespidy tab = new RequestResponseViewerTab_littlespidy(null);
        ImportedCollection_littlespidy col = new ImportedCollection_littlespidy("Orders API", "OpenAPI", "SESSION", "/tmp/orders.session");
        col.setEndpoints(List.of(ep));
        tab.updateCollections(List.of(col));

        RequestResponseViewerTab_littlespidy.RequestTableModel model = tab.getTableModel();
        assertNotNull(model);
        assertEquals(1, model.getRowCount());
        String tableParams = (String) model.getValueAt(0, 7);
        assertTrue(tableParams.contains("orderId"));
        assertTrue(tableParams.contains("status"));
        assertTrue(tableParams.contains("note"));

        // Trigger onRefresh
        tab.onRefresh();
        assertEquals(1, model.getRowCount());
        assertEquals(tableParams, model.getValueAt(0, 7));
    }

    @Test
    @DisplayName("Verify Fill Parameters dialog discovers collection-wide parameters matching Parameter Collector")
    void testFillParametersCollectionWideDiscovery() {
        // Create an API collection with multiple endpoints
        ImportedCollection_littlespidy col = new ImportedCollection_littlespidy("Store API", "OpenAPI", "SESSION", "/tmp/store.session");

        DiscoveredEndpoint_littlespidy ep1 = new DiscoveredEndpoint_littlespidy("GET", "/api/v1/users/{userId}?role=admin", "Get User");
        DiscoveredEndpoint_littlespidy ep2 = new DiscoveredEndpoint_littlespidy("POST", "/api/v1/orders/{orderId}?status=open&page=1", "Create Order");
        ep2.setRequestBodySample("{\n  \"item\": \"book\",\n  \"quantity\": 2\n}");

        col.setEndpoints(List.of(ep1, ep2));

        // 1. Verify ParameterCollectorTab.collectParameters extracts all unique params across collection
        ParameterCollectorTab_littlespidy.DiscoveredParameters discovered =
                ParameterCollectorTab_littlespidy.collectParameters(List.of(col));

        assertTrue(discovered.pathParams.containsKey("userId"));
        assertTrue(discovered.pathParams.containsKey("orderId"));
        assertTrue(discovered.queryParams.containsKey("role"));
        assertTrue(discovered.queryParams.containsKey("status"));
        assertTrue(discovered.queryParams.containsKey("page"));
        assertTrue(discovered.bodyParams.containsKey("item"));
        assertTrue(discovered.bodyParams.containsKey("quantity"));

        // 2. Open FillParametersDialog for ep1 (which only has userId and role locally)
        if (!java.awt.GraphicsEnvironment.isHeadless()) {
            FillParametersDialog_littlespidy dialog = new FillParametersDialog_littlespidy(
                    null,
                    ep1,
                    col,
                    List.of(col),
                    "https://api.store.com",
                    "GET /api/v1/users/usr_123?role=admin HTTP/1.1\r\nHost: api.store.com\r\n\r\n",
                    null,
                    null
            );

            // Path Table: should contain both userId (Pre-filled with live value) and orderId (Empty because placeholder only)
            var pathModel = dialog.getPathTableModel();
            assertNotNull(pathModel);
            assertTrue(pathModel.getRowCount() >= 2);
            boolean foundUserId = false;
            boolean foundOrderId = false;
            for (int r = 0; r < pathModel.getRowCount(); r++) {
                String param = (String) pathModel.getValueAt(r, 0);
                String status = (String) pathModel.getValueAt(r, 2);
                String val = (String) pathModel.getValueAt(r, 3);
                if ("userId".equals(param)) {
                    foundUserId = true;
                    assertEquals("Pre-filled", status);
                    assertEquals("usr_123", val, "Live request userId value must be prefilled");
                } else if ("orderId".equals(param)) {
                    foundOrderId = true;
                    assertEquals("Empty", status);
                    assertEquals("", val);
                }
            }
            assertTrue(foundUserId, "Active endpoint path param userId must be in table");
            assertTrue(foundOrderId, "Collection path param orderId must be auto-populated in table as Empty");

            // Query Table: should contain role (Pre-filled), plus status and page pre-filled with sample values from collection
            var queryModel = dialog.getQueryTableModel();
            assertNotNull(queryModel);
            assertTrue(queryModel.getRowCount() >= 3);
            boolean foundRole = false;
            boolean foundStatus = false;
            boolean foundPage = false;
            for (int r = 0; r < queryModel.getRowCount(); r++) {
                String param = (String) queryModel.getValueAt(r, 0);
                String status = (String) queryModel.getValueAt(r, 2);
                String val = (String) queryModel.getValueAt(r, 3);
                if ("role".equals(param)) {
                    foundRole = true;
                    assertEquals("Pre-filled", status);
                    assertEquals("admin", val);
                } else if ("status".equals(param)) {
                    foundStatus = true;
                    assertEquals("Pre-filled", status);
                    assertEquals("open", val, "Sample value from collection must be prefilled");
                } else if ("page".equals(param)) {
                    foundPage = true;
                    assertEquals("Pre-filled", status);
                    assertEquals("1", val, "Sample value from collection must be prefilled");
                }
            }
            assertTrue(foundRole, "Active query param role must be Pre-filled");
            assertTrue(foundStatus, "Collection query param status must be Pre-filled with sample value");
            assertTrue(foundPage, "Collection query param page must be Pre-filled with sample value");

            // Body Table: should contain item and quantity pre-filled with sample values from collection
            var bodyModel = dialog.getBodyTableModel();
            assertNotNull(bodyModel);
            assertTrue(bodyModel.getRowCount() >= 2);
            boolean foundItem = false;
            boolean foundQuantity = false;
            for (int r = 0; r < bodyModel.getRowCount(); r++) {
                String param = (String) bodyModel.getValueAt(r, 0);
                String status = (String) bodyModel.getValueAt(r, 2);
                String val = (String) bodyModel.getValueAt(r, 3);
                if ("item".equals(param)) {
                    foundItem = true;
                    assertEquals("Pre-filled", status);
                    assertEquals("book", val, "Sample value from collection JSON must be prefilled");
                } else if ("quantity".equals(param)) {
                    foundQuantity = true;
                    assertEquals("Pre-filled", status);
                    assertEquals("2", val, "Sample value from collection JSON must be prefilled");
                }
            }
            assertTrue(foundItem, "Collection body param item must be prefilled with sample value");
            assertTrue(foundQuantity, "Collection body param quantity must be prefilled with sample value");
        }
    }

    @Test
    @DisplayName("Verify URLImportDialog has empty text and no dummy URL")
    void testUrlImportDialogNoDummyUrl() {
        if (!GraphicsEnvironment.isHeadless()) {
            URLImportDialog_littlespidy dlg = new URLImportDialog_littlespidy(null, null);
            JTextArea area = findComponent(dlg, JTextArea.class);
            assertNotNull(area, "JTextArea should be present in URLImportDialog");
            assertEquals("", area.getText().trim(), "URL text area must not contain dummy petstore URL");
        }
    }

    @Test
    @DisplayName("Verify SessionStoreDialog has line wrapping and vertical-only scrolling")
    void testSessionStoreDialogLineWrap() {
        if (!GraphicsEnvironment.isHeadless()) {
            SessionStore_littlespidy store = new SessionStore_littlespidy();
            SessionStoreDialog_littlespidy dlg = new SessionStoreDialog_littlespidy(null, store, null);
            JTextArea area = findComponent(dlg, JTextArea.class);
            assertNotNull(area, "JTextArea should be present in SessionStoreDialog");
            assertTrue(area.getLineWrap(), "Line wrap must be enabled");
            assertTrue(area.getWrapStyleWord(), "Word wrap style must be enabled");

            JScrollPane scroll = findComponent(dlg, JScrollPane.class);
            assertNotNull(scroll, "JScrollPane should be present in SessionStoreDialog");
            assertEquals(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER, scroll.getHorizontalScrollBarPolicy(),
                    "Horizontal scroll bar must be disabled in favor of vertical-only scrolling");
        }
    }

    @Test
    @DisplayName("Verify RequestResponseViewerTab pane borders are renamed to Request and Response")
    void testRequestResponseViewerPaneTitles() {
        RequestResponseViewerTab_littlespidy tab = new RequestResponseViewerTab_littlespidy(null);
        List<javax.swing.border.TitledBorder> borders = findTitledBorders(tab);

        boolean foundRequest = false;
        boolean foundResponse = false;
        boolean foundOldHttpRequest = false;
        boolean foundOldHttpResponse = false;

        for (javax.swing.border.TitledBorder b : borders) {
            String title = b.getTitle();
            if ("Request".equals(title)) foundRequest = true;
            if ("Response".equals(title)) foundResponse = true;
            if ("HTTP Request (Editable)".equals(title)) foundOldHttpRequest = true;
            if ("HTTP Response".equals(title)) foundOldHttpResponse = true;
        }

        assertTrue(foundRequest, "Must have pane titled 'Request'");
        assertTrue(foundResponse, "Must have pane titled 'Response'");
        assertFalse(foundOldHttpRequest, "Must not have old title 'HTTP Request (Editable)'");
        assertFalse(foundOldHttpResponse, "Must not have old title 'HTTP Response'");
    }

    @SuppressWarnings("unchecked")
    private static <T extends Component> T findComponent(Container root, Class<T> clazz) {
        for (Component c : root.getComponents()) {
            if (clazz.isInstance(c)) return (T) c;
            if (c instanceof Container) {
                T found = findComponent((Container) c, clazz);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static List<javax.swing.border.TitledBorder> findTitledBorders(Container root) {
        List<javax.swing.border.TitledBorder> list = new java.util.ArrayList<>();
        if (root instanceof JComponent jc && jc.getBorder() instanceof javax.swing.border.TitledBorder tb) {
            list.add(tb);
        }
        for (Component c : root.getComponents()) {
            if (c instanceof Container cont) {
                list.addAll(findTitledBorders(cont));
            }
        }
        return list;
    }
}
