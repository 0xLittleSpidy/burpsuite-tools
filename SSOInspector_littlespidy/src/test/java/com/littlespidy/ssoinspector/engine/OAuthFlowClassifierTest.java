// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.engine;

import com.littlespidy.ssoinspector.model.OAuthFlowType;
import com.littlespidy.ssoinspector.model.OAuthParam;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class OAuthFlowClassifierTest {

    @Test
    public void testAuthorizationCodePkceFlow() {
        List<OAuthParam> params = new ArrayList<>();
        params.add(new OAuthParam("response_type", "code", "code", OAuthParam.ParamLocation.QUERY, "", true, false));
        params.add(new OAuthParam("client_id", "my-client", "my-client", OAuthParam.ParamLocation.QUERY, "", true, false));
        params.add(new OAuthParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", OAuthParam.ParamLocation.QUERY, "", true, false));
        params.add(new OAuthParam("code_challenge_method", "S256", "S256", OAuthParam.ParamLocation.QUERY, "", true, false));

        OAuthFlowType flow = OAuthFlowClassifier.classify("/oauth/authorize", params);
        assertEquals(OAuthFlowType.AUTHORIZATION_CODE_PKCE, flow);
    }

    @Test
    public void testAuthorizationCodeStandardFlow() {
        List<OAuthParam> params = new ArrayList<>();
        params.add(new OAuthParam("response_type", "code", "code", OAuthParam.ParamLocation.QUERY, "", true, false));
        params.add(new OAuthParam("client_id", "my-client", "my-client", OAuthParam.ParamLocation.QUERY, "", true, false));

        OAuthFlowType flow = OAuthFlowClassifier.classify("/oauth/authorize", params);
        assertEquals(OAuthFlowType.AUTHORIZATION_CODE, flow);
    }

    @Test
    public void testImplicitFlow() {
        List<OAuthParam> params = new ArrayList<>();
        params.add(new OAuthParam("response_type", "token", "token", OAuthParam.ParamLocation.QUERY, "", true, false));
        params.add(new OAuthParam("client_id", "my-client", "my-client", OAuthParam.ParamLocation.QUERY, "", true, false));

        OAuthFlowType flow = OAuthFlowClassifier.classify("/oauth/authorize", params);
        assertEquals(OAuthFlowType.IMPLICIT, flow);
    }

    @Test
    public void testHybridFlow() {
        List<OAuthParam> params = new ArrayList<>();
        params.add(new OAuthParam("response_type", "code id_token", "code id_token", OAuthParam.ParamLocation.QUERY, "", true, false));

        OAuthFlowType flow = OAuthFlowClassifier.classify("/oauth/authorize", params);
        assertEquals(OAuthFlowType.HYBRID, flow);
    }

    @Test
    public void testClientCredentialsFlow() {
        List<OAuthParam> params = new ArrayList<>();
        params.add(new OAuthParam("grant_type", "client_credentials", "client_credentials", OAuthParam.ParamLocation.BODY, "", true, false));

        OAuthFlowType flow = OAuthFlowClassifier.classify("/oauth/token", params);
        assertEquals(OAuthFlowType.CLIENT_CREDENTIALS, flow);
    }

    @Test
    public void testResourceOwnerPasswordFlow() {
        List<OAuthParam> params = new ArrayList<>();
        params.add(new OAuthParam("grant_type", "password", "password", OAuthParam.ParamLocation.BODY, "", true, false));

        OAuthFlowType flow = OAuthFlowClassifier.classify("/oauth/token", params);
        assertEquals(OAuthFlowType.RESOURCE_OWNER_PASSWORD, flow);
    }

    @Test
    public void testWellKnownDiscovery() {
        OAuthFlowType flow = OAuthFlowClassifier.classify("/.well-known/openid-configuration", List.of());
        assertEquals(OAuthFlowType.DISCOVERY_WELL_KNOWN, flow);
    }
}
