// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.engine;

import com.littlespidy.ssoinspector.model.OAuthFlowType;
import com.littlespidy.ssoinspector.model.OAuthParam;

import java.util.List;

public class OAuthFlowClassifier {

    public static OAuthFlowType classify(String path, List<OAuthParam> parameters) {
        if (path != null && (path.contains("/.well-known/openid-configuration") || path.contains("/.well-known/oauth-authorization-server") || path.contains("/.well-known/webfinger"))) {
            return OAuthFlowType.DISCOVERY_WELL_KNOWN;
        }

        if (parameters == null || parameters.isEmpty()) {
            return OAuthFlowType.UNKNOWN_OR_CUSTOM;
        }

        String responseType = getParam(parameters, "response_type");
        String grantType = getParam(parameters, "grant_type");
        boolean hasCodeChallenge = getParam(parameters, "code_challenge") != null;
        boolean hasAssertion = getParam(parameters, "assertion") != null || getParam(parameters, "client_assertion") != null;
        boolean hasDeviceCode = getParam(parameters, "device_code") != null;

        if (responseType != null) {
            String rt = responseType.trim().toLowerCase();

            // Hybrid flows: code + id_token, code + token, code + id_token + token
            if (rt.contains("code") && (rt.contains("token") || rt.contains("id_token"))) {
                return OAuthFlowType.HYBRID;
            }

            // Implicit flow: token, id_token, or token id_token
            if (!rt.contains("code") && (rt.contains("token") || rt.contains("id_token"))) {
                return OAuthFlowType.IMPLICIT;
            }

            // Authorization Code flow
            if (rt.equals("code") || rt.contains("code")) {
                if (hasCodeChallenge) {
                    return OAuthFlowType.AUTHORIZATION_CODE_PKCE;
                }
                return OAuthFlowType.AUTHORIZATION_CODE;
            }
        }

        if (grantType != null) {
            String gt = grantType.trim().toLowerCase();
            if (gt.equals("authorization_code")) {
                if (getParam(parameters, "code_verifier") != null) {
                    return OAuthFlowType.AUTHORIZATION_CODE_PKCE;
                }
                return OAuthFlowType.AUTHORIZATION_CODE;
            }
            if (gt.equals("client_credentials")) {
                return OAuthFlowType.CLIENT_CREDENTIALS;
            }
            if (gt.equals("password")) {
                return OAuthFlowType.RESOURCE_OWNER_PASSWORD;
            }
            if (gt.contains("token-exchange")) {
                return OAuthFlowType.TOKEN_EXCHANGE;
            }
            if (gt.contains("jwt-bearer") || gt.contains("saml2-bearer")) {
                return OAuthFlowType.JWT_BEARER;
            }
            if (gt.contains("device_code")) {
                return OAuthFlowType.DEVICE_CODE;
            }
        }

        if (hasAssertion) {
            return OAuthFlowType.JWT_BEARER;
        }

        if (hasDeviceCode) {
            return OAuthFlowType.DEVICE_CODE;
        }

        if (getParam(parameters, "client_id") != null && getParam(parameters, "redirect_uri") != null) {
            return OAuthFlowType.AUTHORIZATION_CODE;
        }

        return OAuthFlowType.UNKNOWN_OR_CUSTOM;
    }

    private static String getParam(List<OAuthParam> parameters, String name) {
        for (OAuthParam p : parameters) {
            if (p.getName().equalsIgnoreCase(name)) {
                return p.getRawValue();
            }
        }
        return null;
    }
}
