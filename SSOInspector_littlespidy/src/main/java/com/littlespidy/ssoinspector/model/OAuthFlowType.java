// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.model;

public enum OAuthFlowType {
    AUTHORIZATION_CODE_PKCE("Auth Code (PKCE)", "OAuth 2.0 / OIDC Authorization Code Flow with Proof Key for Code Exchange (RFC 7636). Recommended secure standard."),
    AUTHORIZATION_CODE("Auth Code", "OAuth 2.0 / OIDC standard Authorization Code Flow (RFC 6749 Section 4.1). PKCE not detected."),
    IMPLICIT("Implicit Flow", "OAuth 2.0 / OIDC Implicit Flow (RFC 6749 Section 4.2). Deprecated due to token leakage risks in URL fragments."),
    HYBRID("Hybrid Flow", "OpenID Connect Hybrid Flow returning authorization code and tokens directly from the authorization endpoint."),
    CLIENT_CREDENTIALS("Client Credentials", "OAuth 2.0 Client Credentials Flow (RFC 6749 Section 4.4) for machine-to-machine authentication."),
    RESOURCE_OWNER_PASSWORD("ROPC (Password)", "OAuth 2.0 Resource Owner Password Credentials Flow (RFC 6749 Section 4.3). Deprecated and insecure."),
    TOKEN_EXCHANGE("Token Exchange", "OAuth 2.0 Token Exchange Flow (RFC 8693) for requesting security tokens based on existing tokens."),
    JWT_BEARER("JWT Bearer", "OAuth 2.0 JWT Bearer Token Profile (RFC 7523) using assertions for authorization."),
    DEVICE_CODE("Device Code", "OAuth 2.0 Device Authorization Grant (RFC 8628) for browserless/input-constrained devices."),
    DISCOVERY_WELL_KNOWN("Discovery / Well-Known", "OpenID Connect Discovery / OAuth 2.0 Authorization Server Metadata endpoint (RFC 8414)."),
    UNKNOWN_OR_CUSTOM("Unknown / Custom", "Unclassified OAuth or SSO request; check parameters and custom headers.");

    private final String displayName;
    private final String description;

    OAuthFlowType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
