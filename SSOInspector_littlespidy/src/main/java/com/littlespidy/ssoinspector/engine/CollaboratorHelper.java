// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.engine;

import burp.api.montoya.MontoyaApi;

public final class CollaboratorHelper {

    private CollaboratorHelper() {
    }

    public static boolean isAvailable(MontoyaApi api) {
        if (api == null) return false;
        try {
            return api.collaborator() != null && api.collaborator().defaultPayloadGenerator() != null;
        } catch (Exception e) {
            return false;
        }
    }

    public static String generatePayload(MontoyaApi api, String fallbackDomain) {
        if (isAvailable(api)) {
            try {
                return api.collaborator().defaultPayloadGenerator().generatePayload().toString();
            } catch (Exception ignored) {
            }
        }
        return (fallbackDomain != null && !fallbackDomain.isBlank()) ? fallbackDomain.trim() : "burpcollaborator.net";
    }
}
