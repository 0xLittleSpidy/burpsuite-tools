// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.engine;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CollaboratorManager_littlespidy {
    private final CollaboratorClient client;
    private final Map<Integer, CollaboratorPayload> payloadMap;

    public CollaboratorManager_littlespidy(CollaboratorClient client) {
        this.client = client;
        this.payloadMap = new HashMap<>();
    }

    public boolean isAvailable() {
        return client != null;
    }

    public synchronized String generatePayloadForId(int id) {
        if (client == null) {
            return "ssrf-collaborator.internal";
        }
        try {
            CollaboratorPayload payload = client.generatePayload();
            payloadMap.put(id, payload);
            return payload.toString();
        } catch (Exception e) {
            return "collaborator-error.internal";
        }
    }

    public synchronized List<Interaction> pollInteractionsForId(int id) {
        if (client == null) {
            return Collections.emptyList();
        }
        CollaboratorPayload payload = payloadMap.get(id);
        if (payload == null) {
            return Collections.emptyList();
        }
        try {
            return client.getInteractions(InteractionFilter.interactionPayloadFilter(payload.toString()));
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    public synchronized List<Interaction> pollAllInteractions() {
        if (client == null) {
            return Collections.emptyList();
        }
        try {
            return client.getAllInteractions();
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }
}
