// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.engine;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.graphqlcop.clairvoyance.ClairvoyanceOracle_littlespidy;
import com.littlespidy.graphqlcop.engine.probes.*;
import com.littlespidy.graphqlcop.inql.EngineFingerprinter_littlespidy;
import com.littlespidy.graphqlcop.model.AuditFinding_littlespidy;
import com.littlespidy.graphqlcop.model.AuditProbeType_littlespidy;
import com.littlespidy.graphqlcop.model.HttpLogEntry_littlespidy;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;

public class AuditEngine_littlespidy {
    private final MontoyaApi api;
    private final Map<AuditProbeType_littlespidy, AuditProbe_littlespidy> probeRegistry = new LinkedHashMap<>();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private Future<?> activeTask = null;
    private volatile boolean isRunning = false;

    public AuditEngine_littlespidy(MontoyaApi api) {
        this.api = api;
        registerProbes();
    }

    private void registerProbes() {
        probeRegistry.put(AuditProbeType_littlespidy.INTROSPECTION, new IntrospectionProbe_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.GRAPHIQL, new GraphiqlProbe_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.GET_METHOD, new GetMethodProbe_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.POST_CSRF, new PostCsrfProbe_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.TRACE_MODE, new TraceModeProbe_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.FIELD_SUGGESTIONS, new FieldSuggestionsProbe_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.DIRECTIVE_OVERLOAD, new DirectiveOverloadProbe_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.CIRCULAR_INTROSPECTION, new CircularIntrospectionProbe_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.FIELD_DUPLICATION, new FieldDuplicationProbe_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.ALIAS_OVERLOAD, new AliasOverloadProbe_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.BATCH_QUERY, new BatchQueryProbe_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.UNHANDLED_ERROR, new UnhandledErrorProbe_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.GET_MUTATION, new GetMutationProbe_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.ENGINE_FINGERPRINT, new EngineFingerprinter_littlespidy());
        probeRegistry.put(AuditProbeType_littlespidy.CLAIRVOYANCE, new ClairvoyanceOracle_littlespidy());
    }

    public synchronized boolean isRunning() {
        return isRunning;
    }

    public synchronized void stop() {
        isRunning = false;
        if (activeTask != null && !activeTask.isDone()) {
            activeTask.cancel(true);
        }
    }

    public synchronized void runProbes(List<AuditProbeType_littlespidy> types, String targetUrl, String customHeaders,
                                       Consumer<HttpLogEntry_littlespidy> logConsumer,
                                       Consumer<AuditFinding_littlespidy> findingConsumer,
                                       Consumer<String> statusConsumer,
                                       Runnable onComplete) {
        if (isRunning) return;
        isRunning = true;

        activeTask = executor.submit(() -> {
            try {
                for (AuditProbeType_littlespidy type : types) {
                    if (!isRunning || Thread.currentThread().isInterrupted()) {
                        break;
                    }

                    AuditProbe_littlespidy probe = probeRegistry.get(type);
                    if (probe != null) {
                        if (statusConsumer != null) {
                            statusConsumer.accept("Running probe: " + type.getDisplayName() + "...");
                        }

                        List<AuditFinding_littlespidy> findings = probe.execute(api, targetUrl, customHeaders, logConsumer);
                        if (findings != null && findingConsumer != null) {
                            for (AuditFinding_littlespidy f : findings) {
                                findingConsumer.accept(f);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                if (statusConsumer != null) {
                    statusConsumer.accept("Error: " + e.getMessage());
                }
            } finally {
                isRunning = false;
                if (statusConsumer != null) {
                    statusConsumer.accept("Idle");
                }
                if (onComplete != null) {
                    onComplete.run();
                }
            }
        });
    }

    public List<AuditProbeType_littlespidy> getAllProbeTypes() {
        return new ArrayList<>(probeRegistry.keySet());
    }
}
