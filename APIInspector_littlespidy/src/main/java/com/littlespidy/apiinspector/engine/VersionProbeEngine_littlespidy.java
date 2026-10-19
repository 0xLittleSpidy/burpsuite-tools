// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import com.littlespidy.apiinspector.model.ProbeMutation_littlespidy;
import com.littlespidy.apiinspector.model.ProbeResult_littlespidy;
import com.littlespidy.apiinspector.strategy.VersionStrategy_littlespidy;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Threaded probing engine executing API version discovery mutations.
 */
public class VersionProbeEngine_littlespidy {

    private final Http http;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private ExecutorService executor;

    public VersionProbeEngine_littlespidy(Http http) {
        this.http = http;
    }

    public synchronized boolean isRunning() {
        return running.get();
    }

    public synchronized void stopProbing() {
        if (running.get()) {
            cancelled.set(true);
            if (executor != null && !executor.isShutdown()) {
                executor.shutdownNow();
            }
        }
    }

    public synchronized void startProbing(
            HttpRequest baselineRequest,
            HttpResponse baselineResponse,
            List<VersionStrategy_littlespidy> activeStrategies,
            List<String> candidateVersions,
            int threadCount,
            int delayMs,
            ProbeProgressListener_littlespidy listener) {

        if (running.get()) {
            if (listener != null) {
                listener.onProbeError("A probing session is already in progress.");
            }
            return;
        }

        running.set(true);
        cancelled.set(false);

        Thread coordinator = new Thread(() -> {
            try {
                // Generate all mutations from active strategies
                List<ProbeMutation_littlespidy> allMutations = new ArrayList<>();
                for (VersionStrategy_littlespidy strat : activeStrategies) {
                    if (cancelled.get()) break;
                    List<ProbeMutation_littlespidy> m = strat.generateMutations(baselineRequest, candidateVersions);
                    if (m != null) {
                        allMutations.addAll(m);
                    }
                }

                int totalCount = allMutations.size();
                if (listener != null) {
                    listener.onProbeStarted(totalCount);
                }

                if (totalCount == 0 || cancelled.get()) {
                    running.set(false);
                    if (listener != null) {
                        listener.onProbeFinished(cancelled.get());
                    }
                    return;
                }

                int threads = Math.max(1, Math.min(threadCount, 20));
                executor = Executors.newFixedThreadPool(threads);
                AtomicInteger completedCount = new AtomicInteger(0);
                AtomicInteger idCounter = new AtomicInteger(1);

                for (ProbeMutation_littlespidy mutation : allMutations) {
                    if (cancelled.get()) break;

                    executor.submit(() -> {
                        if (cancelled.get()) return;

                        if (delayMs > 0) {
                            try {
                                Thread.sleep(delayMs);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                return;
                            }
                        }

                        if (cancelled.get()) return;

                        int probeId = idCounter.getAndIncrement();
                        long startTime = System.currentTimeMillis();
                        HttpResponse probeResponse = null;
                        int status = 0;
                        int length = 0;
                        String mime = "-";

                        try {
                            if (http != null) {
                                HttpRequestResponse reqResp = http.sendRequest(mutation.getRequest());
                                if (reqResp != null && reqResp.hasResponse()) {
                                    probeResponse = reqResp.response();
                                    status = probeResponse.statusCode();
                                    length = probeResponse.body() != null ? probeResponse.body().length() : 0;
                                    if (probeResponse.mimeType() != null) {
                                        mime = probeResponse.mimeType().name();
                                    } else {
                                        String ct = probeResponse.headerValue("Content-Type");
                                        mime = ct != null ? ct : "-";
                                    }
                                }
                            }
                        } catch (Exception ex) {
                            status = 0;
                        }

                        long latency = System.currentTimeMillis() - startTime;
                        String diff = BaselineDiffAnalyzer_littlespidy.analyze(baselineResponse, probeResponse);

                        ProbeResult_littlespidy result = new ProbeResult_littlespidy(
                                probeId,
                                mutation.getStrategyName(),
                                mutation.getVariationDescription(),
                                status,
                                length,
                                mime,
                                diff,
                                latency,
                                mutation.getRequest(),
                                probeResponse
                        );

                        int done = completedCount.incrementAndGet();
                        if (listener != null) {
                            listener.onProbeResult(result, done, totalCount);
                        }
                    });
                }

                executor.shutdown();
                try {
                    executor.awaitTermination(30, TimeUnit.MINUTES);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }

            } catch (Exception e) {
                if (listener != null) {
                    listener.onProbeError("Probing encountered an error: " + e.getMessage());
                }
            } finally {
                running.set(false);
                if (listener != null) {
                    listener.onProbeFinished(cancelled.get());
                }
            }
        }, "APIInspector-ProbeCoordinator");

        coordinator.start();
    }
}
