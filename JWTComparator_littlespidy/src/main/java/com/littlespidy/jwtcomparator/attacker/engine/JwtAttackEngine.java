// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.attacker.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.jwtcomparator.attacker.model.AttackedRequestEntry;
import com.littlespidy.jwtcomparator.attacker.model.JwtTokenInjector;
import com.littlespidy.jwtcomparator.attacker.model.TokenAttackResult;
import com.littlespidy.jwtcomparator.model.JWTTokenModel;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Multi-threaded replay and authorization assessment engine.
 * Replays queued HTTP requests using each loaded JWT token and unauthenticated probe.
 */
public class JwtAttackEngine {

    public interface AttackListener {
        void onProgress(int completedTasks, int totalTasks);
        void onRequestUpdated(AttackedRequestEntry entry);
        void onAttackFinished();
        void onAttackStatusChanged(boolean isRunning, boolean isPaused);
    }

    private final MontoyaApi api;
    private ExecutorService executor;

    private volatile boolean isRunning = false;
    private volatile boolean isPaused = false;
    private volatile boolean isCancelled = false;
    private final Object pauseLock = new Object();

    public JwtAttackEngine(MontoyaApi api) {
        this.api = api;
    }

    public synchronized boolean isRunning() {
        return isRunning;
    }

    public synchronized boolean isPaused() {
        return isPaused;
    }

    public synchronized void pauseAttack(AttackListener listener) {
        if (isRunning && !isPaused) {
            isPaused = true;
            if (listener != null) {
                listener.onAttackStatusChanged(isRunning, isPaused);
            }
        }
    }

    public synchronized void resumeAttack(AttackListener listener) {
        if (isRunning && isPaused) {
            isPaused = false;
            synchronized (pauseLock) {
                pauseLock.notifyAll();
            }
            if (listener != null) {
                listener.onAttackStatusChanged(isRunning, isPaused);
            }
        }
    }

    public synchronized void stopAttack(AttackListener listener) {
        if (isRunning) {
            isCancelled = true;
            isPaused = false;
            synchronized (pauseLock) {
                pauseLock.notifyAll();
            }
            if (executor != null) {
                executor.shutdownNow();
            }
            isRunning = false;
            if (listener != null) {
                listener.onAttackStatusChanged(false, false);
                listener.onAttackFinished();
            }
        }
    }

    public synchronized void startAttack(List<AttackedRequestEntry> requests,
                                        List<JWTTokenModel> tokens,
                                        boolean testUnauth,
                                        int threadCount,
                                        int delayMs,
                                        AttackListener listener) {
        if (isRunning) {
            return;
        }

        if (requests == null || requests.isEmpty()) {
            return;
        }

        // Filter valid non-empty tokens
        List<JWTTokenModel> validTokens = new ArrayList<>();
        if (tokens != null) {
            for (JWTTokenModel tm : tokens) {
                if (tm.getRawToken() != null && !tm.getRawToken().trim().isEmpty()) {
                    validTokens.add(tm);
                }
            }
        }

        if (validTokens.isEmpty() && !testUnauth) {
            return;
        }

        isRunning = true;
        isPaused = false;
        isCancelled = false;

        if (listener != null) {
            listener.onAttackStatusChanged(true, false);
        }

        int probesPerRequest = validTokens.size() + (testUnauth ? 1 : 0);
        int totalTasks = requests.size() * probesPerRequest;
        AtomicInteger completedTasks = new AtomicInteger(0);

        int threads = Math.max(1, Math.min(threadCount, 32));
        executor = Executors.newFixedThreadPool(threads);

        // Run replay in background worker
        new Thread(() -> {
            try {
                for (AttackedRequestEntry entry : requests) {
                    if (isCancelled) break;

                    entry.clearResults();
                    entry.setStatus("Attacking");
                    if (listener != null) {
                        listener.onRequestUpdated(entry);
                    }

                    // 1. Test each valid token
                    for (JWTTokenModel token : validTokens) {
                        checkWaitPause();
                        if (isCancelled) break;

                        if (delayMs > 0) {
                            try {
                                Thread.sleep(delayMs);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                break;
                            }
                        }

                        TokenAttackResult res = executeSingleProbe(entry.getOriginalRequest(), token.getRawToken(),
                                token.getSlotIndex(), token.getLabel());
                        entry.addTokenResult(token.getSlotIndex(), res);

                        int done = completedTasks.incrementAndGet();
                        if (listener != null) {
                            listener.onRequestUpdated(entry);
                            listener.onProgress(done, totalTasks);
                        }
                    }

                    // 2. Test unauthenticated baseline if enabled
                    if (testUnauth && !isCancelled) {
                        checkWaitPause();
                        if (isCancelled) break;

                        if (delayMs > 0) {
                            try {
                                Thread.sleep(delayMs);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                break;
                            }
                        }

                        TokenAttackResult unauthRes = executeUnauthProbe(entry.getOriginalRequest());
                        entry.setUnauthenticatedResult(unauthRes);

                        int done = completedTasks.incrementAndGet();
                        if (listener != null) {
                            listener.onRequestUpdated(entry);
                            listener.onProgress(done, totalTasks);
                        }
                    }

                    // 3. Evaluate overall assessment for this request
                    String assessment = evaluateAssessment(entry, validTokens, testUnauth);
                    entry.setAssessment(assessment);
                    entry.setStatus(isCancelled ? "Stopped" : "Completed");

                    if (listener != null) {
                        listener.onRequestUpdated(entry);
                    }
                }
            } finally {
                synchronized (this) {
                    isRunning = false;
                    isPaused = false;
                    if (executor != null) {
                        executor.shutdown();
                    }
                }
                if (listener != null) {
                    listener.onAttackStatusChanged(false, false);
                    listener.onAttackFinished();
                }
            }
        }, "JwtAttackEngine-Worker").start();
    }

    private void checkWaitPause() {
        synchronized (pauseLock) {
            while (isPaused && !isCancelled) {
                try {
                    pauseLock.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    private TokenAttackResult executeSingleProbe(HttpRequest originalRequest, String token, int slotIndex, String tokenLabel) {
        if (originalRequest == null) {
            return TokenAttackResult.failed(slotIndex, tokenLabel, null, "No request provided");
        }

        HttpRequest mutated = JwtTokenInjector.injectToken(originalRequest, token);
        return sendAndMeasure(mutated, slotIndex, tokenLabel);
    }

    private TokenAttackResult executeUnauthProbe(HttpRequest originalRequest) {
        if (originalRequest == null) {
            return TokenAttackResult.failed(0, "Unauthenticated", null, "No request provided");
        }

        HttpRequest stripped = JwtTokenInjector.stripAuth(originalRequest);
        return sendAndMeasure(stripped, 0, "Unauthenticated");
    }

    private TokenAttackResult sendAndMeasure(HttpRequest request, int slotIndex, String label) {
        if (api == null || api.http() == null) {
            return TokenAttackResult.failed(slotIndex, label, request, "Montoya HTTP service unavailable");
        }

        long start = System.currentTimeMillis();
        try {
            HttpRequestResponse response = api.http().sendRequest(request);
            long duration = System.currentTimeMillis() - start;

            if (response != null && response.hasResponse()) {
                HttpResponse httpResp = response.response();
                int statusCode = httpResp.statusCode();
                String reason = httpResp.reasonPhrase();
                int length = httpResp.body() != null ? httpResp.body().length() : 0;
                return new TokenAttackResult(slotIndex, label, statusCode, reason, length, duration, request, httpResp, null);
            } else {
                return TokenAttackResult.failed(slotIndex, label, request, "No HTTP response received");
            }
        } catch (Exception ex) {
            long duration = System.currentTimeMillis() - start;
            return new TokenAttackResult(slotIndex, label, 0, "Error", 0, duration, request, null, ex.getMessage());
        }
    }

    /**
     * Automated authorization logic evaluating whether endpoint enforces auth, allows unauthenticated access,
     * or exhibits BOLA/IDOR behavior across multiple tokens.
     */
    public static String evaluateAssessment(AttackedRequestEntry entry, List<JWTTokenModel> tokens, boolean testUnauth) {
        if (entry == null) {
            return "N/A";
        }

        TokenAttackResult unauth = entry.getUnauthenticatedResult();
        if (testUnauth && unauth != null && unauth.isAccepted()) {
            return "⚠️ Unauthenticated Access (2xx)";
        }

        if (tokens == null || tokens.isEmpty()) {
            if (unauth != null) {
                return unauth.isAccepted() ? "⚠️ Unauthenticated Allowed" : "✔ Enforced";
            }
            return "Completed";
        }

        int acceptedCount = 0;
        int rejectedCount = 0;
        int serverErrorCount = 0;
        int failedCount = 0;

        for (JWTTokenModel tm : tokens) {
            TokenAttackResult r = entry.getTokenResult(tm.getSlotIndex());
            if (r == null) continue;
            if (r.isAccepted()) acceptedCount++;
            else if (r.isRejected()) rejectedCount++;
            else if (r.getStatusType() == TokenAttackResult.StatusType.SERVER_ERROR) serverErrorCount++;
            else if (r.getStatusType() == TokenAttackResult.StatusType.FAILED) failedCount++;
        }

        int totalEvaluated = acceptedCount + rejectedCount + serverErrorCount + failedCount;
        if (totalEvaluated == 0) {
            return "No Results";
        }

        // BOLA check: If more than 1 token was tested, and multiple tokens received 2xx
        if (tokens.size() > 1 && acceptedCount > 1) {
            return "🚨 BOLA / Access Bypass (Multi-Token 2xx)";
        }

        // Differentiated check: Token 1 was accepted, but other tokens were rejected (401/403)
        JWTTokenModel firstToken = tokens.get(0);
        TokenAttackResult firstRes = entry.getTokenResult(firstToken.getSlotIndex());
        if (firstRes != null && firstRes.isAccepted() && rejectedCount > 0 && acceptedCount == 1) {
            return "✔ Access Enforced (Role Differentiated)";
        }

        if (rejectedCount == totalEvaluated) {
            return "🔒 Access Denied (All Rejected)";
        }

        if (acceptedCount == 1 && tokens.size() == 1) {
            return "✔ Accepted (2xx)";
        }

        if (serverErrorCount > 0) {
            return "💥 Server Error (5xx)";
        }

        if (failedCount == totalEvaluated) {
            return "❌ Connection Failed";
        }

        return "ℹ️ Mixed (" + acceptedCount + " accepted, " + rejectedCount + " rejected)";
    }
}
