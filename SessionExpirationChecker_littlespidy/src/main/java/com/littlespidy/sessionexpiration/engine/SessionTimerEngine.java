// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.littlespidy.sessionexpiration.model.ProbeResult;
import com.littlespidy.sessionexpiration.model.SessionState;
import com.littlespidy.sessionexpiration.model.SessionTask;
import com.littlespidy.sessionexpiration.model.TimerInterval;

import javax.swing.*;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Background execution engine that manages scheduled timers and executes probes
 * using the Montoya HTTP API.
 *
 * @author littlespidy
 */
public class SessionTimerEngine {

    private final MontoyaApi api;
    private final ScheduledExecutorService scheduler;
    private final ExecutorService workerPool;

    public SessionTimerEngine(MontoyaApi api) {
        this.api = api;
        AtomicInteger threadCount = new AtomicInteger(1);
        this.scheduler = Executors.newScheduledThreadPool(4, r -> {
            Thread t = new Thread(r, "SessionTimerEngine-" + threadCount.getAndIncrement());
            t.setDaemon(true);
            return t;
        });

        AtomicInteger workerCount = new AtomicInteger(1);
        this.workerPool = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "SessionTimerWorker-" + workerCount.getAndIncrement());
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Initiates scheduling for all configured intervals of a task from T0 = now.
     */
    public void startSession(SessionTask task, Runnable onUpdate) {
        workerPool.submit(() -> {
            try {
                // Ensure baseline response exists
                if (task.getBaseline() == null || !task.getBaseline().hasResponse()) {
                    api.logging().logToOutput("[Session #" + task.getId() + "] Sending initial baseline probe...");
                    HttpRequestResponse baselineRR = api.http().sendRequest(task.getOriginalRequest());
                    task.setBaseline(baselineRR);
                    api.logging().logToOutput("[Session #" + task.getId() + "] Baseline captured with status "
                            + (baselineRR.hasResponse() ? baselineRR.response().statusCode() : "none"));
                }

                Instant t0 = Instant.now();
                task.setCreatedAt(t0);
                task.setState(SessionState.PENDING);
                task.setLastVerdict("Scheduled " + task.getIntervals().size() + " milestones from T0");

                for (TimerInterval interval : task.getIntervals()) {
                    Instant targetTime = t0.plusSeconds(interval.getDelaySeconds());
                    interval.setScheduledTargetTime(targetTime);
                    interval.setStatus(TimerInterval.IntervalStatus.SCHEDULED);

                    long delayMs = Duration.between(Instant.now(), targetTime).toMillis();
                    if (delayMs < 0) {
                        delayMs = 0;
                    }

                    ScheduledFuture<?> future = scheduler.schedule(
                            () -> executeProbe(task, interval, onUpdate),
                            delayMs,
                            TimeUnit.MILLISECONDS
                    );
                    interval.setScheduledFuture(future);
                }

                if (onUpdate != null) {
                    SwingUtilities.invokeLater(onUpdate);
                }

            } catch (Exception e) {
                api.logging().logToError("[Session #" + task.getId() + "] Error starting session: " + e.getMessage());
                task.setState(SessionState.ERROR);
                task.setLastVerdict("Start error: " + e.getMessage());
                if (onUpdate != null) {
                    SwingUtilities.invokeLater(onUpdate);
                }
            }
        });
    }

    /**
     * Executes an individual milestone probe.
     */
    public void executeProbe(SessionTask task, TimerInterval interval, Runnable onUpdate) {
        // Abort if task was already cancelled or marked expired
        if (task.getState() == SessionState.CANCELLED || task.getState() == SessionState.EXPIRED) {
            interval.setStatus(TimerInterval.IntervalStatus.CANCELLED);
            if (onUpdate != null) {
                SwingUtilities.invokeLater(onUpdate);
            }
            return;
        }

        interval.setStatus(TimerInterval.IntervalStatus.RUNNING);
        task.setState(SessionState.RUNNING);
        if (onUpdate != null) {
            SwingUtilities.invokeLater(onUpdate);
        }

        long start = System.currentTimeMillis();
        try {
            HttpRequestResponse probeRR = api.http().sendRequest(task.getOriginalRequest());
            long duration = System.currentTimeMillis() - start;

            SessionVerifier.VerificationVerdict verdict = SessionVerifier.verify(
                    (task.getBaseline() != null && task.getBaseline().hasResponse()) ? task.getBaseline().response() : null,
                    probeRR.response()
            );

            ProbeResult result = ProbeResult.success(
                    Instant.now(),
                    probeRR,
                    verdict.isExpired(),
                    verdict.getSignal(),
                    duration
            );

            interval.setExecutedTime(Instant.now());
            interval.setProbeResult(result);

            if (verdict.isExpired()) {
                interval.setStatus(TimerInterval.IntervalStatus.EXPIRED);
                task.setState(SessionState.EXPIRED);
                task.setLastVerdict(verdict.getSignal() + " at " + interval.getLabel());

                if (task.isCancelOnExpire()) {
                    task.cancelRemainingFutures();
                    api.logging().logToOutput("[Session #" + task.getId() + "] EXPIRED at "
                            + interval.getLabel() + ". Remaining scheduled intervals cancelled.");
                }
            } else {
                interval.setStatus(TimerInterval.IntervalStatus.PASSED);

                // Check if any scheduled milestones remain
                if (task.getNextScheduledInterval() == null) {
                    task.setState(SessionState.COMPLETED);
                    task.setLastVerdict("All milestones completed. Session active!");
                } else {
                    task.setState(SessionState.ACTIVE);
                    task.setLastVerdict(verdict.getSignal() + " at " + interval.getLabel());
                }

                api.logging().logToOutput("[Session #" + task.getId() + "] Milestone "
                        + interval.getLabel() + " passed: " + verdict.getSignal());
            }

        } catch (Exception ex) {
            long duration = System.currentTimeMillis() - start;
            api.logging().logToError("[Session #" + task.getId() + "] Probe error: " + ex.getMessage());

            ProbeResult result = ProbeResult.failure(Instant.now(), ex.getMessage(), duration);
            interval.setExecutedTime(Instant.now());
            interval.setProbeResult(result);
            interval.setStatus(TimerInterval.IntervalStatus.ERROR);
            task.setState(SessionState.ERROR);
            task.setLastVerdict("Probe error: " + ex.getMessage());
        }

        if (onUpdate != null) {
            SwingUtilities.invokeLater(onUpdate);
        }
    }

    /**
     * Executes an immediate probe on demand for a task and interval.
     */
    public void runProbeNow(SessionTask task, TimerInterval interval, Runnable onUpdate) {
        workerPool.submit(() -> executeProbe(task, interval, onUpdate));
    }

    /**
     * Refreshes the baseline request/response for a session task.
     */
    public void refreshBaseline(SessionTask task, Runnable onUpdate) {
        workerPool.submit(() -> {
            try {
                api.logging().logToOutput("[Session #" + task.getId() + "] Refreshing baseline...");
                HttpRequestResponse newBaseline = api.http().sendRequest(task.getOriginalRequest());
                task.setBaseline(newBaseline);
                api.logging().logToOutput("[Session #" + task.getId() + "] Baseline refreshed: Status "
                        + (newBaseline.hasResponse() ? newBaseline.response().statusCode() : "none"));
            } catch (Exception ex) {
                api.logging().logToError("[Session #" + task.getId() + "] Error refreshing baseline: " + ex.getMessage());
            }
            if (onUpdate != null) {
                SwingUtilities.invokeLater(onUpdate);
            }
        });
    }

    /**
     * Manually cancels all active and pending timers for a task.
     */
    public void cancelTask(SessionTask task, Runnable onUpdate) {
        task.cancelRemainingFutures();
        task.setState(SessionState.CANCELLED);
        task.setLastVerdict("Cancelled by user");
        if (onUpdate != null) {
            SwingUtilities.invokeLater(onUpdate);
        }
    }

    /**
     * Shuts down all scheduler and worker daemon pools cleanly.
     */
    public void shutdown() {
        try {
            scheduler.shutdownNow();
            workerPool.shutdownNow();
        } catch (Exception ignored) {
        }
    }
}
