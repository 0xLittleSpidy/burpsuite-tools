// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Represents a tracked session request and its scheduled expiration milestones.
 *
 * @author littlespidy
 */
public class SessionTask {

    private final int id;
    private final HttpRequest originalRequest;
    private HttpRequestResponse baseline;
    private Instant createdAt;

    private final String method;
    private final String host;
    private final String path;
    private final String url;

    private int baselineStatusCode;
    private long baselineLength;

    private final List<TimerInterval> intervals = new CopyOnWriteArrayList<>();
    private SessionState state = SessionState.PENDING;
    private String lastVerdict = "Awaiting first scheduled check";
    private boolean cancelOnExpire = true;

    public SessionTask(int id, HttpRequest originalRequest, HttpRequestResponse baseline) {
        this.id = id;
        this.originalRequest = originalRequest;
        this.baseline = baseline;
        this.createdAt = Instant.now();

        this.method = (originalRequest != null && originalRequest.method() != null) ? originalRequest.method() : "GET";
        this.url = (originalRequest != null && originalRequest.url() != null) ? originalRequest.url() : "";
        this.path = (originalRequest != null && originalRequest.path() != null) ? originalRequest.path() : "/";
        this.host = (originalRequest != null && originalRequest.httpService() != null) ? originalRequest.httpService().host() : "";

        if (baseline != null && baseline.hasResponse()) {
            HttpResponse resp = baseline.response();
            this.baselineStatusCode = resp.statusCode();
            this.baselineLength = resp.toByteArray().length();
        } else {
            this.baselineStatusCode = 0;
            this.baselineLength = 0;
        }
    }

    public int getId() {
        return id;
    }

    public HttpRequest getOriginalRequest() {
        return originalRequest;
    }

    public HttpRequestResponse getBaseline() {
        return baseline;
    }

    public void setBaseline(HttpRequestResponse baseline) {
        this.baseline = baseline;
        if (baseline != null && baseline.hasResponse()) {
            HttpResponse resp = baseline.response();
            this.baselineStatusCode = resp.statusCode();
            this.baselineLength = resp.toByteArray().length();
        }
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public String getMethod() {
        return method;
    }

    public String getHost() {
        return host;
    }

    public String getPath() {
        return path;
    }

    public String getUrl() {
        return url;
    }

    public int getBaselineStatusCode() {
        return baselineStatusCode;
    }

    public long getBaselineLength() {
        return baselineLength;
    }

    public List<TimerInterval> getIntervals() {
        return intervals;
    }

    public void setIntervals(List<TimerInterval> newIntervals) {
        this.intervals.clear();
        if (newIntervals != null) {
            List<TimerInterval> sorted = new ArrayList<>(newIntervals);
            Collections.sort(sorted);
            this.intervals.addAll(sorted);
        }
    }

    public void addInterval(TimerInterval interval) {
        this.intervals.add(interval);
        Collections.sort(this.intervals);
    }

    public SessionState getState() {
        return state;
    }

    public void setState(SessionState state) {
        this.state = state;
    }

    public String getLastVerdict() {
        return lastVerdict;
    }

    public void setLastVerdict(String lastVerdict) {
        this.lastVerdict = lastVerdict;
    }

    public boolean isCancelOnExpire() {
        return cancelOnExpire;
    }

    public void setCancelOnExpire(boolean cancelOnExpire) {
        this.cancelOnExpire = cancelOnExpire;
    }

    /**
     * Finds the next scheduled interval waiting to run.
     */
    public TimerInterval getNextScheduledInterval() {
        for (TimerInterval interval : intervals) {
            if (interval.getStatus() == TimerInterval.IntervalStatus.SCHEDULED) {
                return interval;
            }
        }
        return null;
    }

    /**
     * Formats countdown to next scheduled probe or current state string.
     */
    public String getNextCountdownFormatted() {
        if (state == SessionState.EXPIRED) {
            return "Expired (Stopped)";
        }
        if (state == SessionState.CANCELLED) {
            return "Cancelled";
        }
        if (state == SessionState.COMPLETED) {
            return "Completed";
        }
        if (state == SessionState.RUNNING) {
            return "Probing now...";
        }

        TimerInterval next = getNextScheduledInterval();
        if (next == null || next.getScheduledTargetTime() == null) {
            return "None pending";
        }

        long secondsLeft = Duration.between(Instant.now(), next.getScheduledTargetTime()).toSeconds();
        if (secondsLeft <= 0) {
            return "Due now";
        }

        return TimerInterval.formatDuration(secondsLeft) + " (" + next.getLabel() + ")";
    }

    /**
     * Counts completed intervals vs total.
     */
    public String getIntervalProgressFormatted() {
        int done = 0;
        for (TimerInterval ti : intervals) {
            if (ti.getStatus() == TimerInterval.IntervalStatus.PASSED
                    || ti.getStatus() == TimerInterval.IntervalStatus.EXPIRED
                    || ti.getStatus() == TimerInterval.IntervalStatus.ERROR) {
                done++;
            }
        }
        return done + "/" + intervals.size();
    }

    /**
     * Cancels all remaining scheduled futures for this task.
     */
    public void cancelRemainingFutures() {
        for (TimerInterval ti : intervals) {
            if (ti.getStatus() == TimerInterval.IntervalStatus.SCHEDULED) {
                ti.cancelFuture();
            }
        }
    }

    /**
     * Returns the latest executed probe result across all intervals.
     */
    public ProbeResult getLatestProbeResult() {
        for (int i = intervals.size() - 1; i >= 0; i--) {
            ProbeResult pr = intervals.get(i).getProbeResult();
            if (pr != null) {
                return pr;
            }
        }
        return null;
    }
}
