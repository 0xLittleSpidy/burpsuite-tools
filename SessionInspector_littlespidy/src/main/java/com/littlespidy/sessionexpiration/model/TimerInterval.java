// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledFuture;

/**
 * Represents an individual timed probe milestone (e.g. +30 min, +1 hr, +3 hr).
 *
 * @author littlespidy
 */
public class TimerInterval implements Comparable<TimerInterval> {

    public enum IntervalStatus {
        SCHEDULED("Scheduled"),
        RUNNING("Running"),
        PASSED("Active / Passed"),
        EXPIRED("Expired"),
        CANCELLED("Cancelled"),
        ERROR("Error");

        private final String label;
        IntervalStatus(String label) { this.label = label; }
        public String getLabel() { return label; }
        @Override public String toString() { return label; }
    }

    private final long delaySeconds;
    private final String label;
    private Instant scheduledTargetTime;
    private Instant executedTime;
    private IntervalStatus status = IntervalStatus.SCHEDULED;
    private ProbeResult probeResult;
    private transient ScheduledFuture<?> scheduledFuture;

    public TimerInterval(long delaySeconds, String label) {
        this.delaySeconds = delaySeconds;
        this.label = label;
    }

    public static String formatDuration(long seconds) {
        if (seconds < 60) {
            return seconds + "s";
        }
        long minutes = seconds / 60;
        if (minutes < 60) {
            long remSec = seconds % 60;
            return remSec > 0 ? minutes + "m " + remSec + "s" : minutes + "m";
        }
        long hours = minutes / 60;
        long remMin = minutes % 60;
        if (hours < 24) {
            return remMin > 0 ? hours + "h " + remMin + "m" : hours + "h";
        }
        long days = hours / 24;
        long remHrs = hours % 24;
        return remHrs > 0 ? days + "d " + remHrs + "h" : days + "d";
    }

    public static TimerInterval ofMinutes(long minutes) {
        return new TimerInterval(minutes * 60, formatDuration(minutes * 60));
    }

    public static TimerInterval ofHours(long hours) {
        return new TimerInterval(hours * 3600, formatDuration(hours * 3600));
    }

    public static TimerInterval ofSeconds(long seconds) {
        return new TimerInterval(seconds, formatDuration(seconds));
    }

    /**
     * Creates the standard 16 milestone intervals every 30 minutes from 30 min up to 8 hours:
     * 30m, 1h, 1h 30m, 2h, 2h 30m, 3h, 3h 30m, 4h, 4h 30m, 5h, 5h 30m, 6h, 6h 30m, 7h, 7h 30m, 8h.
     */
    public static List<TimerInterval> createDefaultMilestones() {
        List<TimerInterval> list = new ArrayList<>();
        for (int i = 1; i <= 16; i++) {
            list.add(TimerInterval.ofMinutes(i * 30L));
        }
        return list;
    }

    public long getDelaySeconds() {
        return delaySeconds;
    }

    public String getLabel() {
        return label;
    }

    public Instant getScheduledTargetTime() {
        return scheduledTargetTime;
    }

    public void setScheduledTargetTime(Instant scheduledTargetTime) {
        this.scheduledTargetTime = scheduledTargetTime;
    }

    public Instant getExecutedTime() {
        return executedTime;
    }

    public void setExecutedTime(Instant executedTime) {
        this.executedTime = executedTime;
    }

    public IntervalStatus getStatus() {
        return status;
    }

    public void setStatus(IntervalStatus status) {
        this.status = status;
    }

    public ProbeResult getProbeResult() {
        return probeResult;
    }

    public void setProbeResult(ProbeResult probeResult) {
        this.probeResult = probeResult;
    }

    public ScheduledFuture<?> getScheduledFuture() {
        return scheduledFuture;
    }

    public void setScheduledFuture(ScheduledFuture<?> scheduledFuture) {
        this.scheduledFuture = scheduledFuture;
    }

    public void cancelFuture() {
        if (scheduledFuture != null && !scheduledFuture.isDone()) {
            scheduledFuture.cancel(true);
        }
        if (status == IntervalStatus.SCHEDULED) {
            status = IntervalStatus.CANCELLED;
        }
    }

    @Override
    public int compareTo(TimerInterval o) {
        return Long.compare(this.delaySeconds, o.delaySeconds);
    }
}
