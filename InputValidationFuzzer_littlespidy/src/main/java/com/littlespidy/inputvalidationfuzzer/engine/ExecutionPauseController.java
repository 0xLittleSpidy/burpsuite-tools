package com.littlespidy.inputvalidationfuzzer.engine;

import java.util.function.BooleanSupplier;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Cooperative pause/resume gate that allows non-blocking worker thread control.
 *
 * @author littlespidy
 */
public class ExecutionPauseController {
    private final Object lock = new Object();
    private volatile boolean paused = false;

    public void pause() {
        synchronized (lock) {
            paused = true;
        }
    }

    public void resume() {
        synchronized (lock) {
            paused = false;
            lock.notifyAll();
        }
    }

    public boolean isPaused() {
        return paused;
    }

    public void awaitIfPaused(BooleanSupplier shouldContinue) {
        synchronized (lock) {
            while (paused && shouldContinue.getAsBoolean()) {
                try {
                    lock.wait(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }
}
