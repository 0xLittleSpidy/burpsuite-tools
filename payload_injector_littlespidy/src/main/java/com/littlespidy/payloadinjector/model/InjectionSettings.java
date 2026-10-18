// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.model;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Configuration holder for parameter injection modes, encodings, and target parameter types.
 *
 * @author littlespidy
 */
public class InjectionSettings {

    public enum InjectionMode {
        REPLACE("Replace parameter value"),
        APPEND("Append to parameter value"),
        PREPEND("Prepend to parameter value");

        private final String display;
        InjectionMode(String display) { this.display = display; }
        public String getDisplay() { return display; }
        @Override public String toString() { return display; }
    }

    public enum EncodingMode {
        AUTO("Auto (URL encode Query/Body, Raw for JSON)"),
        URL_ENCODE("Always URL encode special characters"),
        NONE("Raw (No URL encoding)");

        private final String display;
        EncodingMode(String display) { this.display = display; }
        public String getDisplay() { return display; }
        @Override public String toString() { return display; }
    }

    private InjectionMode injectionMode = InjectionMode.REPLACE;
    private EncodingMode encodingMode = EncodingMode.AUTO;
    private boolean targetUrlParams = true;
    private boolean targetBodyParams = true;
    private boolean targetJsonParams = true;
    private boolean targetCookieParams = false;

    private final List<Runnable> changeListeners = new CopyOnWriteArrayList<>();

    public InjectionMode getInjectionMode() {
        return injectionMode;
    }

    public void setInjectionMode(InjectionMode injectionMode) {
        this.injectionMode = injectionMode;
        notifyChange();
    }

    public EncodingMode getEncodingMode() {
        return encodingMode;
    }

    public void setEncodingMode(EncodingMode encodingMode) {
        this.encodingMode = encodingMode;
        notifyChange();
    }

    public boolean isTargetUrlParams() {
        return targetUrlParams;
    }

    public void setTargetUrlParams(boolean targetUrlParams) {
        this.targetUrlParams = targetUrlParams;
        notifyChange();
    }

    public boolean isTargetBodyParams() {
        return targetBodyParams;
    }

    public void setTargetBodyParams(boolean targetBodyParams) {
        this.targetBodyParams = targetBodyParams;
        notifyChange();
    }

    public boolean isTargetJsonParams() {
        return targetJsonParams;
    }

    public void setTargetJsonParams(boolean targetJsonParams) {
        this.targetJsonParams = targetJsonParams;
        notifyChange();
    }

    public boolean isTargetCookieParams() {
        return targetCookieParams;
    }

    public void setTargetCookieParams(boolean targetCookieParams) {
        this.targetCookieParams = targetCookieParams;
        notifyChange();
    }

    public void addChangeListener(Runnable listener) {
        changeListeners.add(listener);
    }

    public void removeChangeListener(Runnable listener) {
        changeListeners.remove(listener);
    }

    private void notifyChange() {
        for (Runnable r : changeListeners) {
            try {
                r.run();
            } catch (Exception ignored) {}
        }
    }
}
