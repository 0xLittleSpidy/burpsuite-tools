package com.littlespidy.uploadscanner.model;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Master configuration for Upload Scanner execution.
 *
 * @author littlespidy
 */
public class UploadScannerConfig {
    private final ReDownloaderConfig redownloaderConfig = new ReDownloaderConfig();
    private int throttleMs = 50;
    private boolean followRedirects = true;

    private boolean testWebShells = true;
    private boolean testPolyglots = true;
    private boolean testPathTraversal = true;
    private boolean testExtensionBypasses = true;
    private boolean testSvgXss = true;
    private boolean testEicar = true;

    public ReDownloaderConfig getRedownloaderConfig() {
        return redownloaderConfig;
    }

    public int getThrottleMs() {
        return throttleMs;
    }

    public void setThrottleMs(int throttleMs) {
        this.throttleMs = Math.max(0, throttleMs);
    }

    public boolean isFollowRedirects() {
        return followRedirects;
    }

    public void setFollowRedirects(boolean followRedirects) {
        this.followRedirects = followRedirects;
    }

    public boolean isTestWebShells() {
        return testWebShells;
    }

    public void setTestWebShells(boolean testWebShells) {
        this.testWebShells = testWebShells;
    }

    public boolean isTestPolyglots() {
        return testPolyglots;
    }

    public void setTestPolyglots(boolean testPolyglots) {
        this.testPolyglots = testPolyglots;
    }

    public boolean isTestPathTraversal() {
        return testPathTraversal;
    }

    public void setTestPathTraversal(boolean testPathTraversal) {
        this.testPathTraversal = testPathTraversal;
    }

    public boolean isTestExtensionBypasses() {
        return testExtensionBypasses;
    }

    public void setTestExtensionBypasses(boolean testExtensionBypasses) {
        this.testExtensionBypasses = testExtensionBypasses;
    }

    public boolean isTestSvgXss() {
        return testSvgXss;
    }

    public void setTestSvgXss(boolean testSvgXss) {
        this.testSvgXss = testSvgXss;
    }

    public boolean isTestEicar() {
        return testEicar;
    }

    public void setTestEicar(boolean testEicar) {
        this.testEicar = testEicar;
    }
}
