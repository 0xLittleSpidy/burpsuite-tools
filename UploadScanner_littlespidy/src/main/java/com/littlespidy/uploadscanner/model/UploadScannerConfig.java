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

    // Category 1: Server-Side Execution (RCE)
    private boolean testPhp = true;
    private boolean testJsp = true;
    private boolean testAsp = true;
    private boolean testHtaccess = true;
    private boolean testWebConfig = true;
    private boolean testCgi = true;
    private boolean testSsiEsi = true;

    // Category 2: Image Library Exploits
    private boolean testImageTragick = true;
    private boolean testMagickDelegates = true;
    private boolean testGhostscript = true;
    private boolean testLibavformat = true;

    // Category 3: XML & Document Attacks
    private boolean testXxeSvg = true;
    private boolean testXxeXml = true;
    private boolean testXxeOffice = true;
    private boolean testXxeXmp = true;
    private boolean testPdfInjections = true;
    private boolean testCsvFormula = true;

    // Category 4: Client-Side & Polyglots
    private boolean testXssHtml = true;
    private boolean testXssSvg = true;
    private boolean testXssSwf = true;
    private boolean testPolyglotJpeg = true;
    private boolean testPolyglotGif = true;

    // Category 5: Archives, Quirks & DoS
    private boolean testZipSlip = true;
    private boolean testTarSymlink = true;
    private boolean testUploadQuirks = true;
    private boolean testEicar = true;
    private boolean testPixelFlood = false; // DoS off by default
    private boolean testBillionLaughs = false; // DoS off by default

    // Category 6: Allowed Extensions Matrix
    private boolean testAllowedExtensions = true;
    private boolean testExtImages = true;
    private boolean testExtDocuments = true;
    private boolean testExtWebData = true;
    private boolean testExtArchives = true;
    private boolean testExtMedia = true;
    private String customExtensions = "";

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

    // Category 1: Server-Side Execution Getters & Setters
    public boolean isTestPhp() { return testPhp; }
    public void setTestPhp(boolean testPhp) { this.testPhp = testPhp; }

    public boolean isTestJsp() { return testJsp; }
    public void setTestJsp(boolean testJsp) { this.testJsp = testJsp; }

    public boolean isTestAsp() { return testAsp; }
    public void setTestAsp(boolean testAsp) { this.testAsp = testAsp; }

    public boolean isTestHtaccess() { return testHtaccess; }
    public void setTestHtaccess(boolean testHtaccess) { this.testHtaccess = testHtaccess; }

    public boolean isTestWebConfig() { return testWebConfig; }
    public void setTestWebConfig(boolean testWebConfig) { this.testWebConfig = testWebConfig; }

    public boolean isTestCgi() { return testCgi; }
    public void setTestCgi(boolean testCgi) { this.testCgi = testCgi; }

    public boolean isTestSsiEsi() { return testSsiEsi; }
    public void setTestSsiEsi(boolean testSsiEsi) { this.testSsiEsi = testSsiEsi; }

    // Category 2: Image Libraries Getters & Setters
    public boolean isTestImageTragick() { return testImageTragick; }
    public void setTestImageTragick(boolean testImageTragick) { this.testImageTragick = testImageTragick; }

    public boolean isTestMagickDelegates() { return testMagickDelegates; }
    public void setTestMagickDelegates(boolean testMagickDelegates) { this.testMagickDelegates = testMagickDelegates; }

    public boolean isTestGhostscript() { return testGhostscript; }
    public void setTestGhostscript(boolean testGhostscript) { this.testGhostscript = testGhostscript; }

    public boolean isTestLibavformat() { return testLibavformat; }
    public void setTestLibavformat(boolean testLibavformat) { this.testLibavformat = testLibavformat; }

    // Category 3: XML & Document Attacks Getters & Setters
    public boolean isTestXxeSvg() { return testXxeSvg; }
    public void setTestXxeSvg(boolean testXxeSvg) { this.testXxeSvg = testXxeSvg; }

    public boolean isTestXxeXml() { return testXxeXml; }
    public void setTestXxeXml(boolean testXxeXml) { this.testXxeXml = testXxeXml; }

    public boolean isTestXxeOffice() { return testXxeOffice; }
    public void setTestXxeOffice(boolean testXxeOffice) { this.testXxeOffice = testXxeOffice; }

    public boolean isTestXxeXmp() { return testXxeXmp; }
    public void setTestXxeXmp(boolean testXxeXmp) { this.testXxeXmp = testXxeXmp; }

    public boolean isTestPdfInjections() { return testPdfInjections; }
    public void setTestPdfInjections(boolean testPdfInjections) { this.testPdfInjections = testPdfInjections; }

    public boolean isTestCsvFormula() { return testCsvFormula; }
    public void setTestCsvFormula(boolean testCsvFormula) { this.testCsvFormula = testCsvFormula; }

    // Category 4: Client-Side & Polyglots Getters & Setters
    public boolean isTestXssHtml() { return testXssHtml; }
    public void setTestXssHtml(boolean testXssHtml) { this.testXssHtml = testXssHtml; }

    public boolean isTestXssSvg() { return testXssSvg; }
    public void setTestXssSvg(boolean testXssSvg) { this.testXssSvg = testXssSvg; }

    public boolean isTestXssSwf() { return testXssSwf; }
    public void setTestXssSwf(boolean testXssSwf) { this.testXssSwf = testXssSwf; }

    public boolean isTestPolyglotJpeg() { return testPolyglotJpeg; }
    public void setTestPolyglotJpeg(boolean testPolyglotJpeg) { this.testPolyglotJpeg = testPolyglotJpeg; }

    public boolean isTestPolyglotGif() { return testPolyglotGif; }
    public void setTestPolyglotGif(boolean testPolyglotGif) { this.testPolyglotGif = testPolyglotGif; }

    // Category 5: Archives, Quirks & DoS Getters & Setters
    public boolean isTestZipSlip() { return testZipSlip; }
    public void setTestZipSlip(boolean testZipSlip) { this.testZipSlip = testZipSlip; }

    public boolean isTestTarSymlink() { return testTarSymlink; }
    public void setTestTarSymlink(boolean testTarSymlink) { this.testTarSymlink = testTarSymlink; }

    public boolean isTestUploadQuirks() { return testUploadQuirks; }
    public void setTestUploadQuirks(boolean testUploadQuirks) { this.testUploadQuirks = testUploadQuirks; }

    public boolean isTestEicar() { return testEicar; }
    public void setTestEicar(boolean testEicar) { this.testEicar = testEicar; }

    public boolean isTestPixelFlood() { return testPixelFlood; }
    public void setTestPixelFlood(boolean testPixelFlood) { this.testPixelFlood = testPixelFlood; }

    public boolean isTestBillionLaughs() { return testBillionLaughs; }
    public void setTestBillionLaughs(boolean testBillionLaughs) { this.testBillionLaughs = testBillionLaughs; }

    // Category 6: Allowed Extensions Getters & Setters
    public boolean isTestAllowedExtensions() { return testAllowedExtensions; }
    public void setTestAllowedExtensions(boolean testAllowedExtensions) { this.testAllowedExtensions = testAllowedExtensions; }

    public boolean isTestExtImages() { return testExtImages; }
    public void setTestExtImages(boolean testExtImages) { this.testExtImages = testExtImages; }

    public boolean isTestExtDocuments() { return testExtDocuments; }
    public void setTestExtDocuments(boolean testExtDocuments) { this.testExtDocuments = testExtDocuments; }

    public boolean isTestExtWebData() { return testExtWebData; }
    public void setTestExtWebData(boolean testExtWebData) { this.testExtWebData = testExtWebData; }

    public boolean isTestExtArchives() { return testExtArchives; }
    public void setTestExtArchives(boolean testExtArchives) { this.testExtArchives = testExtArchives; }

    public boolean isTestExtMedia() { return testExtMedia; }
    public void setTestExtMedia(boolean testExtMedia) { this.testExtMedia = testExtMedia; }

    public String getCustomExtensions() { return customExtensions; }
    public void setCustomExtensions(String customExtensions) { this.customExtensions = customExtensions != null ? customExtensions.trim() : ""; }

    // Category Bulk Selectors
    public void selectCategory(String category, boolean selected) {
        if ("Server RCE".equalsIgnoreCase(category)) {
            setTestPhp(selected);
            setTestJsp(selected);
            setTestAsp(selected);
            setTestHtaccess(selected);
            setTestWebConfig(selected);
            setTestCgi(selected);
            setTestSsiEsi(selected);
        } else if ("Image Libraries".equalsIgnoreCase(category)) {
            setTestImageTragick(selected);
            setTestMagickDelegates(selected);
            setTestGhostscript(selected);
            setTestLibavformat(selected);
        } else if ("XML & Documents".equalsIgnoreCase(category)) {
            setTestXxeSvg(selected);
            setTestXxeXml(selected);
            setTestXxeOffice(selected);
            setTestXxeXmp(selected);
            setTestPdfInjections(selected);
            setTestCsvFormula(selected);
        } else if ("Client-Side".equalsIgnoreCase(category) || "Client & Polyglots".equalsIgnoreCase(category)) {
            setTestXssHtml(selected);
            setTestXssSvg(selected);
            setTestXssSwf(selected);
            setTestPolyglotJpeg(selected);
            setTestPolyglotGif(selected);
        } else if ("Archives & Quirks".equalsIgnoreCase(category) || "Archives & DoS".equalsIgnoreCase(category)) {
            setTestZipSlip(selected);
            setTestTarSymlink(selected);
            setTestUploadQuirks(selected);
            setTestEicar(selected);
            setTestPixelFlood(selected);
            setTestBillionLaughs(selected);
        } else if ("Allowed Extensions".equalsIgnoreCase(category) || "Allowed Extensions Matrix".equalsIgnoreCase(category)) {
            setTestAllowedExtensions(selected);
            setTestExtImages(selected);
            setTestExtDocuments(selected);
            setTestExtWebData(selected);
            setTestExtArchives(selected);
            setTestExtMedia(selected);
        }
    }

    public void selectAll(boolean selected) {
        selectCategory("Server RCE", selected);
        selectCategory("Image Libraries", selected);
        selectCategory("XML & Documents", selected);
        selectCategory("Client & Polyglots", selected);
        selectCategory("Archives & Quirks", selected);
        selectCategory("Allowed Extensions", selected);
    }

    // Backwards-Compatible Aliases
    public boolean isTestWebShells() { return testPhp || testJsp || testAsp; }
    public void setTestWebShells(boolean val) { setTestPhp(val); setTestJsp(val); setTestAsp(val); }

    public boolean isTestPolyglots() { return testPolyglotJpeg || testPolyglotGif; }
    public void setTestPolyglots(boolean val) { setTestPolyglotJpeg(val); setTestPolyglotGif(val); }

    public boolean isTestPathTraversal() { return testZipSlip || testTarSymlink; }
    public void setTestPathTraversal(boolean val) { setTestZipSlip(val); setTestTarSymlink(val); }

    public boolean isTestExtensionBypasses() { return testUploadQuirks; }
    public void setTestExtensionBypasses(boolean val) { setTestUploadQuirks(val); }

    public boolean isTestSvgXss() { return testXssSvg; }
    public void setTestSvgXss(boolean val) { setTestXssSvg(val); }
}
