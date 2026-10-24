// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.engine;

import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import com.littlespidy.wordpressinspector.model.PluginFinding_littlespidy;
import com.littlespidy.wordpressinspector.model.ThemeFinding_littlespidy;
import com.littlespidy.wordpressinspector.model.WordPressDataStore_littlespidy;
import com.littlespidy.wordpressinspector.model.WordPressTarget_littlespidy;

import java.util.List;
import java.util.Set;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Passively intercepts Burp Suite Proxy responses to detect WordPress installations,
 * versions, plugins, and themes during normal web security testing.
 */
public class WordPressPassiveHandler_littlespidy implements ProxyResponseHandler {

    private final WordPressDataStore_littlespidy dataStore;

    public WordPressPassiveHandler_littlespidy(WordPressDataStore_littlespidy dataStore) {
        this.dataStore = dataStore;
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        if (!dataStore.getConfig().isLiveScanEnabled()) {
            return ProxyResponseReceivedAction.continueWith(response);
        }

        try {
            String body = response.bodyToString();
            List<String> headers = response.headers().stream().map(h -> h.name() + ": " + h.value()).toList();

            if (WordPressDetectionEngine_littlespidy.isWordPressTraffic(body, headers)) {
                String host = response.initiatingRequest().httpService().host();
                String url = response.initiatingRequest().url();

                WordPressTarget_littlespidy target = dataStore.getOrCreateTarget(url, host);

                // Detect Core Version
                if ("Unknown".equals(target.getDetectedVersion())) {
                    String version = WordPressDetectionEngine_littlespidy.extractVersion(body);
                    if (version != null) {
                        target.setDetectedVersion(version);
                    }
                }

                // Detect Plugins
                Set<String> plugins = WordPressDetectionEngine_littlespidy.extractPlugins(body);
                for (String slug : plugins) {
                    PluginFinding_littlespidy p = new PluginFinding_littlespidy(slug);
                    p.setHighRisk(WordPressDetectionEngine_littlespidy.isHighRiskPlugin(slug));
                    p.setDetectionSource("Live Traffic");
                    target.addPlugin(p);
                }

                // Detect Themes
                Set<String> themes = WordPressDetectionEngine_littlespidy.extractThemes(body);
                for (String slug : themes) {
                    ThemeFinding_littlespidy t = new ThemeFinding_littlespidy(slug);
                    t.setDetectionPath("Live HTTP Response");
                    target.addTheme(t);
                }

                target.notifyUpdate();
            }
        } catch (Exception ignored) {
        }

        return ProxyResponseReceivedAction.continueWith(response);
    }

    @Override
    public burp.api.montoya.proxy.http.ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        return burp.api.montoya.proxy.http.ProxyResponseToBeSentAction.continueWith(response);
    }
}
