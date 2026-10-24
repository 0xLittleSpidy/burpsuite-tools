// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.model;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Thread-safe global data store for WordPress targets, cache, and configurations.
 */
public class WordPressDataStore_littlespidy {
    private final Map<String, WordPressTarget_littlespidy> targetMap = new ConcurrentHashMap<>();
    private final List<WordPressTarget_littlespidy> targetList = new CopyOnWriteArrayList<>();
    private final ScanConfig_littlespidy config = new ScanConfig_littlespidy();

    // 24-hour WPScan API in-memory cache
    private final Map<String, CachedApiEntry_littlespidy> apiCache = new ConcurrentHashMap<>();
    private static final long CACHE_TTL_MS = 24L * 60L * 60L * 1000L;

    public interface DataStoreListener {
        void onTargetAdded(WordPressTarget_littlespidy target);
        void onTargetRemoved(WordPressTarget_littlespidy target);
    }

    private final List<DataStoreListener> listeners = new CopyOnWriteArrayList<>();

    public void addListener(DataStoreListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public void removeListener(DataStoreListener listener) {
        listeners.remove(listener);
    }

    public WordPressTarget_littlespidy getOrCreateTarget(String rawUrl, String host) {
        String normalizedKey = normalizeHost(host != null && !host.isEmpty() ? host : rawUrl);
        WordPressTarget_littlespidy existing = targetMap.get(normalizedKey);
        if (existing != null) {
            return existing;
        }

        String safeUrl = rawUrl != null && !rawUrl.isEmpty() ? rawUrl : "https://" + normalizedKey + "/";
        WordPressTarget_littlespidy created = new WordPressTarget_littlespidy(safeUrl, normalizedKey);
        targetMap.put(normalizedKey, created);
        targetList.add(created);

        for (DataStoreListener listener : listeners) {
            listener.onTargetAdded(created);
        }
        return created;
    }

    public WordPressTarget_littlespidy getTarget(String hostOrKey) {
        String normalizedKey = normalizeHost(hostOrKey);
        return targetMap.get(normalizedKey);
    }

    public List<WordPressTarget_littlespidy> getAllTargets() {
        return Collections.unmodifiableList(targetList);
    }

    public void removeTarget(String hostOrKey) {
        String normalizedKey = normalizeHost(hostOrKey);
        WordPressTarget_littlespidy removed = targetMap.remove(normalizedKey);
        if (removed != null) {
            targetList.remove(removed);
            for (DataStoreListener listener : listeners) {
                listener.onTargetRemoved(removed);
            }
        }
    }

    public void clearAllTargets() {
        for (WordPressTarget_littlespidy target : new ArrayList<>(targetList)) {
            removeTarget(target.getRootDomain());
        }
    }

    public ScanConfig_littlespidy getConfig() {
        return config;
    }

    // ── Cache Operations ──
    public static class CachedApiEntry_littlespidy {
        private final List<VulnerabilityEntry_littlespidy> vulnerabilities;
        private final long timestamp;

        public CachedApiEntry_littlespidy(List<VulnerabilityEntry_littlespidy> vulnerabilities) {
            this.vulnerabilities = vulnerabilities != null ? vulnerabilities : new ArrayList<>();
            this.timestamp = System.currentTimeMillis();
        }

        public boolean isValid() {
            return (System.currentTimeMillis() - timestamp) < CACHE_TTL_MS;
        }

        public List<VulnerabilityEntry_littlespidy> getVulnerabilities() {
            return vulnerabilities;
        }
    }

    public CachedApiEntry_littlespidy getCachedEntry(String type, String slugOrVersion) {
        if (!config.isCache24hEnabled()) {
            return null;
        }
        String key = type.toLowerCase() + ":" + slugOrVersion.toLowerCase();
        CachedApiEntry_littlespidy entry = apiCache.get(key);
        if (entry != null && entry.isValid()) {
            return entry;
        }
        if (entry != null && !entry.isValid()) {
            apiCache.remove(key);
        }
        return null;
    }

    public void putCacheEntry(String type, String slugOrVersion, List<VulnerabilityEntry_littlespidy> vulns) {
        String key = type.toLowerCase() + ":" + slugOrVersion.toLowerCase();
        apiCache.put(key, new CachedApiEntry_littlespidy(vulns));
    }

    public static String normalizeHost(String input) {
        if (input == null) return "";
        String s = input.trim().toLowerCase();
        if (s.startsWith("http://")) s = s.substring(7);
        if (s.startsWith("https://")) s = s.substring(8);
        int slashIdx = s.indexOf('/');
        if (slashIdx != -1) s = s.substring(0, slashIdx);
        int colonIdx = s.indexOf(':');
        if (colonIdx != -1) s = s.substring(0, colonIdx);
        return s;
    }
}
