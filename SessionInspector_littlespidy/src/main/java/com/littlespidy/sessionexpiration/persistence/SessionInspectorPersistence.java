// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.persistence;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.sessionexpiration.cookiefinder.FinderResult;
import com.littlespidy.sessionexpiration.cookiefinder.SessionCookieFinderTab;
import com.littlespidy.sessionexpiration.cookiefinder.SingleCookieFinderPanel;
import com.littlespidy.sessionexpiration.cookiestore.knowledge.CookieDocRecord;
import com.littlespidy.sessionexpiration.cookiestore.knowledge.CookieSearchKnowledgeBase;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieNameGroup;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieSource;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieStoreDataStore;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieValueRecord;
import com.littlespidy.sessionexpiration.model.*;

import java.awt.Component;
import java.awt.Frame;
import java.awt.GraphicsEnvironment;
import java.awt.Window;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;

/**
 * Manages full persistent storage of Session Inspector data across extension reloads,
 * uninstalls/re-adds, and Burp Suite restarts.
 *
 * Saves state to a dedicated JSON database (by default in the Burp project directory,
 * or user-specified folder for temporary projects).
 * Features thread-safe atomic writes via temporary files, non-blocking debounced auto-saves,
 * and high-fidelity serialization of Montoya HTTP request and response objects.
 *
 * @author littlespidy
 */
public class SessionInspectorPersistence {

    public static final String PREF_KEY_STORAGE_DIR = "session_inspector_storage_dir";
    public static final String FILE_NAME = "session_inspector_store.json";
    private static final String DEFAULT_FALLBACK_DIR = ".burp_session_inspector";

    private static Path currentStorageDirectory = null;

    private static final ScheduledExecutorService DEBOUNCE_EXECUTOR = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "SessionInspector-Persistence-Thread");
        t.setDaemon(true);
        return t;
    });

    private static ScheduledFuture<?> pendingSaveTask = null;
    private static final Object SAVE_LOCK = new Object();
    private static long lastSaveTimestamp = 0;

    public static Path getStorageDirectory() {
        if (currentStorageDirectory == null) {
            currentStorageDirectory = Paths.get(System.getProperty("user.home"), DEFAULT_FALLBACK_DIR);
        }
        return currentStorageDirectory;
    }

    public static void setStorageDirectory(Path dir) {
        if (dir != null) {
            currentStorageDirectory = dir;
        }
    }

    /**
     * Returns the absolute Path to the persistent storage file.
     */
    public static Path getStoragePath() {
        return getStorageDirectory().resolve(FILE_NAME);
    }

    public static Path resolveStorageDirectory(MontoyaApi api) {
        return resolveStorageDirectory(api, null);
    }

    public static Path resolveStorageDirectory(MontoyaApi api, Window parentWindow) {
        // 1. Try detecting active Burp project file on disk
        Path detectedProjectDir = detectBurpProjectDirectory(api);
        if (detectedProjectDir != null && Files.isDirectory(detectedProjectDir)) {
            currentStorageDirectory = detectedProjectDir;
            if (api != null) {
                api.logging().logToOutput("[Session Inspector] Using active Burp project directory: " + currentStorageDirectory);
            }
            return currentStorageDirectory;
        }

        // 2. Running in a Temporary Project (no disk project available)
        String savedPrefDir = null;
        try {
            if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
                savedPrefDir = api.persistence().preferences().getString(PREF_KEY_STORAGE_DIR);
            }
        } catch (Exception ignored) {}

        Path chosenDir = promptUserForStorageDirectory(api, parentWindow, savedPrefDir);
        if (chosenDir != null) {
            currentStorageDirectory = chosenDir;
            try {
                if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
                    api.persistence().preferences().setString(PREF_KEY_STORAGE_DIR, chosenDir.toAbsolutePath().toString());
                }
            } catch (Exception ignored) {}
            if (api != null) {
                api.logging().logToOutput("[Session Inspector] Temporary project storage directory set to: " + currentStorageDirectory);
            }
            return currentStorageDirectory;
        }

        if (savedPrefDir != null && !savedPrefDir.isBlank()) {
            Path p = Paths.get(savedPrefDir);
            if (Files.exists(p)) {
                currentStorageDirectory = p;
                if (api != null) {
                    api.logging().logToOutput("[Session Inspector] Using previously configured temporary project storage directory: " + currentStorageDirectory);
                }
                return currentStorageDirectory;
            }
        }

        currentStorageDirectory = Paths.get(System.getProperty("user.home"), DEFAULT_FALLBACK_DIR);
        if (api != null) {
            api.logging().logToOutput("[Session Inspector] Fallback storage directory: " + currentStorageDirectory);
        }
        return currentStorageDirectory;
    }

    public static Path detectBurpProjectDirectory(MontoyaApi api) {
        if (api == null) return null;

        // A. Check command line arguments
        try {
            List<String> args = api.burpSuite().commandLineArguments();
            if (args != null) {
                for (int i = 0; i < args.size(); i++) {
                    String arg = args.get(i);
                    if (arg.startsWith("--project-file=")) {
                        String filePath = arg.substring("--project-file=".length()).trim();
                        Path p = Paths.get(filePath);
                        if (p.getParent() != null && Files.exists(p.getParent())) {
                            return p.getParent();
                        }
                    } else if ("--project-file".equals(arg) && i + 1 < args.size()) {
                        String filePath = args.get(i + 1).trim();
                        Path p = Paths.get(filePath);
                        if (p.getParent() != null && Files.exists(p.getParent())) {
                            return p.getParent();
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        // B. Check Burp Suite Frame title
        try {
            Frame frame = api.userInterface() != null && api.userInterface().swingUtils() != null
                    ? api.userInterface().swingUtils().suiteFrame()
                    : null;
            if (frame != null) {
                String title = frame.getTitle();
                if (title != null && !title.isBlank()) {
                    if (title.contains("[Temporary Project]") || title.contains("Temporary Project")) {
                        return null;
                    }

                    int burpIdx = title.lastIndexOf(".burp");
                    if (burpIdx > 0) {
                        int startIdx = title.lastIndexOf(" - ", burpIdx);
                        String candidateStr = (startIdx != -1) ? title.substring(startIdx + 3, burpIdx + 5).trim() : title.substring(0, burpIdx + 5).trim();
                        Path candidatePath = Paths.get(candidateStr);
                        if (Files.exists(candidatePath)) {
                            return candidatePath.getParent();
                        } else if (candidatePath.getParent() != null && Files.exists(candidatePath.getParent())) {
                            return candidatePath.getParent();
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        return null;
    }

    public static Path promptUserForStorageDirectory(MontoyaApi api, Window parentWindow, String initialDir) {
        if (GraphicsEnvironment.isHeadless()) {
            return (initialDir != null && !initialDir.isBlank()) ? Paths.get(initialDir) : null;
        }

        final Path[] result = new Path[1];
        Runnable r = () -> {
            Component parent = parentWindow;
            if (parent == null && api != null && api.userInterface() != null && api.userInterface().swingUtils() != null) {
                parent = api.userInterface().swingUtils().suiteFrame();
            }

            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Select Directory to Store Session Inspector Data (Temporary Project)");
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setAcceptAllFileFilterUsed(false);

            if (initialDir != null && !initialDir.isBlank()) {
                File initFile = new File(initialDir);
                if (initFile.exists()) {
                    chooser.setSelectedFile(initFile);
                }
            } else {
                chooser.setCurrentDirectory(new File(System.getProperty("user.home")));
            }

            int opt = chooser.showOpenDialog(parent);
            if (opt == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
                result[0] = chooser.getSelectedFile().toPath();
            }
        };

        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            try {
                SwingUtilities.invokeAndWait(r);
            } catch (Exception ex) {
                r.run();
            }
        }

        return result[0];
    }

    public static long getLastSaveTimestamp() {
        return lastSaveTimestamp;
    }

    public static long getFileSize() {
        try {
            Path p = getStoragePath();
            return Files.exists(p) ? Files.size(p) : 0;
        } catch (Exception ignored) {
            return 0;
        }
    }

    /**
     * Schedules a debounced asynchronous save (2000ms delay) to coalesce rapid updates.
     */
    public static synchronized void saveAsync(
            SessionDataStore sessionStore,
            CookieStoreDataStore cookieStore,
            SessionCookieFinderTab finderTab
    ) {
        if (pendingSaveTask != null && !pendingSaveTask.isDone()) {
            pendingSaveTask.cancel(false);
        }
        pendingSaveTask = DEBOUNCE_EXECUTOR.schedule(() -> {
            saveSync(sessionStore, cookieStore, finderTab);
        }, 2000, TimeUnit.MILLISECONDS);
    }

    /**
     * Synchronously persists all extension data to disk using an atomic file move.
     */
    public static void saveSync(
            SessionDataStore sessionStore,
            CookieStoreDataStore cookieStore,
            SessionCookieFinderTab finderTab
    ) {
        synchronized (SAVE_LOCK) {
            try {
                Path targetPath = getStoragePath();
                Path parentDir = targetPath.getParent();
                if (parentDir != null && !Files.exists(parentDir)) {
                    Files.createDirectories(parentDir);
                }

                Map<String, Object> root = new LinkedHashMap<>();
                root.put("version", 1);
                root.put("savedAt", System.currentTimeMillis());

                // 1. Serialize CookieStore
                if (cookieStore != null) {
                    root.put("cookieStore", serializeCookieStore(cookieStore));
                }

                // 2. Serialize SessionMonitor
                if (sessionStore != null) {
                    root.put("sessionMonitor", serializeSessionMonitor(sessionStore));
                }

                // 3. Serialize CookieFinder
                if (finderTab != null) {
                    root.put("cookieFinder", serializeCookieFinder(finderTab));
                }

                // 4. Serialize dynamic CookieSearch cache
                root.put("cookieSearchCache", serializeKnowledgeCache());

                String json = SimpleJson.serialize(root);
                Path tmpPath = targetPath.resolveSibling(FILE_NAME + ".tmp");

                Files.writeString(tmpPath, json, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

                try {
                    Files.move(tmpPath, targetPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmpPath, targetPath, StandardCopyOption.REPLACE_EXISTING);
                }

                lastSaveTimestamp = System.currentTimeMillis();
            } catch (Exception ex) {
                System.err.println("[Session Inspector] Error saving persistent state: " + ex.getMessage());
            }
        }
    }

    /**
     * Loads and restores all persisted state into the provided data stores and UI models.
     *
     * @return Summary message of restored items
     */
    @SuppressWarnings("unchecked")
    public static String load(
            SessionDataStore sessionStore,
            CookieStoreDataStore cookieStore,
            SessionCookieFinderTab finderTab,
            MontoyaApi api
    ) {
        synchronized (SAVE_LOCK) {
            Path targetPath = getStoragePath();
            if (!Files.exists(targetPath)) {
                return "No existing persistent state found.";
            }

            try {
                String json = Files.readString(targetPath, StandardCharsets.UTF_8);
                Object parsed = SimpleJson.parse(json);
                if (!(parsed instanceof Map<?, ?> rootMap)) {
                    return "Corrupted persistent storage file.";
                }

                Map<String, Object> root = (Map<String, Object>) rootMap;
                int cookiesRestored = 0;
                int tasksRestored = 0;
                int findingsRestored = 0;

                // 1. Restore dynamic Knowledge Base cache
                List<Object> kbCache = SimpleJson.getList(root, "cookieSearchCache");
                for (Object item : kbCache) {
                    if (item instanceof Map<?, ?> dMap) {
                        CookieDocRecord doc = deserializeCookieDoc((Map<String, Object>) dMap);
                        if (doc != null) {
                            CookieSearchKnowledgeBase.put(doc);
                        }
                    }
                }

                // 2. Restore CookieStore
                Map<String, Object> csMap = SimpleJson.getMap(root, "cookieStore");
                if (!csMap.isEmpty() && cookieStore != null) {
                    cookiesRestored = deserializeCookieStore(csMap, cookieStore, api);
                }

                // 3. Restore SessionMonitor Tasks
                Map<String, Object> smMap = SimpleJson.getMap(root, "sessionMonitor");
                if (!smMap.isEmpty() && sessionStore != null) {
                    tasksRestored = deserializeSessionMonitor(smMap, sessionStore, api);
                }

                // 4. Restore CookieFinder Findings
                Map<String, Object> cfMap = SimpleJson.getMap(root, "cookieFinder");
                if (!cfMap.isEmpty() && finderTab != null) {
                    findingsRestored = deserializeCookieFinder(cfMap, finderTab, api);
                }

                lastSaveTimestamp = SimpleJson.getLong(root, "savedAt", System.currentTimeMillis());

                return String.format("Restored %d cookies, %d session tasks, %d finder findings from persistent store.",
                        cookiesRestored, tasksRestored, findingsRestored);
            } catch (Exception ex) {
                System.err.println("[Session Inspector] Error loading persistent state: " + ex.getMessage());
                return "Error loading persistent state: " + ex.getMessage();
            }
        }
    }

    /**
     * Deletes the persistent file from disk.
     */
    public static boolean clearPersistentFile() {
        synchronized (SAVE_LOCK) {
            try {
                Path targetPath = getStoragePath();
                if (Files.exists(targetPath)) {
                    Files.delete(targetPath);
                }
                lastSaveTimestamp = 0;
                return true;
            } catch (Exception ex) {
                System.err.println("[Session Inspector] Error deleting persistent store: " + ex.getMessage());
                return false;
            }
        }
    }

    // ── Serialization Helpers ────────────────────────────────────────────────

    private static Map<String, Object> serializeCookieStore(CookieStoreDataStore cookieStore) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("totalMessagesProcessed", cookieStore.totalMessagesProcessed());

        List<Map<String, Object>> groupsList = new ArrayList<>();
        for (CookieNameGroup group : cookieStore.getAllGroups()) {
            Map<String, Object> gMap = new LinkedHashMap<>();
            gMap.put("displayName", group.displayName());
            gMap.put("source", group.source().name());

            List<Map<String, Object>> valuesList = new ArrayList<>();
            for (CookieValueRecord rec : group.getValues()) {
                Map<String, Object> vMap = new LinkedHashMap<>();
                vMap.put("id", rec.id());
                vMap.put("value", rec.value());
                vMap.put("source", rec.source().name());
                vMap.put("domains", new ArrayList<>(rec.domains()));
                vMap.put("occurrences", rec.occurrences());
                vMap.put("attributes", rec.attributes());
                vMap.put("sampleUrl", rec.sampleUrl());
                vMap.put("sampleMethod", rec.sampleMethod());
                vMap.put("sampleStatusCode", rec.sampleStatusCode());

                HttpRequestResponse msg = rec.sampleMessage();
                if (msg != null && msg.request() != null) {
                    serializeHttpMessage(msg, vMap, "msg");
                }
                valuesList.add(vMap);
            }
            gMap.put("values", valuesList);
            groupsList.add(gMap);
        }
        map.put("groups", groupsList);
        return map;
    }

    private static Map<String, Object> serializeSessionMonitor(SessionDataStore sessionStore) {
        Map<String, Object> map = new LinkedHashMap<>();
        List<Map<String, Object>> tasksList = new ArrayList<>();

        for (SessionTask task : sessionStore.getAllTasks()) {
            Map<String, Object> tMap = new LinkedHashMap<>();
            tMap.put("id", task.getId());
            tMap.put("method", task.getMethod());
            tMap.put("url", task.getUrl());
            tMap.put("host", task.getHost());
            tMap.put("path", task.getPath());
            tMap.put("state", task.getState().name());
            tMap.put("lastVerdict", task.getLastVerdict());
            tMap.put("cancelOnExpire", task.isCancelOnExpire());
            tMap.put("createdAt", (task.getCreatedAt() != null) ? task.getCreatedAt().toEpochMilli() : System.currentTimeMillis());
            tMap.put("baselineStatusCode", task.getBaselineStatusCode());
            tMap.put("baselineLength", task.getBaselineLength());

            if (task.getOriginalRequestResponse() != null) {
                serializeHttpMessage(task.getOriginalRequestResponse(), tMap, "orig");
            }
            if (task.getBaseline() != null) {
                serializeHttpMessage(task.getBaseline(), tMap, "base");
            }

            List<Map<String, Object>> intervalsList = new ArrayList<>();
            for (TimerInterval interval : task.getIntervals()) {
                Map<String, Object> iMap = new LinkedHashMap<>();
                iMap.put("delaySeconds", interval.getDelaySeconds());
                iMap.put("label", interval.getLabel());
                iMap.put("status", interval.getStatus().name());
                if (interval.getScheduledTargetTime() != null) {
                    iMap.put("scheduledTargetTime", interval.getScheduledTargetTime().toEpochMilli());
                }
                if (interval.getExecutedTime() != null) {
                    iMap.put("executedTime", interval.getExecutedTime().toEpochMilli());
                }

                ProbeResult pr = interval.getProbeResult();
                if (pr != null) {
                    Map<String, Object> prMap = new LinkedHashMap<>();
                    prMap.put("timestamp", pr.getTimestamp() != null ? pr.getTimestamp().toEpochMilli() : 0);
                    prMap.put("statusCode", pr.getStatusCode());
                    prMap.put("responseLength", pr.getResponseLength());
                    prMap.put("expired", pr.isExpired());
                    prMap.put("signal", pr.getSignal());
                    prMap.put("durationMillis", pr.getDurationMillis());
                    prMap.put("errorDetails", pr.getErrorDetails());
                    prMap.put("serverDate", pr.getServerDate());
                    if (pr.getRequestResponse() != null) {
                        serializeHttpMessage(pr.getRequestResponse(), prMap, "pr");
                    }
                    iMap.put("probeResult", prMap);
                }
                intervalsList.add(iMap);
            }
            tMap.put("intervals", intervalsList);
            tasksList.add(tMap);
        }
        map.put("tasks", tasksList);
        return map;
    }

    private static Map<String, Object> serializeCookieFinder(SessionCookieFinderTab finderTab) {
        Map<String, Object> map = new LinkedHashMap<>();

        List<SingleCookieFinderPanel> panels = finderTab.getAllPanels();
        List<Map<String, Object>> targetsList = new ArrayList<>();

        for (SingleCookieFinderPanel p : panels) {
            Map<String, Object> tMap = new LinkedHashMap<>();
            tMap.put("tabTitle", p.getTabTitle());
            tMap.put("customHeaders", p.getCustomHeaders());
            tMap.put("customHeadersEnabled", p.isCustomHeadersEnabled());

            HttpRequestResponse target = p.getTargetRequestResponse();
            if (target != null) {
                serializeHttpMessage(target, tMap, "target");
            }

            List<Map<String, Object>> resList = new ArrayList<>();
            for (FinderResult r : p.getAllResults()) {
                Map<String, Object> rMap = new LinkedHashMap<>();
                rMap.put("id", r.getId());
                rMap.put("componentName", r.getComponentName());
                rMap.put("type", r.getType().name());
                rMap.put("rawValuePreview", r.getRawValuePreview());
                rMap.put("statusCode", r.getStatusCode());
                rMap.put("responseLength", r.getResponseLength());
                rMap.put("lengthDelta", r.getLengthDelta());
                rMap.put("verdict", r.getVerdict());
                rMap.put("signalDetails", r.getSignalDetails());
                rMap.put("durationMs", r.getDurationMs());
                rMap.put("isSessionToken", r.isSessionToken());

                if (r.getRequestResponse() != null) {
                    serializeHttpMessage(r.getRequestResponse(), rMap, "item");
                }
                resList.add(rMap);
            }
            tMap.put("results", resList);
            targetsList.add(tMap);
        }

        map.put("targets", targetsList);

        // Keep top-level keys for backward compatibility
        if (!panels.isEmpty()) {
            SingleCookieFinderPanel first = panels.get(0);
            map.put("customHeaders", first.getCustomHeaders());
            if (first.getTargetRequestResponse() != null) {
                serializeHttpMessage(first.getTargetRequestResponse(), map, "target");
            }
            List<Map<String, Object>> firstResList = new ArrayList<>();
            for (FinderResult r : first.getAllResults()) {
                Map<String, Object> rMap = new LinkedHashMap<>();
                rMap.put("id", r.getId());
                rMap.put("componentName", r.getComponentName());
                rMap.put("type", r.getType().name());
                rMap.put("rawValuePreview", r.getRawValuePreview());
                rMap.put("statusCode", r.getStatusCode());
                rMap.put("responseLength", r.getResponseLength());
                rMap.put("lengthDelta", r.getLengthDelta());
                rMap.put("verdict", r.getVerdict());
                rMap.put("signalDetails", r.getSignalDetails());
                rMap.put("durationMs", r.getDurationMs());
                rMap.put("isSessionToken", r.isSessionToken());
                if (r.getRequestResponse() != null) {
                    serializeHttpMessage(r.getRequestResponse(), rMap, "item");
                }
                firstResList.add(rMap);
            }
            map.put("results", firstResList);
        }

        return map;
    }

    private static List<Map<String, Object>> serializeKnowledgeCache() {
        List<Map<String, Object>> list = new ArrayList<>();
        for (CookieDocRecord doc : CookieSearchKnowledgeBase.getAll()) {
            Map<String, Object> dMap = new LinkedHashMap<>();
            dMap.put("name", doc.name());
            dMap.put("category", doc.category());
            dMap.put("cookieId", doc.cookieId());
            dMap.put("url", doc.url());
            dMap.put("script", doc.script());
            dMap.put("description", doc.description());
            dMap.put("referenceUrl", doc.referenceUrl());
            dMap.put("related", doc.related() != null ? doc.related() : Collections.emptyList());
            list.add(dMap);
        }
        return list;
    }

    private static void serializeHttpMessage(HttpRequestResponse msg, Map<String, Object> targetMap, String prefix) {
        if (msg == null || msg.request() == null) return;
        HttpRequest req = msg.request();
        if (req.httpService() != null) {
            targetMap.put(prefix + "Host", req.httpService().host());
            targetMap.put(prefix + "Port", req.httpService().port());
            targetMap.put(prefix + "Secure", req.httpService().secure());
        }
        targetMap.put(prefix + "ReqBase64", Base64.getEncoder().encodeToString(req.toByteArray().getBytes()));
        if (msg.hasResponse() && msg.response() != null) {
            targetMap.put(prefix + "RespBase64", Base64.getEncoder().encodeToString(msg.response().toByteArray().getBytes()));
        }
    }

    // ── Deserialization Helpers ──────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private static int deserializeCookieStore(Map<String, Object> csMap, CookieStoreDataStore store, MontoyaApi api) {
        int totalProcessed = SimpleJson.getInt(csMap, "totalMessagesProcessed", 0);
        store.setTotalMessagesProcessed(totalProcessed);

        int count = 0;
        List<Object> groupsList = SimpleJson.getList(csMap, "groups");
        for (Object gObj : groupsList) {
            if (!(gObj instanceof Map<?, ?> gMap)) continue;
            String displayName = SimpleJson.getString((Map<String, Object>) gMap, "displayName", "");
            String sourceStr = SimpleJson.getString((Map<String, Object>) gMap, "source", "REQUEST");
            CookieSource groupSource = parseCookieSource(sourceStr);

            List<Object> valuesList = SimpleJson.getList((Map<String, Object>) gMap, "values");
            for (Object vObj : valuesList) {
                if (!(vObj instanceof Map<?, ?> vMap)) continue;
                Map<String, Object> valData = (Map<String, Object>) vObj;

                int id = SimpleJson.getInt(valData, "id", 0);
                String value = SimpleJson.getString(valData, "value", "");
                CookieSource valSource = parseCookieSource(SimpleJson.getString(valData, "source", "REQUEST"));

                Set<String> domains = new LinkedHashSet<>();
                for (Object d : SimpleJson.getList(valData, "domains")) {
                    if (d != null) domains.add(d.toString());
                }

                int occurrences = SimpleJson.getInt(valData, "occurrences", 1);
                String attributes = SimpleJson.getString(valData, "attributes", "");
                String sampleUrl = SimpleJson.getString(valData, "sampleUrl", "");
                String sampleMethod = SimpleJson.getString(valData, "sampleMethod", "GET");
                int sampleStatusCode = SimpleJson.getInt(valData, "sampleStatusCode", 0);

                HttpRequestResponse sampleMsg = deserializeHttpMessage(valData, "msg", api);

                CookieValueRecord rec = new CookieValueRecord(
                        id,
                        displayName,
                        valSource,
                        value,
                        domains,
                        occurrences,
                        attributes,
                        sampleMsg,
                        sampleUrl,
                        sampleMethod,
                        sampleStatusCode
                );
                store.restoreRecord(displayName, groupSource, rec);
                count++;
            }
        }
        return count;
    }

    @SuppressWarnings("unchecked")
    private static int deserializeSessionMonitor(Map<String, Object> smMap, SessionDataStore store, MontoyaApi api) {
        List<SessionTask> tasks = new ArrayList<>();
        List<Object> tasksList = SimpleJson.getList(smMap, "tasks");

        for (Object tObj : tasksList) {
            if (!(tObj instanceof Map<?, ?> tMap)) continue;
            Map<String, Object> taskData = (Map<String, Object>) tMap;

            int id = SimpleJson.getInt(taskData, "id", 0);
            SessionState state = SessionState.PENDING;
            try {
                state = SessionState.valueOf(SimpleJson.getString(taskData, "state", "PENDING"));
            } catch (Exception ignored) {}

            String lastVerdict = SimpleJson.getString(taskData, "lastVerdict", "");
            boolean cancelOnExpire = SimpleJson.getBoolean(taskData, "cancelOnExpire", true);
            long createdAtMs = SimpleJson.getLong(taskData, "createdAt", System.currentTimeMillis());
            Instant createdAt = Instant.ofEpochMilli(createdAtMs);

            HttpRequestResponse origMsg = deserializeHttpMessage(taskData, "orig", api);
            HttpRequestResponse baseMsg = deserializeHttpMessage(taskData, "base", api);
            HttpRequest origReq = (origMsg != null) ? origMsg.request() : null;

            List<TimerInterval> intervals = new ArrayList<>();
            List<Object> intList = SimpleJson.getList(taskData, "intervals");
            for (Object iObj : intList) {
                if (!(iObj instanceof Map<?, ?> iMap)) continue;
                Map<String, Object> iData = (Map<String, Object>) iObj;

                long delaySeconds = SimpleJson.getLong(iData, "delaySeconds", 1800);
                String label = SimpleJson.getString(iData, "label", TimerInterval.formatDuration(delaySeconds));
                TimerInterval interval = new TimerInterval(delaySeconds, label);

                TimerInterval.IntervalStatus status = TimerInterval.IntervalStatus.SCHEDULED;
                try {
                    status = TimerInterval.IntervalStatus.valueOf(SimpleJson.getString(iData, "status", "SCHEDULED"));
                } catch (Exception ignored) {}
                interval.setStatus(status);

                long schedTarget = SimpleJson.getLong(iData, "scheduledTargetTime", 0);
                if (schedTarget > 0) interval.setScheduledTargetTime(Instant.ofEpochMilli(schedTarget));

                long execTime = SimpleJson.getLong(iData, "executedTime", 0);
                if (execTime > 0) interval.setExecutedTime(Instant.ofEpochMilli(execTime));

                Map<String, Object> prData = SimpleJson.getMap(iData, "probeResult");
                if (!prData.isEmpty()) {
                    long prTs = SimpleJson.getLong(prData, "timestamp", 0);
                    int statusCode = SimpleJson.getInt(prData, "statusCode", 0);
                    long responseLength = SimpleJson.getLong(prData, "responseLength", 0);
                    boolean expired = SimpleJson.getBoolean(prData, "expired", false);
                    String signal = SimpleJson.getString(prData, "signal", "");
                    long duration = SimpleJson.getLong(prData, "durationMillis", 0);
                    String error = SimpleJson.getString(prData, "errorDetails", null);
                    String sDate = SimpleJson.getString(prData, "serverDate", null);
                    HttpRequestResponse prMsg = deserializeHttpMessage(prData, "pr", api);

                    ProbeResult pr = new ProbeResult(
                            prTs > 0 ? Instant.ofEpochMilli(prTs) : Instant.now(),
                            prMsg,
                            statusCode,
                            responseLength,
                            expired,
                            signal,
                            duration,
                            error,
                            sDate
                    );
                    interval.setProbeResult(pr);
                }
                intervals.add(interval);
            }

            SessionTask task = new SessionTask(
                    id,
                    origReq,
                    origMsg,
                    baseMsg,
                    createdAt,
                    state,
                    lastVerdict,
                    cancelOnExpire,
                    intervals
            );
            tasks.add(task);
        }

        store.restoreTasks(tasks);
        return tasks.size();
    }

    @SuppressWarnings("unchecked")
    private static int deserializeCookieFinder(Map<String, Object> cfMap, SessionCookieFinderTab finderTab, MontoyaApi api) {
        int totalFindings = 0;
        List<Object> targetsList = SimpleJson.getList(cfMap, "targets");

        if (!targetsList.isEmpty()) {
            for (Object tObj : targetsList) {
                if (!(tObj instanceof Map<?, ?> tMap)) continue;
                Map<String, Object> tData = (Map<String, Object>) tMap;
                String tabTitle = SimpleJson.getString(tData, "tabTitle", null);
                String customHeaders = SimpleJson.getString(tData, "customHeaders", "");
                boolean customHeadersEnabled = SimpleJson.getBoolean(tData, "customHeadersEnabled", true);
                HttpRequestResponse targetMsg = deserializeHttpMessage(tData, "target", api);

                List<FinderResult> results = deserializeFinderResults(tData, api);
                if (targetMsg != null) {
                    finderTab.restoreTarget(targetMsg, customHeaders, results, tabTitle, customHeadersEnabled);
                    totalFindings += results.size();
                }
            }
        } else {
            // Legacy single target support
            String customHeaders = SimpleJson.getString(cfMap, "customHeaders", "");
            HttpRequestResponse targetMsg = deserializeHttpMessage(cfMap, "target", api);
            List<FinderResult> results = deserializeFinderResults(cfMap, api);
            if (targetMsg != null) {
                finderTab.restoreState(targetMsg, customHeaders, results);
                totalFindings += results.size();
            }
        }

        return totalFindings;
    }

    @SuppressWarnings("unchecked")
    private static List<FinderResult> deserializeFinderResults(Map<String, Object> map, MontoyaApi api) {
        List<FinderResult> results = new ArrayList<>();
        List<Object> resList = SimpleJson.getList(map, "results");

        for (Object rObj : resList) {
            if (!(rObj instanceof Map<?, ?> rMap)) continue;
            Map<String, Object> rData = (Map<String, Object>) rObj;

            int id = SimpleJson.getInt(rData, "id", 0);
            String componentName = SimpleJson.getString(rData, "componentName", "");
            FinderResult.TestType type = FinderResult.TestType.COOKIE;
            try {
                type = FinderResult.TestType.valueOf(SimpleJson.getString(rData, "type", "COOKIE"));
            } catch (Exception ignored) {}

            String preview = SimpleJson.getString(rData, "rawValuePreview", "");
            int statusCode = SimpleJson.getInt(rData, "statusCode", 0);
            long length = SimpleJson.getLong(rData, "responseLength", 0);
            long delta = SimpleJson.getLong(rData, "lengthDelta", 0);
            String verdict = SimpleJson.getString(rData, "verdict", "");
            String signal = SimpleJson.getString(rData, "signalDetails", "");
            long duration = SimpleJson.getLong(rData, "durationMs", 0);
            boolean isToken = SimpleJson.getBoolean(rData, "isSessionToken", false);
            HttpRequestResponse reqResp = deserializeHttpMessage(rData, "item", api);

            FinderResult result = new FinderResult(
                    id, componentName, type, preview, statusCode,
                    length, delta, verdict, signal, duration, reqResp, isToken
            );
            results.add(result);
        }
        return results;
    }

    @SuppressWarnings("unchecked")
    private static CookieDocRecord deserializeCookieDoc(Map<String, Object> map) {
        String name = SimpleJson.getString(map, "name", "");
        if (name.isEmpty()) return null;
        String category = SimpleJson.getString(map, "category", "");
        String cookieId = SimpleJson.getString(map, "cookieId", name);
        String url = SimpleJson.getString(map, "url", "");
        String script = SimpleJson.getString(map, "script", "");
        String description = SimpleJson.getString(map, "description", "");
        String referenceUrl = SimpleJson.getString(map, "referenceUrl", "");

        List<String> related = new ArrayList<>();
        for (Object o : SimpleJson.getList(map, "related")) {
            if (o != null) related.add(o.toString());
        }

        return new CookieDocRecord(name, category, cookieId, url, script, description, referenceUrl, related);
    }

    private static HttpRequestResponse deserializeHttpMessage(Map<String, Object> map, String prefix, MontoyaApi api) {
        String host = SimpleJson.getString(map, prefix + "Host", "");
        String reqBase64 = SimpleJson.getString(map, prefix + "ReqBase64", "");
        if (reqBase64.isEmpty()) return null;

        int port = SimpleJson.getInt(map, prefix + "Port", 443);
        boolean secure = SimpleJson.getBoolean(map, prefix + "Secure", true);
        String respBase64 = SimpleJson.getString(map, prefix + "RespBase64", "");

        try {
            HttpService service = (host != null && !host.isBlank())
                    ? HttpService.httpService(host, port > 0 ? port : (secure ? 443 : 80), secure)
                    : null;

            byte[] reqBytes = Base64.getDecoder().decode(reqBase64);
            HttpRequest req = (service != null)
                    ? HttpRequest.httpRequest(service, ByteArray.byteArray(reqBytes))
                    : HttpRequest.httpRequest(ByteArray.byteArray(reqBytes));

            HttpResponse resp = null;
            if (!respBase64.isEmpty()) {
                byte[] respBytes = Base64.getDecoder().decode(respBase64);
                resp = HttpResponse.httpResponse(ByteArray.byteArray(respBytes));
            }

            return HttpRequestResponse.httpRequestResponse(req, resp);
        } catch (Exception ex) {
            return null;
        }
    }

    private static CookieSource parseCookieSource(String str) {
        if (str == null) return CookieSource.REQUEST;
        try {
            return CookieSource.valueOf(str.trim().toUpperCase(Locale.ROOT));
        } catch (Exception ignored) {
            return CookieSource.REQUEST;
        }
    }
}
