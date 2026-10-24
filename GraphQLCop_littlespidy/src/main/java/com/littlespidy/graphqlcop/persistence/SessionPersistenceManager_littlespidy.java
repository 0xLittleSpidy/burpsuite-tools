// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.persistence;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.littlespidy.graphqlcop.model.SessionData_littlespidy;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

public class SessionPersistenceManager_littlespidy {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Type SESSION_LIST_TYPE = new TypeToken<List<SessionData_littlespidy>>(){}.getType();
    private static final File STORAGE_FILE = new File(System.getProperty("user.home"), ".graphqlcop_sessions_littlespidy.json");

    private Timer debounceTimer;

    public synchronized void scheduleSave(List<SessionData_littlespidy> sessions) {
        if (debounceTimer != null) {
            debounceTimer.cancel();
        }
        debounceTimer = new Timer(true);
        debounceTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                saveImmediately(sessions);
            }
        }, 1200);
    }

    public synchronized void saveImmediately(List<SessionData_littlespidy> sessions) {
        try {
            File tempFile = new File(STORAGE_FILE.getAbsolutePath() + ".tmp");
            try (Writer writer = new OutputStreamWriter(new FileOutputStream(tempFile), StandardCharsets.UTF_8)) {
                GSON.toJson(sessions, SESSION_LIST_TYPE, writer);
            }
            Files.move(tempFile.toPath(), STORAGE_FILE.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception ignored) {}
    }

    public synchronized List<SessionData_littlespidy> loadSessions() {
        if (!STORAGE_FILE.exists() || STORAGE_FILE.length() == 0) {
            return new ArrayList<>();
        }
        try (Reader reader = new InputStreamReader(new FileInputStream(STORAGE_FILE), StandardCharsets.UTF_8)) {
            List<SessionData_littlespidy> list = GSON.fromJson(reader, SESSION_LIST_TYPE);
            return list != null ? list : new ArrayList<>();
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    public boolean hasExistingSessions() {
        return STORAGE_FILE.exists() && STORAGE_FILE.length() > 10;
    }

    public void clearSavedSessions() {
        if (STORAGE_FILE.exists()) {
            STORAGE_FILE.delete();
        }
    }
}
