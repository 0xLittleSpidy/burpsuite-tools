// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.graphqlcop.model.SessionData_littlespidy;
import com.littlespidy.graphqlcop.persistence.SessionPersistenceManager_littlespidy;
import com.littlespidy.graphqlcop.persistence.SessionStartupDialog_littlespidy;
import com.littlespidy.graphqlcop.voyager.LocalVoyagerServer_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class GraphQLCopRootTab_littlespidy extends JPanel {
    private final MontoyaApi api;
    private final LocalVoyagerServer_littlespidy voyagerServer;
    private final SessionPersistenceManager_littlespidy persistenceManager;
    private final JTabbedPane sessionTabbedPane;
    private final List<GraphQLSessionPanel_littlespidy> sessionPanels = new ArrayList<>();
    private int sessionCounter = 1;

    public GraphQLCopRootTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        this.voyagerServer = new LocalVoyagerServer_littlespidy();
        this.voyagerServer.start();

        this.persistenceManager = new SessionPersistenceManager_littlespidy();

        // Top Toolbar
        JPanel topToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton newSessionBtn = new JButton("+ New Session Tab");
        newSessionBtn.addActionListener(e -> addNewSession("Session " + sessionCounter, "https://", ""));
        topToolbar.add(newSessionBtn);

        JButton clearSessionsBtn = new JButton("Clear All Saved Sessions");
        clearSessionsBtn.addActionListener(e -> {
            int res = JOptionPane.showConfirmDialog(this, "Are you sure you want to clear saved sessions?", "Confirm Clear", JOptionPane.YES_NO_OPTION);
            if (res == JOptionPane.YES_OPTION) {
                persistenceManager.clearSavedSessions();
                JOptionPane.showMessageDialog(this, "Saved session cache cleared.", "Cleared", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        topToolbar.add(clearSessionsBtn);

        add(topToolbar, BorderLayout.NORTH);

        sessionTabbedPane = new JTabbedPane();
        add(sessionTabbedPane, BorderLayout.CENTER);

        // Check for existing saved sessions
        SwingUtilities.invokeLater(this::initSessions);
    }

    private void initSessions() {
        if (persistenceManager.hasExistingSessions()) {
            List<SessionData_littlespidy> saved = persistenceManager.loadSessions();
            if (!saved.isEmpty() && SessionStartupDialog_littlespidy.promptToRestore(this, saved.size())) {
                for (SessionData_littlespidy data : saved) {
                    GraphQLSessionPanel_littlespidy panel = createSessionPanel(data.getSessionId(), data.getTabTitle(), data.getTargetUrl());
                    panel.loadSessionData(data);
                }
                sessionCounter = sessionPanels.size() + 1;
                return;
            }
        }
        addNewSession("Session 1", "https://", "");
    }

    public GraphQLSessionPanel_littlespidy addNewSession(String title, String url, String headers) {
        String sessionId = UUID.randomUUID().toString();
        GraphQLSessionPanel_littlespidy panel = createSessionPanel(sessionId, title, url);
        panel.setCustomHeaders(headers);
        sessionTabbedPane.setSelectedComponent(panel);
        triggerSave();
        return panel;
    }

    private GraphQLSessionPanel_littlespidy createSessionPanel(String sessionId, String title, String url) {
        GraphQLSessionPanel_littlespidy panel = new GraphQLSessionPanel_littlespidy(
                api, voyagerServer, sessionId, title, url, v -> triggerSave()
        );
        sessionPanels.add(panel);

        sessionTabbedPane.addTab(title, panel);
        int index = sessionTabbedPane.indexOfComponent(panel);

        EditableTabHeader_littlespidy tabHeader = new EditableTabHeader_littlespidy(
                title,
                sessionTabbedPane,
                panel,
                newTitle -> {
                    panel.setTabTitle(newTitle);
                    triggerSave();
                },
                () -> closeSession(panel)
        );
        sessionTabbedPane.setTabComponentAt(index, tabHeader);
        sessionCounter++;
        return panel;
    }

    private void closeSession(GraphQLSessionPanel_littlespidy panel) {
        if (sessionPanels.size() <= 1) {
            JOptionPane.showMessageDialog(this, "At least one session tab must remain open.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int index = sessionTabbedPane.indexOfComponent(panel);
        if (index >= 0) {
            sessionTabbedPane.removeTabAt(index);
            sessionPanels.remove(panel);
            triggerSave();
        }
    }

    private void triggerSave() {
        List<SessionData_littlespidy> list = new ArrayList<>();
        for (GraphQLSessionPanel_littlespidy p : sessionPanels) {
            list.add(p.exportSessionData());
        }
        persistenceManager.scheduleSave(list);
    }

    public void cleanup() {
        voyagerServer.stop();
        triggerSave();
    }
}
