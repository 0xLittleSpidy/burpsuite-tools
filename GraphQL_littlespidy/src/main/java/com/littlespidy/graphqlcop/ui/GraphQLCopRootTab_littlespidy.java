// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.graphqlcop.model.SessionData_littlespidy;
import com.littlespidy.graphqlcop.model.WorkspaceSessionData_littlespidy;
import com.littlespidy.graphqlcop.persistence.SessionManager_littlespidy;
import com.littlespidy.graphqlcop.voyager.LocalVoyagerServer_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class GraphQLCopRootTab_littlespidy extends JPanel implements SessionManager_littlespidy.SessionPersistenceCallback {
    private final MontoyaApi api;
    private final LocalVoyagerServer_littlespidy voyagerServer;
    private final SessionManager_littlespidy sessionManager;
    private final JTabbedPane endpointTabbedPane;
    private final List<GraphQLSessionPanel_littlespidy> endpointPanels = new ArrayList<>();
    private int endpointCounter = 1;

    public GraphQLCopRootTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        this.voyagerServer = new LocalVoyagerServer_littlespidy();
        this.voyagerServer.start();

        this.sessionManager = new SessionManager_littlespidy(api, this);

        // Top Standard Session Toolbar (from extension_architecture.md)
        JPanel topContainer = new JPanel(new BorderLayout());
        topContainer.add(sessionManager.createSessionToolbarComponent(this), BorderLayout.NORTH);

        // Tab actions bar: [+ New Test Tab]
        JPanel tabActionsBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        JButton newTabBtn = new JButton("+ New Test Tab");
        newTabBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        newTabBtn.addActionListener(e -> addNewEndpointTab("#" + endpointCounter + " POST /graphql", "https://", ""));
        tabActionsBar.add(newTabBtn);
        topContainer.add(tabActionsBar, BorderLayout.SOUTH);

        add(topContainer, BorderLayout.NORTH);

        endpointTabbedPane = new JTabbedPane();
        add(endpointTabbedPane, BorderLayout.CENTER);

        // Initialize default workspace
        addNewEndpointTab("#1 POST /graphql", "https://", "");

        // Show session startup dialog
        SwingUtilities.invokeLater(() -> sessionManager.initializeOnStartup(this));
    }

    public GraphQLSessionPanel_littlespidy addNewEndpointTab(String title, String url, String headers) {
        String sessionId = UUID.randomUUID().toString();
        GraphQLSessionPanel_littlespidy panel = createEndpointPanel(sessionId, title, url);
        panel.setCustomHeaders(headers);
        endpointTabbedPane.setSelectedComponent(panel);
        sessionManager.markDirty();
        return panel;
    }

    private GraphQLSessionPanel_littlespidy createEndpointPanel(String sessionId, String title, String url) {
        GraphQLSessionPanel_littlespidy panel = new GraphQLSessionPanel_littlespidy(
                api, voyagerServer, sessionId, title, url, v -> sessionManager.markDirty()
        );
        endpointPanels.add(panel);

        endpointTabbedPane.addTab(title, panel);
        int index = endpointTabbedPane.indexOfComponent(panel);

        EditableTabHeader_littlespidy tabHeader = new EditableTabHeader_littlespidy(
                title,
                endpointTabbedPane,
                panel,
                newTitle -> {
                    panel.setTabTitle(newTitle);
                    sessionManager.markDirty();
                },
                () -> closeEndpointTab(panel)
        );
        endpointTabbedPane.setTabComponentAt(index, tabHeader);
        endpointCounter++;
        return panel;
    }

    private void closeEndpointTab(GraphQLSessionPanel_littlespidy panel) {
        if (endpointPanels.size() <= 1) {
            JOptionPane.showMessageDialog(this, "At least one test tab must remain open.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int index = endpointTabbedPane.indexOfComponent(panel);
        if (index >= 0) {
            endpointTabbedPane.removeTabAt(index);
            endpointPanels.remove(panel);
            sessionManager.markDirty();
        }
    }

    @Override
    public WorkspaceSessionData_littlespidy exportCurrentSession() {
        WorkspaceSessionData_littlespidy ws = new WorkspaceSessionData_littlespidy();
        List<SessionData_littlespidy> list = new ArrayList<>();
        for (GraphQLSessionPanel_littlespidy p : endpointPanels) {
            list.add(p.exportSessionData());
        }
        ws.setEndpointTabs(list);
        return ws;
    }

    @Override
    public void importSession(WorkspaceSessionData_littlespidy data) {
        if (data == null || data.getEndpointTabs() == null || data.getEndpointTabs().isEmpty()) {
            return;
        }
        endpointTabbedPane.removeAll();
        endpointPanels.clear();
        endpointCounter = 1;

        for (SessionData_littlespidy tabData : data.getEndpointTabs()) {
            GraphQLSessionPanel_littlespidy panel = createEndpointPanel(tabData.getSessionId(), tabData.getTabTitle(), tabData.getTargetUrl());
            panel.loadSessionData(tabData);
        }
    }

    @Override
    public void resetSession() {
        endpointTabbedPane.removeAll();
        endpointPanels.clear();
        endpointCounter = 1;
        addNewEndpointTab("#1 POST /graphql", "https://", "");
    }

    public void cleanup() {
        voyagerServer.stop();
        sessionManager.saveSync();
    }
}
