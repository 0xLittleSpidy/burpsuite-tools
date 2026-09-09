package com.littlespidy.uploadscanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Root suite tab for Upload Scanner providing the Welcome Guide,
 * the global "Done Uploads" activity log, and dynamic closeable per-request session tabs.
 *
 * Follows extension_architecture.md standards.
 *
 * @author littlespidy
 */
public class UploadScannerTab extends JPanel {

    private final MontoyaApi api;
    private final JTabbedPane rootTabbedPane;
    private final ExecutionLogPanel executionLogPanel;
    private final List<UploadSessionPanel> activeSessions = new ArrayList<>();

    public UploadScannerTab(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;

        this.rootTabbedPane = new JTabbedPane();
        this.executionLogPanel = new ExecutionLogPanel(api);

        rootTabbedPane.addTab("📖 Welcome & Guide", new WelcomeGuidePanel());
        rootTabbedPane.addTab("📋 Done Uploads", executionLogPanel);

        add(rootTabbedPane, BorderLayout.CENTER);
    }

    public ExecutionLogPanel getExecutionLogPanel() {
        return executionLogPanel;
    }

    public void addNewSessionTab(HttpRequest request, HttpResponse response) {
        String path = request.path();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        if (path.length() > 22) {
            path = path.substring(0, 19) + "...";
        }
        String tabTitle = request.method() + " " + path;

        UploadSessionPanel sessionPanel = new UploadSessionPanel(
                api,
                request,
                response,
                executionLogPanel::addLogEntry
        );

        activeSessions.add(sessionPanel);
        rootTabbedPane.addTab(tabTitle, sessionPanel);
        int tabIndex = rootTabbedPane.indexOfComponent(sessionPanel);

        // Custom Tab Header with Title and Close Button
        JPanel tabHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        tabHeader.setOpaque(false);
        JLabel titleLabel = new JLabel("🎯 " + tabTitle);

        JButton closeBtn = new JButton("×");
        closeBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        closeBtn.setMargin(new Insets(0, 4, 0, 4));
        closeBtn.setBorder(BorderFactory.createEmptyBorder());
        closeBtn.setContentAreaFilled(false);
        closeBtn.setFocusable(false);
        closeBtn.setToolTipText("Close this session");
        closeBtn.addActionListener(e -> closeSession(sessionPanel));

        tabHeader.add(titleLabel);
        tabHeader.add(closeBtn);
        rootTabbedPane.setTabComponentAt(tabIndex, tabHeader);

        // Switch to the newly created session tab
        rootTabbedPane.setSelectedIndex(tabIndex);
    }

    public void closeSession(UploadSessionPanel sessionPanel) {
        int confirm = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to close this upload session?",
                "Close Session",
                JOptionPane.YES_NO_OPTION
        );
        if (confirm == JOptionPane.YES_OPTION) {
            sessionPanel.cleanup();
            activeSessions.remove(sessionPanel);
            rootTabbedPane.remove(sessionPanel);
        }
    }

    public void cleanupAll() {
        for (UploadSessionPanel session : activeSessions) {
            session.cleanup();
        }
        activeSessions.clear();
    }
}
