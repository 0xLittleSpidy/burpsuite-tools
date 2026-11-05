// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.ssrfmap.engine.CollaboratorManager_littlespidy;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

public class SSRFmapMainTab_littlespidy extends JPanel {
    private final MontoyaApi api;
    private final CollaboratorManager_littlespidy collaboratorManager;
    private final JTabbedPane rootTabbedPane;
    private final AtomicInteger tabCounter = new AtomicInteger(1);

    public SSRFmapMainTab_littlespidy(MontoyaApi api, CollaboratorManager_littlespidy collaboratorManager) {
        super(new BorderLayout());
        this.api = api;
        this.collaboratorManager = collaboratorManager;

        // Header Bar
        JPanel headerBar = new JPanel(new BorderLayout());
        headerBar.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));

        JPanel titlePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JLabel titleLabel = new JLabel("SSRFmap - SSRF Automation and Testing [littlespidy]");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));
        titlePanel.add(titleLabel);

        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton newSessionBtn = new JButton("+ New Empty Session");
        newSessionBtn.addActionListener(e -> addNewSession(null));
        controlsPanel.add(newSessionBtn);

        headerBar.add(titlePanel, BorderLayout.WEST);
        headerBar.add(controlsPanel, BorderLayout.EAST);
        add(headerBar, BorderLayout.NORTH);

        rootTabbedPane = new JTabbedPane();
        add(rootTabbedPane, BorderLayout.CENTER);

        // Add default initial empty session
        addNewSession(null);
    }

    public void addNewSession(HttpRequestResponse reqResp) {
        int id = tabCounter.getAndIncrement();
        String title = "Session " + id;
        if (reqResp != null && reqResp.request() != null) {
            String path = reqResp.request().path();
            String method = reqResp.request().method();
            if (path != null && path.length() > 25) {
                path = path.substring(0, 25) + "...";
            }
            title = id + ": " + method + " " + path;
        }

        SSRFmapSessionTab_littlespidy sessionTab = new SSRFmapSessionTab_littlespidy(api, collaboratorManager, reqResp);
        rootTabbedPane.addTab(title, sessionTab);

        int tabIndex = rootTabbedPane.indexOfComponent(sessionTab);
        JPanel tabHeader = createTabHeader(title, sessionTab);
        rootTabbedPane.setTabComponentAt(tabIndex, tabHeader);
        rootTabbedPane.setSelectedComponent(sessionTab);
    }

    private JPanel createTabHeader(String title, SSRFmapSessionTab_littlespidy sessionTab) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        panel.setOpaque(false);

        JLabel label = new JLabel(title);
        panel.add(label);

        JButton closeBtn = new JButton("x");
        closeBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        closeBtn.setMargin(new java.awt.Insets(0, 2, 0, 2));
        closeBtn.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
        closeBtn.setContentAreaFilled(false);
        closeBtn.setFocusable(false);
        closeBtn.addActionListener(e -> {
            int idx = rootTabbedPane.indexOfComponent(sessionTab);
            if (idx != -1) {
                rootTabbedPane.remove(idx);
                if (rootTabbedPane.getTabCount() == 0) {
                    addNewSession(null);
                }
            }
        });
        panel.add(closeBtn);

        return panel;
    }
}
