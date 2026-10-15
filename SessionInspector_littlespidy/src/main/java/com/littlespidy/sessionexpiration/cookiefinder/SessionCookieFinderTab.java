// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiefinder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.sessionexpiration.engine.SessionTimerEngine;
import com.littlespidy.sessionexpiration.model.SessionDataStore;
import com.littlespidy.sessionexpiration.ui.SessionExpirationTab;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Suite tab for Session Cookie & Auth Header Finder.
 * Manages multiple target requests as individual sub-tabs so testers can systematically
 * isolate credentials across multiple requests simultaneously without overwriting previous sessions.
 *
 * @author littlespidy
 */
public class SessionCookieFinderTab extends JPanel {

    private final MontoyaApi api;
    private final SessionDataStore dataStore;
    private final SessionTimerEngine timerEngine;
    private final SessionExpirationTab parentTab;

    private final CardLayout cardLayout = new CardLayout();
    private final JPanel cardsPanel = new JPanel(cardLayout);

    private final JTabbedPane targetTabbedPane = new JTabbedPane();
    private final JPanel emptyPlaceholderPanel = new JPanel(new GridBagLayout());

    private final AtomicInteger targetCounter = new AtomicInteger(1);
    private final List<SingleCookieFinderPanel> panels = new ArrayList<>();

    public SessionCookieFinderTab(MontoyaApi api, SessionDataStore dataStore,
                                  SessionTimerEngine timerEngine, SessionExpirationTab parentTab) {
        this.api = api;
        this.dataStore = dataStore;
        this.timerEngine = timerEngine;
        this.parentTab = parentTab;

        setLayout(new BorderLayout());

        initEmptyPlaceholder();

        targetTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);

        cardsPanel.add(emptyPlaceholderPanel, "EMPTY");
        cardsPanel.add(targetTabbedPane, "TABS");

        add(cardsPanel, BorderLayout.CENTER);
        cardLayout.show(cardsPanel, "EMPTY");
    }

    private void initEmptyPlaceholder() {
        emptyPlaceholderPanel.setBackground(UIManager.getColor("Panel.background"));

        JPanel centerBox = new JPanel();
        centerBox.setLayout(new BoxLayout(centerBox, BoxLayout.Y_AXIS));
        centerBox.setOpaque(false);

        JLabel titleLabel = new JLabel("No Target Requests Loaded", SwingConstants.CENTER);
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16));
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel subtitleLabel = new JLabel("<html><center>"
                + "Right-click any HTTP request in Burp Suite (<b>Proxy, Repeater, Logger, Scanner</b>)<br>"
                + "and choose <b>'Send to Session Cookie Finder'</b>.<br><br>"
                + "Each request will open as an independent tab with dedicated isolation tests and response editors."
                + "</center></html>", SwingConstants.CENTER);
        subtitleLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        subtitleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        centerBox.add(titleLabel);
        centerBox.add(Box.createVerticalStrut(8));
        centerBox.add(subtitleLabel);

        emptyPlaceholderPanel.add(centerBox);
    }

    /**
     * Adds a new target request as an independent tab.
     */
    public SingleCookieFinderPanel addTargetRequest(HttpRequest request, HttpRequestResponse requestResponse) {
        if (request == null) return null;

        int id = targetCounter.getAndIncrement();
        SingleCookieFinderPanel panel = new SingleCookieFinderPanel(
                api, dataStore, timerEngine, parentTab, request, requestResponse, id,
                () -> {
                    if (parentTab != null) {
                        parentTab.triggerAutoSave();
                    }
                }
        );

        panels.add(panel);

        String method = request.method() != null ? request.method().toUpperCase() : "GET";
        String path = request.path() != null ? request.path() : "/";
        String shortPath = path.length() > 24 ? path.substring(0, 21) + "..." : path;
        String title = "#" + id + " " + method + " " + shortPath;
        String fullUrl = request.url() != null ? request.url() : path;

        panel.setTabTitle(title);
        targetTabbedPane.addTab(title, panel);
        int tabIndex = targetTabbedPane.indexOfComponent(panel);
        targetTabbedPane.setToolTipTextAt(tabIndex, fullUrl);

        // Custom tab header component with close button
        targetTabbedPane.setTabComponentAt(tabIndex, createTabHeader(title, panel));
        targetTabbedPane.setSelectedComponent(panel);

        cardLayout.show(cardsPanel, "TABS");

        if (parentTab != null) {
            parentTab.triggerAutoSave();
        }

        return panel;
    }

    /**
     * Compatibility wrapper for existing callers.
     */
    public void setTargetRequest(HttpRequest request, HttpRequestResponse requestResponse) {
        addTargetRequest(request, requestResponse);
    }

    private Component createTabHeader(String title, SingleCookieFinderPanel panel) {
        JPanel headerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        headerPanel.setOpaque(false);

        JLabel label = new JLabel(title);
        label.setToolTipText("Double-click to rename tab");
        label.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    promptRenameTab(panel, label);
                }
            }
        });
        headerPanel.add(label);

        JButton closeBtn = new JButton("x");
        closeBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        closeBtn.setMargin(new Insets(0, 2, 0, 2));
        closeBtn.setBorder(BorderFactory.createEmptyBorder(0, 3, 0, 3));
        closeBtn.setFocusable(false);
        closeBtn.setContentAreaFilled(false);
        closeBtn.setToolTipText("Close this request tab");

        closeBtn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                closeBtn.setForeground(Color.RED);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                closeBtn.setForeground(UIManager.getColor("Label.foreground"));
            }
        });

        closeBtn.addActionListener(e -> closePanel(panel));
        headerPanel.add(closeBtn);

        // Context menu on tab header
        JPopupMenu menu = new JPopupMenu();
        JMenuItem renameItem = new JMenuItem("Rename Tab");
        renameItem.addActionListener(e -> promptRenameTab(panel, label));
        menu.add(renameItem);
        menu.addSeparator();

        JMenuItem closeItem = new JMenuItem("Close Tab");
        closeItem.addActionListener(e -> closePanel(panel));
        menu.add(closeItem);

        JMenuItem closeOthersItem = new JMenuItem("Close Other Tabs");
        closeOthersItem.addActionListener(e -> closeOtherPanels(panel));
        menu.add(closeOthersItem);

        JMenuItem closeAllItem = new JMenuItem("Close All Tabs");
        closeAllItem.addActionListener(e -> closeAllTabs());
        menu.add(closeAllItem);

        headerPanel.setComponentPopupMenu(menu);
        label.setComponentPopupMenu(menu);

        return headerPanel;
    }

    private void promptRenameTab(SingleCookieFinderPanel panel, JLabel label) {
        String current = label.getText();
        String newName = JOptionPane.showInputDialog(
                this,
                "Enter new tab name:",
                "Rename Tab",
                JOptionPane.PLAIN_MESSAGE,
                null,
                null,
                current
        ) instanceof String str ? str.trim() : null;

        if (newName != null && !newName.isEmpty()) {
            label.setText(newName);
            panel.setTabTitle(newName);
            int idx = targetTabbedPane.indexOfComponent(panel);
            if (idx >= 0) {
                targetTabbedPane.setTitleAt(idx, newName);
            }
            if (parentTab != null) {
                parentTab.triggerAutoSave();
            }
        }
    }

    public void closePanel(SingleCookieFinderPanel panel) {
        if (panel == null) return;
        panel.cleanup();
        panels.remove(panel);
        targetTabbedPane.remove(panel);

        if (targetTabbedPane.getTabCount() == 0) {
            cardLayout.show(cardsPanel, "EMPTY");
        }

        if (parentTab != null) {
            parentTab.triggerAutoSave();
        }
    }

    public void closeOtherPanels(SingleCookieFinderPanel keepPanel) {
        List<SingleCookieFinderPanel> toRemove = new ArrayList<>();
        for (SingleCookieFinderPanel p : panels) {
            if (p != keepPanel) {
                toRemove.add(p);
            }
        }
        for (SingleCookieFinderPanel p : toRemove) {
            closePanel(p);
        }
    }

    public void closeAllTabs() {
        for (SingleCookieFinderPanel p : panels) {
            p.cleanup();
        }
        panels.clear();
        targetTabbedPane.removeAll();
        cardLayout.show(cardsPanel, "EMPTY");

        if (parentTab != null) {
            parentTab.triggerAutoSave();
        }
    }

    public List<SingleCookieFinderPanel> getAllPanels() {
        return Collections.unmodifiableList(panels);
    }

    public SingleCookieFinderPanel getSelectedPanel() {
        Component comp = targetTabbedPane.getSelectedComponent();
        if (comp instanceof SingleCookieFinderPanel scfp) {
            return scfp;
        }
        return panels.isEmpty() ? null : panels.get(0);
    }

    public HttpRequestResponse getTargetRequestResponse() {
        SingleCookieFinderPanel selected = getSelectedPanel();
        return selected != null ? selected.getTargetRequestResponse() : null;
    }

    public String getCustomHeaders() {
        SingleCookieFinderPanel selected = getSelectedPanel();
        return selected != null ? selected.getCustomHeaders() : "";
    }

    public List<FinderResult> getAllResults() {
        SingleCookieFinderPanel selected = getSelectedPanel();
        return selected != null ? selected.getAllResults() : Collections.emptyList();
    }

    public void cleanup() {
        for (SingleCookieFinderPanel p : panels) {
            p.cleanup();
        }
    }

    public void clearAll() {
        closeAllTabs();
    }

    /**
     * Restores state for backward compatibility or single target.
     */
    public void restoreState(HttpRequestResponse target, String customHeaders, List<FinderResult> results) {
        if (target != null && target.request() != null) {
            SingleCookieFinderPanel panel = addTargetRequest(target.request(), target);
            if (panel != null) {
                if (customHeaders != null && !customHeaders.isBlank()) {
                    panel.setCustomHeaders(customHeaders);
                }
                if (results != null && !results.isEmpty()) {
                    panel.setResults(results);
                }
            }
        }
    }

    public SingleCookieFinderPanel restoreTarget(HttpRequestResponse target, String customHeaders, List<FinderResult> results) {
        return restoreTarget(target, customHeaders, results, null, true);
    }

    public SingleCookieFinderPanel restoreTarget(HttpRequestResponse target, String customHeaders, List<FinderResult> results, String tabTitle, boolean customHeadersEnabled) {
        if (target == null || target.request() == null) return null;
        SingleCookieFinderPanel panel = addTargetRequest(target.request(), target);
        if (panel != null) {
            if (customHeaders != null && !customHeaders.isBlank()) {
                panel.setCustomHeaders(customHeaders);
            }
            panel.setCustomHeadersEnabled(customHeadersEnabled);
            if (results != null && !results.isEmpty()) {
                panel.setResults(results);
            }
            if (tabTitle != null && !tabTitle.isBlank()) {
                panel.setTabTitle(tabTitle);
                int idx = targetTabbedPane.indexOfComponent(panel);
                if (idx >= 0) {
                    targetTabbedPane.setTitleAt(idx, tabTitle);
                    Component c = targetTabbedPane.getTabComponentAt(idx);
                    if (c instanceof JPanel jp) {
                        for (Component comp : jp.getComponents()) {
                            if (comp instanceof JLabel lbl) {
                                lbl.setText(tabTitle);
                                break;
                            }
                        }
                    }
                }
            }
        }
        return panel;
    }
}
