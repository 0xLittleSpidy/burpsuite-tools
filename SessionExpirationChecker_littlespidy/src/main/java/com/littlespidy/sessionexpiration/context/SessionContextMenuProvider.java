// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.context;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.littlespidy.sessionexpiration.engine.SessionTimerEngine;
import com.littlespidy.sessionexpiration.model.SessionDataStore;
import com.littlespidy.sessionexpiration.model.SessionTask;
import com.littlespidy.sessionexpiration.model.TimerInterval;
import com.littlespidy.sessionexpiration.ui.SessionExpirationTab;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Context menu provider that enables testers to right-click any HTTP request/response
 * across Burp tools (Proxy, Repeater, Logger, Scanner) and send it directly to
 * the Session Expiration Checker.
 *
 * @author littlespidy
 */
public class SessionContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final SessionDataStore dataStore;
    private final SessionTimerEngine timerEngine;
    private final SessionExpirationTab mainTab;

    public SessionContextMenuProvider(MontoyaApi api, SessionDataStore dataStore,
                                      SessionTimerEngine timerEngine, SessionExpirationTab mainTab) {
        this.api = api;
        this.dataStore = dataStore;
        this.timerEngine = timerEngine;
        this.mainTab = mainTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        List<HttpRequestResponse> targetRequests = new ArrayList<>(event.selectedRequestResponses());
        if (targetRequests.isEmpty() && event.messageEditorRequestResponse().isPresent()) {
            targetRequests.add(event.messageEditorRequestResponse().get().requestResponse());
        }

        if (targetRequests.isEmpty()) {
            JMenuItem openTabItem = new JMenuItem("⏱️ Open Session Expiration Checker");
            openTabItem.addActionListener(e -> {
                mainTab.selectMonitorTab();
                mainTab.refreshView();
            });
            items.add(openTabItem);
            return items;
        }

        int count = targetRequests.size();
        String menuTitle = (count == 1)
                ? "⏱️ Send to Session Expiration Checker"
                : "⏱️ Send " + count + " Requests to Session Expiration Checker";

        JMenuItem sendItem = new JMenuItem(menuTitle);
        sendItem.addActionListener(e -> handleSendRequests(targetRequests));
        items.add(sendItem);

        return items;
    }

    private void handleSendRequests(List<HttpRequestResponse> requests) {
        SwingUtilities.invokeLater(() -> {
            if (requests.size() == 1) {
                HttpRequestResponse rr = requests.get(0);
                HttpRequest req = rr.request();
                SessionTask task = new SessionTask(dataStore.nextId(), req, rr.hasResponse() ? rr : null);
                dataStore.addTask(task);

                // Open dialog for interactive milestone configuration
                mainTab.openConfigDialogForTask(task);
            } else {
                // Multiple requests: create tasks with default milestone timers (16 milestones: 30m to 8h)
                for (HttpRequestResponse rr : requests) {
                    HttpRequest req = rr.request();
                    SessionTask task = new SessionTask(dataStore.nextId(), req, rr.hasResponse() ? rr : null);

                    List<TimerInterval> defaultIntervals = TimerInterval.createDefaultMilestones();
                    task.setIntervals(defaultIntervals);
                    task.setCancelOnExpire(true);

                    dataStore.addTask(task);
                    timerEngine.startSession(task, mainTab::refreshView);
                }
                mainTab.selectMonitorTab();
                mainTab.refreshView();
                JOptionPane.showMessageDialog(mainTab,
                        "Added " + requests.size() + " session tasks with 16 default milestones (every 30m up to 8h).",
                        "Sessions Scheduled", JOptionPane.INFORMATION_MESSAGE);
            }
        });
    }
}
