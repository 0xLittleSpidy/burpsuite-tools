// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.List;

/**
 * Dynamic multi-select dropdown button for filtering test results by HTTP status code.
 * Discovered status codes are added dynamically and sorted in ascending order.
 */
public class StatusCodeFilterDropDown_littlespidy extends JButton {

    private final Map<Integer, JCheckBox> statusCheckBoxMap = new TreeMap<>();
    private final JCheckBox selectAllCheckBox = new JCheckBox("Select All", true);
    private final JPopupMenu popupMenu = new JPopupMenu();
    private final JPanel itemsPanel = new JPanel();
    private final List<Runnable> listeners = new ArrayList<>();
    private boolean updatingProgrammatically = false;

    public StatusCodeFilterDropDown_littlespidy() {
        super("Status Code: All");
        initUI();
    }

    private void initUI() {
        JPanel mainPopupPanel = new JPanel();
        mainPopupPanel.setLayout(new BoxLayout(mainPopupPanel, BoxLayout.Y_AXIS));
        mainPopupPanel.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        selectAllCheckBox.addActionListener(e -> {
            if (updatingProgrammatically) {
                return;
            }
            boolean selected = selectAllCheckBox.isSelected();
            updatingProgrammatically = true;
            for (JCheckBox cb : statusCheckBoxMap.values()) {
                cb.setSelected(selected);
            }
            updatingProgrammatically = false;
            updateButtonLabel();
            notifyListeners();
        });
        mainPopupPanel.add(selectAllCheckBox);
        mainPopupPanel.add(new JSeparator());

        itemsPanel.setLayout(new BoxLayout(itemsPanel, BoxLayout.Y_AXIS));
        JScrollPane scrollPane = new JScrollPane(itemsPanel,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setBorder(null);
        scrollPane.setPreferredSize(new Dimension(170, 150));
        mainPopupPanel.add(scrollPane);

        popupMenu.add(mainPopupPanel);

        addActionListener(e -> {
            if (popupMenu.isVisible()) {
                popupMenu.setVisible(false);
            } else {
                popupMenu.show(this, 0, getHeight());
            }
        });
        updateButtonLabel();
    }

    public synchronized void registerStatusCode(int statusCode) {
        if (statusCode <= 0) return;
        if (!statusCheckBoxMap.containsKey(statusCode)) {
            ActionListener itemListener = e -> {
                if (updatingProgrammatically) {
                    return;
                }
                syncSelectAllState();
                updateButtonLabel();
                notifyListeners();
            };

            boolean defaultSelected = selectAllCheckBox.isSelected();
            JCheckBox cb = new JCheckBox(String.valueOf(statusCode), defaultSelected);
            cb.addActionListener(itemListener);
            statusCheckBoxMap.put(statusCode, cb);

            rebuildItemsPanel();
            syncSelectAllState();
            updateButtonLabel();
        }
    }

    public synchronized void registerStatusCodes(Collection<Integer> codes) {
        if (codes == null || codes.isEmpty()) return;
        boolean added = false;
        for (Integer code : codes) {
            if (code != null && code > 0 && !statusCheckBoxMap.containsKey(code)) {
                ActionListener itemListener = e -> {
                    if (updatingProgrammatically) {
                        return;
                    }
                    syncSelectAllState();
                    updateButtonLabel();
                    notifyListeners();
                };
                boolean defaultSelected = selectAllCheckBox.isSelected();
                JCheckBox cb = new JCheckBox(String.valueOf(code), defaultSelected);
                cb.addActionListener(itemListener);
                statusCheckBoxMap.put(code, cb);
                added = true;
            }
        }
        if (added) {
            rebuildItemsPanel();
            syncSelectAllState();
            updateButtonLabel();
        }
    }

    private void rebuildItemsPanel() {
        itemsPanel.removeAll();
        for (JCheckBox cb : statusCheckBoxMap.values()) {
            itemsPanel.add(cb);
        }
        itemsPanel.revalidate();
        itemsPanel.repaint();
    }

    public synchronized void clearRegisteredCodes() {
        statusCheckBoxMap.clear();
        itemsPanel.removeAll();
        itemsPanel.revalidate();
        itemsPanel.repaint();
        selectAllCheckBox.setSelected(true);
        updateButtonLabel();
    }

    public void clear() {
        clearRegisteredCodes();
    }

    public synchronized boolean isStatusCodeSelected(int statusCode) {
        if (statusCheckBoxMap.isEmpty()) {
            return true;
        }
        JCheckBox cb = statusCheckBoxMap.get(statusCode);
        return cb != null && cb.isSelected();
    }

    public boolean matches(int statusCode) {
        return isStatusCodeSelected(statusCode);
    }

    public synchronized Set<Integer> getAvailableStatusCodes() {
        return new TreeSet<>(statusCheckBoxMap.keySet());
    }

    public synchronized Set<Integer> getSelectedStatusCodes() {
        Set<Integer> selected = new HashSet<>();
        for (Map.Entry<Integer, JCheckBox> entry : statusCheckBoxMap.entrySet()) {
            if (entry.getValue().isSelected()) {
                selected.add(entry.getKey());
            }
        }
        return selected;
    }

    public synchronized void setSelectedStatusCodes(Set<Integer> codes) {
        updatingProgrammatically = true;
        try {
            for (Map.Entry<Integer, JCheckBox> entry : statusCheckBoxMap.entrySet()) {
                boolean sel = (codes != null && codes.contains(entry.getKey()));
                entry.getValue().setSelected(sel);
            }
        } finally {
            updatingProgrammatically = false;
        }
        syncSelectAllState();
        updateButtonLabel();
        notifyListeners();
    }

    public void addFilterChangeListener(Runnable listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    private void notifyListeners() {
        for (Runnable listener : listeners) {
            try {
                listener.run();
            } catch (Exception ignored) {
            }
        }
    }

    private void syncSelectAllState() {
        int selectedCount = 0;
        for (JCheckBox cb : statusCheckBoxMap.values()) {
            if (cb.isSelected()) {
                selectedCount++;
            }
        }
        updatingProgrammatically = true;
        selectAllCheckBox.setSelected(statusCheckBoxMap.isEmpty() || selectedCount == statusCheckBoxMap.size());
        updatingProgrammatically = false;
    }

    private void updateButtonLabel() {
        if (statusCheckBoxMap.isEmpty()) {
            setText("Status Code: All");
            return;
        }

        int selectedCount = 0;
        Integer singleCode = null;
        for (Map.Entry<Integer, JCheckBox> entry : statusCheckBoxMap.entrySet()) {
            if (entry.getValue().isSelected()) {
                selectedCount++;
                if (singleCode == null) {
                    singleCode = entry.getKey();
                }
            }
        }

        if (selectedCount == statusCheckBoxMap.size()) {
            setText("Status Code: All");
        } else if (selectedCount == 0) {
            setText("Status Code: None (0)");
        } else if (selectedCount == 1 && singleCode != null) {
            setText("Status: " + singleCode);
        } else {
            setText("Status: (" + selectedCount + "/" + statusCheckBoxMap.size() + ")");
        }
    }
}
