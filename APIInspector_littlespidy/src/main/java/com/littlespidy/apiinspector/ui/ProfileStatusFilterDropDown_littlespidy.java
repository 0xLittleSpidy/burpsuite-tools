// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.AuthTestResult_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.List;

/**
 * Multi-select dropdown button for dynamically filtering authentication test results
 * by Profile and Status Code combinations (e.g. Admin - 200, Admin - 404, User - 201).
 */
public class ProfileStatusFilterDropDown_littlespidy extends JButton {

    private final Map<String, JCheckBox> optionCheckBoxMap = new LinkedHashMap<>();
    private final JCheckBox selectAllCheckBox = new JCheckBox("Select All", true);
    private final JPopupMenu popupMenu = new JPopupMenu();
    private final JPanel itemsPanel = new JPanel();
    private final List<Runnable> listeners = new ArrayList<>();
    private boolean updatingProgrammatically = false;

    public ProfileStatusFilterDropDown_littlespidy() {
        super("Status Filter: All");
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
            for (JCheckBox cb : optionCheckBoxMap.values()) {
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
        scrollPane.setPreferredSize(new Dimension(220, 160));
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

    public synchronized void updateOptions(List<AuthTestResult_littlespidy> results) {
        if (results == null) {
            return;
        }

        // Collect unique (Profile - StatusCode) combinations
        Set<String> discoveredKeys = new TreeSet<>();
        for (AuthTestResult_littlespidy r : results) {
            int code = r.getAuthStatusCode();
            if (code > 0) {
                String profName = (r.getProfileName() != null && !r.getProfileName().isBlank())
                        ? r.getProfileName()
                        : (r.getProfileId() != null ? r.getProfileId() : "Unauth");
                discoveredKeys.add(profName + " - " + code);
            }
        }

        // Remove options that are no longer present
        Iterator<Map.Entry<String, JCheckBox>> it = optionCheckBoxMap.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, JCheckBox> entry = it.next();
            if (!discoveredKeys.contains(entry.getKey())) {
                itemsPanel.remove(entry.getValue());
                it.remove();
            }
        }

        ActionListener itemListener = e -> {
            if (updatingProgrammatically) {
                return;
            }
            syncSelectAllState();
            updateButtonLabel();
            notifyListeners();
        };

        boolean hadAny = !optionCheckBoxMap.isEmpty();
        for (String key : discoveredKeys) {
            if (!optionCheckBoxMap.containsKey(key)) {
                boolean defaultSelected = !hadAny || selectAllCheckBox.isSelected();
                JCheckBox cb = new JCheckBox(key, defaultSelected);
                cb.setToolTipText(key);
                cb.addActionListener(itemListener);
                optionCheckBoxMap.put(key, cb);
                itemsPanel.add(cb);
            }
        }

        itemsPanel.revalidate();
        itemsPanel.repaint();
        syncSelectAllState();
        updateButtonLabel();
    }

    private void syncSelectAllState() {
        int selectedCount = 0;
        for (JCheckBox cb : optionCheckBoxMap.values()) {
            if (cb.isSelected()) {
                selectedCount++;
            }
        }
        updatingProgrammatically = true;
        if (selectedCount == optionCheckBoxMap.size() && !optionCheckBoxMap.isEmpty()) {
            selectAllCheckBox.setSelected(true);
        } else {
            selectAllCheckBox.setSelected(false);
        }
        updatingProgrammatically = false;
    }

    private void updateButtonLabel() {
        if (optionCheckBoxMap.isEmpty()) {
            setText("Status Filter: All");
            return;
        }

        int total = optionCheckBoxMap.size();
        int selectedCount = 0;
        for (JCheckBox cb : optionCheckBoxMap.values()) {
            if (cb.isSelected()) {
                selectedCount++;
            }
        }

        if (selectedCount == total) {
            setText("Status Filter: All");
        } else if (selectedCount == 0) {
            setText("Status Filter: None");
        } else {
            setText("Status Filter: " + selectedCount + "/" + total);
        }
    }

    public boolean matches(AuthTestingTab_littlespidy.EndpointResultRow_littlespidy row) {
        if (optionCheckBoxMap.isEmpty()) {
            return true;
        }

        // If all are selected, pass all
        int selectedCount = 0;
        for (JCheckBox cb : optionCheckBoxMap.values()) {
            if (cb.isSelected()) {
                selectedCount++;
            }
        }
        if (selectedCount == optionCheckBoxMap.size()) {
            return true;
        }
        if (selectedCount == 0) {
            return false;
        }

        if (row == null || row.getProfileResults() == null) {
            return false;
        }

        for (Map.Entry<String, AuthTestResult_littlespidy> entry : row.getProfileResults().entrySet()) {
            AuthTestResult_littlespidy res = entry.getValue();
            if (res != null && res.getAuthStatusCode() > 0) {
                String profName = (res.getProfileName() != null && !res.getProfileName().isBlank())
                        ? res.getProfileName()
                        : entry.getKey();
                String key = profName + " - " + res.getAuthStatusCode();
                JCheckBox cb = optionCheckBoxMap.get(key);
                if (cb != null && cb.isSelected()) {
                    return true;
                }
            }
        }
        return false;
    }

    public void selectAll(boolean sel) {
        updatingProgrammatically = true;
        selectAllCheckBox.setSelected(sel);
        for (JCheckBox cb : optionCheckBoxMap.values()) {
            cb.setSelected(sel);
        }
        updatingProgrammatically = false;
        updateButtonLabel();
        notifyListeners();
    }

    public void addFilterChangeListener(Runnable listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    private void notifyListeners() {
        for (Runnable r : listeners) {
            try {
                r.run();
            } catch (Exception ignored) {
            }
        }
    }

    public Map<String, JCheckBox> getOptionCheckBoxMap() {
        return optionCheckBoxMap;
    }
}
