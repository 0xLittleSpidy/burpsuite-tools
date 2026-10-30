// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.CorsTestResult_littlespidy;

import javax.swing.*;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * Multi-select dropdown button for filtering CORS test outcomes.
 */
public class CorsOutcomeFilterDropDown_littlespidy extends JButton {

    private final JCheckBox selectAllCheckBox = new JCheckBox("Select All", true);
    private final JCheckBox reflectedCheckBox = new JCheckBox("Origin Reflected", true);
    private final JCheckBox credentialsCheckBox = new JCheckBox("Credentials Allowed (ACAC)", true);
    private final JCheckBox secureCheckBox = new JCheckBox("Secure / Not Reflected", true);

    private final JPopupMenu popupMenu = new JPopupMenu();
    private final List<Runnable> listeners = new ArrayList<>();
    private boolean updatingProgrammatically = false;

    public CorsOutcomeFilterDropDown_littlespidy() {
        super("CORS Status: All");
        initUI();
    }

    private void initUI() {
        JPanel mainPopupPanel = new JPanel();
        mainPopupPanel.setLayout(new BoxLayout(mainPopupPanel, BoxLayout.Y_AXIS));
        mainPopupPanel.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        selectAllCheckBox.addActionListener(e -> {
            if (updatingProgrammatically) return;
            boolean selected = selectAllCheckBox.isSelected();
            updatingProgrammatically = true;
            reflectedCheckBox.setSelected(selected);
            credentialsCheckBox.setSelected(selected);
            secureCheckBox.setSelected(selected);
            updatingProgrammatically = false;
            updateButtonLabel();
            notifyListeners();
        });
        mainPopupPanel.add(selectAllCheckBox);
        mainPopupPanel.add(new JSeparator());

        ActionListener itemListener = e -> {
            if (updatingProgrammatically) return;
            syncSelectAllState();
            updateButtonLabel();
            notifyListeners();
        };

        reflectedCheckBox.addActionListener(itemListener);
        credentialsCheckBox.addActionListener(itemListener);
        secureCheckBox.addActionListener(itemListener);

        mainPopupPanel.add(reflectedCheckBox);
        mainPopupPanel.add(credentialsCheckBox);
        mainPopupPanel.add(secureCheckBox);

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

    public boolean matches(CorsTestResult_littlespidy result) {
        if (result == null) return false;
        boolean hasAcao = result.getReflectedAcao() != null && !result.getReflectedAcao().isBlank();
        boolean hasAcac = result.isAcacPresent();

        if (hasAcac && credentialsCheckBox.isSelected()) {
            return true;
        }
        if (hasAcao && reflectedCheckBox.isSelected()) {
            return true;
        }
        if (!hasAcao && !hasAcac && secureCheckBox.isSelected()) {
            return true;
        }
        return false;
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
            } catch (Exception ignored) {}
        }
    }

    private void syncSelectAllState() {
        boolean all = reflectedCheckBox.isSelected() && credentialsCheckBox.isSelected() && secureCheckBox.isSelected();
        updatingProgrammatically = true;
        selectAllCheckBox.setSelected(all);
        updatingProgrammatically = false;
    }

    private void updateButtonLabel() {
        int count = 0;
        if (reflectedCheckBox.isSelected()) count++;
        if (credentialsCheckBox.isSelected()) count++;
        if (secureCheckBox.isSelected()) count++;

        if (count == 3) {
            setText("CORS Status: All");
        } else if (count == 0) {
            setText("CORS Status: None (0)");
        } else {
            setText("CORS Status: (" + count + "/3)");
        }
    }
}
