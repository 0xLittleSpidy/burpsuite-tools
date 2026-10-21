// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import javax.swing.*;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * Multi-select dropdown button for filtering endpoints by authentication requirement.
 * Allows filtering between endpoints requiring authentication and endpoints not requiring authentication.
 */
public class AuthFilterDropDown_littlespidy extends JButton {

    private final JCheckBox selectAllCheckBox = new JCheckBox("Select All", true);
    private final JCheckBox requiresAuthCheckBox = new JCheckBox("Requires Auth", true);
    private final JCheckBox noAuthCheckBox = new JCheckBox("No Auth Required", true);
    private final JPopupMenu popupMenu = new JPopupMenu();
    private final List<Runnable> listeners = new ArrayList<>();
    private boolean updatingProgrammatically = false;

    public AuthFilterDropDown_littlespidy() {
        super("Auth: All");
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
            requiresAuthCheckBox.setSelected(selected);
            noAuthCheckBox.setSelected(selected);
            updatingProgrammatically = false;
            updateButtonLabel();
            notifyListeners();
        });
        mainPopupPanel.add(selectAllCheckBox);
        mainPopupPanel.add(new JSeparator());

        ActionListener itemListener = e -> {
            if (updatingProgrammatically) {
                return;
            }
            syncSelectAllState();
            updateButtonLabel();
            notifyListeners();
        };

        requiresAuthCheckBox.addActionListener(itemListener);
        noAuthCheckBox.addActionListener(itemListener);

        mainPopupPanel.add(requiresAuthCheckBox);
        mainPopupPanel.add(noAuthCheckBox);
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

    private void syncSelectAllState() {
        updatingProgrammatically = true;
        selectAllCheckBox.setSelected(requiresAuthCheckBox.isSelected() && noAuthCheckBox.isSelected());
        updatingProgrammatically = false;
    }

    private void updateButtonLabel() {
        boolean req = requiresAuthCheckBox.isSelected();
        boolean noReq = noAuthCheckBox.isSelected();

        if (req && noReq) {
            setText("Auth: All");
        } else if (req) {
            setText("Auth: Required");
        } else if (noReq) {
            setText("Auth: None");
        } else {
            setText("Auth: 0 Selected");
        }
    }

    public boolean isAuthOptionSelected(boolean requiresAuth) {
        if (requiresAuth) {
            return requiresAuthCheckBox.isSelected();
        } else {
            return noAuthCheckBox.isSelected();
        }
    }

    public boolean isRequiresAuthSelected() {
        return requiresAuthCheckBox.isSelected();
    }

    public boolean isNoAuthSelected() {
        return noAuthCheckBox.isSelected();
    }

    public void selectAll(boolean select) {
        updatingProgrammatically = true;
        selectAllCheckBox.setSelected(select);
        requiresAuthCheckBox.setSelected(select);
        noAuthCheckBox.setSelected(select);
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
}
