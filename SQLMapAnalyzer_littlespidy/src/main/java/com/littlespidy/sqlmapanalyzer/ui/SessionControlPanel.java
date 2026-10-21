// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui;

import com.littlespidy.sqlmapanalyzer.persistence.SQLMapPersistenceManager;
import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Top-level toolbar for persistent session management actions.
 * Plain ASCII text only.
 */
public class SessionControlPanel extends JPanel {

    private final SQLMapPersistenceManager persistenceManager;

    public SessionControlPanel(SQLMapPersistenceManager persistenceManager) {
        this.persistenceManager = persistenceManager;
        setLayout(new BorderLayout(10, 0));
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                new EmptyBorder(6, 10, 6, 10)
        ));

        // Left side: Session status indicator
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        leftPanel.add(persistenceManager.getSessionStatusLabel());
        add(leftPanel, BorderLayout.WEST);

        // Right side: Session action buttons
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));

        JButton btnNew = SwingUtils.createStyledButton("New Session");
        btnNew.setToolTipText("Create a new session bound to a directory on disk");
        btnNew.addActionListener(e -> persistenceManager.createNewSession(this));

        JButton btnOpen = SwingUtils.createStyledButton("Open Session");
        btnOpen.setToolTipText("Open an existing session JSON file");
        btnOpen.addActionListener(e -> persistenceManager.openSession(this));

        JButton btnSaveAs = SwingUtils.createStyledButton("Save As...");
        btnSaveAs.setToolTipText("Save current state to a new session JSON file");
        btnSaveAs.addActionListener(e -> persistenceManager.saveSessionAs(this));

        JButton btnOffboard = SwingUtils.createStyledButton("Offboard Session");
        btnOffboard.setToolTipText("Unbind active session and clear workspace to fresh state");
        btnOffboard.addActionListener(e -> persistenceManager.offboardSession(this));

        rightPanel.add(btnNew);
        rightPanel.add(btnOpen);
        rightPanel.add(btnSaveAs);
        rightPanel.add(btnOffboard);

        add(rightPanel, BorderLayout.EAST);
    }
}
