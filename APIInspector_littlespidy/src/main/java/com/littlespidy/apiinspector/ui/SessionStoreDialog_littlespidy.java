// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.SessionStore_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Dialog for managing session-specific authentication information including
 * tokens, custom HTTP headers, cookies, and scope rules.
 */
public class SessionStoreDialog_littlespidy extends JDialog {

    private final SessionStore_littlespidy sessionStore;
    private final Runnable onSaveCallback;

    private JCheckBox enableCheckBox;
    private JRadioButton authOnlyRadio;
    private JRadioButton allRequestsRadio;
    private JTextField tokenField;
    private DefaultTableModel headersTableModel;
    private JTable headersTable;
    private JTextField cookieNameField;
    private JTextField cookieValueField;

    public SessionStoreDialog_littlespidy(Window parent, SessionStore_littlespidy sessionStore, Runnable onSaveCallback) {
        super(parent, "Session Authentication Store", ModalityType.APPLICATION_MODAL);
        this.sessionStore = sessionStore;
        this.onSaveCallback = onSaveCallback;

        initComponents();
        loadFromStore();
        pack();
        setMinimumSize(new Dimension(540, 480));
        setLocationRelativeTo(parent);
    }

    private void initComponents() {
        JPanel contentPane = new JPanel(new BorderLayout(8, 8));
        contentPane.setBorder(new EmptyBorder(12, 12, 12, 12));

        JPanel formPanel = new JPanel();
        formPanel.setLayout(new BoxLayout(formPanel, BoxLayout.Y_AXIS));

        // 1. General & Scope Section
        JPanel scopeCard = new JPanel();
        scopeCard.setLayout(new BoxLayout(scopeCard, BoxLayout.Y_AXIS));
        scopeCard.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "General & Scope Settings", TitledBorder.LEFT, TitledBorder.TOP));

        enableCheckBox = new JCheckBox("Enable Session Store Authentication");
        enableCheckBox.setFont(enableCheckBox.getFont().deriveFont(Font.BOLD));
        scopeCard.add(enableCheckBox);
        scopeCard.add(Box.createVerticalStrut(6));

        JPanel scopeRadioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        authOnlyRadio = new JRadioButton("Only endpoints requiring authentication");
        allRequestsRadio = new JRadioButton("All endpoints");
        ButtonGroup scopeGroup = new ButtonGroup();
        scopeGroup.add(authOnlyRadio);
        scopeGroup.add(allRequestsRadio);
        scopeRadioPanel.add(new JLabel("Apply to:"));
        scopeRadioPanel.add(authOnlyRadio);
        scopeRadioPanel.add(allRequestsRadio);
        scopeCard.add(scopeRadioPanel);

        formPanel.add(scopeCard);
        formPanel.add(Box.createVerticalStrut(8));

        // 2. Authentication Token Section
        JPanel tokenCard = new JPanel(new BorderLayout(6, 4));
        tokenCard.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Authentication Token", TitledBorder.LEFT, TitledBorder.TOP));

        JPanel tokenRow = new JPanel(new BorderLayout(6, 2));
        tokenRow.setBorder(new EmptyBorder(4, 6, 4, 6));
        tokenRow.add(new JLabel("Bearer / API Token:"), BorderLayout.WEST);
        tokenField = new JTextField();
        tokenRow.add(tokenField, BorderLayout.CENTER);
        tokenCard.add(tokenRow, BorderLayout.CENTER);

        JLabel tokenHelp = new JLabel("Injected as 'Authorization: Bearer <token>' header.");
        tokenHelp.setFont(tokenHelp.getFont().deriveFont(Font.ITALIC, 11f));
        tokenHelp.setForeground(Color.GRAY);
        tokenHelp.setBorder(new EmptyBorder(0, 6, 4, 6));
        tokenCard.add(tokenHelp, BorderLayout.SOUTH);

        formPanel.add(tokenCard);
        formPanel.add(Box.createVerticalStrut(8));

        // 3. Custom HTTP Headers Section
        JPanel headersCard = new JPanel(new BorderLayout(6, 4));
        headersCard.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Custom HTTP Headers", TitledBorder.LEFT, TitledBorder.TOP));

        String[] headerCols = {"Header Name", "Header Value"};
        headersTableModel = new DefaultTableModel(headerCols, 0);
        headersTable = new JTable(headersTableModel);
        headersTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane headerScroll = new JScrollPane(headersTable);
        headerScroll.setPreferredSize(new Dimension(480, 100));
        headersCard.add(headerScroll, BorderLayout.CENTER);

        JPanel headerButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton addHeaderBtn = new JButton("Add Header");
        addHeaderBtn.addActionListener(e -> headersTableModel.addRow(new Object[]{"X-Custom-Header", "value"}));
        JButton removeHeaderBtn = new JButton("Remove Header");
        removeHeaderBtn.addActionListener(e -> {
            int selected = headersTable.getSelectedRow();
            if (selected >= 0) {
                headersTableModel.removeRow(selected);
            }
        });
        headerButtons.add(addHeaderBtn);
        headerButtons.add(removeHeaderBtn);
        headersCard.add(headerButtons, BorderLayout.SOUTH);

        formPanel.add(headersCard);
        formPanel.add(Box.createVerticalStrut(8));

        // 4. Session Cookie Section
        JPanel cookieCard = new JPanel(new BorderLayout(6, 4));
        cookieCard.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Session Cookie", TitledBorder.LEFT, TitledBorder.TOP));

        JPanel cookieRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        cookieRow.add(new JLabel("Cookie Name:"));
        cookieNameField = new JTextField(12);
        cookieRow.add(cookieNameField);
        cookieRow.add(new JLabel("Value:"));
        cookieValueField = new JTextField(18);
        cookieRow.add(cookieValueField);
        cookieCard.add(cookieRow, BorderLayout.CENTER);

        formPanel.add(cookieCard);

        contentPane.add(formPanel, BorderLayout.CENTER);

        // --- Bottom Action Buttons ---
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        JButton saveBtn = new JButton("Save & Apply");
        saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD));
        saveBtn.addActionListener(e -> onSave());

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        bottomBar.add(saveBtn);
        bottomBar.add(cancelBtn);
        contentPane.add(bottomBar, BorderLayout.SOUTH);

        setContentPane(contentPane);
    }

    private void loadFromStore() {
        if (sessionStore == null) return;
        enableCheckBox.setSelected(sessionStore.isEnabled());
        if (SessionStore_littlespidy.MODE_ALL_REQUESTS.equals(sessionStore.getApplyMode())) {
            allRequestsRadio.setSelected(true);
        } else {
            authOnlyRadio.setSelected(true);
        }
        tokenField.setText(sessionStore.getBearerToken());

        headersTableModel.setRowCount(0);
        if (sessionStore.getCustomHeaders() != null) {
            for (Map.Entry<String, String> entry : sessionStore.getCustomHeaders().entrySet()) {
                headersTableModel.addRow(new Object[]{entry.getKey(), entry.getValue()});
            }
        }

        cookieNameField.setText(sessionStore.getCookieName());
        cookieValueField.setText(sessionStore.getCookieValue());
    }

    private void onSave() {
        if (headersTable.isEditing()) {
            headersTable.getCellEditor().stopCellEditing();
        }

        sessionStore.setEnabled(enableCheckBox.isSelected());
        sessionStore.setApplyMode(allRequestsRadio.isSelected()
                ? SessionStore_littlespidy.MODE_ALL_REQUESTS
                : SessionStore_littlespidy.MODE_AUTH_REQUIRED_ONLY);
        sessionStore.setBearerToken(tokenField.getText().trim());

        Map<String, String> customHeaders = new LinkedHashMap<>();
        for (int i = 0; i < headersTableModel.getRowCount(); i++) {
            Object k = headersTableModel.getValueAt(i, 0);
            Object v = headersTableModel.getValueAt(i, 1);
            if (k != null && !k.toString().isBlank()) {
                customHeaders.put(k.toString().trim(), v != null ? v.toString().trim() : "");
            }
        }
        sessionStore.setCustomHeaders(customHeaders);
        sessionStore.setCookieName(cookieNameField.getText().trim());
        sessionStore.setCookieValue(cookieValueField.getText().trim());

        if (onSaveCallback != null) {
            onSaveCallback.run();
        }
        dispose();
    }
}
