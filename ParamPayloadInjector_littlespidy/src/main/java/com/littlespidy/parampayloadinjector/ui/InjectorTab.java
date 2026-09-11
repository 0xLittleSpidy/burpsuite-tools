package com.littlespidy.parampayloadinjector.ui;

import com.littlespidy.parampayloadinjector.model.InjectionConfig;
import com.littlespidy.parampayloadinjector.model.PayloadTemplate;
import com.littlespidy.parampayloadinjector.model.ReflectionFinding;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.UUID;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Main Suite Tab containing the Reflection Monitor and Payload Template Configuration panels.
 */
public class InjectorTab extends JPanel {

    private final MontoyaApi api;
    private final InjectionConfig config;
    private final ReflectionTableModel reflectionTableModel;
    private final TemplateTableModel templateTableModel;

    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private JLabel reflectionCountBadge;

    public InjectorTab(MontoyaApi api, InjectionConfig config, ReflectionTableModel reflectionTableModel, TemplateTableModel templateTableModel) {
        this.api = api;
        this.config = config;
        this.reflectionTableModel = reflectionTableModel;
        this.templateTableModel = templateTableModel;

        setLayout(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Reflection Monitor", createReflectionMonitorPanel());
        tabbedPane.addTab("Payload Templates & Settings", createSettingsPanel());

        add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel createReflectionMonitorPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        // ── Top Toolbar ──
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        JButton clearBtn = new JButton("Clear Results");
        clearBtn.addActionListener(e -> {
            reflectionTableModel.clear();
            updateCountBadge();
        });
        toolbar.add(clearBtn);

        JCheckBox inScopeCheck = new JCheckBox("In-Scope Only", false);
        inScopeCheck.addActionListener(e -> reflectionTableModel.setInScopeOnly(inScopeCheck.isSelected()));
        toolbar.add(inScopeCheck);

        toolbar.add(new JLabel("Category:"));
        JComboBox<String> categoryCombo = new JComboBox<>(new String[]{"All", "XSS", "Angular CSTI", "Custom"});
        categoryCombo.addActionListener(e -> reflectionTableModel.setCategoryFilter((String) categoryCombo.getSelectedItem()));
        toolbar.add(categoryCombo);

        toolbar.add(new JLabel("Search:"));
        JTextField searchField = new JTextField(16);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { updateSearch(); }
            @Override public void removeUpdate(DocumentEvent e) { updateSearch(); }
            @Override public void changedUpdate(DocumentEvent e) { updateSearch(); }
            private void updateSearch() {
                reflectionTableModel.setSearchText(searchField.getText());
                updateCountBadge();
            }
        });
        toolbar.add(searchField);

        reflectionCountBadge = new JLabel("Findings: 0");
        reflectionCountBadge.setFont(reflectionCountBadge.getFont().deriveFont(Font.BOLD));
        toolbar.add(reflectionCountBadge);

        panel.add(toolbar, BorderLayout.NORTH);

        // ── Table of Findings ──
        JTable table = new JTable(reflectionTableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(800, 240));

        // ── Bottom Request / Response Split View ──
        this.requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        JPanel reqPanel = new JPanel(new BorderLayout());
        reqPanel.setBorder(new TitledBorder("HTTP Request"));
        reqPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);

        JPanel respPanel = new JPanel(new BorderLayout());
        respPanel.setBorder(new TitledBorder("HTTP Response (Reflection Highlighted)"));
        respPanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);

        JSplitPane httpSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, respPanel);
        httpSplit.setResizeWeight(0.5);

        // Connect table selection to editor update
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) {
                    int modelRow = table.convertRowIndexToModel(selectedRow);
                    ReflectionFinding finding = reflectionTableModel.getFindingAt(modelRow);
                    if (finding != null && finding.getRequestResponse() != null) {
                        requestEditor.setRequest(finding.getRequestResponse().request());
                        responseEditor.setResponse(finding.getRequestResponse().response());
                        responseEditor.setSearchExpression(finding.getParameterName());
                    }
                }
            }
        });

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, httpSplit);
        mainSplit.setResizeWeight(0.35);

        panel.add(mainSplit, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createSettingsPanel() {
        JPanel mainSettings = new JPanel(new BorderLayout(10, 10));
        mainSettings.setBorder(new EmptyBorder(10, 10, 10, 10));

        // ── Configuration Controls ──
        JPanel configPanel = new JPanel(new GridLayout(2, 2, 10, 10));
        configPanel.setBorder(new TitledBorder("Injection Rules & Target Scope"));

        // 1. Injection Mode
        JPanel modePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        modePanel.add(new JLabel("Value Insertion:"));
        JComboBox<InjectionConfig.InjectionMode> modeCombo = new JComboBox<>(InjectionConfig.InjectionMode.values());
        modeCombo.setSelectedItem(config.getInjectionMode());
        modeCombo.addActionListener(e -> config.setInjectionMode((InjectionConfig.InjectionMode) modeCombo.getSelectedItem()));
        modePanel.add(modeCombo);
        configPanel.add(modePanel);

        // 2. Encoding Mode
        JPanel encPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        encPanel.add(new JLabel("Encoding:"));
        JComboBox<InjectionConfig.EncodingMode> encCombo = new JComboBox<>(InjectionConfig.EncodingMode.values());
        encCombo.setSelectedItem(config.getEncodingMode());
        encCombo.addActionListener(e -> config.setEncodingMode((InjectionConfig.EncodingMode) encCombo.getSelectedItem()));
        encPanel.add(encCombo);
        configPanel.add(encPanel);

        // 3. Target Scope Checkboxes
        JPanel scopePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        scopePanel.add(new JLabel("Target Types:"));
        JCheckBox cbUrl = new JCheckBox("URL Query", config.isTargetUrlParams());
        cbUrl.addActionListener(e -> config.setTargetUrlParams(cbUrl.isSelected()));
        scopePanel.add(cbUrl);

        JCheckBox cbBody = new JCheckBox("Form Body", config.isTargetBodyParams());
        cbBody.addActionListener(e -> config.setTargetBodyParams(cbBody.isSelected()));
        scopePanel.add(cbBody);

        JCheckBox cbJson = new JCheckBox("JSON Keys", config.isTargetJsonParams());
        cbJson.addActionListener(e -> config.setTargetJsonParams(cbJson.isSelected()));
        scopePanel.add(cbJson);

        JCheckBox cbCookie = new JCheckBox("Cookies", config.isTargetCookieParams());
        cbCookie.addActionListener(e -> config.setTargetCookieParams(cbCookie.isSelected()));
        scopePanel.add(cbCookie);
        configPanel.add(scopePanel);

        // 4. Passive Detection Toggles
        JPanel detectPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        JCheckBox cbDetect = new JCheckBox("Passive Reflection Detection", config.isReflectionDetectionEnabled());
        cbDetect.addActionListener(e -> config.setReflectionDetectionEnabled(cbDetect.isSelected()));
        detectPanel.add(cbDetect);

        JCheckBox cbAnnotate = new JCheckBox("Annotate Burp History (Notes & Highlights)", config.isAnnotateBurpHistory());
        cbAnnotate.addActionListener(e -> config.setAnnotateBurpHistory(cbAnnotate.isSelected()));
        detectPanel.add(cbAnnotate);
        configPanel.add(detectPanel);

        mainSettings.add(configPanel, BorderLayout.NORTH);

        // ── Template Table & Actions ──
        JPanel templatesPanel = new JPanel(new BorderLayout(5, 5));
        templatesPanel.setBorder(new TitledBorder("Active Payload Templates ({param}, {value}, {rand})"));

        JTable table = new JTable(templateTableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(0).setMaxWidth(60);
        table.getColumnModel().getColumn(1).setPreferredWidth(100);
        table.getColumnModel().getColumn(2).setPreferredWidth(180);
        table.getColumnModel().getColumn(3).setPreferredWidth(320);

        JScrollPane scrollPane = new JScrollPane(table);
        templatesPanel.add(scrollPane, BorderLayout.CENTER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 5));
        JButton addBtn = new JButton("Add Template");
        addBtn.addActionListener(e -> showAddEditDialog(null));
        btnPanel.add(addBtn);

        JButton editBtn = new JButton("Edit Selected");
        editBtn.addActionListener(e -> {
            int sel = table.getSelectedRow();
            if (sel != -1) {
                PayloadTemplate t = templateTableModel.getTemplateAt(table.convertRowIndexToModel(sel));
                if (t != null) showAddEditDialog(t);
            } else {
                JOptionPane.showMessageDialog(this, "Please select a template to edit.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        btnPanel.add(editBtn);

        JButton deleteBtn = new JButton("Delete Selected");
        deleteBtn.addActionListener(e -> {
            int sel = table.getSelectedRow();
            if (sel != -1) {
                PayloadTemplate t = templateTableModel.getTemplateAt(table.convertRowIndexToModel(sel));
                if (t != null) {
                    config.removeTemplate(t);
                }
            }
        });
        btnPanel.add(deleteBtn);

        JButton resetBtn = new JButton("Reset to Defaults");
        resetBtn.addActionListener(e -> {
            int choice = JOptionPane.showConfirmDialog(this, "Reset all templates to default XSS & Angular CSTI presets?", "Confirm Reset", JOptionPane.YES_NO_OPTION);
            if (choice == JOptionPane.YES_OPTION) {
                config.resetToDefaults();
            }
        });
        btnPanel.add(resetBtn);

        templatesPanel.add(btnPanel, BorderLayout.SOUTH);
        mainSettings.add(templatesPanel, BorderLayout.CENTER);

        return mainSettings;
    }

    private void showAddEditDialog(PayloadTemplate existing) {
        boolean isEdit = (existing != null);
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), isEdit ? "Edit Template" : "Add New Template", true);
        dialog.setLayout(new BorderLayout(10, 10));

        JPanel form = new JPanel(new GridLayout(4, 2, 8, 8));
        form.setBorder(new EmptyBorder(12, 12, 12, 12));

        form.add(new JLabel("Category:"));
        JComboBox<String> catBox = new JComboBox<>(new String[]{"XSS", "Angular CSTI", "Custom"});
        catBox.setEditable(true);
        if (isEdit) catBox.setSelectedItem(existing.getCategory());
        form.add(catBox);

        form.add(new JLabel("Name:"));
        JTextField nameField = new JTextField(isEdit ? existing.getName() : "");
        form.add(nameField);

        form.add(new JLabel("Template String:"));
        JTextField templateField = new JTextField(isEdit ? existing.getTemplate() : "\"><script>alert('{param}')</script>");
        form.add(templateField);

        form.add(new JLabel("Description:"));
        JTextField descField = new JTextField(isEdit ? existing.getDescription() : "");
        form.add(descField);

        dialog.add(form, BorderLayout.CENTER);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveBtn = new JButton("Save");
        saveBtn.addActionListener(e -> {
            String cat = catBox.getSelectedItem() != null ? catBox.getSelectedItem().toString().trim() : "Custom";
            String name = nameField.getText().trim();
            String tpl = templateField.getText().trim();
            String desc = descField.getText().trim();

            if (name.isEmpty() || tpl.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "Name and Template cannot be empty.", "Validation Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (isEdit) {
                existing.setCategory(cat);
                existing.setName(name);
                existing.setTemplate(tpl);
                existing.setDescription(desc);
                config.updateTemplate(existing);
            } else {
                PayloadTemplate newT = new PayloadTemplate(UUID.randomUUID().toString(), cat, name, tpl, desc, true);
                config.addTemplate(newT);
            }
            dialog.dispose();
        });
        actions.add(saveBtn);

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dialog.dispose());
        actions.add(cancelBtn);

        dialog.add(actions, BorderLayout.SOUTH);
        dialog.pack();
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }

    public void updateCountBadge() {
        SwingUtilities.invokeLater(() -> {
            if (reflectionCountBadge != null) {
                reflectionCountBadge.setText("Findings: " + reflectionTableModel.getFilteredCount() + " (Total: " + reflectionTableModel.getTotalCount() + ")");
            }
        });
    }
}
