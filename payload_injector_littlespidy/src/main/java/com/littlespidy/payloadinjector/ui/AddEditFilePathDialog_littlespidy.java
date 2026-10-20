// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.ui;

import com.littlespidy.payloadinjector.model.FilePathEntry_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.UUID;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Modal dialog for creating or editing target file path entries.
 *
 * @author littlespidy
 */
public class AddEditFilePathDialog_littlespidy extends JDialog {

    private final JTextField pathField;
    private final JComboBox<String> categoryCombo;
    private final JTextField descField;
    private final JLabel errorLabel;

    private FilePathEntry_littlespidy result = null;

    private static final String[] DEFAULT_CATEGORIES = {
            "System Accounts",
            "System Configuration",
            "Process & Kernel",
            "Web Applications",
            "Web Server Config",
            "Server Logs",
            "SSH & User Files",
            "SAM & Registry",
            "Unattended Setup",
            "IIS & Web Apps",
            "System Files",
            "General"
    };

    public AddEditFilePathDialog_littlespidy(Window owner, String platform, FilePathEntry_littlespidy existing) {
        super(owner, (existing == null ? "Add " : "Edit ") + platform + " Target File Path", ModalityType.APPLICATION_MODAL);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setResizable(true);

        boolean isEdit = existing != null;

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(new EmptyBorder(12, 14, 6, 14));

        GridBagConstraints lc = labelConstraints();
        GridBagConstraints fc = fieldConstraints();

        int gridy = 0;

        // Path
        form.add(bold("Target Path *"), row(lc, gridy));
        pathField = new JTextField(isEdit ? existing.getPath() : "", 35);
        form.add(pathField, row(fc, gridy++));

        // Error label
        errorLabel = new JLabel(" ");
        errorLabel.setForeground(new Color(200, 0, 0));
        errorLabel.setFont(errorLabel.getFont().deriveFont(11f));
        GridBagConstraints ec = row(fc, gridy++);
        ec.insets = new Insets(0, 4, 4, 4);
        form.add(errorLabel, ec);

        // Category
        form.add(bold("Category"), row(lc, gridy));
        categoryCombo = new JComboBox<>(DEFAULT_CATEGORIES);
        categoryCombo.setEditable(true);
        if (isEdit && existing.getCategory() != null && !existing.getCategory().isBlank()) {
            categoryCombo.setSelectedItem(existing.getCategory());
        } else {
            categoryCombo.setSelectedItem("System Configuration");
        }
        form.add(categoryCombo, row(fc, gridy++));

        // Description
        form.add(bold("Description"), row(lc, gridy));
        descField = new JTextField(isEdit ? existing.getDescription() : "", 35);
        form.add(descField, row(fc, gridy++));

        // Buttons
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        JButton saveBtn = new JButton("Save");
        saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD));
        saveBtn.addActionListener(e -> {
            String path = pathField.getText().trim();
            Object catObj = categoryCombo.getSelectedItem();
            String cat = (catObj != null) ? catObj.toString().trim() : "General";
            String desc = descField.getText().trim();

            if (path.isEmpty()) {
                errorLabel.setText("Target file path cannot be empty.");
                pathField.requestFocusInWindow();
                return;
            }

            String id = isEdit ? existing.getId() : UUID.randomUUID().toString();
            String srcType = isEdit ? existing.getSourceType() : "Manual";
            String srcFile = isEdit ? existing.getSourceFile() : "N/A";
            result = new FilePathEntry_littlespidy(id, path, cat, desc, platform, true, srcType, srcFile);
            dispose();
        });

        getRootPane().setDefaultButton(saveBtn);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        buttons.add(cancelBtn);
        buttons.add(saveBtn);

        setLayout(new BorderLayout());
        add(form, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);

        pack();
        setMinimumSize(new Dimension(520, 240));
        setLocationRelativeTo(owner);
    }

    public FilePathEntry_littlespidy getResult() {
        return result;
    }

    private static GridBagConstraints row(GridBagConstraints base, int row) {
        GridBagConstraints c = (GridBagConstraints) base.clone();
        c.gridy = row;
        return c;
    }

    private static GridBagConstraints labelConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        c.insets = new Insets(6, 4, 4, 10);
        return c;
    }

    private static GridBagConstraints fieldConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 1;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        c.insets = new Insets(6, 4, 4, 4);
        return c;
    }

    private static JLabel bold(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD));
        return l;
    }
}
