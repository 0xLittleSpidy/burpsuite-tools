// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.ui;

import com.littlespidy.sessionexpiration.model.SessionTask;
import com.littlespidy.sessionexpiration.model.TimerInterval;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Dialog allowing testers to configure custom milestone timers (e.g., 30 min, 1 hr, 3 hr, 8 hr)
 * and cancellation preferences before scheduling a session task.
 *
 * @author littlespidy
 */
public class TimerConfigDialog extends JDialog {

    private boolean confirmed = false;
    private final List<TimerInterval> intervals = new ArrayList<>();
    private final DefaultTableModel tableModel;
    private final JTable intervalTable;

    private final JCheckBox cancelOnExpireBox;
    private final JCheckBox refreshBaselineBox;

    public TimerConfigDialog(Window owner, SessionTask task) {
        super(owner, "⏱️ Configure Session Expiration Timers", ModalityType.APPLICATION_MODAL);
        setLayout(new BorderLayout(10, 10));
        setSize(580, 520);
        setLocationRelativeTo(owner);

        // ── Top Header / Target Details ─────────────────────────────────────
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 12, 5, 12));

        String title = "Target: " + task.getMethod() + " " + task.getUrl();
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));
        topPanel.add(titleLabel, BorderLayout.NORTH);

        String baselineInfo = "Baseline: " + (task.getBaselineStatusCode() > 0
                ? (task.getBaselineStatusCode() + " (" + task.getBaselineLength() + " bytes)")
                : "Not yet captured (will execute on start)");
        JLabel subLabel = new JLabel(baselineInfo);
        subLabel.setFont(subLabel.getFont().deriveFont(Font.ITALIC, 11f));
        topPanel.add(subLabel, BorderLayout.SOUTH);

        add(topPanel, BorderLayout.NORTH);

        // ── Center: Presets, Custom Input & Table ───────────────────────────
        JPanel centerPanel = new JPanel(new BorderLayout(8, 8));
        centerPanel.setBorder(BorderFactory.createEmptyBorder(0, 12, 5, 12));

        // Quick Preset Buttons
        JPanel presetsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        presetsPanel.setBorder(BorderFactory.createTitledBorder("Quick-Add Milestones"));

        JButton defaultAllBtn = new JButton("⚡ 30m to 8h (All 16)");
        defaultAllBtn.setFont(defaultAllBtn.getFont().deriveFont(Font.BOLD, 11f));
        defaultAllBtn.setToolTipText("Load all 16 milestones: 30m, 1h, 1.5h, 2h ... up to 8h");
        defaultAllBtn.addActionListener(e -> {
            for (TimerInterval ti : TimerInterval.createDefaultMilestones()) {
                addInterval(ti);
            }
        });
        presetsPanel.add(defaultAllBtn);

        String[][] presets = {
                {"+15m", "900"},
                {"+30m", "1800"},
                {"+1h", "3600"},
                {"+1.5h", "5400"},
                {"+2h", "7200"},
                {"+2.5h", "9000"},
                {"+3h", "10800"},
                {"+4h", "14400"},
                {"+6h", "21600"},
                {"+8h", "28800"},
                {"+24h", "86400"}
        };

        for (String[] p : presets) {
            JButton btn = new JButton(p[0]);
            btn.setFont(btn.getFont().deriveFont(11f));
            long secs = Long.parseLong(p[1]);
            btn.addActionListener(e -> addInterval(new TimerInterval(secs, TimerInterval.formatDuration(secs))));
            presetsPanel.add(btn);
        }

        // Custom Add Row
        JPanel customPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        customPanel.setBorder(BorderFactory.createTitledBorder("Custom Interval"));

        JSpinner valueSpinner = new JSpinner(new SpinnerNumberModel(45, 1, 10000, 1));
        JComboBox<String> unitCombo = new JComboBox<>(new String[]{"Minutes", "Hours", "Seconds"});
        JButton addBtn = new JButton("➕ Add Milestone");

        addBtn.addActionListener(e -> {
            int val = (Integer) valueSpinner.getValue();
            String unit = (String) unitCombo.getSelectedItem();
            long secs;
            if ("Hours".equalsIgnoreCase(unit)) {
                secs = (long) val * 3600;
            } else if ("Seconds".equalsIgnoreCase(unit)) {
                secs = val;
            } else {
                secs = (long) val * 60;
            }
            addInterval(new TimerInterval(secs, TimerInterval.formatDuration(secs)));
        });

        customPanel.add(new JLabel("Value:"));
        customPanel.add(valueSpinner);
        customPanel.add(unitCombo);
        customPanel.add(addBtn);

        JPanel inputContainer = new JPanel(new GridLayout(2, 1, 4, 4));
        inputContainer.add(presetsPanel);
        inputContainer.add(customPanel);
        centerPanel.add(inputContainer, BorderLayout.NORTH);

        // Intervals Table
        String[] columns = {"#", "Milestone Offset (from T0)", "Delay in Seconds"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        intervalTable = new JTable(tableModel);
        intervalTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JScrollPane tableScroll = new JScrollPane(intervalTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Scheduled Milestones"));

        JPanel tableActionsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 4));
        JButton removeBtn = new JButton("❌ Remove Selected");
        removeBtn.addActionListener(e -> removeSelected());
        JButton clearBtn = new JButton("Clear All");
        clearBtn.addActionListener(e -> clearAllIntervals());

        tableActionsPanel.add(removeBtn);
        tableActionsPanel.add(clearBtn);

        JPanel tableContainer = new JPanel(new BorderLayout());
        tableContainer.add(tableScroll, BorderLayout.CENTER);
        tableContainer.add(tableActionsPanel, BorderLayout.SOUTH);

        centerPanel.add(tableContainer, BorderLayout.CENTER);

        add(centerPanel, BorderLayout.CENTER);

        // ── Bottom Panel: Checkboxes & Confirmation ─────────────────────────
        JPanel bottomPanel = new JPanel(new BorderLayout(6, 6));
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(6, 12, 10, 12));

        JPanel optionsPanel = new JPanel(new GridLayout(2, 1, 2, 2));
        cancelOnExpireBox = new JCheckBox("Cancel remaining scheduled timers if session expires", true);
        refreshBaselineBox = new JCheckBox("Send immediate baseline request now to establish baseline response",
                task.getBaseline() == null || !task.getBaseline().hasResponse());
        optionsPanel.add(cancelOnExpireBox);
        optionsPanel.add(refreshBaselineBox);
        bottomPanel.add(optionsPanel, BorderLayout.NORTH);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        JButton startBtn = new JButton("▶️ Start Tracking");
        startBtn.setFont(startBtn.getFont().deriveFont(Font.BOLD));
        startBtn.addActionListener(e -> {
            if (intervals.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        "Please configure at least one milestone timer before starting.",
                        "No Milestones Configured", JOptionPane.WARNING_MESSAGE);
                return;
            }
            confirmed = true;
            dispose();
        });

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        buttonPanel.add(startBtn);
        buttonPanel.add(cancelBtn);
        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);

        add(bottomPanel, BorderLayout.SOUTH);

        // Load existing intervals or defaults (30m, 1h, 3h, 8h)
        if (task.getIntervals() != null && !task.getIntervals().isEmpty()) {
            for (TimerInterval ti : task.getIntervals()) {
                addInterval(new TimerInterval(ti.getDelaySeconds(), ti.getLabel()));
            }
        } else {
            // Default configuration: 16 milestones every 30m up to 8h
            for (TimerInterval ti : TimerInterval.createDefaultMilestones()) {
                addInterval(ti);
            }
        }
    }

    private void addInterval(TimerInterval interval) {
        // Prevent duplicate delays
        for (TimerInterval existing : intervals) {
            if (existing.getDelaySeconds() == interval.getDelaySeconds()) {
                return;
            }
        }
        intervals.add(interval);
        Collections.sort(intervals);
        refreshTable();
    }

    private void removeSelected() {
        int[] rows = intervalTable.getSelectedRows();
        if (rows.length == 0) return;

        List<TimerInterval> toRemove = new ArrayList<>();
        for (int r : rows) {
            int modelIdx = intervalTable.convertRowIndexToModel(r);
            if (modelIdx >= 0 && modelIdx < intervals.size()) {
                toRemove.add(intervals.get(modelIdx));
            }
        }
        intervals.removeAll(toRemove);
        refreshTable();
    }

    private void clearAllIntervals() {
        intervals.clear();
        refreshTable();
    }

    private void refreshTable() {
        tableModel.setRowCount(0);
        for (int i = 0; i < intervals.size(); i++) {
            TimerInterval ti = intervals.get(i);
            tableModel.addRow(new Object[]{
                    (i + 1),
                    ti.getLabel() + " (" + ti.getDelaySeconds() + "s from T0)",
                    ti.getDelaySeconds()
            });
        }
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public List<TimerInterval> getSelectedIntervals() {
        return Collections.unmodifiableList(intervals);
    }

    public boolean isCancelOnExpire() {
        return cancelOnExpireBox.isSelected();
    }

    public boolean isRefreshBaseline() {
        return refreshBaselineBox.isSelected();
    }
}
