// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredSecurityBypass;
import com.littlespidy.jssourcemapexplorer.model.JsDataStore;
import com.littlespidy.jssourcemapexplorer.model.JsFileEntry;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Dedicated top-level tab panel for analyzing, filtering, and classifying framework-specific
 * sanitization bypasses and dangerous DOM sinks from JavaScript assets and unpacked Source Maps.
 *
 * @author littlespidy
 */
public class SecurityBypassesPanel_littlespidy extends BaseFindingPanel_littlespidy {

    private final SecurityBypassesTableModel tableModel;
    private MultiSelectFilterButton frameworkFilterBtn;
    private MultiSelectFilterButton riskFilterBtn;

    private final List<DiscoveredSecurityBypass> allBypasses = new ArrayList<>();

    public SecurityBypassesPanel_littlespidy(MontoyaApi api, JsDataStore dataStore) {
        this(api, dataStore, new SecurityBypassesTableModel());
    }

    private SecurityBypassesPanel_littlespidy(MontoyaApi api, JsDataStore dataStore, SecurityBypassesTableModel model) {
        super(api, dataStore, "Security Bypasses", model);
        this.tableModel = model;
    }

    @Override
    protected void addCategoryFiltersToToolbar(JPanel toolbar) {
        JLabel fwLbl = new JLabel("Framework:");
        fwLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(fwLbl);

        frameworkFilterBtn = new MultiSelectFilterButton(
            "Framework",
            List.of("All Frameworks", "Angular", "React", "Vue", "Svelte", "Sanitizer / Policy Bypass", "Vanilla DOM Sink", "jQuery"),
            sel -> applyFilter()
        );
        toolbar.add(frameworkFilterBtn);

        JLabel riskLbl = new JLabel("Risk:");
        riskLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(riskLbl);

        riskFilterBtn = new MultiSelectFilterButton(
            "Risk",
            List.of("All Risks", "Critical", "High", "Medium"),
            sel -> applyFilter()
        );
        toolbar.add(riskFilterBtn);
    }

    @Override
    protected void resetCategoryFilters() {
        if (frameworkFilterBtn != null) frameworkFilterBtn.clearSelection();
        if (riskFilterBtn != null) riskFilterBtn.clearSelection();
    }

    @Override
    public synchronized void refreshFromDataStore() {
        allBypasses.clear();
        if (dataStore != null) {
            for (JsFileEntry entry : dataStore.getEntries()) {
                allBypasses.addAll(entry.getJsSecurityBypasses());
                if (entry.getUnpackedProject() != null) {
                    allBypasses.addAll(entry.getUnpackedProject().getAllSecurityBypasses());
                }
            }
        }
        applyFilter();
    }

    @Override
    public synchronized void applyFilter() {
        Set<String> selectedFrameworks = frameworkFilterBtn != null ? frameworkFilterBtn.getSelected() : Collections.emptySet();
        Set<String> selectedRisks = riskFilterBtn != null ? riskFilterBtn.getSelected() : Collections.emptySet();
        String query = searchField.getText().trim().toLowerCase();

        List<DiscoveredSecurityBypass> filtered = new ArrayList<>();
        int tpCount = 0;
        int fpCount = 0;
        int unclassCount = 0;

        for (DiscoveredSecurityBypass bypass : allBypasses) {
            String cls = bypass.classification() != null ? bypass.classification() : "Not Classified";
            if ("True Positive".equalsIgnoreCase(cls)) tpCount++;
            else if ("False Positive".equalsIgnoreCase(cls)) fpCount++;
            else unclassCount++;

            if (!selectedFrameworks.isEmpty() && !selectedFrameworks.contains(bypass.framework())) {
                continue;
            }
            if (!selectedRisks.isEmpty() && !selectedRisks.contains(bypass.risk())) {
                continue;
            }
            if (!matchesClassification(bypass.classification())) {
                continue;
            }
            if (!query.isEmpty()) {
                boolean match = (bypass.method() != null && bypass.method().toLowerCase().contains(query))
                    || (bypass.framework() != null && bypass.framework().toLowerCase().contains(query))
                    || (bypass.description() != null && bypass.description().toLowerCase().contains(query))
                    || (bypass.sourceLocation() != null && bypass.sourceLocation().toLowerCase().contains(query))
                    || (bypass.contextSnippet() != null && bypass.contextSnippet().toLowerCase().contains(query));
                if (!match) continue;
            }
            filtered.add(bypass);
        }

        tableModel.updateData(filtered);
        if (allBypasses.isEmpty()) {
            statsLabel.setText("Security Bypasses: 0 (No findings found)");
        } else {
            statsLabel.setText(String.format("Security Bypasses: %d (Visible: %d | TP: %d | FP: %d | Unclassified: %d)",
                allBypasses.size(), filtered.size(), tpCount, fpCount, unclassCount));
        }
    }

    @Override
    protected String getClassificationAt(int modelRow) {
        DiscoveredSecurityBypass bypass = tableModel.getBypassAt(modelRow);
        return bypass != null ? bypass.classification() : "Not Classified";
    }

    @Override
    protected void updateClassification(int modelRow, String classification) {
        DiscoveredSecurityBypass bypass = tableModel.getBypassAt(modelRow);
        if (bypass == null) return;

        DiscoveredSecurityBypass updated = bypass.withClassification(classification);
        tableModel.setBypassAt(modelRow, updated);

        for (int i = 0; i < allBypasses.size(); i++) {
            DiscoveredSecurityBypass cur = allBypasses.get(i);
            if (cur == bypass || (Objects.equals(cur.method(), bypass.method()) && Objects.equals(cur.sourceLocation(), bypass.sourceLocation()))) {
                allBypasses.set(i, updated);
                break;
            }
        }

        syncClassificationToStore(bypass, updated);
    }

    private void syncClassificationToStore(DiscoveredSecurityBypass oldBypass, DiscoveredSecurityBypass newBypass) {
        if (dataStore == null) return;
        for (JsFileEntry entry : dataStore.getEntries()) {
            if (entry.updateSecurityBypass(oldBypass, newBypass)) {
                return;
            }
            if (entry.getUnpackedProject() != null) {
                if (entry.getUnpackedProject().updateSecurityBypass(oldBypass, newBypass)) {
                    return;
                }
            }
        }
    }

    @Override
    protected String getFindingTextAt(int modelRow) {
        DiscoveredSecurityBypass bypass = tableModel.getBypassAt(modelRow);
        return bypass != null ? bypass.method() : "";
    }

    @Override
    protected int getStartOffsetAt(int modelRow) {
        DiscoveredSecurityBypass bypass = tableModel.getBypassAt(modelRow);
        return bypass != null ? bypass.startOffset() : -1;
    }

    @Override
    protected int getEndOffsetAt(int modelRow) {
        DiscoveredSecurityBypass bypass = tableModel.getBypassAt(modelRow);
        return bypass != null ? bypass.endOffset() : -1;
    }

    @Override
    protected String getSourceLocationAt(int modelRow) {
        DiscoveredSecurityBypass bypass = tableModel.getBypassAt(modelRow);
        return bypass != null ? bypass.sourceLocation() : "";
    }

    @Override
    protected void exportTsv(JTable tbl) {
        int[] rows = tbl.getSelectedRows();
        boolean useAll = rows.length == 0;
        int count = useAll ? tbl.getRowCount() : rows.length;

        StringBuilder sb = new StringBuilder();
        for (int c = 0; c < tableModel.getColumnCount(); c++) {
            if (c > 0) sb.append("\t");
            sb.append(tableModel.getColumnName(c));
        }
        sb.append("\n");

        for (int i = 0; i < count; i++) {
            int rowIdx = useAll ? i : rows[i];
            int modelRow = tbl.convertRowIndexToModel(rowIdx);
            for (int c = 0; c < tableModel.getColumnCount(); c++) {
                if (c > 0) sb.append("\t");
                Object val = tableModel.getValueAt(modelRow, c);
                sb.append(val != null ? val.toString().replace("\t", " ").replace("\n", " ") : "");
            }
            sb.append("\n");
        }

        copyToClipboard(sb.toString());
        JOptionPane.showMessageDialog(this, String.format("Copied %d security bypass(es) to clipboard as TSV.", count), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
    }

    private static class SecurityBypassesTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "#", "Framework", "Bypass Method / Sink", "Risk", "Confidence", "Description", "Source Type", "Source Location", "Line"
        };
        private final List<DiscoveredSecurityBypass> list = new ArrayList<>();

        public synchronized void updateData(List<DiscoveredSecurityBypass> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized DiscoveredSecurityBypass getBypassAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        public synchronized void setBypassAt(int row, DiscoveredSecurityBypass bypass) {
            if (row >= 0 && row < list.size()) {
                list.set(row, bypass);
                fireTableRowsUpdated(row, row);
            }
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) {
            return (c == 0 || c == 8) ? Integer.class : String.class;
        }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            DiscoveredSecurityBypass item = list.get(r);
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> item.framework();
                case 2 -> item.method();
                case 3 -> item.risk();
                case 4 -> item.confidence();
                case 5 -> item.description();
                case 6 -> item.sourceType();
                case 7 -> item.sourceLocation();
                case 8 -> item.line();
                default -> null;
            };
        }
    }
}
