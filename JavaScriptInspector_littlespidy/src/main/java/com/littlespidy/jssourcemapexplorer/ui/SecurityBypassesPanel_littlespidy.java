// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.jssourcemapexplorer.model.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Dedicated top-level tab panel for analyzing, filtering, and classifying framework-specific
 * sanitization bypasses and dangerous DOM sinks from JavaScript assets and unpacked Source Maps.
 * Groups duplicate security bypasses across files with an Occurrences column and occurrence navigation.
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

        Map<String, GroupedFinding_littlespidy<DiscoveredSecurityBypass>> groupedMap = new LinkedHashMap<>();
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
            if (!matchesSourceType(bypass.sourceType())) {
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

            String key = (bypass.method() != null ? bypass.method().trim() : "")
                + "||" + (bypass.framework() != null ? bypass.framework().trim() : "")
                + "||" + (bypass.risk() != null ? bypass.risk().trim() : "");

            FindingOccurrence_littlespidy occ = new FindingOccurrence_littlespidy(
                bypass.sourceLocation(),
                bypass.sourceType(),
                bypass.method(),
                bypass.line(),
                bypass.startOffset(),
                bypass.endOffset(),
                bypass.contextSnippet()
            );

            GroupedFinding_littlespidy<DiscoveredSecurityBypass> grp = groupedMap.get(key);
            if (grp == null) {
                grp = new GroupedFinding_littlespidy<>(bypass, occ);
                groupedMap.put(key, grp);
            } else {
                grp.addOccurrence(bypass, occ);
                if (!"Not Classified".equalsIgnoreCase(bypass.classification())
                    && "Not Classified".equalsIgnoreCase(grp.getPrimary().classification())) {
                    grp.setPrimary(grp.getPrimary().withClassification(bypass.classification()));
                }
            }
        }

        List<GroupedFinding_littlespidy<DiscoveredSecurityBypass>> result = new ArrayList<>(groupedMap.values());
        tableModel.updateData(result);

        if (allBypasses.isEmpty()) {
            statsLabel.setText("Security Bypasses: 0 (No findings found)");
        } else {
            statsLabel.setText(String.format("Security Bypasses: %d unique (%d total) | Visible: %d | TP: %d | FP: %d | Unclassified: %d",
                groupedMap.size(), allBypasses.size(), result.size(), tpCount, fpCount, unclassCount));
        }
    }

    @Override
    protected List<FindingOccurrence_littlespidy> getOccurrencesAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecurityBypass> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getNavOccurrences() : Collections.emptyList();
    }

    @Override
    protected int getOccurrenceCountAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecurityBypass> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getCount() : 0;
    }

    @Override
    protected String getClassificationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecurityBypass> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().classification() : "Not Classified";
    }

    @Override
    protected void updateClassification(int modelRow, String classification) {
        GroupedFinding_littlespidy<DiscoveredSecurityBypass> grp = tableModel.getGroupAt(modelRow);
        if (grp == null) return;

        DiscoveredSecurityBypass updatedPrimary = grp.getPrimary().withClassification(classification);
        grp.setPrimary(updatedPrimary);

        for (DiscoveredSecurityBypass oldBypass : grp.getOccurrences()) {
            DiscoveredSecurityBypass updated = oldBypass.withClassification(classification);
            syncClassificationToStore(oldBypass, updated);

            for (int i = 0; i < allBypasses.size(); i++) {
                DiscoveredSecurityBypass cur = allBypasses.get(i);
                if (cur == oldBypass || (Objects.equals(cur.method(), oldBypass.method())
                        && Objects.equals(cur.sourceLocation(), oldBypass.sourceLocation())
                        && cur.line() == oldBypass.line())) {
                    allBypasses.set(i, updated);
                }
            }
        }

        tableModel.fireTableRowsUpdated(modelRow, modelRow);
    }

    private void syncClassificationToStore(DiscoveredSecurityBypass oldBypass, DiscoveredSecurityBypass newBypass) {
        if (dataStore == null) return;
        for (JsFileEntry entry : dataStore.getEntries()) {
            boolean done = entry.updateSecurityBypass(oldBypass, newBypass);
            if (entry.getUnpackedProject() != null) {
                if (entry.getUnpackedProject().updateSecurityBypass(oldBypass, newBypass)) {
                    done = true;
                }
            }
            if (done) return;
        }
    }

    @Override
    protected String getFindingTextAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecurityBypass> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().method() : "";
    }

    @Override
    protected int getStartOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecurityBypass> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().startOffset() : -1;
    }

    @Override
    protected int getEndOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecurityBypass> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().endOffset() : -1;
    }

    @Override
    protected String getSourceLocationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecurityBypass> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().sourceLocation() : "";
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
            "#", "Occurrences", "Framework", "Bypass Method / Sink", "Risk", "Description", "Source Type", "Source Location", "Line"
        };
        private final List<GroupedFinding_littlespidy<DiscoveredSecurityBypass>> list = new ArrayList<>();

        public synchronized void updateData(List<GroupedFinding_littlespidy<DiscoveredSecurityBypass>> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized GroupedFinding_littlespidy<DiscoveredSecurityBypass> getGroupAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) {
            return (c == 0 || c == 1 || c == 8) ? Integer.class : String.class;
        }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            GroupedFinding_littlespidy<DiscoveredSecurityBypass> item = list.get(r);
            DiscoveredSecurityBypass primary = item.getPrimary();
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> item.getCount();
                case 2 -> primary.framework();
                case 3 -> primary.method();
                case 4 -> primary.risk();
                case 5 -> primary.description();
                case 6 -> primary.sourceType();
                case 7 -> primary.sourceLocation();
                case 8 -> primary.line();
                default -> null;
            };
        }
    }
}
