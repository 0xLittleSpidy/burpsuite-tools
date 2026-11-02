// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.jssourcemapexplorer.engine.DependencyVerifier;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredDependency;
import com.littlespidy.jssourcemapexplorer.model.JsDataStore;
import com.littlespidy.jssourcemapexplorer.model.JsFileEntry;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Dedicated top-level tab panel for analyzing, filtering, and classifying package dependencies
 * (NPM packages, Dependency Confusion candidates) from JavaScript assets and unpacked Source Maps.
 *
 * @author littlespidy
 */
public class DependenciesPanel_littlespidy extends BaseFindingPanel_littlespidy {

    private final DependenciesTableModel tableModel;
    private final DependencyVerifier dependencyVerifier;
    private MultiSelectFilterButton depStatusFilterBtn;

    private final List<DiscoveredDependency> allDependencies = new ArrayList<>();

    public DependenciesPanel_littlespidy(MontoyaApi api, JsDataStore dataStore) {
        this(api, dataStore, new DependenciesTableModel());
    }

    private DependenciesPanel_littlespidy(MontoyaApi api, JsDataStore dataStore, DependenciesTableModel model) {
        super(api, dataStore, "Dependencies", model);
        this.tableModel = model;
        this.dependencyVerifier = new DependencyVerifier(api);
    }

    @Override
    protected void addCategoryFiltersToToolbar(JPanel toolbar) {
        JLabel statLbl = new JLabel("Status:");
        statLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(statLbl);

        depStatusFilterBtn = new MultiSelectFilterButton(
            "Status",
            List.of("All Statuses", "VULNERABLE: 404 Unclaimed", "Registered (OK)", "Org Not Found", "Unverified"),
            sel -> applyFilter()
        );
        toolbar.add(depStatusFilterBtn);

        JButton verifyAllBtn = new JButton("Check All on npm");
        verifyAllBtn.setToolTipText("Verify all visible dependencies against the public NPM registry for Dependency Confusion");
        verifyAllBtn.addActionListener(e -> verifyVisibleDependencies());
        toolbar.add(verifyAllBtn);
    }

    @Override
    protected void resetCategoryFilters() {
        if (depStatusFilterBtn != null) depStatusFilterBtn.clearSelection();
    }

    private void verifyVisibleDependencies() {
        List<DiscoveredDependency> targets = new ArrayList<>();
        for (int i = 0; i < table.getRowCount(); i++) {
            int modelRow = table.convertRowIndexToModel(i);
            DiscoveredDependency dep = tableModel.getDependencyAt(modelRow);
            if (dep != null) targets.add(dep);
        }

        if (targets.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No dependencies to verify.", "Check Dependencies", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        dependencyVerifier.verifyAll(targets, () -> SwingUtilities.invokeLater(this::applyFilter));
    }

    @Override
    public synchronized void refreshFromDataStore() {
        allDependencies.clear();
        if (dataStore != null) {
            for (JsFileEntry entry : dataStore.getEntries()) {
                allDependencies.addAll(entry.getJsDependencies());
                if (entry.getUnpackedProject() != null) {
                    allDependencies.addAll(entry.getUnpackedProject().getAllDependencies());
                }
            }
        }
        applyFilter();
    }

    @Override
    public synchronized void applyFilter() {
        Set<String> selectedStatuses = depStatusFilterBtn != null ? depStatusFilterBtn.getSelected() : Collections.emptySet();
        String query = searchField.getText().trim().toLowerCase();

        List<DiscoveredDependency> filtered = new ArrayList<>();
        int tpCount = 0;
        int fpCount = 0;
        int unclassCount = 0;

        for (DiscoveredDependency dep : allDependencies) {
            String cls = dep.getClassification();
            if ("True Positive".equalsIgnoreCase(cls)) tpCount++;
            else if ("False Positive".equalsIgnoreCase(cls)) fpCount++;
            else unclassCount++;

            if (!selectedStatuses.isEmpty() && !selectedStatuses.contains(dep.status())) {
                continue;
            }
            if (!matchesClassification(dep.getClassification())) {
                continue;
            }
            if (!query.isEmpty()) {
                boolean match = (dep.packageName() != null && dep.packageName().toLowerCase().contains(query))
                    || (dep.version() != null && dep.version().toLowerCase().contains(query))
                    || (dep.status() != null && dep.status().toLowerCase().contains(query))
                    || (dep.sourceLocation() != null && dep.sourceLocation().toLowerCase().contains(query))
                    || (dep.contextSnippet() != null && dep.contextSnippet().toLowerCase().contains(query));
                if (!match) continue;
            }
            filtered.add(dep);
        }

        tableModel.updateData(filtered);
        statsLabel.setText(String.format("Dependencies: %d (Visible: %d | TP: %d | FP: %d | Unclassified: %d)",
            allDependencies.size(), filtered.size(), tpCount, fpCount, unclassCount));
    }

    @Override
    protected String getClassificationAt(int modelRow) {
        DiscoveredDependency dep = tableModel.getDependencyAt(modelRow);
        return dep != null ? dep.getClassification() : "Not Classified";
    }

    @Override
    protected void updateClassification(int modelRow, String classification) {
        DiscoveredDependency dep = tableModel.getDependencyAt(modelRow);
        if (dep == null) return;

        dep.setClassification(classification);
        tableModel.fireTableRowsUpdated(modelRow, modelRow);
    }

    @Override
    protected String getFindingTextAt(int modelRow) {
        DiscoveredDependency dep = tableModel.getDependencyAt(modelRow);
        return dep != null ? dep.packageName() : "";
    }

    @Override
    protected int getStartOffsetAt(int modelRow) {
        DiscoveredDependency dep = tableModel.getDependencyAt(modelRow);
        return dep != null ? dep.startOffset() : -1;
    }

    @Override
    protected int getEndOffsetAt(int modelRow) {
        DiscoveredDependency dep = tableModel.getDependencyAt(modelRow);
        return dep != null ? dep.endOffset() : -1;
    }

    @Override
    protected String getSourceLocationAt(int modelRow) {
        DiscoveredDependency dep = tableModel.getDependencyAt(modelRow);
        return dep != null ? dep.sourceLocation() : "";
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
        JOptionPane.showMessageDialog(this, String.format("Copied %d dependencies to clipboard as TSV.", count), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
    }

    private static class DependenciesTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "#", "Package Name", "Version", "Dependency Type", "Verification Status", "Verification Detail", "Source Location", "Line", "Classification"
        };
        private final List<DiscoveredDependency> list = new ArrayList<>();

        public synchronized void updateData(List<DiscoveredDependency> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized DiscoveredDependency getDependencyAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) {
            return (c == 0 || c == 7) ? Integer.class : String.class;
        }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            DiscoveredDependency item = list.get(r);
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> item.packageName();
                case 2 -> item.version();
                case 3 -> item.dependencyType();
                case 4 -> item.status();
                case 5 -> item.verificationDetail();
                case 6 -> item.sourceLocation();
                case 7 -> item.line();
                case 8 -> item.getClassification();
                default -> null;
            };
        }
    }
}
