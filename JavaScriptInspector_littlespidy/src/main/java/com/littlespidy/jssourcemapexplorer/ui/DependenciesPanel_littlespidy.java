// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.jssourcemapexplorer.engine.DependencyVerifier;
import com.littlespidy.jssourcemapexplorer.model.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Dedicated top-level tab panel for analyzing, filtering, and verifying package dependencies
 * (extracted from package.json or node_modules paths) for Dependency Confusion vulnerabilities.
 * Groups duplicate dependencies across files with an Occurrences column and occurrence navigation.
 *
 * @author littlespidy
 */
public class DependenciesPanel_littlespidy extends BaseFindingPanel_littlespidy {

    private final DependenciesTableModel tableModel;
    private MultiSelectFilterButton depStatusFilterBtn;
    private JButton checkAllConfusionBtn;

    private final List<DiscoveredDependency> allDependencies = new ArrayList<>();

    public DependenciesPanel_littlespidy(MontoyaApi api, JsDataStore dataStore) {
        this(api, dataStore, new DependenciesTableModel());
    }

    private DependenciesPanel_littlespidy(MontoyaApi api, JsDataStore dataStore, DependenciesTableModel model) {
        super(api, dataStore, "Dependencies", model);
        this.tableModel = model;
    }

    @Override
    protected void addCategoryFiltersToToolbar(JPanel toolbar) {
        JLabel statLbl = new JLabel("Status:");
        statLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(statLbl);

        depStatusFilterBtn = new MultiSelectFilterButton(
            "Status",
            List.of("All Statuses", "Unverified", "Registered (OK)", "VULNERABLE: 404 Unclaimed", "Org Not Found", "Check Failed"),
            sel -> applyFilter()
        );
        toolbar.add(depStatusFilterBtn);

        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        if (checkAllConfusionBtn == null) {
            checkAllConfusionBtn = new JButton("Check Dependency Confusion");
            checkAllConfusionBtn.setToolTipText("Verify all discovered packages against the public NPM registry for unclaimed 404 confusion risks");
            checkAllConfusionBtn.addActionListener(e -> checkAllDependencies());
        }
        toolbar.add(checkAllConfusionBtn);
    }

    @Override
    protected void resetCategoryFilters() {
        if (depStatusFilterBtn != null) depStatusFilterBtn.clearSelection();
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

        Map<String, GroupedFinding_littlespidy<DiscoveredDependency>> groupedMap = new LinkedHashMap<>();
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
            if (!matchesSourceType(dep.sourceType())) {
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

            String key = (dep.packageName() != null ? dep.packageName().trim() : "")
                + "||" + (dep.version() != null ? dep.version().trim() : "")
                + "||" + (dep.dependencyType() != null ? dep.dependencyType().trim() : "");

            FindingOccurrence_littlespidy occ = new FindingOccurrence_littlespidy(
                dep.sourceLocation(),
                dep.sourceType(),
                dep.packageName(),
                dep.line(),
                dep.startOffset(),
                dep.endOffset(),
                dep.contextSnippet()
            );

            GroupedFinding_littlespidy<DiscoveredDependency> grp = groupedMap.get(key);
            if (grp == null) {
                grp = new GroupedFinding_littlespidy<>(dep, occ);
                groupedMap.put(key, grp);
            } else {
                grp.addOccurrence(dep, occ);
                if (!"Not Classified".equalsIgnoreCase(dep.getClassification())
                    && "Not Classified".equalsIgnoreCase(grp.getPrimary().getClassification())) {
                    grp.setPrimary(grp.getPrimary().withClassification(dep.getClassification()));
                }
            }
        }

        List<GroupedFinding_littlespidy<DiscoveredDependency>> result = new ArrayList<>(groupedMap.values());
        tableModel.updateData(result);

        if (allDependencies.isEmpty()) {
            statsLabel.setText("Dependencies: 0 (No findings found)");
        } else {
            statsLabel.setText(String.format("Dependencies: %d unique (%d total) | Visible: %d | TP: %d | FP: %d | Unclassified: %d",
                groupedMap.size(), allDependencies.size(), result.size(), tpCount, fpCount, unclassCount));
        }
    }

    private void checkAllDependencies() {
        if (allDependencies.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No dependencies available to verify.", "Check Dependencies", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        checkAllConfusionBtn.setEnabled(false);
        checkAllConfusionBtn.setText("Checking NPM...");

        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                DependencyVerifier verifier = new DependencyVerifier(api);
                verifier.verifyAll(allDependencies, () -> SwingUtilities.invokeLater(tableModel::fireTableDataChanged));
                return null;
            }

            @Override
            protected void done() {
                checkAllConfusionBtn.setEnabled(true);
                checkAllConfusionBtn.setText("Check Dependency Confusion");
                applyFilter();
            }
        };

        worker.execute();
    }

    @Override
    protected List<FindingOccurrence_littlespidy> getOccurrencesAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredDependency> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getNavOccurrences() : Collections.emptyList();
    }

    @Override
    protected int getOccurrenceCountAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredDependency> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getCount() : 0;
    }

    @Override
    protected String getClassificationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredDependency> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().getClassification() : "Not Classified";
    }

    @Override
    protected void updateClassification(int modelRow, String classification) {
        GroupedFinding_littlespidy<DiscoveredDependency> grp = tableModel.getGroupAt(modelRow);
        if (grp == null) return;

        DiscoveredDependency updatedPrimary = grp.getPrimary().withClassification(classification);
        grp.setPrimary(updatedPrimary);

        for (DiscoveredDependency oldDep : grp.getOccurrences()) {
            DiscoveredDependency updated = oldDep.withClassification(classification);
            oldDep.setClassification(classification);
            syncClassificationToStore(oldDep, updated);

            for (int i = 0; i < allDependencies.size(); i++) {
                DiscoveredDependency cur = allDependencies.get(i);
                if (cur == oldDep || (Objects.equals(cur.packageName(), oldDep.packageName())
                        && Objects.equals(cur.sourceLocation(), oldDep.sourceLocation())
                        && cur.line() == oldDep.line())) {
                    cur.setClassification(classification);
                }
            }
        }

        tableModel.fireTableRowsUpdated(modelRow, modelRow);
    }

    private void syncClassificationToStore(DiscoveredDependency oldDep, DiscoveredDependency newDep) {
        if (dataStore == null) return;
        for (JsFileEntry entry : dataStore.getEntries()) {
            boolean done = entry.updateDependency(oldDep, newDep);
            if (entry.getUnpackedProject() != null) {
                if (entry.getUnpackedProject().updateDependency(oldDep, newDep)) {
                    done = true;
                }
            }
            if (done) return;
        }
    }

    @Override
    protected String getFindingTextAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredDependency> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().packageName() : "";
    }

    @Override
    protected int getStartOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredDependency> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().startOffset() : -1;
    }

    @Override
    protected int getEndOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredDependency> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().endOffset() : -1;
    }

    @Override
    protected String getSourceLocationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredDependency> grp = tableModel.getGroupAt(modelRow);
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
        JOptionPane.showMessageDialog(this, String.format("Copied %d dependencies to clipboard as TSV.", count), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
    }

    private static class DependenciesTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "#", "Occurrences", "Package Name", "Version", "Dependency Type", "Verification Status", "Verification Detail", "Source Location", "Line"
        };
        private final List<GroupedFinding_littlespidy<DiscoveredDependency>> list = new ArrayList<>();

        public synchronized void updateData(List<GroupedFinding_littlespidy<DiscoveredDependency>> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized GroupedFinding_littlespidy<DiscoveredDependency> getGroupAt(int row) {
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
            GroupedFinding_littlespidy<DiscoveredDependency> item = list.get(r);
            DiscoveredDependency primary = item.getPrimary();
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> item.getCount();
                case 2 -> primary.packageName();
                case 3 -> primary.version();
                case 4 -> primary.dependencyType();
                case 5 -> primary.status();
                case 6 -> primary.verificationDetail();
                case 7 -> primary.sourceLocation();
                case 8 -> primary.line();
                default -> null;
            };
        }
    }
}
