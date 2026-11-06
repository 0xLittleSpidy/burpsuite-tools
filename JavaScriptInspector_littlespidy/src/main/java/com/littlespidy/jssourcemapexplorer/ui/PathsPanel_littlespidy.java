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
 * Dedicated top-level tab panel for analyzing, filtering, and classifying discovered
 * API routes, endpoints, and paths from JavaScript assets and unpacked Source Maps.
 * Groups duplicate endpoints across files with an Occurrences column and occurrence navigation.
 *
 * @author littlespidy
 */
public class PathsPanel_littlespidy extends BaseFindingPanel_littlespidy {

    private final EndpointsTableModel tableModel;
    private MultiSelectFilterButton methodFilterBtn;
    private MultiSelectFilterButton techniqueFilterBtn;

    private final List<DiscoveredEndpoint> allEndpoints = new ArrayList<>();

    public PathsPanel_littlespidy(MontoyaApi api, JsDataStore dataStore) {
        this(api, dataStore, new EndpointsTableModel());
    }

    private PathsPanel_littlespidy(MontoyaApi api, JsDataStore dataStore, EndpointsTableModel model) {
        super(api, dataStore, "Paths", model);
        this.tableModel = model;
    }

    @Override
    protected void addCategoryFiltersToToolbar(JPanel toolbar) {
        JLabel mthdLbl = new JLabel("Method:");
        mthdLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(mthdLbl);

        methodFilterBtn = new MultiSelectFilterButton(
            "Method",
            List.of("All Methods", "GET", "POST", "PUT", "DELETE", "PATCH", "ROUTE", "URL"),
            sel -> applyFilter()
        );
        toolbar.add(methodFilterBtn);

        JLabel techLbl = new JLabel("Technique:");
        techLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(techLbl);

        techniqueFilterBtn = new MultiSelectFilterButton(
            "Technique",
            List.of("All Techniques", "HTTP Verb Call", "API Namespace", "Relative Path", "Absolute URL", "REST Endpoint", "File Extension"),
            sel -> applyFilter()
        );
        toolbar.add(techniqueFilterBtn);

        JButton pathRegexBtn = new JButton("Whitelist / Blacklist");
        pathRegexBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        pathRegexBtn.setToolTipText("View active path whitelist patterns and blacklist suppression rules");
        pathRegexBtn.addActionListener(e -> {
            Window owner = SwingUtilities.getWindowAncestor(this);
            PathRegexDialog_littlespidy dlg = new PathRegexDialog_littlespidy(owner);
            dlg.setVisible(true);
        });
        toolbar.add(pathRegexBtn);
    }

    @Override
    protected void resetCategoryFilters() {
        if (methodFilterBtn != null) methodFilterBtn.clearSelection();
        if (techniqueFilterBtn != null) techniqueFilterBtn.clearSelection();
    }

    @Override
    public synchronized void refreshFromDataStore() {
        allEndpoints.clear();
        if (dataStore != null) {
            for (JsFileEntry entry : dataStore.getEntries()) {
                allEndpoints.addAll(entry.getJsEndpoints());
                if (entry.getUnpackedProject() != null) {
                    allEndpoints.addAll(entry.getUnpackedProject().getAllEndpoints());
                }
            }
        }
        applyFilter();
    }

    @Override
    public synchronized void applyFilter() {
        Set<String> selectedMethods = methodFilterBtn != null ? methodFilterBtn.getSelected() : Collections.emptySet();
        Set<String> selectedTechs = techniqueFilterBtn != null ? techniqueFilterBtn.getSelected() : Collections.emptySet();
        String query = searchField.getText().trim().toLowerCase();

        Map<String, GroupedFinding_littlespidy<DiscoveredEndpoint>> groupedMap = new LinkedHashMap<>();
        int tpCount = 0;
        int fpCount = 0;
        int unclassCount = 0;

        for (DiscoveredEndpoint ep : allEndpoints) {
            String cls = ep.classification() != null ? ep.classification() : "Not Classified";
            if ("True Positive".equalsIgnoreCase(cls)) tpCount++;
            else if ("False Positive".equalsIgnoreCase(cls)) fpCount++;
            else unclassCount++;

            if (!selectedMethods.isEmpty() && !selectedMethods.contains(ep.methodGuess())) {
                continue;
            }
            if (!selectedTechs.isEmpty() && !selectedTechs.contains(ep.technique())) {
                continue;
            }
            if (!matchesClassification(ep.classification())) {
                continue;
            }
            if (!matchesSourceType(ep.sourceType())) {
                continue;
            }
            if (!query.isEmpty()) {
                boolean match = (ep.endpoint() != null && ep.endpoint().toLowerCase().contains(query))
                    || (ep.methodGuess() != null && ep.methodGuess().toLowerCase().contains(query))
                    || (ep.technique() != null && ep.technique().toLowerCase().contains(query))
                    || (ep.sourceLocation() != null && ep.sourceLocation().toLowerCase().contains(query))
                    || (ep.contextSnippet() != null && ep.contextSnippet().toLowerCase().contains(query));
                if (!match) continue;
            }

            String key = (ep.endpoint() != null ? ep.endpoint().trim() : "")
                + "||" + (ep.methodGuess() != null ? ep.methodGuess().trim() : "");

            FindingOccurrence_littlespidy occ = new FindingOccurrence_littlespidy(
                ep.sourceLocation(),
                ep.sourceType(),
                ep.endpoint(),
                ep.line(),
                ep.startOffset(),
                ep.endOffset(),
                ep.contextSnippet()
            );

            GroupedFinding_littlespidy<DiscoveredEndpoint> grp = groupedMap.get(key);
            if (grp == null) {
                grp = new GroupedFinding_littlespidy<>(ep, occ);
                groupedMap.put(key, grp);
            } else {
                grp.addOccurrence(ep, occ);
                if (!"Not Classified".equalsIgnoreCase(ep.classification())
                    && "Not Classified".equalsIgnoreCase(grp.getPrimary().classification())) {
                    grp.setPrimary(grp.getPrimary().withClassification(ep.classification()));
                }
            }
        }

        List<GroupedFinding_littlespidy<DiscoveredEndpoint>> result = new ArrayList<>(groupedMap.values());
        tableModel.updateData(result);

        if (allEndpoints.isEmpty()) {
            statsLabel.setText("Paths: 0 (No findings found)");
        } else {
            statsLabel.setText(String.format("Paths: %d unique (%d total) | Visible: %d | TP: %d | FP: %d | Unclassified: %d",
                groupedMap.size(), allEndpoints.size(), result.size(), tpCount, fpCount, unclassCount));
        }
    }

    @Override
    protected List<FindingOccurrence_littlespidy> getOccurrencesAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredEndpoint> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getNavOccurrences() : Collections.emptyList();
    }

    @Override
    protected int getOccurrenceCountAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredEndpoint> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getCount() : 0;
    }

    @Override
    protected String getClassificationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredEndpoint> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().classification() : "Not Classified";
    }

    @Override
    protected void updateClassification(int modelRow, String classification) {
        GroupedFinding_littlespidy<DiscoveredEndpoint> grp = tableModel.getGroupAt(modelRow);
        if (grp == null) return;

        DiscoveredEndpoint updatedPrimary = grp.getPrimary().withClassification(classification);
        grp.setPrimary(updatedPrimary);

        for (DiscoveredEndpoint oldEp : grp.getOccurrences()) {
            DiscoveredEndpoint updated = oldEp.withClassification(classification);
            syncClassificationToStore(oldEp, updated);

            for (int i = 0; i < allEndpoints.size(); i++) {
                DiscoveredEndpoint cur = allEndpoints.get(i);
                if (cur == oldEp || (Objects.equals(cur.endpoint(), oldEp.endpoint())
                        && Objects.equals(cur.sourceLocation(), oldEp.sourceLocation())
                        && cur.line() == oldEp.line())) {
                    allEndpoints.set(i, updated);
                }
            }
        }

        tableModel.fireTableRowsUpdated(modelRow, modelRow);
    }

    private void syncClassificationToStore(DiscoveredEndpoint oldEp, DiscoveredEndpoint newEp) {
        if (dataStore == null) return;
        for (JsFileEntry entry : dataStore.getEntries()) {
            boolean done = entry.updateEndpoint(oldEp, newEp);
            if (entry.getUnpackedProject() != null) {
                if (entry.getUnpackedProject().updateEndpoint(oldEp, newEp)) {
                    done = true;
                }
            }
            if (done) return;
        }
    }

    @Override
    protected String getFindingTextAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredEndpoint> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().endpoint() : "";
    }

    @Override
    protected int getStartOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredEndpoint> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().startOffset() : -1;
    }

    @Override
    protected int getEndOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredEndpoint> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().endOffset() : -1;
    }

    @Override
    protected String getSourceLocationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredEndpoint> grp = tableModel.getGroupAt(modelRow);
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
        JOptionPane.showMessageDialog(this, String.format("Copied %d path(s) to clipboard as TSV.", count), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
    }

    private static class EndpointsTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "#", "Occurrences", "Method", "Endpoint / Route", "Technique", "Source Type", "Source Location", "Line"
        };
        private final List<GroupedFinding_littlespidy<DiscoveredEndpoint>> list = new ArrayList<>();

        public synchronized void updateData(List<GroupedFinding_littlespidy<DiscoveredEndpoint>> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized GroupedFinding_littlespidy<DiscoveredEndpoint> getGroupAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) {
            return (c == 0 || c == 1 || c == 7) ? Integer.class : String.class;
        }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            GroupedFinding_littlespidy<DiscoveredEndpoint> item = list.get(r);
            DiscoveredEndpoint primary = item.getPrimary();
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> item.getCount();
                case 2 -> primary.methodGuess();
                case 3 -> primary.endpoint();
                case 4 -> primary.technique();
                case 5 -> primary.sourceType();
                case 6 -> primary.sourceLocation();
                case 7 -> primary.line();
                default -> null;
            };
        }
    }
}
