// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredEndpoint;
import com.littlespidy.jssourcemapexplorer.model.JsDataStore;
import com.littlespidy.jssourcemapexplorer.model.JsFileEntry;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Dedicated top-level tab panel for analyzing, filtering, and classifying discovered
 * API routes, endpoints, and paths from JavaScript assets and unpacked Source Maps.
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

        List<DiscoveredEndpoint> filtered = new ArrayList<>();
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
            if (!query.isEmpty()) {
                boolean match = (ep.endpoint() != null && ep.endpoint().toLowerCase().contains(query))
                    || (ep.methodGuess() != null && ep.methodGuess().toLowerCase().contains(query))
                    || (ep.technique() != null && ep.technique().toLowerCase().contains(query))
                    || (ep.sourceLocation() != null && ep.sourceLocation().toLowerCase().contains(query))
                    || (ep.contextSnippet() != null && ep.contextSnippet().toLowerCase().contains(query));
                if (!match) continue;
            }
            filtered.add(ep);
        }

        tableModel.updateData(filtered);
        statsLabel.setText(String.format("Paths: %d (Visible: %d | TP: %d | FP: %d | Unclassified: %d)",
            allEndpoints.size(), filtered.size(), tpCount, fpCount, unclassCount));
    }

    @Override
    protected String getClassificationAt(int modelRow) {
        DiscoveredEndpoint ep = tableModel.getEndpointAt(modelRow);
        return ep != null ? ep.classification() : "Not Classified";
    }

    @Override
    protected void updateClassification(int modelRow, String classification) {
        DiscoveredEndpoint ep = tableModel.getEndpointAt(modelRow);
        if (ep == null) return;

        DiscoveredEndpoint updated = ep.withClassification(classification);
        tableModel.setEndpointAt(modelRow, updated);

        // Update in allEndpoints list as well
        for (int i = 0; i < allEndpoints.size(); i++) {
            DiscoveredEndpoint cur = allEndpoints.get(i);
            if (cur == ep || (Objects.equals(cur.endpoint(), ep.endpoint()) && Objects.equals(cur.sourceLocation(), ep.sourceLocation()))) {
                allEndpoints.set(i, updated);
                break;
            }
        }

        // Synchronize back to parent JsFileEntry
        syncClassificationToStore(ep, updated);
    }

    private void syncClassificationToStore(DiscoveredEndpoint oldEp, DiscoveredEndpoint newEp) {
        if (dataStore == null) return;
        for (JsFileEntry entry : dataStore.getEntries()) {
            List<DiscoveredEndpoint> jsEps = entry.getJsEndpoints();
            for (int i = 0; i < jsEps.size(); i++) {
                if (jsEps.get(i) == oldEp || (Objects.equals(jsEps.get(i).endpoint(), oldEp.endpoint()) && Objects.equals(jsEps.get(i).sourceLocation(), oldEp.sourceLocation()))) {
                    jsEps.set(i, newEp);
                    return;
                }
            }
            if (entry.getUnpackedProject() != null) {
                List<DiscoveredEndpoint> unpEps = entry.getUnpackedProject().getAllEndpoints();
                for (int i = 0; i < unpEps.size(); i++) {
                    if (unpEps.get(i) == oldEp || (Objects.equals(unpEps.get(i).endpoint(), oldEp.endpoint()) && Objects.equals(unpEps.get(i).sourceLocation(), oldEp.sourceLocation()))) {
                        unpEps.set(i, newEp);
                        return;
                    }
                }
            }
        }
    }

    @Override
    protected String getFindingTextAt(int modelRow) {
        DiscoveredEndpoint ep = tableModel.getEndpointAt(modelRow);
        return ep != null ? ep.endpoint() : "";
    }

    @Override
    protected int getStartOffsetAt(int modelRow) {
        DiscoveredEndpoint ep = tableModel.getEndpointAt(modelRow);
        return ep != null ? ep.startOffset() : -1;
    }

    @Override
    protected int getEndOffsetAt(int modelRow) {
        DiscoveredEndpoint ep = tableModel.getEndpointAt(modelRow);
        return ep != null ? ep.endOffset() : -1;
    }

    @Override
    protected String getSourceLocationAt(int modelRow) {
        DiscoveredEndpoint ep = tableModel.getEndpointAt(modelRow);
        return ep != null ? ep.sourceLocation() : "";
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
            "#", "Method", "Endpoint / Route", "Technique", "Source Type", "Source Location", "Line", "Classification"
        };
        private final List<DiscoveredEndpoint> list = new ArrayList<>();

        public synchronized void updateData(List<DiscoveredEndpoint> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized DiscoveredEndpoint getEndpointAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        public synchronized void setEndpointAt(int row, DiscoveredEndpoint ep) {
            if (row >= 0 && row < list.size()) {
                list.set(row, ep);
                fireTableRowsUpdated(row, row);
            }
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) {
            return (c == 0 || c == 6) ? Integer.class : String.class;
        }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            DiscoveredEndpoint item = list.get(r);
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> item.methodGuess();
                case 2 -> item.endpoint();
                case 3 -> item.technique();
                case 4 -> item.sourceType();
                case 5 -> item.sourceLocation();
                case 6 -> item.line();
                case 7 -> item.classification();
                default -> null;
            };
        }
    }
}
