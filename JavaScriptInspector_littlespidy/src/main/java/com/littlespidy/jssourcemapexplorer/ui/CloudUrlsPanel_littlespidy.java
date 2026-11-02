// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredCloudUrl;
import com.littlespidy.jssourcemapexplorer.model.JsDataStore;
import com.littlespidy.jssourcemapexplorer.model.JsFileEntry;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Dedicated top-level tab panel for analyzing, filtering, and classifying cloud storage
 * and object bucket URLs (S3, Azure Blob, Google Cloud, Firebase) from JavaScript assets.
 *
 * @author littlespidy
 */
public class CloudUrlsPanel_littlespidy extends BaseFindingPanel_littlespidy {

    private final CloudUrlsTableModel tableModel;
    private MultiSelectFilterButton cloudProviderFilterBtn;

    private final List<DiscoveredCloudUrl> allCloudUrls = new ArrayList<>();

    public CloudUrlsPanel_littlespidy(MontoyaApi api, JsDataStore dataStore) {
        this(api, dataStore, new CloudUrlsTableModel());
    }

    private CloudUrlsPanel_littlespidy(MontoyaApi api, JsDataStore dataStore, CloudUrlsTableModel model) {
        super(api, dataStore, "Cloud URLs", model);
        this.tableModel = model;
    }

    @Override
    protected void addCategoryFiltersToToolbar(JPanel toolbar) {
        JLabel provLbl = new JLabel("Provider:");
        provLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(provLbl);

        cloudProviderFilterBtn = new MultiSelectFilterButton(
            "Provider",
            List.of("All Providers", "AWS", "Google Cloud", "Azure", "Firebase", "DigitalOcean", "Other Cloud"),
            sel -> applyFilter()
        );
        toolbar.add(cloudProviderFilterBtn);
    }

    @Override
    protected void resetCategoryFilters() {
        if (cloudProviderFilterBtn != null) cloudProviderFilterBtn.clearSelection();
    }

    @Override
    public synchronized void refreshFromDataStore() {
        allCloudUrls.clear();
        if (dataStore != null) {
            for (JsFileEntry entry : dataStore.getEntries()) {
                allCloudUrls.addAll(entry.getJsCloudUrls());
                if (entry.getUnpackedProject() != null) {
                    allCloudUrls.addAll(entry.getUnpackedProject().getAllCloudUrls());
                }
            }
        }
        applyFilter();
    }

    @Override
    public synchronized void applyFilter() {
        Set<String> selectedProviders = cloudProviderFilterBtn != null ? cloudProviderFilterBtn.getSelected() : Collections.emptySet();
        String query = searchField.getText().trim().toLowerCase();

        List<DiscoveredCloudUrl> filtered = new ArrayList<>();
        int tpCount = 0;
        int fpCount = 0;
        int unclassCount = 0;

        for (DiscoveredCloudUrl cu : allCloudUrls) {
            String cls = cu.classification() != null ? cu.classification() : "Not Classified";
            if ("True Positive".equalsIgnoreCase(cls)) tpCount++;
            else if ("False Positive".equalsIgnoreCase(cls)) fpCount++;
            else unclassCount++;

            if (!selectedProviders.isEmpty() && !selectedProviders.contains(cu.cloudProvider())) {
                continue;
            }
            if (!matchesClassification(cu.classification())) {
                continue;
            }
            if (!query.isEmpty()) {
                boolean match = (cu.cloudUrl() != null && cu.cloudUrl().toLowerCase().contains(query))
                    || (cu.cloudProvider() != null && cu.cloudProvider().toLowerCase().contains(query))
                    || (cu.sourceLocation() != null && cu.sourceLocation().toLowerCase().contains(query))
                    || (cu.contextSnippet() != null && cu.contextSnippet().toLowerCase().contains(query));
                if (!match) continue;
            }
            filtered.add(cu);
        }

        tableModel.updateData(filtered);
        if (allCloudUrls.isEmpty()) {
            statsLabel.setText("Cloud URLs: 0 (No findings found)");
        } else {
            statsLabel.setText(String.format("Cloud URLs: %d (Visible: %d | TP: %d | FP: %d | Unclassified: %d)",
                allCloudUrls.size(), filtered.size(), tpCount, fpCount, unclassCount));
        }
    }

    @Override
    protected String getClassificationAt(int modelRow) {
        DiscoveredCloudUrl cu = tableModel.getCloudUrlAt(modelRow);
        return cu != null ? cu.classification() : "Not Classified";
    }

    @Override
    protected void updateClassification(int modelRow, String classification) {
        DiscoveredCloudUrl cu = tableModel.getCloudUrlAt(modelRow);
        if (cu == null) return;

        DiscoveredCloudUrl updated = cu.withClassification(classification);
        tableModel.setCloudUrlAt(modelRow, updated);

        for (int i = 0; i < allCloudUrls.size(); i++) {
            DiscoveredCloudUrl cur = allCloudUrls.get(i);
            if (cur == cu || (Objects.equals(cur.cloudUrl(), cu.cloudUrl()) && Objects.equals(cur.sourceLocation(), cu.sourceLocation()))) {
                allCloudUrls.set(i, updated);
                break;
            }
        }

        syncClassificationToStore(cu, updated);
    }

    private void syncClassificationToStore(DiscoveredCloudUrl oldCu, DiscoveredCloudUrl newCu) {
        if (dataStore == null) return;
        for (JsFileEntry entry : dataStore.getEntries()) {
            if (entry.updateCloudUrl(oldCu, newCu)) {
                return;
            }
            if (entry.getUnpackedProject() != null) {
                if (entry.getUnpackedProject().updateCloudUrl(oldCu, newCu)) {
                    return;
                }
            }
        }
    }

    @Override
    protected String getFindingTextAt(int modelRow) {
        DiscoveredCloudUrl cu = tableModel.getCloudUrlAt(modelRow);
        return cu != null ? cu.cloudUrl() : "";
    }

    @Override
    protected int getStartOffsetAt(int modelRow) {
        DiscoveredCloudUrl cu = tableModel.getCloudUrlAt(modelRow);
        return cu != null ? cu.startOffset() : -1;
    }

    @Override
    protected int getEndOffsetAt(int modelRow) {
        DiscoveredCloudUrl cu = tableModel.getCloudUrlAt(modelRow);
        return cu != null ? cu.endOffset() : -1;
    }

    @Override
    protected String getSourceLocationAt(int modelRow) {
        DiscoveredCloudUrl cu = tableModel.getCloudUrlAt(modelRow);
        return cu != null ? cu.sourceLocation() : "";
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
        JOptionPane.showMessageDialog(this, String.format("Copied %d cloud URL(s) to clipboard as TSV.", count), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
    }

    private static class CloudUrlsTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "#", "Cloud Provider", "Discovered Cloud URL", "Source Type", "Source Location", "Line"
        };
        private final List<DiscoveredCloudUrl> list = new ArrayList<>();

        public synchronized void updateData(List<DiscoveredCloudUrl> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized DiscoveredCloudUrl getCloudUrlAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        public synchronized void setCloudUrlAt(int row, DiscoveredCloudUrl cu) {
            if (row >= 0 && row < list.size()) {
                list.set(row, cu);
                fireTableRowsUpdated(row, row);
            }
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) {
            return (c == 0 || c == 5) ? Integer.class : String.class;
        }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            DiscoveredCloudUrl item = list.get(r);
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> item.cloudProvider();
                case 2 -> item.cloudUrl();
                case 3 -> item.sourceType();
                case 4 -> item.sourceLocation();
                case 5 -> item.line();
                default -> null;
            };
        }
    }
}
