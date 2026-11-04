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
 * Dedicated top-level tab panel for analyzing, filtering, and classifying cloud storage
 * and object bucket URLs (S3, Azure Blob, Google Cloud, Firebase) from JavaScript assets.
 * Groups duplicate cloud URLs across files with an Occurrences column and occurrence navigation.
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
            List.of("All Providers", "AWS", "Azure", "Google Cloud", "Firebase", "Cloudflare",
                    "DigitalOcean", "Supabase", "PaaS / Serverless", "Oracle Cloud",
                    "Alibaba Cloud", "Object Storage", "Rackspace", "DreamHost", "Cloud Resource"),
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

        Map<String, GroupedFinding_littlespidy<DiscoveredCloudUrl>> groupedMap = new LinkedHashMap<>();
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

            String key = (cu.cloudUrl() != null ? cu.cloudUrl().trim() : "")
                + "||" + (cu.cloudProvider() != null ? cu.cloudProvider().trim() : "");

            FindingOccurrence_littlespidy occ = new FindingOccurrence_littlespidy(
                cu.sourceLocation(),
                cu.sourceType(),
                cu.cloudUrl(),
                cu.line(),
                cu.startOffset(),
                cu.endOffset(),
                cu.contextSnippet()
            );

            GroupedFinding_littlespidy<DiscoveredCloudUrl> grp = groupedMap.get(key);
            if (grp == null) {
                grp = new GroupedFinding_littlespidy<>(cu, occ);
                groupedMap.put(key, grp);
            } else {
                grp.addOccurrence(cu, occ);
                if (!"Not Classified".equalsIgnoreCase(cu.classification())
                    && "Not Classified".equalsIgnoreCase(grp.getPrimary().classification())) {
                    grp.setPrimary(grp.getPrimary().withClassification(cu.classification()));
                }
            }
        }

        List<GroupedFinding_littlespidy<DiscoveredCloudUrl>> result = new ArrayList<>(groupedMap.values());
        tableModel.updateData(result);

        if (allCloudUrls.isEmpty()) {
            statsLabel.setText("Cloud URLs: 0 (No findings found)");
        } else {
            statsLabel.setText(String.format("Cloud URLs: %d unique (%d total) | Visible: %d | TP: %d | FP: %d | Unclassified: %d",
                groupedMap.size(), allCloudUrls.size(), result.size(), tpCount, fpCount, unclassCount));
        }
    }

    @Override
    protected List<FindingOccurrence_littlespidy> getOccurrencesAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredCloudUrl> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getNavOccurrences() : Collections.emptyList();
    }

    @Override
    protected int getOccurrenceCountAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredCloudUrl> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getCount() : 0;
    }

    @Override
    protected String getClassificationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredCloudUrl> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().classification() : "Not Classified";
    }

    @Override
    protected void updateClassification(int modelRow, String classification) {
        GroupedFinding_littlespidy<DiscoveredCloudUrl> grp = tableModel.getGroupAt(modelRow);
        if (grp == null) return;

        DiscoveredCloudUrl updatedPrimary = grp.getPrimary().withClassification(classification);
        grp.setPrimary(updatedPrimary);

        for (DiscoveredCloudUrl oldCu : grp.getOccurrences()) {
            DiscoveredCloudUrl updated = oldCu.withClassification(classification);
            syncClassificationToStore(oldCu, updated);

            for (int i = 0; i < allCloudUrls.size(); i++) {
                DiscoveredCloudUrl cur = allCloudUrls.get(i);
                if (cur == oldCu || (Objects.equals(cur.cloudUrl(), oldCu.cloudUrl())
                        && Objects.equals(cur.sourceLocation(), oldCu.sourceLocation())
                        && cur.line() == oldCu.line())) {
                    allCloudUrls.set(i, updated);
                }
            }
        }

        tableModel.fireTableRowsUpdated(modelRow, modelRow);
    }

    private void syncClassificationToStore(DiscoveredCloudUrl oldCu, DiscoveredCloudUrl newCu) {
        if (dataStore == null) return;
        for (JsFileEntry entry : dataStore.getEntries()) {
            boolean done = entry.updateCloudUrl(oldCu, newCu);
            if (entry.getUnpackedProject() != null) {
                if (entry.getUnpackedProject().updateCloudUrl(oldCu, newCu)) {
                    done = true;
                }
            }
            if (done) return;
        }
    }

    @Override
    protected String getFindingTextAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredCloudUrl> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().cloudUrl() : "";
    }

    @Override
    protected int getStartOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredCloudUrl> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().startOffset() : -1;
    }

    @Override
    protected int getEndOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredCloudUrl> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().endOffset() : -1;
    }

    @Override
    protected String getSourceLocationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredCloudUrl> grp = tableModel.getGroupAt(modelRow);
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
        JOptionPane.showMessageDialog(this, String.format("Copied %d cloud URL(s) to clipboard as TSV.", count), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
    }

    private static class CloudUrlsTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "#", "Occurrences", "Cloud Provider", "Discovered Cloud URL", "Source Type", "Source Location", "Line"
        };
        private final List<GroupedFinding_littlespidy<DiscoveredCloudUrl>> list = new ArrayList<>();

        public synchronized void updateData(List<GroupedFinding_littlespidy<DiscoveredCloudUrl>> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized GroupedFinding_littlespidy<DiscoveredCloudUrl> getGroupAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) {
            return (c == 0 || c == 1 || c == 6) ? Integer.class : String.class;
        }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            GroupedFinding_littlespidy<DiscoveredCloudUrl> item = list.get(r);
            DiscoveredCloudUrl primary = item.getPrimary();
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> item.getCount();
                case 2 -> primary.cloudProvider();
                case 3 -> primary.cloudUrl();
                case 4 -> primary.sourceType();
                case 5 -> primary.sourceLocation();
                case 6 -> primary.line();
                default -> null;
            };
        }
    }
}
