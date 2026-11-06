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
 * Internal IP Addresses (RFC 1918, Loopback, Link-Local, IPv6) and Social Security Numbers (SSN)
 * from JavaScript assets and unpacked Source Maps.
 *
 * @author littlespidy
 */
public class InternalIpAndSsnPanel_littlespidy extends BaseFindingPanel_littlespidy {

    private final InternalIpAndSsnTableModel tableModel;
    private MultiSelectFilterButton typeFilterBtn;
    private MultiSelectFilterButton subtypeFilterBtn;

    private final List<DiscoveredInternalIpAndSsn_littlespidy> allFindings = new ArrayList<>();

    public InternalIpAndSsnPanel_littlespidy(MontoyaApi api, JsDataStore dataStore) {
        this(api, dataStore, new InternalIpAndSsnTableModel());
    }

    private InternalIpAndSsnPanel_littlespidy(MontoyaApi api, JsDataStore dataStore, InternalIpAndSsnTableModel model) {
        super(api, dataStore, "Internal IPs & SSNs", model);
        this.tableModel = model;
    }

    @Override
    protected void addCategoryFiltersToToolbar(JPanel toolbar) {
        JLabel typeLbl = new JLabel("Finding Type:");
        typeLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(typeLbl);

        typeFilterBtn = new MultiSelectFilterButton(
            "Finding Type",
            List.of("All Types", "Internal IP Address", "Social Security Number (SSN)"),
            sel -> applyFilter()
        );
        toolbar.add(typeFilterBtn);

        JLabel subLbl = new JLabel("Subtype / CIDR:");
        subLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(subLbl);

        subtypeFilterBtn = new MultiSelectFilterButton(
            "Subtype",
            List.of("All Subtypes", "RFC 1918 (10.x)", "RFC 1918 (172.16-31.x)", "RFC 1918 (192.168.x)",
                    "Loopback (127.x)", "Link-Local / Carrier NAT", "IPv6 Unique Local",
                    "SSN (Standard Formatted)", "SSN (Key-Value)"),
            sel -> applyFilter()
        );
        toolbar.add(subtypeFilterBtn);
    }

    @Override
    protected void resetCategoryFilters() {
        if (typeFilterBtn != null) typeFilterBtn.clearSelection();
        if (subtypeFilterBtn != null) subtypeFilterBtn.clearSelection();
    }

    @Override
    public synchronized void refreshFromDataStore() {
        allFindings.clear();
        if (dataStore != null) {
            for (JsFileEntry entry : dataStore.getEntries()) {
                allFindings.addAll(entry.getJsInternalIpsAndSsns());
                if (entry.getUnpackedProject() != null) {
                    allFindings.addAll(entry.getUnpackedProject().getAllInternalIpsAndSsns());
                }
            }
        }
        applyFilter();
    }

    @Override
    public synchronized void applyFilter() {
        Set<String> selectedTypes = typeFilterBtn != null ? typeFilterBtn.getSelected() : Collections.emptySet();
        Set<String> selectedSubtypes = subtypeFilterBtn != null ? subtypeFilterBtn.getSelected() : Collections.emptySet();
        String query = searchField.getText().trim().toLowerCase();

        Map<String, GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy>> groupedMap = new LinkedHashMap<>();
        int tpCount = 0;
        int fpCount = 0;
        int unclassCount = 0;

        for (DiscoveredInternalIpAndSsn_littlespidy item : allFindings) {
            String cls = item.classification() != null ? item.classification() : "Not Classified";
            if ("True Positive".equalsIgnoreCase(cls)) tpCount++;
            else if ("False Positive".equalsIgnoreCase(cls)) fpCount++;
            else unclassCount++;

            if (!selectedTypes.isEmpty() && !selectedTypes.contains(item.findingType())) {
                continue;
            }
            if (!selectedSubtypes.isEmpty() && !selectedSubtypes.contains(item.subtype())) {
                continue;
            }
            if (!matchesClassification(item.classification())) {
                continue;
            }
            if (!matchesSourceType(item.sourceType())) {
                continue;
            }
            if (!query.isEmpty()) {
                boolean match = (item.matchValue() != null && item.matchValue().toLowerCase().contains(query))
                    || (item.findingType() != null && item.findingType().toLowerCase().contains(query))
                    || (item.subtype() != null && item.subtype().toLowerCase().contains(query))
                    || (item.sourceLocation() != null && item.sourceLocation().toLowerCase().contains(query))
                    || (item.contextSnippet() != null && item.contextSnippet().toLowerCase().contains(query));
                if (!match) continue;
            }

            String key = (item.matchValue() != null ? item.matchValue().trim() : "")
                + "||" + (item.findingType() != null ? item.findingType().trim() : "")
                + "||" + (item.subtype() != null ? item.subtype().trim() : "");

            FindingOccurrence_littlespidy occ = new FindingOccurrence_littlespidy(
                item.sourceLocation(),
                item.sourceType(),
                item.matchValue(),
                item.line(),
                item.startOffset(),
                item.endOffset(),
                item.contextSnippet()
            );

            GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy> grp = groupedMap.get(key);
            if (grp == null) {
                grp = new GroupedFinding_littlespidy<>(item, occ);
                groupedMap.put(key, grp);
            } else {
                grp.addOccurrence(item, occ);
                if (!"Not Classified".equalsIgnoreCase(item.classification())
                    && "Not Classified".equalsIgnoreCase(grp.getPrimary().classification())) {
                    grp.setPrimary(grp.getPrimary().withClassification(item.classification()));
                }
            }
        }

        List<GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy>> result = new ArrayList<>(groupedMap.values());
        tableModel.updateData(result);

        if (allFindings.isEmpty()) {
            statsLabel.setText("Internal IPs and SSNs: 0 (No findings found)");
        } else {
            statsLabel.setText(String.format("Findings: %d unique (%d total) | Visible: %d | TP: %d | FP: %d | Unclassified: %d",
                groupedMap.size(), allFindings.size(), result.size(), tpCount, fpCount, unclassCount));
        }
    }

    @Override
    protected List<FindingOccurrence_littlespidy> getOccurrencesAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getNavOccurrences() : Collections.emptyList();
    }

    @Override
    protected int getOccurrenceCountAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getCount() : 0;
    }

    @Override
    protected String getClassificationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().classification() : "Not Classified";
    }

    @Override
    protected void updateClassification(int modelRow, String classification) {
        GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy> grp = tableModel.getGroupAt(modelRow);
        if (grp == null) return;

        DiscoveredInternalIpAndSsn_littlespidy updatedPrimary = grp.getPrimary().withClassification(classification);
        grp.setPrimary(updatedPrimary);

        for (DiscoveredInternalIpAndSsn_littlespidy oldItem : grp.getOccurrences()) {
            DiscoveredInternalIpAndSsn_littlespidy updated = oldItem.withClassification(classification);
            syncClassificationToStore(oldItem, updated);

            for (int i = 0; i < allFindings.size(); i++) {
                DiscoveredInternalIpAndSsn_littlespidy cur = allFindings.get(i);
                if (cur == oldItem || (Objects.equals(cur.matchValue(), oldItem.matchValue())
                        && Objects.equals(cur.sourceLocation(), oldItem.sourceLocation())
                        && cur.line() == oldItem.line())) {
                    allFindings.set(i, updated);
                }
            }
        }

        tableModel.fireTableRowsUpdated(modelRow, modelRow);
    }

    private void syncClassificationToStore(DiscoveredInternalIpAndSsn_littlespidy oldItem, DiscoveredInternalIpAndSsn_littlespidy newItem) {
        if (dataStore == null) return;
        for (JsFileEntry entry : dataStore.getEntries()) {
            entry.updateInternalIpAndSsn(oldItem, newItem);
            if (entry.getUnpackedProject() != null) {
                entry.getUnpackedProject().updateInternalIpAndSsn(oldItem, newItem);
            }
        }
    }

    @Override
    protected String getFindingTextAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().matchValue() : "";
    }

    @Override
    protected int getStartOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().startOffset() : -1;
    }

    @Override
    protected int getEndOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().endOffset() : -1;
    }

    @Override
    protected String getSourceLocationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy> grp = tableModel.getGroupAt(modelRow);
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
        JOptionPane.showMessageDialog(this, String.format("Copied %d finding(s) to clipboard as TSV.", count), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
    }

    private static class InternalIpAndSsnTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "#", "Occurrences", "Finding Type", "Value / Match", "Subtype / CIDR", "Source Type", "Source Location", "Line"
        };
        private final List<GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy>> list = new ArrayList<>();

        public synchronized void updateData(List<GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy>> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy> getGroupAt(int row) {
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
            GroupedFinding_littlespidy<DiscoveredInternalIpAndSsn_littlespidy> item = list.get(r);
            DiscoveredInternalIpAndSsn_littlespidy primary = item.getPrimary();
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> item.getCount();
                case 2 -> primary.findingType();
                case 3 -> primary.matchValue();
                case 4 -> primary.subtype();
                case 5 -> primary.sourceType();
                case 6 -> primary.sourceLocation();
                case 7 -> primary.line();
                default -> null;
            };
        }
    }
}
