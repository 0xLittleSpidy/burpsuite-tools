// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.jssourcemapexplorer.engine.SecretAndEndpointMiner;
import com.littlespidy.jssourcemapexplorer.model.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Dedicated top-level tab panel for analyzing, filtering, and classifying discovered
 * secrets, tokens, API keys, and credentials from JavaScript assets and unpacked Source Maps.
 * Groups duplicate secrets across files with an Occurrences column and occurrence navigation.
 *
 * @author littlespidy
 */
public class SecretsPanel_littlespidy extends BaseFindingPanel_littlespidy {

    private final SecretsTableModel tableModel;
    private MultiSelectFilterButton tokenTypeFilterBtn;

    private final List<DiscoveredSecret> allSecrets = new ArrayList<>();

    public SecretsPanel_littlespidy(MontoyaApi api, JsDataStore dataStore) {
        this(api, dataStore, new SecretsTableModel());
    }

    private SecretsPanel_littlespidy(MontoyaApi api, JsDataStore dataStore, SecretsTableModel model) {
        super(api, dataStore, "Secrets", model);
        this.tableModel = model;
    }

    @Override
    protected void addCategoryFiltersToToolbar(JPanel toolbar) {
        tokenTypeFilterBtn = new MultiSelectFilterButton(
            "Token Type",
            SecretAndEndpointMiner.getAllSignatureNames(),
            sel -> applyFilter()
        );
        toolbar.add(tokenTypeFilterBtn);

        JButton secretRegexBtn = new JButton("Secret Regex");
        secretRegexBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        secretRegexBtn.setToolTipText("View active secret and credential regex detection patterns");
        secretRegexBtn.addActionListener(e -> {
            Window owner = SwingUtilities.getWindowAncestor(this);
            SecretRegexDialog_littlespidy dlg = new SecretRegexDialog_littlespidy(owner);
            dlg.setVisible(true);
        });
        toolbar.add(secretRegexBtn);
    }

    @Override
    protected void resetCategoryFilters() {
        if (tokenTypeFilterBtn != null) tokenTypeFilterBtn.clearSelection();
    }

    @Override
    public synchronized void refreshFromDataStore() {
        allSecrets.clear();
        if (dataStore != null) {
            for (JsFileEntry entry : dataStore.getEntries()) {
                allSecrets.addAll(entry.getJsSecrets());
                if (entry.getUnpackedProject() != null) {
                    allSecrets.addAll(entry.getUnpackedProject().getAllSecrets());
                }
            }
        }
        applyFilter();
    }

    @Override
    public synchronized void applyFilter() {
        Set<String> selectedTypes = tokenTypeFilterBtn != null ? tokenTypeFilterBtn.getSelected() : Collections.emptySet();
        String query = searchField.getText().trim().toLowerCase();

        Map<String, GroupedFinding_littlespidy<DiscoveredSecret>> groupedMap = new LinkedHashMap<>();
        int tpCount = 0;
        int fpCount = 0;
        int unclassCount = 0;

        for (DiscoveredSecret sec : allSecrets) {
            String cls = sec.classification() != null ? sec.classification() : "Not Classified";
            if ("True Positive".equalsIgnoreCase(cls)) tpCount++;
            else if ("False Positive".equalsIgnoreCase(cls)) fpCount++;
            else unclassCount++;

            if (!selectedTypes.isEmpty() && !selectedTypes.contains(sec.technique())) {
                continue;
            }
            if (!matchesClassification(sec.classification())) {
                continue;
            }
            if (!matchesSourceType(sec.sourceType())) {
                continue;
            }
            if (!query.isEmpty()) {
                boolean match = (sec.secretValue() != null && sec.secretValue().toLowerCase().contains(query))
                    || (sec.technique() != null && sec.technique().toLowerCase().contains(query))
                    || (sec.sourceLocation() != null && sec.sourceLocation().toLowerCase().contains(query))
                    || (sec.contextSnippet() != null && sec.contextSnippet().toLowerCase().contains(query));
                if (!match) continue;
            }

            String key = (sec.secretValue() != null ? sec.secretValue().trim() : "")
                + "||" + (sec.technique() != null ? sec.technique().trim() : "");

            FindingOccurrence_littlespidy occ = new FindingOccurrence_littlespidy(
                sec.sourceLocation(),
                sec.sourceType(),
                sec.secretValue(),
                sec.line(),
                sec.startOffset(),
                sec.endOffset(),
                sec.contextSnippet()
            );

            GroupedFinding_littlespidy<DiscoveredSecret> grp = groupedMap.get(key);
            if (grp == null) {
                grp = new GroupedFinding_littlespidy<>(sec, occ);
                groupedMap.put(key, grp);
            } else {
                grp.addOccurrence(sec, occ);
                if (!"Not Classified".equalsIgnoreCase(sec.classification())
                    && "Not Classified".equalsIgnoreCase(grp.getPrimary().classification())) {
                    grp.setPrimary(grp.getPrimary().withClassification(sec.classification()));
                }
            }
        }

        List<GroupedFinding_littlespidy<DiscoveredSecret>> result = new ArrayList<>(groupedMap.values());
        tableModel.updateData(result);

        if (allSecrets.isEmpty()) {
            statsLabel.setText("Secrets: 0 (No findings found)");
        } else {
            statsLabel.setText(String.format("Secrets: %d unique (%d total) | Visible: %d | TP: %d | FP: %d | Unclassified: %d",
                groupedMap.size(), allSecrets.size(), result.size(), tpCount, fpCount, unclassCount));
        }
    }

    @Override
    protected List<FindingOccurrence_littlespidy> getOccurrencesAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecret> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getNavOccurrences() : Collections.emptyList();
    }

    @Override
    protected int getOccurrenceCountAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecret> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getCount() : 0;
    }

    @Override
    protected String getClassificationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecret> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().classification() : "Not Classified";
    }

    @Override
    protected void updateClassification(int modelRow, String classification) {
        GroupedFinding_littlespidy<DiscoveredSecret> grp = tableModel.getGroupAt(modelRow);
        if (grp == null) return;

        DiscoveredSecret updatedPrimary = grp.getPrimary().withClassification(classification);
        grp.setPrimary(updatedPrimary);

        for (DiscoveredSecret oldSec : grp.getOccurrences()) {
            DiscoveredSecret updated = oldSec.withClassification(classification);
            syncClassificationToStore(oldSec, updated);

            for (int i = 0; i < allSecrets.size(); i++) {
                DiscoveredSecret cur = allSecrets.get(i);
                if (cur == oldSec || (Objects.equals(cur.secretValue(), oldSec.secretValue())
                        && Objects.equals(cur.sourceLocation(), oldSec.sourceLocation())
                        && cur.line() == oldSec.line())) {
                    allSecrets.set(i, updated);
                }
            }
        }

        tableModel.fireTableRowsUpdated(modelRow, modelRow);
    }

    private void syncClassificationToStore(DiscoveredSecret oldSec, DiscoveredSecret newSec) {
        if (dataStore == null) return;
        for (JsFileEntry entry : dataStore.getEntries()) {
            boolean done = entry.updateSecret(oldSec, newSec);
            if (entry.getUnpackedProject() != null) {
                if (entry.getUnpackedProject().updateSecret(oldSec, newSec)) {
                    done = true;
                }
            }
            if (done) return;
        }
    }

    @Override
    protected String getFindingTextAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecret> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().secretValue() : "";
    }

    @Override
    protected int getStartOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecret> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().startOffset() : -1;
    }

    @Override
    protected int getEndOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecret> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().endOffset() : -1;
    }

    @Override
    protected String getSourceLocationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredSecret> grp = tableModel.getGroupAt(modelRow);
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
        JOptionPane.showMessageDialog(this, String.format("Copied %d secret(s) to clipboard as TSV.", count), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
    }

    private static class SecretsTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "#", "Occurrences", "Token Type", "Secret Value / Match", "Length", "Source Type", "Source Location", "Line"
        };
        private final List<GroupedFinding_littlespidy<DiscoveredSecret>> list = new ArrayList<>();

        public synchronized void updateData(List<GroupedFinding_littlespidy<DiscoveredSecret>> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized GroupedFinding_littlespidy<DiscoveredSecret> getGroupAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) {
            return (c == 0 || c == 1 || c == 4 || c == 7) ? Integer.class : String.class;
        }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            GroupedFinding_littlespidy<DiscoveredSecret> item = list.get(r);
            DiscoveredSecret primary = item.getPrimary();
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> item.getCount();
                case 2 -> primary.technique(); // Token Type
                case 3 -> primary.secretValue();
                case 4 -> primary.secretValue() != null ? primary.secretValue().length() : 0;
                case 5 -> primary.sourceType();
                case 6 -> primary.sourceLocation();
                case 7 -> primary.line();
                default -> null;
            };
        }
    }
}
