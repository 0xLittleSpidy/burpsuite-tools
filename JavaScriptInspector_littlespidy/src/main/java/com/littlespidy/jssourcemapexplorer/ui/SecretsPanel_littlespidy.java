// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.jssourcemapexplorer.engine.SecretAndEndpointMiner;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredSecret;
import com.littlespidy.jssourcemapexplorer.model.JsDataStore;
import com.littlespidy.jssourcemapexplorer.model.JsFileEntry;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Dedicated top-level tab panel for analyzing, filtering, and classifying discovered
 * secrets, tokens, API keys, and credentials from JavaScript assets and unpacked Source Maps.
 *
 * @author littlespidy
 */
public class SecretsPanel_littlespidy extends BaseFindingPanel_littlespidy {

    private final SecretsTableModel tableModel;
    private MultiSelectFilterButton categoryFilterBtn;
    private MultiSelectFilterButton signatureFilterBtn;

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
        JLabel catLbl = new JLabel("Category:");
        catLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(catLbl);

        categoryFilterBtn = new MultiSelectFilterButton(
            "Category",
            SecretAndEndpointMiner.getAllCategories(),
            sel -> applyFilter()
        );
        toolbar.add(categoryFilterBtn);

        JLabel sigLbl = new JLabel("Signature:");
        sigLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(sigLbl);

        signatureFilterBtn = new MultiSelectFilterButton(
            "Signature",
            SecretAndEndpointMiner.getAllSignatureNames(),
            sel -> applyFilter()
        );
        toolbar.add(signatureFilterBtn);
    }

    @Override
    protected void resetCategoryFilters() {
        if (categoryFilterBtn != null) categoryFilterBtn.clearSelection();
        if (signatureFilterBtn != null) signatureFilterBtn.clearSelection();
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
        Set<String> selectedCategories = categoryFilterBtn != null ? categoryFilterBtn.getSelected() : Collections.emptySet();
        Set<String> selectedSigs = signatureFilterBtn != null ? signatureFilterBtn.getSelected() : Collections.emptySet();
        String query = searchField.getText().trim().toLowerCase();

        List<DiscoveredSecret> filtered = new ArrayList<>();
        int tpCount = 0;
        int fpCount = 0;
        int unclassCount = 0;

        for (DiscoveredSecret sec : allSecrets) {
            String cls = sec.classification() != null ? sec.classification() : "Not Classified";
            if ("True Positive".equalsIgnoreCase(cls)) tpCount++;
            else if ("False Positive".equalsIgnoreCase(cls)) fpCount++;
            else unclassCount++;

            if (!selectedCategories.isEmpty() && !selectedCategories.contains(sec.category())) {
                continue;
            }
            if (!selectedSigs.isEmpty() && !selectedSigs.contains(sec.technique())) {
                continue;
            }
            if (!matchesClassification(sec.classification())) {
                continue;
            }
            if (!query.isEmpty()) {
                boolean match = (sec.secretValue() != null && sec.secretValue().toLowerCase().contains(query))
                    || (sec.category() != null && sec.category().toLowerCase().contains(query))
                    || (sec.technique() != null && sec.technique().toLowerCase().contains(query))
                    || (sec.sourceLocation() != null && sec.sourceLocation().toLowerCase().contains(query))
                    || (sec.contextSnippet() != null && sec.contextSnippet().toLowerCase().contains(query));
                if (!match) continue;
            }
            filtered.add(sec);
        }

        tableModel.updateData(filtered);
        statsLabel.setText(String.format("Secrets: %d (Visible: %d | TP: %d | FP: %d | Unclassified: %d)",
            allSecrets.size(), filtered.size(), tpCount, fpCount, unclassCount));
    }

    @Override
    protected String getClassificationAt(int modelRow) {
        DiscoveredSecret sec = tableModel.getSecretAt(modelRow);
        return sec != null ? sec.classification() : "Not Classified";
    }

    @Override
    protected void updateClassification(int modelRow, String classification) {
        DiscoveredSecret sec = tableModel.getSecretAt(modelRow);
        if (sec == null) return;

        DiscoveredSecret updated = sec.withClassification(classification);
        tableModel.setSecretAt(modelRow, updated);

        // Update in allSecrets list
        for (int i = 0; i < allSecrets.size(); i++) {
            DiscoveredSecret cur = allSecrets.get(i);
            if (cur == sec || (Objects.equals(cur.secretValue(), sec.secretValue()) && Objects.equals(cur.sourceLocation(), sec.sourceLocation()))) {
                allSecrets.set(i, updated);
                break;
            }
        }

        // Synchronize back to parent JsFileEntry
        syncClassificationToStore(sec, updated);
    }

    private void syncClassificationToStore(DiscoveredSecret oldSec, DiscoveredSecret newSec) {
        if (dataStore == null) return;
        for (JsFileEntry entry : dataStore.getEntries()) {
            List<DiscoveredSecret> jsSecs = entry.getJsSecrets();
            for (int i = 0; i < jsSecs.size(); i++) {
                if (jsSecs.get(i) == oldSec || (Objects.equals(jsSecs.get(i).secretValue(), oldSec.secretValue()) && Objects.equals(jsSecs.get(i).sourceLocation(), oldSec.sourceLocation()))) {
                    jsSecs.set(i, newSec);
                    return;
                }
            }
            if (entry.getUnpackedProject() != null) {
                List<DiscoveredSecret> unpSecs = entry.getUnpackedProject().getAllSecrets();
                for (int i = 0; i < unpSecs.size(); i++) {
                    if (unpSecs.get(i) == oldSec || (Objects.equals(unpSecs.get(i).secretValue(), oldSec.secretValue()) && Objects.equals(unpSecs.get(i).sourceLocation(), oldSec.sourceLocation()))) {
                        unpSecs.set(i, newSec);
                        return;
                    }
                }
            }
        }
    }

    @Override
    protected String getFindingTextAt(int modelRow) {
        DiscoveredSecret sec = tableModel.getSecretAt(modelRow);
        return sec != null ? sec.secretValue() : "";
    }

    @Override
    protected int getStartOffsetAt(int modelRow) {
        DiscoveredSecret sec = tableModel.getSecretAt(modelRow);
        return sec != null ? sec.startOffset() : -1;
    }

    @Override
    protected int getEndOffsetAt(int modelRow) {
        DiscoveredSecret sec = tableModel.getSecretAt(modelRow);
        return sec != null ? sec.endOffset() : -1;
    }

    @Override
    protected String getSourceLocationAt(int modelRow) {
        DiscoveredSecret sec = tableModel.getSecretAt(modelRow);
        return sec != null ? sec.sourceLocation() : "";
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
            "#", "Category", "Secret Value / Match", "Signature", "Severity", "Confidence", "Entropy", "Source Type", "Source Location", "Line", "Classification"
        };
        private final List<DiscoveredSecret> list = new ArrayList<>();

        public synchronized void updateData(List<DiscoveredSecret> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized DiscoveredSecret getSecretAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        public synchronized void setSecretAt(int row, DiscoveredSecret sec) {
            if (row >= 0 && row < list.size()) {
                list.set(row, sec);
                fireTableRowsUpdated(row, row);
            }
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) {
            return switch (c) {
                case 0, 9 -> Integer.class;
                case 6 -> Double.class;
                default -> String.class;
            };
        }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            DiscoveredSecret item = list.get(r);
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> item.category();
                case 2 -> item.secretValue();
                case 3 -> item.technique();
                case 4 -> item.severity();
                case 5 -> item.confidence();
                case 6 -> Math.round(item.entropy() * 100.0) / 100.0;
                case 7 -> item.sourceType();
                case 8 -> item.sourceLocation();
                case 9 -> item.line();
                case 10 -> item.classification();
                default -> null;
            };
        }
    }
}
