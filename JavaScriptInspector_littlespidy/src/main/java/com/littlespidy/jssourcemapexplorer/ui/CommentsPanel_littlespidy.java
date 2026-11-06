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
 * Dedicated top-level tab panel for analyzing, filtering, and classifying developer comments
 * (TODOs, credentials, debug info, flags) from JavaScript assets and unpacked Source Maps.
 * Groups duplicate comments across files with an Occurrences column and occurrence navigation.
 *
 * @author littlespidy
 */
public class CommentsPanel_littlespidy extends BaseFindingPanel_littlespidy {

    private final CommentsTableModel tableModel;
    private MultiSelectFilterButton commentTypeFilterBtn;
    private MultiSelectFilterButton commentCategoryFilterBtn;

    private final List<DiscoveredComment> allComments = new ArrayList<>();

    public CommentsPanel_littlespidy(MontoyaApi api, JsDataStore dataStore) {
        this(api, dataStore, new CommentsTableModel());
    }

    private CommentsPanel_littlespidy(MontoyaApi api, JsDataStore dataStore, CommentsTableModel model) {
        super(api, dataStore, "Comments", model);
        this.tableModel = model;
    }

    @Override
    protected void addCategoryFiltersToToolbar(JPanel toolbar) {
        JLabel typeLbl = new JLabel("Type:");
        typeLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(typeLbl);

        commentTypeFilterBtn = new MultiSelectFilterButton(
            "Type",
            List.of("All Types", "Single-Line (//)", "Multi-Line (/* */)", "HTML (<!-- -->)"),
            sel -> applyFilter()
        );
        toolbar.add(commentTypeFilterBtn);

        JLabel catLbl = new JLabel("Category:");
        catLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(catLbl);

        commentCategoryFilterBtn = new MultiSelectFilterButton(
            "Category",
            List.of("All Categories", "TODO / FIXME", "Credentials / Auth", "Debug / Config", "General"),
            sel -> applyFilter()
        );
        toolbar.add(commentCategoryFilterBtn);
    }

    @Override
    protected void resetCategoryFilters() {
        if (commentTypeFilterBtn != null) commentTypeFilterBtn.clearSelection();
        if (commentCategoryFilterBtn != null) commentCategoryFilterBtn.clearSelection();
    }

    @Override
    public synchronized void refreshFromDataStore() {
        allComments.clear();
        if (dataStore != null) {
            for (JsFileEntry entry : dataStore.getEntries()) {
                allComments.addAll(entry.getJsComments());
                if (entry.getUnpackedProject() != null) {
                    allComments.addAll(entry.getUnpackedProject().getAllComments());
                }
            }
        }
        applyFilter();
    }

    @Override
    public synchronized void applyFilter() {
        Set<String> selectedTypes = commentTypeFilterBtn != null ? commentTypeFilterBtn.getSelected() : Collections.emptySet();
        Set<String> selectedCats = commentCategoryFilterBtn != null ? commentCategoryFilterBtn.getSelected() : Collections.emptySet();
        String query = searchField.getText().trim().toLowerCase();

        Map<String, GroupedFinding_littlespidy<DiscoveredComment>> groupedMap = new LinkedHashMap<>();
        int tpCount = 0;
        int fpCount = 0;
        int unclassCount = 0;

        for (DiscoveredComment comm : allComments) {
            String cls = comm.classification() != null ? comm.classification() : "Not Classified";
            if ("True Positive".equalsIgnoreCase(cls)) tpCount++;
            else if ("False Positive".equalsIgnoreCase(cls)) fpCount++;
            else unclassCount++;

            if (!selectedTypes.isEmpty() && !selectedTypes.contains(comm.commentType())) {
                continue;
            }
            if (!selectedCats.isEmpty() && !selectedCats.contains(comm.category())) {
                continue;
            }
            if (!matchesClassification(comm.classification())) {
                continue;
            }
            if (!matchesSourceType(comm.sourceType())) {
                continue;
            }
            if (!query.isEmpty()) {
                boolean match = (comm.commentText() != null && comm.commentText().toLowerCase().contains(query))
                    || (comm.category() != null && comm.category().toLowerCase().contains(query))
                    || (comm.commentType() != null && comm.commentType().toLowerCase().contains(query))
                    || (comm.sourceLocation() != null && comm.sourceLocation().toLowerCase().contains(query))
                    || (comm.contextSnippet() != null && comm.contextSnippet().toLowerCase().contains(query));
                if (!match) continue;
            }

            String key = (comm.commentText() != null ? comm.commentText().trim() : "")
                + "||" + (comm.commentType() != null ? comm.commentType().trim() : "")
                + "||" + (comm.category() != null ? comm.category().trim() : "");

            FindingOccurrence_littlespidy occ = new FindingOccurrence_littlespidy(
                comm.sourceLocation(),
                comm.sourceType(),
                comm.commentText(),
                comm.line(),
                comm.startOffset(),
                comm.endOffset(),
                comm.contextSnippet()
            );

            GroupedFinding_littlespidy<DiscoveredComment> grp = groupedMap.get(key);
            if (grp == null) {
                grp = new GroupedFinding_littlespidy<>(comm, occ);
                groupedMap.put(key, grp);
            } else {
                grp.addOccurrence(comm, occ);
                if (!"Not Classified".equalsIgnoreCase(comm.classification())
                    && "Not Classified".equalsIgnoreCase(grp.getPrimary().classification())) {
                    grp.setPrimary(grp.getPrimary().withClassification(comm.classification()));
                }
            }
        }

        List<GroupedFinding_littlespidy<DiscoveredComment>> result = new ArrayList<>(groupedMap.values());
        tableModel.updateData(result);

        if (allComments.isEmpty()) {
            statsLabel.setText("Comments: 0 (No findings found)");
        } else {
            statsLabel.setText(String.format("Comments: %d unique (%d total) | Visible: %d | TP: %d | FP: %d | Unclassified: %d",
                groupedMap.size(), allComments.size(), result.size(), tpCount, fpCount, unclassCount));
        }
    }

    @Override
    protected List<FindingOccurrence_littlespidy> getOccurrencesAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredComment> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getNavOccurrences() : Collections.emptyList();
    }

    @Override
    protected int getOccurrenceCountAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredComment> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getCount() : 0;
    }

    @Override
    protected String getClassificationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredComment> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().classification() : "Not Classified";
    }

    @Override
    protected void updateClassification(int modelRow, String classification) {
        GroupedFinding_littlespidy<DiscoveredComment> grp = tableModel.getGroupAt(modelRow);
        if (grp == null) return;

        DiscoveredComment updatedPrimary = grp.getPrimary().withClassification(classification);
        grp.setPrimary(updatedPrimary);

        for (DiscoveredComment oldComm : grp.getOccurrences()) {
            DiscoveredComment updated = oldComm.withClassification(classification);
            syncClassificationToStore(oldComm, updated);

            for (int i = 0; i < allComments.size(); i++) {
                DiscoveredComment cur = allComments.get(i);
                if (cur == oldComm || (Objects.equals(cur.commentText(), oldComm.commentText())
                        && Objects.equals(cur.sourceLocation(), oldComm.sourceLocation())
                        && cur.line() == oldComm.line())) {
                    allComments.set(i, updated);
                }
            }
        }

        tableModel.fireTableRowsUpdated(modelRow, modelRow);
    }

    private void syncClassificationToStore(DiscoveredComment oldComm, DiscoveredComment newComm) {
        if (dataStore == null) return;
        for (JsFileEntry entry : dataStore.getEntries()) {
            boolean done = entry.updateComment(oldComm, newComm);
            if (entry.getUnpackedProject() != null) {
                if (entry.getUnpackedProject().updateComment(oldComm, newComm)) {
                    done = true;
                }
            }
            if (done) return;
        }
    }

    @Override
    protected String getFindingTextAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredComment> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().commentText() : "";
    }

    @Override
    protected int getStartOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredComment> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().startOffset() : -1;
    }

    @Override
    protected int getEndOffsetAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredComment> grp = tableModel.getGroupAt(modelRow);
        return grp != null ? grp.getPrimary().endOffset() : -1;
    }

    @Override
    protected String getSourceLocationAt(int modelRow) {
        GroupedFinding_littlespidy<DiscoveredComment> grp = tableModel.getGroupAt(modelRow);
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
        JOptionPane.showMessageDialog(this, String.format("Copied %d comment(s) to clipboard as TSV.", count), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
    }

    private static class CommentsTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "#", "Occurrences", "Type", "Category", "Comment Text", "Source Type", "Source Location", "Line"
        };
        private final List<GroupedFinding_littlespidy<DiscoveredComment>> list = new ArrayList<>();

        public synchronized void updateData(List<GroupedFinding_littlespidy<DiscoveredComment>> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized GroupedFinding_littlespidy<DiscoveredComment> getGroupAt(int row) {
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
            GroupedFinding_littlespidy<DiscoveredComment> item = list.get(r);
            DiscoveredComment primary = item.getPrimary();
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> item.getCount();
                case 2 -> primary.commentType();
                case 3 -> primary.category();
                case 4 -> primary.commentText();
                case 5 -> primary.sourceType();
                case 6 -> primary.sourceLocation();
                case 7 -> primary.line();
                default -> null;
            };
        }
    }
}
