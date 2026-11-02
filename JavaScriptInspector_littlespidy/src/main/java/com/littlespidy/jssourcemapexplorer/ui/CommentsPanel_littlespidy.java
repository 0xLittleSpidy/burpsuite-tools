// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredComment;
import com.littlespidy.jssourcemapexplorer.model.JsDataStore;
import com.littlespidy.jssourcemapexplorer.model.JsFileEntry;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Dedicated top-level tab panel for analyzing, filtering, and classifying developer comments
 * (TODOs, credentials, debug info, flags) from JavaScript assets and unpacked Source Maps.
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

        List<DiscoveredComment> filtered = new ArrayList<>();
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
            if (!query.isEmpty()) {
                boolean match = (comm.commentText() != null && comm.commentText().toLowerCase().contains(query))
                    || (comm.category() != null && comm.category().toLowerCase().contains(query))
                    || (comm.commentType() != null && comm.commentType().toLowerCase().contains(query))
                    || (comm.sourceLocation() != null && comm.sourceLocation().toLowerCase().contains(query))
                    || (comm.contextSnippet() != null && comm.contextSnippet().toLowerCase().contains(query));
                if (!match) continue;
            }
            filtered.add(comm);
        }

        tableModel.updateData(filtered);
        if (allComments.isEmpty()) {
            statsLabel.setText("Comments: 0 (No findings found)");
        } else {
            statsLabel.setText(String.format("Comments: %d (Visible: %d | TP: %d | FP: %d | Unclassified: %d)",
                allComments.size(), filtered.size(), tpCount, fpCount, unclassCount));
        }
    }

    @Override
    protected String getClassificationAt(int modelRow) {
        DiscoveredComment comm = tableModel.getCommentAt(modelRow);
        return comm != null ? comm.classification() : "Not Classified";
    }

    @Override
    protected void updateClassification(int modelRow, String classification) {
        DiscoveredComment comm = tableModel.getCommentAt(modelRow);
        if (comm == null) return;

        DiscoveredComment updated = comm.withClassification(classification);
        tableModel.setCommentAt(modelRow, updated);

        for (int i = 0; i < allComments.size(); i++) {
            DiscoveredComment cur = allComments.get(i);
            if (cur == comm || (Objects.equals(cur.commentText(), comm.commentText()) && Objects.equals(cur.sourceLocation(), comm.sourceLocation()))) {
                allComments.set(i, updated);
                break;
            }
        }

        syncClassificationToStore(comm, updated);
    }

    private void syncClassificationToStore(DiscoveredComment oldComm, DiscoveredComment newComm) {
        if (dataStore == null) return;
        for (JsFileEntry entry : dataStore.getEntries()) {
            if (entry.updateComment(oldComm, newComm)) {
                return;
            }
            if (entry.getUnpackedProject() != null) {
                if (entry.getUnpackedProject().updateComment(oldComm, newComm)) {
                    return;
                }
            }
        }
    }

    @Override
    protected String getFindingTextAt(int modelRow) {
        DiscoveredComment comm = tableModel.getCommentAt(modelRow);
        return comm != null ? comm.commentText() : "";
    }

    @Override
    protected int getStartOffsetAt(int modelRow) {
        DiscoveredComment comm = tableModel.getCommentAt(modelRow);
        return comm != null ? comm.startOffset() : -1;
    }

    @Override
    protected int getEndOffsetAt(int modelRow) {
        DiscoveredComment comm = tableModel.getCommentAt(modelRow);
        return comm != null ? comm.endOffset() : -1;
    }

    @Override
    protected String getSourceLocationAt(int modelRow) {
        DiscoveredComment comm = tableModel.getCommentAt(modelRow);
        return comm != null ? comm.sourceLocation() : "";
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
            "#", "Type", "Category", "Comment Text", "Source Type", "Source Location", "Line"
        };
        private final List<DiscoveredComment> list = new ArrayList<>();

        public synchronized void updateData(List<DiscoveredComment> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized DiscoveredComment getCommentAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        public synchronized void setCommentAt(int row, DiscoveredComment comm) {
            if (row >= 0 && row < list.size()) {
                list.set(row, comm);
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
            DiscoveredComment item = list.get(r);
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> item.commentType();
                case 2 -> item.category();
                case 3 -> item.commentText();
                case 4 -> item.sourceType();
                case 5 -> item.sourceLocation();
                case 6 -> item.line();
                default -> null;
            };
        }
    }
}
