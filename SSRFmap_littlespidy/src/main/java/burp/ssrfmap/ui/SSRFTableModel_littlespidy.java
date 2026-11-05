// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.ui;

import burp.ssrfmap.model.SSRFResultEntry_littlespidy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.table.AbstractTableModel;

public class SSRFTableModel_littlespidy extends AbstractTableModel {
    private final String[] columnNames = {
        "#",
        "Module",
        "Scheme",
        "Payload",
        "Status",
        "Length",
        "Time",
        "Diff / Match Indicator",
        "Collaborator",
        "Result"
    };

    private final List<SSRFResultEntry_littlespidy> entries = Collections.synchronizedList(new ArrayList<>());

    @Override
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= entries.size()) {
            return null;
        }
        SSRFResultEntry_littlespidy entry = entries.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return entry.getId();
            case 1:
                return entry.getModule();
            case 2:
                return entry.getScheme();
            case 3:
                return entry.getPayload();
            case 4:
                return entry.getStatusCode() > 0 ? entry.getStatusCode() : "-";
            case 5:
                return entry.getLength() >= 0 ? entry.getLength() + " B" : "-";
            case 6:
                return entry.getResponseTimeMs() >= 0 ? entry.getResponseTimeMs() + " ms" : "-";
            case 7:
                return entry.getDiffIndicator();
            case 8:
                return entry.getCollaboratorInfo();
            case 9:
                return entry.getStatus();
            default:
                return "";
        }
    }

    public synchronized void addEntry(SSRFResultEntry_littlespidy entry) {
        int index = entries.size();
        entries.add(entry);
        fireTableRowsInserted(index, index);
    }

    public synchronized void updateEntry(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < entries.size()) {
            fireTableRowsUpdated(rowIndex, rowIndex);
        }
    }

    public synchronized SSRFResultEntry_littlespidy getEntry(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < entries.size()) {
            return entries.get(rowIndex);
        }
        return null;
    }

    public synchronized void clear() {
        entries.clear();
        fireTableDataChanged();
    }

    public List<SSRFResultEntry_littlespidy> getAllEntries() {
        return new ArrayList<>(entries);
    }
}
