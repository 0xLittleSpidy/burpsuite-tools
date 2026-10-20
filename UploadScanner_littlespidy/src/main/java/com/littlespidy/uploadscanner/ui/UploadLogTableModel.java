package com.littlespidy.uploadscanner.ui;

import com.littlespidy.uploadscanner.model.StageType;
import com.littlespidy.uploadscanner.model.UploadEntry;

import javax.swing.table.AbstractTableModel;
import java.util.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Table model for the "Done Uploads" activity log with multi-select triage filtering.
 *
 * @author littlespidy
 */
public class UploadLogTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "#", "Stage", "Method", "Status", "Filename / Payload", "Length (B)", "URL"
    };

    private static final Class<?>[] COLUMN_CLASSES = {
            Integer.class, String.class, String.class, Integer.class, String.class, Integer.class, String.class
    };

    private final List<UploadEntry> allEntries = new ArrayList<>();
    private final List<UploadEntry> displayedEntries = new ArrayList<>();

    private Set<String> stageFilter = Collections.emptySet();
    private Set<String> statusFilter = Collections.emptySet();
    private Set<String> methodFilter = Collections.emptySet();
    private String lengthFilter = "";
    private String searchFilter = "";

    public synchronized void addEntry(UploadEntry entry) {
        allEntries.add(entry);
        if (matches(entry)) {
            int row = displayedEntries.size();
            displayedEntries.add(entry);
            fireTableRowsInserted(row, row);
        }
    }

    public synchronized void addEntries(List<UploadEntry> entries) {
        if (entries == null || entries.isEmpty()) return;
        for (UploadEntry entry : entries) {
            allEntries.add(entry);
            if (matches(entry)) {
                displayedEntries.add(entry);
            }
        }
        fireTableDataChanged();
    }

    public synchronized void clear() {
        allEntries.clear();
        displayedEntries.clear();
        fireTableDataChanged();
    }

    public synchronized UploadEntry getEntryAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < displayedEntries.size()) {
            return displayedEntries.get(rowIndex);
        }
        return null;
    }

    public synchronized List<UploadEntry> getAllEntries() {
        return new ArrayList<>(allEntries);
    }

    public synchronized void applyFilters(Set<String> stages, Set<String> statuses, Set<String> methods, String search) {
        applyFilters(stages, statuses, methods, "", search);
    }

    public synchronized void applyFilters(Set<String> stages, Set<String> statuses, Set<String> methods, String lengthFilter, String search) {
        this.stageFilter = stages != null ? new HashSet<>(stages) : Collections.emptySet();
        this.statusFilter = statuses != null ? new HashSet<>(statuses) : Collections.emptySet();
        this.methodFilter = methods != null ? new HashSet<>(methods) : Collections.emptySet();
        this.lengthFilter = lengthFilter != null ? lengthFilter.trim() : "";
        this.searchFilter = search != null ? search.trim().toLowerCase() : "";

        displayedEntries.clear();
        for (UploadEntry entry : allEntries) {
            if (matches(entry)) {
                displayedEntries.add(entry);
            }
        }
        fireTableDataChanged();
    }

    private boolean matches(UploadEntry entry) {
        // Stage filter
        if (!stageFilter.isEmpty()) {
            boolean matched = false;
            for (String s : stageFilter) {
                if (entry.getStage().name().equalsIgnoreCase(s) ||
                        entry.getStage().getDisplayName().equalsIgnoreCase(s)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) return false;
        }

        // Method filter
        if (!methodFilter.isEmpty()) {
            if (!methodFilter.contains(entry.getMethod().toUpperCase())) {
                return false;
            }
        }

        // Status code filter (e.g. 200, 2xx, 3xx, 4xx, 5xx)
        if (!statusFilter.isEmpty()) {
            boolean statusMatched = false;
            int code = entry.getStatusCode();
            String codeStr = String.valueOf(code);
            String groupStr = (code / 100) + "xx";

            for (String sf : statusFilter) {
                if (sf.equalsIgnoreCase(codeStr) || sf.equalsIgnoreCase(groupStr)) {
                    statusMatched = true;
                    break;
                }
            }
            if (!statusMatched) return false;
        }

        // Response length filter
        if (!lengthFilter.isEmpty()) {
            if (!matchesLength(entry.getResponseLength(), lengthFilter)) {
                return false;
            }
        }

        // Search text
        if (!searchFilter.isEmpty()) {
            boolean searchMatched = entry.getUrl().toLowerCase().contains(searchFilter)
                    || entry.getPayloadName().toLowerCase().contains(searchFilter)
                    || entry.getMethod().toLowerCase().contains(searchFilter)
                    || String.valueOf(entry.getStatusCode()).contains(searchFilter)
                    || entry.getStage().getDisplayName().toLowerCase().contains(searchFilter);
            if (!searchMatched) return false;
        }

        return true;
    }

    public static boolean matchesLength(int responseLength, String filterText) {
        if (filterText == null || filterText.trim().isEmpty()) {
            return true;
        }
        String filter = filterText.trim();
        String[] parts = filter.split("[,;]");
        for (String rawPart : parts) {
            String part = rawPart.trim().replaceAll("\\s+", "");
            if (part.isEmpty()) continue;

            if (part.startsWith(">=")) {
                try {
                    int val = Integer.parseInt(part.substring(2));
                    if (responseLength < val) return false;
                } catch (NumberFormatException ignored) {}
            } else if (part.startsWith("<=")) {
                try {
                    int val = Integer.parseInt(part.substring(2));
                    if (responseLength > val) return false;
                } catch (NumberFormatException ignored) {}
            } else if (part.startsWith(">")) {
                try {
                    int val = Integer.parseInt(part.substring(1));
                    if (responseLength <= val) return false;
                } catch (NumberFormatException ignored) {}
            } else if (part.startsWith("<")) {
                try {
                    int val = Integer.parseInt(part.substring(1));
                    if (responseLength >= val) return false;
                } catch (NumberFormatException ignored) {}
            } else if (part.startsWith("!=") || part.startsWith("!")) {
                try {
                    int val = Integer.parseInt(part.startsWith("!=") ? part.substring(2) : part.substring(1));
                    if (responseLength == val) return false;
                } catch (NumberFormatException ignored) {}
            } else if (part.contains("-")) {
                String[] range = part.split("-");
                if (range.length == 2) {
                    try {
                        int min = Integer.parseInt(range[0]);
                        int max = Integer.parseInt(range[1]);
                        if (min > max) {
                            int t = min; min = max; max = t;
                        }
                        if (responseLength < min || responseLength > max) return false;
                    } catch (NumberFormatException ignored) {}
                }
            } else if (part.startsWith("=")) {
                try {
                    int val = Integer.parseInt(part.substring(1));
                    if (responseLength != val) return false;
                } catch (NumberFormatException ignored) {}
            } else {
                try {
                    int val = Integer.parseInt(part);
                    if (responseLength != val) return false;
                } catch (NumberFormatException ignored) {}
            }
        }
        return true;
    }

    @Override
    public int getRowCount() {
        return displayedEntries.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return COLUMN_CLASSES[columnIndex];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        UploadEntry entry = getEntryAt(rowIndex);
        if (entry == null) {
            return null;
        }

        return switch (columnIndex) {
            case 0 -> entry.getId();
            case 1 -> entry.getStage().getDisplayName();
            case 2 -> entry.getMethod();
            case 3 -> (int) entry.getStatusCode();
            case 4 -> entry.getPayloadName();
            case 5 -> entry.getResponseLength();
            case 6 -> entry.getUrl();
            default -> "";
        };
    }
}
