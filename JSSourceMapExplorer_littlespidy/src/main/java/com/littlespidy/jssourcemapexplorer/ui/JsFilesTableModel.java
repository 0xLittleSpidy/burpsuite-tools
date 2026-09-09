// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import com.littlespidy.jssourcemapexplorer.model.JsFileEntry;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model displaying discovered JavaScript scripts, their origin classifications,
 * detected framework (Next.js, Vue, React, Angular, Svelte, Nuxt), passive source map findings,
 * active probe results, and recon/secret metrics for both the JS file and the Source Map.
 *
 * @author littlespidy
 */
public class JsFilesTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "#",
        "Origin",
        "Framework",
        "Status",
        "Host",
        "JS Path",
        "Passive .map",
        "On-Demand Probe",
        "JS Recon (Paths / Keys)",
        "Map Recon (Paths / Keys)",
        "SourceMap Location",
        "Unpacked Files",
        "Size"
    };

    private final List<JsFileEntry> entries = new ArrayList<>();

    public synchronized void updateData(List<JsFileEntry> newEntries) {
        entries.clear();
        if (newEntries != null) {
            entries.addAll(newEntries);
        }
        fireTableDataChanged();
    }

    public synchronized JsFileEntry getEntryAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < entries.size()) {
            return entries.get(rowIndex);
        }
        return null;
    }

    public synchronized List<JsFileEntry> getAllEntries() {
        return new ArrayList<>(entries);
    }

    @Override
    public synchronized int getRowCount() {
        return entries.size();
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
        return switch (columnIndex) {
            case 0, 3 -> Integer.class;
            default -> String.class;
        };
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= entries.size()) {
            return null;
        }

        JsFileEntry entry = entries.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> entry.getId();
            case 1 -> entry.getOriginLabel();
            case 2 -> entry.getFramework();
            case 3 -> entry.getStatusCode();
            case 4 -> entry.getHost();
            case 5 -> entry.getPath();
            case 6 -> entry.getPassiveMapStatus() != null ? entry.getPassiveMapStatus().getLabel() : "Not Found";
            case 7 -> entry.getActiveProbeStatus() != null ? entry.getActiveProbeStatus().getLabel() : "-";
            case 8 -> entry.getJsReconSummary();
            case 9 -> entry.getMapReconSummary();
            case 10 -> entry.getSourceMapLocation() != null ? entry.getSourceMapLocation() : "-";
            case 11 -> entry.getUnpackedProject() != null ? entry.getUnpackedProject().getTotalFiles() + " files" : "-";
            case 12 -> formatSize(entry.getContentLength());
            default -> null;
        };
    }

    private String formatSize(int bytes) {
        if (bytes <= 0) return "0 B";
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
    }
}
