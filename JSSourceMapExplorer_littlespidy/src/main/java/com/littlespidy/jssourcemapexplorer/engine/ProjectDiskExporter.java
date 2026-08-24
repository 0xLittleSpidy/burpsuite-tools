// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.UnpackedProject;
import com.littlespidy.jssourcemapexplorer.model.UnpackedSourceFile;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Exports reconstructed project source trees to local disk directories for offline VS Code analysis.
 *
 * @author littlespidy
 */
public class ProjectDiskExporter {

    public record ExportResult(
        boolean success,
        int filesExported,
        String destinationPath,
        String errorMessage
    ) {}

    public static ExportResult exportProject(UnpackedProject project, File targetDirectory) {
        if (project == null || project.getFilesByPath().isEmpty()) {
            return new ExportResult(false, 0, null, "No files available in project to export.");
        }

        if (targetDirectory == null) {
            return new ExportResult(false, 0, null, "No destination directory specified.");
        }

        if (!targetDirectory.exists() && !targetDirectory.mkdirs()) {
            return new ExportResult(false, 0, null, "Failed to create destination directory: " + targetDirectory.getAbsolutePath());
        }

        int exportedCount = 0;

        try {
            for (UnpackedSourceFile file : project.getFilesByPath().values()) {
                String cleanRelPath = file.relativePath();
                File destFile = new File(targetDirectory, cleanRelPath);

                File parentDir = destFile.getParentFile();
                if (parentDir != null && !parentDir.exists()) {
                    parentDir.mkdirs();
                }

                try (FileOutputStream fos = new FileOutputStream(destFile)) {
                    fos.write(file.content().getBytes(StandardCharsets.UTF_8));
                    exportedCount++;
                }
            }

            return new ExportResult(true, exportedCount, targetDirectory.getAbsolutePath(), null);

        } catch (Exception ex) {
            return new ExportResult(false, exportedCount, targetDirectory.getAbsolutePath(), ex.getMessage());
        }
    }
}
