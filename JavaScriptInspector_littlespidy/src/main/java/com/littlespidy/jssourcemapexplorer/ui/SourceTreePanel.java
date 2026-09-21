// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import com.littlespidy.jssourcemapexplorer.model.UnpackedProject;
import com.littlespidy.jssourcemapexplorer.model.UnpackedSourceFile;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;

/**
 * Interactive JTree panel representing the reconstructed folder hierarchy of unpacked source files.
 *
 * @author littlespidy
 */
public class SourceTreePanel extends JPanel {

    private final DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode("Root");
    private final DefaultTreeModel treeModel = new DefaultTreeModel(rootNode);
    private final JTree fileTree = new JTree(treeModel);
    private final JTextField searchField = new JTextField(15);
    private final JLabel countLabel = new JLabel("Files: 0");

    private UnpackedProject currentProject;
    private final Consumer<UnpackedSourceFile> fileSelectionListener;

    public SourceTreePanel(Consumer<UnpackedSourceFile> fileSelectionListener) {
        this.fileSelectionListener = fileSelectionListener;
        setLayout(new BorderLayout(5, 5));

        // ── Top Search Bar ──
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));
        topPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JPanel searchBox = new JPanel(new BorderLayout(4, 0));
        searchBox.add(new JLabel("Search: "), BorderLayout.WEST);
        searchBox.add(searchField, BorderLayout.CENTER);

        JButton clearBtn = new JButton("Clear");
        clearBtn.setMargin(new Insets(1, 4, 1, 4));
        clearBtn.addActionListener(e -> {
            searchField.setText("");
            rebuildTree(searchField.getText().trim());
        });
        searchBox.add(clearBtn, BorderLayout.EAST);

        topPanel.add(searchBox, BorderLayout.NORTH);
        topPanel.add(countLabel, BorderLayout.SOUTH);

        searchField.addActionListener(e -> rebuildTree(searchField.getText().trim()));

        // ── JTree Setup ──
        fileTree.setRootVisible(true);
        fileTree.setShowsRootHandles(true);
        setupTreeRenderer();

        fileTree.addTreeSelectionListener(e -> {
            TreePath path = e.getPath();
            if (path != null) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
                if (node.getUserObject() instanceof FileNodeData fileData) {
                    if (this.fileSelectionListener != null) {
                        this.fileSelectionListener.accept(fileData.sourceFile());
                    }
                }
            }
        });

        add(topPanel, BorderLayout.NORTH);
        add(new JScrollPane(fileTree), BorderLayout.CENTER);
    }

    public void setProject(UnpackedProject project) {
        this.currentProject = project;
        searchField.setText("");
        rebuildTree("");
        if (project == null || project.getFilesByPath().isEmpty()) {
            if (this.fileSelectionListener != null) {
                this.fileSelectionListener.accept(null);
            }
        }
    }

    private void rebuildTree(String filter) {
        rootNode.removeAllChildren();

        if (currentProject == null || currentProject.getFilesByPath().isEmpty()) {
            rootNode.setUserObject("0 files in reconstructed source tree");
            countLabel.setText("Files: 0");
            treeModel.reload();
            return;
        }

        rootNode.setUserObject("Project (" + currentProject.getTotalFiles() + " files)");
        Map<String, DefaultMutableTreeNode> dirNodes = new HashMap<>();

        int matchedCount = 0;
        String lowerFilter = filter.toLowerCase();

        List<String> sortedPaths = new ArrayList<>(currentProject.getFilesByPath().keySet());
        Collections.sort(sortedPaths);

        for (String filePath : sortedPaths) {
            if (!filter.isEmpty() && !filePath.toLowerCase().contains(lowerFilter)) {
                continue;
            }

            matchedCount++;
            UnpackedSourceFile file = currentProject.getFile(filePath);
            String[] segments = filePath.split("/");

            DefaultMutableTreeNode currentParent = rootNode;
            StringBuilder pathBuilder = new StringBuilder();

            for (int i = 0; i < segments.length - 1; i++) {
                String segment = segments[i];
                if (segment.isEmpty()) continue;

                if (pathBuilder.length() > 0) pathBuilder.append("/");
                pathBuilder.append(segment);
                String currentDirPath = pathBuilder.toString();

                DefaultMutableTreeNode dirNode = dirNodes.get(currentDirPath);
                if (dirNode == null) {
                    dirNode = new DefaultMutableTreeNode(segment);
                    currentParent.add(dirNode);
                    dirNodes.put(currentDirPath, dirNode);
                }
                currentParent = dirNode;
            }

            String fileName = segments[segments.length - 1];
            DefaultMutableTreeNode fileNode = new DefaultMutableTreeNode(new FileNodeData(fileName, file));
            currentParent.add(fileNode);
        }

        countLabel.setText("Files: " + matchedCount + (filter.isEmpty() ? "" : " (filtered)"));
        treeModel.reload();

        // Expand root by default
        fileTree.expandRow(0);
    }

    private void setupTreeRenderer() {
        DefaultTreeCellRenderer renderer = new DefaultTreeCellRenderer();
        renderer.setLeafIcon(UIManager.getIcon("FileView.fileIcon"));
        renderer.setClosedIcon(UIManager.getIcon("Tree.closedIcon"));
        renderer.setOpenIcon(UIManager.getIcon("Tree.openIcon"));
        fileTree.setCellRenderer(renderer);
    }

    private record FileNodeData(String displayName, UnpackedSourceFile sourceFile) {
        @Override
        public String toString() {
            int secretsCount = sourceFile.secrets() != null ? sourceFile.secrets().size() : 0;
            int endpointsCount = sourceFile.endpoints() != null ? sourceFile.endpoints().size() : 0;
            if (secretsCount > 0) {
                return displayName + " 🔑 [" + secretsCount + "]";
            }
            if (endpointsCount > 0) {
                return displayName + " 🌐 [" + endpointsCount + "]";
            }
            return displayName;
        }
    }
}
