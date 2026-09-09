// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import com.littlespidy.jwtcomparator.model.JWTTokenModel;
import com.littlespidy.jwtcomparator.model.TokenSessionManager;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * Container holding dynamic N token cards rendered as vertical columns from left to right.
 * Provides controls for adding/removing slots, token naming, clearing, and JSON session export/import.
 */
public class TokenSlotsContainer extends JPanel implements TokenCardPanel.TokenCardListener {

    public interface SlotsChangeListener {
        void onSlotsChanged();
        default void onIgnoredClaimsImported(List<String> ignoredClaims) {}
        default java.util.Set<String> getIgnoredClaimsForExport() { return java.util.Collections.emptySet(); }
    }

    private final List<TokenCardPanel> cards = new ArrayList<>();
    private final JPanel cardsGridPanel;
    private final SlotsChangeListener listener;
    private boolean initializing = true;

    public TokenSlotsContainer(SlotsChangeListener listener) {
        this.listener = listener;

        setLayout(new BorderLayout(0, 4));

        // Top Toolbar
        JPanel topBar = new JPanel(new BorderLayout(8, 4));
        topBar.setBorder(BorderFactory.createEmptyBorder(3, 6, 5, 6));

        JPanel leftActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));

        JButton addSlotBtn = new JButton("➕ Add Another Token Slot");
        addSlotBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        addSlotBtn.setToolTipText("Add another vertical token column for side-by-side comparison");
        addSlotBtn.addActionListener(e -> addTokenSlot(null, null));

        JButton clearAllBtn = new JButton("🧹 Clear All Tokens");
        clearAllBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        clearAllBtn.setToolTipText("Clear JWT inputs across all token columns");
        clearAllBtn.addActionListener(e -> clearAll());

        JButton exportJsonBtn = new JButton("💾 Export JSON");
        exportJsonBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        exportJsonBtn.setToolTipText("Save token slots, names, and inputs to a JSON file");
        exportJsonBtn.addActionListener(e -> exportJsonSession());

        JButton importJsonBtn = new JButton("📂 Import JSON");
        importJsonBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        importJsonBtn.setToolTipText("Load tokens and slot names from a saved JSON file");
        importJsonBtn.addActionListener(e -> importJsonSession());

        leftActions.add(addSlotBtn);
        leftActions.add(clearAllBtn);
        leftActions.add(new JSeparator(JSeparator.VERTICAL));
        leftActions.add(exportJsonBtn);
        leftActions.add(importJsonBtn);

        JLabel layoutHintLabel = new JLabel("Columns 1..N: Left to Right | Edit Name to rename matrix headers");
        layoutHintLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        layoutHintLabel.setForeground(Color.GRAY);

        topBar.add(leftActions, BorderLayout.WEST);
        topBar.add(layoutHintLabel, BorderLayout.EAST);
        add(topBar, BorderLayout.NORTH);

        // Horizontal Cards Container (Columns Left to Right)
        cardsGridPanel = new JPanel();
        cardsGridPanel.setLayout(new BoxLayout(cardsGridPanel, BoxLayout.X_AXIS));
        cardsGridPanel.setBorder(BorderFactory.createEmptyBorder(4, 6, 6, 6));

        JScrollPane cardsScroll = new JScrollPane(cardsGridPanel);
        cardsScroll.setBorder(BorderFactory.createEmptyBorder());
        cardsScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        cardsScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);

        add(cardsScroll, BorderLayout.CENTER);

        // Initialize with 2 default token slots
        addTokenSlot(null, "Domain A");
        addTokenSlot(null, "Domain B");
        initializing = false;
    }

    public synchronized TokenCardPanel addTokenSlot(String token, String label) {
        int nextIndex = cards.size() + 1;
        String defaultLabel = (label != null && !label.trim().isEmpty()) ?
                label.trim() : "Token " + nextIndex;

        JWTTokenModel model = new JWTTokenModel(nextIndex, defaultLabel);
        TokenCardPanel card = new TokenCardPanel(model, this);

        if (token != null && !token.trim().isEmpty()) {
            card.setTokenWithLabel(token, defaultLabel);
        }

        cards.add(card);
        rebuildCardsPanel();

        if (listener != null && !initializing) {
            listener.onSlotsChanged();
        }

        return card;
    }

    private synchronized void updateRemoveButtons() {
        boolean canRemove = cards.size() > 2;
        for (TokenCardPanel card : cards) {
            card.setRemoveEnabled(canRemove);
        }
    }

    @Override
    public void onTokenChanged(TokenCardPanel card) {
        if (listener != null) {
            listener.onSlotsChanged();
        }
    }

    @Override
    public synchronized void onRemoveRequested(TokenCardPanel card) {
        if (cards.size() <= 2) {
            JOptionPane.showMessageDialog(this,
                    "At least 2 tokens are required for comparison.",
                    "Cannot Remove Slot", JOptionPane.WARNING_MESSAGE);
            return;
        }

        cards.remove(card);
        rebuildCardsPanel();

        if (listener != null) {
            listener.onSlotsChanged();
        }
    }

    private void rebuildCardsPanel() {
        cardsGridPanel.removeAll();
        for (int i = 0; i < cards.size(); i++) {
            TokenCardPanel card = cards.get(i);
            card.getModel().setSlotIndex(i + 1);
            card.updateSlotIndexHeader();
            if (i > 0) {
                cardsGridPanel.add(Box.createHorizontalStrut(10));
            }
            cardsGridPanel.add(card);
        }
        cardsGridPanel.add(Box.createHorizontalGlue());
        updateRemoveButtons();
        revalidate();
        repaint();
    }

    public synchronized void clearAll() {
        for (TokenCardPanel card : cards) {
            card.clearToken();
        }
        if (listener != null) {
            listener.onSlotsChanged();
        }
    }

    public synchronized void exportJsonSession() {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }

        List<JWTTokenModel> tokens = getTokens();
        java.util.Set<String> ignoredClaims = (listener != null) ? listener.getIgnoredClaimsForExport() : java.util.Collections.emptySet();

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Tokens Configuration as JSON");
        chooser.setSelectedFile(new File("jwt-tokens.json"));
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Files (*.json)", "json"));

        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            if (!file.getName().toLowerCase().endsWith(".json")) {
                file = new File(file.getAbsolutePath() + ".json");
            }
            try {
                String json = TokenSessionManager.exportToJson(tokens, ignoredClaims);
                Files.writeString(file.toPath(), json, StandardCharsets.UTF_8);
                JOptionPane.showMessageDialog(this,
                        "Successfully exported " + tokens.size() + " tokens to:\n" + file.getAbsolutePath(),
                        "Tokens Exported", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Error writing JSON file: " + ex.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public synchronized void importJsonSession() {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Tokens from JSON");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Files (*.json)", "json"));

        int res = chooser.showOpenDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try {
                String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
                TokenSessionManager.SessionData sessionData = TokenSessionManager.importSessionFromJson(content);
                List<TokenSessionManager.ExportedToken> imported = sessionData.getTokens();
                if (imported.isEmpty()) {
                    JOptionPane.showMessageDialog(this,
                            "No valid tokens found in the selected JSON file.",
                            "Import Notice", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                int confirm = JOptionPane.showConfirmDialog(this,
                        "Importing " + imported.size() + " tokens will replace current slots. Continue?",
                        "Confirm Import", JOptionPane.YES_NO_OPTION);
                if (confirm != JOptionPane.YES_OPTION) {
                    return;
                }

                importTokens(imported);
                if (listener != null && !sessionData.getIgnoredClaims().isEmpty()) {
                    listener.onIgnoredClaimsImported(sessionData.getIgnoredClaims());
                }

                JOptionPane.showMessageDialog(this,
                        "Successfully imported " + imported.size() + " tokens from:\n" + file.getName(),
                        "Tokens Imported", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Error importing JSON file: " + ex.getMessage(),
                        "Import Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public synchronized void importTokens(List<TokenSessionManager.ExportedToken> importedTokens) {
        if (importedTokens == null || importedTokens.isEmpty()) {
            return;
        }

        cards.clear();
        for (int i = 0; i < importedTokens.size(); i++) {
            TokenSessionManager.ExportedToken et = importedTokens.get(i);
            int slot = i + 1;
            String name = (et.getName() != null && !et.getName().trim().isEmpty()) ?
                    et.getName().trim() : "Token " + slot;
            JWTTokenModel model = new JWTTokenModel(slot, name);
            TokenCardPanel card = new TokenCardPanel(model, this);
            if (et.getRawToken() != null && !et.getRawToken().trim().isEmpty()) {
                card.setTokenWithLabel(et.getRawToken().trim(), name);
            }
            cards.add(card);
        }

        while (cards.size() < 2) {
            int nextIndex = cards.size() + 1;
            String defaultLabel = "Domain " + (char) ('A' + (nextIndex - 1));
            JWTTokenModel model = new JWTTokenModel(nextIndex, defaultLabel);
            TokenCardPanel card = new TokenCardPanel(model, this);
            cards.add(card);
        }

        rebuildCardsPanel();

        if (listener != null) {
            listener.onSlotsChanged();
        }
    }

    public synchronized List<JWTTokenModel> getTokens() {
        List<JWTTokenModel> list = new ArrayList<>();
        for (TokenCardPanel card : cards) {
            list.add(card.getModel());
        }
        return list;
    }

    public synchronized int getSlotCount() {
        return cards.size();
    }

    public synchronized TokenCardPanel getCardAt(int index) {
        if (index >= 0 && index < cards.size()) {
            return cards.get(index);
        }
        return null;
    }

    public synchronized void loadIntoSlot(int slotIndex, String token, String label) {
        if (slotIndex >= 1 && slotIndex <= cards.size()) {
            TokenCardPanel card = cards.get(slotIndex - 1);
            card.setTokenWithLabel(token, label);
        } else {
            addTokenSlot(token, label);
        }
    }
}
