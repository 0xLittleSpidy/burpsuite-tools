// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import com.littlespidy.jwtcomparator.model.JWTTokenModel;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Container holding dynamic N token cards with add/remove controls.
 */
public class TokenSlotsContainer extends JPanel implements TokenCardPanel.TokenCardListener {

    public interface SlotsChangeListener {
        void onSlotsChanged();
    }

    private final List<TokenCardPanel> cards = new ArrayList<>();
    private final JPanel cardsGridPanel;
    private final SlotsChangeListener listener;
    private boolean initializing = true;

    public TokenSlotsContainer(SlotsChangeListener listener) {
        this.listener = listener;

        setLayout(new BorderLayout(8, 8));

        // Cards grid panel
        cardsGridPanel = new JPanel();
        cardsGridPanel.setLayout(new BoxLayout(cardsGridPanel, BoxLayout.Y_AXIS));

        add(cardsGridPanel, BorderLayout.CENTER);

        // Add Token Button Bar
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton addSlotBtn = new JButton("➕ Add Another Token Slot");
        addSlotBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        addSlotBtn.setToolTipText("Add Token " + (cards.size() + 1) + " for comparison");
        addSlotBtn.addActionListener(e -> addTokenSlot(null, null));

        JButton clearAllBtn = new JButton("🧹 Clear All Tokens");
        clearAllBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        clearAllBtn.addActionListener(e -> clearAll());

        bottomBar.add(addSlotBtn);
        bottomBar.add(clearAllBtn);
        add(bottomBar, BorderLayout.SOUTH);

        // Initialize with 2 default token slots
        addTokenSlot(null, "Domain A");
        addTokenSlot(null, "Domain B");
        initializing = false;
    }

    public synchronized TokenCardPanel addTokenSlot(String token, String label) {
        int nextIndex = cards.size() + 1;
        String defaultLabel = (label != null && !label.trim().isEmpty()) ? label.trim() : "Token " + nextIndex;

        JWTTokenModel model = new JWTTokenModel(nextIndex, defaultLabel);
        TokenCardPanel card = new TokenCardPanel(model, this);

        if (token != null && !token.trim().isEmpty()) {
            card.setTokenWithLabel(token, defaultLabel);
        }

        cards.add(card);
        cardsGridPanel.add(card);
        cardsGridPanel.add(Box.createVerticalStrut(6));

        updateRemoveButtons();
        revalidate();
        repaint();

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
            cardsGridPanel.add(card);
            cardsGridPanel.add(Box.createVerticalStrut(6));
        }
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
