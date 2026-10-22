// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.service;

import java.awt.GraphicsEnvironment;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;

/**
 * Service to copy text to system clipboard.
 */
public class ClipboardService_littlespidy {

    /**
     * Copies the given text string to the system clipboard.
     *
     * @param content text to copy
     * @return true if copied successfully, false otherwise
     */
    public boolean copyToClipboard(String content) {
        if (content == null) {
            content = "";
        }

        if (GraphicsEnvironment.isHeadless()) {
            return false;
        }

        try {
            StringSelection selection = new StringSelection(content);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, selection);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
