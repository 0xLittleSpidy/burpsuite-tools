// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.persistence;

import javax.swing.*;
import java.awt.*;

public class SessionStartupDialog_littlespidy {
    public static boolean promptToRestore(Component parent, int sessionCount) {
        String message = "Discovered " + sessionCount + " saved GraphQL Cop session(s) from a previous run.\n" +
                "Would you like to restore them or start with a clean workspace?";
        String[] options = {"Restore Sessions", "Start Fresh"};

        int choice = JOptionPane.showOptionDialog(
                parent,
                message,
                "Restore GraphQL Cop Sessions",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]
        );
        return choice == JOptionPane.YES_OPTION;
    }
}
