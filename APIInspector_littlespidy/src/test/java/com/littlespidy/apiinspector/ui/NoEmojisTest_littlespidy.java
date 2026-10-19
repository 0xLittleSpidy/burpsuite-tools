// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit test ensuring strict compliance with the project emoji prohibition rule.
 * Asserts that zero unicode emojis or decorative symbols exist in src/main.
 */
class NoEmojisTest_littlespidy {

    @Test
    @DisplayName("Verify zero emojis in src/main source code")
    void verifyZeroEmojisInSrcMain() throws IOException {
        Path srcMain = Path.of("src/main");
        if (!Files.exists(srcMain)) {
            srcMain = Path.of(System.getProperty("user.dir"), "src/main");
        }

        assertTrue(Files.exists(srcMain), "src/main directory must exist");

        List<String> violations = new ArrayList<>();

        try (Stream<Path> paths = Files.walk(srcMain)) {
            paths.filter(p -> p.toString().endsWith(".java")).forEach(path -> {
                try {
                    List<String> lines = Files.readAllLines(path);
                    for (int i = 0; i < lines.size(); i++) {
                        String line = lines.get(i);
                        for (int j = 0; j < line.length(); j++) {
                            int codePoint = line.codePointAt(j);
                            if (isEmojiOrSymbol(codePoint)) {
                                violations.add(String.format("%s:%d [U+%04X] %s", path, i + 1, codePoint, line.trim()));
                                break;
                            }
                        }
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        }

        assertTrue(violations.isEmpty(), "Found emoji violations in src/main:\n" + String.join("\n", violations));
    }

    private boolean isEmojiOrSymbol(int codePoint) {
        if (codePoint < 128) return false;
        return (codePoint >= 0x1F300 && codePoint <= 0x1F9FF)
                || (codePoint >= 0x2600 && codePoint <= 0x26FF)
                || (codePoint >= 0x2700 && codePoint <= 0x27BF)
                || (codePoint >= 0x1F600 && codePoint <= 0x1F64F)
                || (codePoint >= 0x1F680 && codePoint <= 0x1F6FF)
                || codePoint == 0x2139 || codePoint == 0x231A || codePoint == 0x231B
                || codePoint == 0x23E9 || codePoint == 0x23EA || codePoint == 0x23EB
                || codePoint == 0x23EC || codePoint == 0x23F0 || codePoint == 0x23F3
                || codePoint == 0x25B6 || codePoint == 0x25C0 || codePoint == 0x2934
                || codePoint == 0x2935 || codePoint == 0x2B05 || codePoint == 0x2B06
                || codePoint == 0x2B07 || codePoint == 0x2B1B || codePoint == 0x2B1C
                || codePoint == 0x2B50 || codePoint == 0x2B55 || codePoint == 0x3030
                || codePoint == 0x303D || codePoint == 0x3297 || codePoint == 0x3299;
    }
}
