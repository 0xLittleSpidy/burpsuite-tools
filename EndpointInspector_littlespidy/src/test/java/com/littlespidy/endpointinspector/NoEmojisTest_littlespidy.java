// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class NoEmojisTest_littlespidy {

    private static final Pattern EMOJI_PATTERN = Pattern.compile(
        "[\\x{1F600}-\\x{1F64F}\\x{1F300}-\\x{1F5FF}\\x{1F680}-\\x{1F6FF}\\x{2600}-\\x{26FF}\\x{2700}-\\x{27BF}]"
    );

    @Test
    @DisplayName("Verify strictly zero emojis exist in Endpoint Inspector codebase")
    void testNoEmojisInCodebase() throws IOException {
        Path rootDir = new File(".").toPath();
        try (Stream<Path> stream = Files.walk(rootDir)) {
            stream.filter(Files::isRegularFile)
                  .filter(p -> p.toString().endsWith(".java") || p.toString().endsWith(".md") || p.toString().endsWith(".html"))
                  .filter(p -> !p.toString().contains("/build/"))
                  .forEach(p -> {
                      try {
                          String content = Files.readString(p);
                          boolean hasEmoji = EMOJI_PATTERN.matcher(content).find();
                          assertFalse(hasEmoji, "File must not contain emojis: " + p);
                      } catch (IOException e) {
                          throw new RuntimeException(e);
                      }
                  });
        }
    }
}
