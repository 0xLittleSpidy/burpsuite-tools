// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop;

import com.littlespidy.graphqlcop.inql.PoiFinding_littlespidy;
import com.littlespidy.graphqlcop.inql.PoiScanner_littlespidy;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class PoiScannerTest_littlespidy {

    @Test
    public void testPoiClassification() {
        String mockSchema = "{\n" +
                "  \"data\": {\n" +
                "    \"__schema\": {\n" +
                "      \"types\": [\n" +
                "        {\n" +
                "          \"name\": \"User\",\n" +
                "          \"fields\": [\n" +
                "            { \"name\": \"id\", \"type\": { \"name\": \"ID\" } },\n" +
                "            { \"name\": \"passwordHash\", \"type\": { \"name\": \"String\" } },\n" +
                "            { \"name\": \"emailAddress\", \"type\": { \"name\": \"String\" } },\n" +
                "            { \"name\": \"creditCardNumber\", \"type\": { \"name\": \"String\" } },\n" +
                "            { \"name\": \"isAdmin\", \"type\": { \"name\": \"Boolean\" } }\n" +
                "          ]\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  }\n" +
                "}";

        List<PoiFinding_littlespidy> findings = PoiScanner_littlespidy.scanSchema(mockSchema);
        assertNotNull(findings);
        assertFalse(findings.isEmpty());

        boolean hasAuth = findings.stream().anyMatch(f -> "Auth".equalsIgnoreCase(f.getCategory()));
        boolean hasPii = findings.stream().anyMatch(f -> "PII".equalsIgnoreCase(f.getCategory()));
        boolean hasPayment = findings.stream().anyMatch(f -> "Payment".equalsIgnoreCase(f.getCategory()));
        boolean hasPrivileged = findings.stream().anyMatch(f -> "Privileged".equalsIgnoreCase(f.getCategory()));

        assertTrue(hasAuth, "Should identify Auth category for password");
        assertTrue(hasPii, "Should identify PII category for email");
        assertTrue(hasPayment, "Should identify Payment category for creditCard");
        assertTrue(hasPrivileged, "Should identify Privileged category for isAdmin");
    }
}
