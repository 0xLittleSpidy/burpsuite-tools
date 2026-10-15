// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator;

import com.google.gson.JsonObject;
import com.littlespidy.jwtcomparator.model.JwtKeyOperations;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtKeyOperationsTest {
    private static final String CLAIMS = "{\"sub\":\"tester\",\"role\":\"user\"}";

    @Test void signsAndVerifiesEverySupportedAlgorithmFamily() throws Exception {
        for (String alg : List.of("HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA")) {
            String secret = alg.startsWith("HS") ? "unit-test-secret" : "";
            String privatePem = "", publicPem = "";
            if (!alg.startsWith("HS")) {
                KeyPair pair = JwtKeyOperations.generateKeyPair(alg);
                privatePem = JwtKeyOperations.toPem("PRIVATE KEY", pair.getPrivate().getEncoded());
                publicPem = JwtKeyOperations.toPem("PUBLIC KEY", pair.getPublic().getEncoded());
            }
            String token = JwtKeyOperations.create(CLAIMS, alg, secret, privatePem);
            assertTrue(JwtKeyOperations.verify(token, secret, publicPem), "valid signature for " + alg);
            assertFalse(JwtKeyOperations.verify(token + "x", secret, publicPem), "tampered signature rejected for " + alg);
        }
    }

    @Test void supportsBlankHmacAndJwksPublicKeyVerification() throws Exception {
        String blankSecretToken = JwtKeyOperations.create(CLAIMS, "HS256", "", "");
        assertTrue(JwtKeyOperations.verify(blankSecretToken, "", ""));

        for (String alg : List.of("RS256", "ES256", "EdDSA")) {
            KeyPair pair = JwtKeyOperations.generateKeyPair(alg);
            JsonObject jwk = JwtKeyOperations.toPublicJwk(pair.getPublic(), "test-key");
            String token = JwtKeyOperations.create(CLAIMS, alg, "", JwtKeyOperations.toPem("PRIVATE KEY", pair.getPrivate().getEncoded()));
            assertTrue(JwtKeyOperations.verifyWithPublicKey(token, JwtKeyOperations.jwkPublicKey(jwk)), "JWKS signature for " + alg);
        }
    }

    @Test void emitsAValidSelfSignedCertificateForGeneratedKeyPair() throws Exception {
        KeyPair pair = JwtKeyOperations.generateKeyPair("RS256");
        byte[] encoded = JwtKeyOperations.selfSignedCertificate(pair, "RS256");
        var certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encoded));
        certificate.verify(pair.getPublic());
    }
}
