package org.keycloak.ishare;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.rule.CryptoInitRule;

import static org.junit.Assert.*;

public class ISHARESignatureTest {
    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    @Test
    public void verifiesAllSpecifiedRsaAlgorithmsAndRejectsWrongSignatures() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair key = generator.generateKeyPair();
        KeyPair otherKey = generator.generateKeyPair();
        X509Certificate cert = CertificateUtils.generateV1SelfSignedCertificate(key, "test");
        String encodedCert = Base64.getEncoder().encodeToString(cert.getEncoded());
        ISHARE ishare = new ISHARE(null) {
            @Override
            protected boolean init() { return true; }
        };
        ishare.iSHARE_CA = cert;
        for (Algorithm algorithm : List.of(Algorithm.RS256, Algorithm.RS384, Algorithm.RS512)) {
            String valid = new JWSBuilder().type("JWT").x5c(List.of(encodedCert))
                    .jsonContent(Map.of("sub", "test")).sign(algorithm, key.getPrivate());
            assertTrue(algorithm.name(), ishare.validateJwtCert(new JWSInput(valid)));
            String invalid = new JWSBuilder().type("JWT").x5c(List.of(encodedCert))
                    .jsonContent(Map.of("sub", "test")).sign(algorithm, otherKey.getPrivate());
            assertFalse(algorithm.name(), ishare.validateJwtCert(new JWSInput(invalid)));
        }
        String hmac = new JWSBuilder().type("JWT").x5c(List.of(encodedCert))
                .jsonContent(Map.of("sub", "test")).hmac256(new byte[32]);
        assertFalse(ishare.validateJwtCert(new JWSInput(hmac)));
    }
}
