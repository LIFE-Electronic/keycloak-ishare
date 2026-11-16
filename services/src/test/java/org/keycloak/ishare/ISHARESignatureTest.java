package org.keycloak.ishare;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.rule.CryptoInitRule;

import static org.junit.Assert.*;

public class ISHARESignatureTest {
    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    private ISHARE ishare;
    private KeyPair key;
    private KeyPair otherKey;
    private String certificate;

    @Before
    public void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        key = generator.generateKeyPair();
        otherKey = generator.generateKeyPair();
        X509Certificate cert = CertificateUtils.generateV1SelfSignedCertificate(key, "test");
        certificate = Base64.getEncoder().encodeToString(cert.getEncoded());
        ishare = new ISHARE(null) {
            @Override
            protected boolean init() { return true; }
        };
        ishare.iSHARE_CA = cert;
    }

    private Map<String, Object> claims() {
        long now = Instant.now().getEpochSecond();
        return Map.of("iss", "client", "sub", "client", "aud", "idp", "iat", now, "exp", now + 30);
    }

    private String sign(Map<String, Object> claims, KeyPair signingKey, Algorithm algorithm) {
        return new JWSBuilder().type("JWT").x5c(List.of(certificate))
                .jsonContent(claims).sign(algorithm, signingKey.getPrivate());
    }

    private String tamper(String token, String payload) {
        String[] parts = token.split("\\.");
        return parts[0] + "." + Base64Url.encode(payload.getBytes(StandardCharsets.UTF_8)) + "." + parts[2];
    }

    @Test
    public void acceptsTrustedRs256Assertion() throws Exception {
        String token = sign(claims(), key, Algorithm.RS256);
        assertTrue(ishare.validateJwtCert(new JWSInput(token)));
        assertTrue(ishare.verifyClientToken("idp", token));
    }

    @Test
    public void rejectsCopiedCertificateSignedByAnotherKey() throws Exception {
        String token = sign(claims(), otherKey, Algorithm.RS256);
        assertFalse(ishare.validateJwtCert(new JWSInput(token)));
        assertFalse(ishare.verifyClientToken("idp", token));
    }

    @Test
    public void rejectsTamperedPayload() throws Exception {
        String token = tamper(sign(claims(), key, Algorithm.RS256), "{\"sub\":\"attacker\"}");
        assertFalse(ishare.validateJwtCert(new JWSInput(token)));
        assertFalse(ishare.verifyClientToken("idp", token));
    }

    @Test
    public void requiresRs256LikeIshareConnect() throws Exception {
        for (Algorithm algorithm : List.of(Algorithm.RS384, Algorithm.RS512)) {
            assertFalse(ishare.validateJwtCert(new JWSInput(sign(claims(), key, algorithm))));
        }
        String hmac = new JWSBuilder().type("JWT").x5c(List.of(certificate))
                .jsonContent(claims()).hmac256(new byte[32]);
        assertFalse(ishare.validateJwtCert(new JWSInput(hmac)));
    }

    @Test
    public void rejectsMissingCertificateAndUntrustedSigner() throws Exception {
        String missing = new JWSBuilder().type("JWT").jsonContent(claims()).rsa256(key.getPrivate());
        assertFalse(ishare.verifyClientToken("idp", missing));
        ishare.iSHARE_CA = CertificateUtils.generateV1SelfSignedCertificate(otherKey, "untrusted");
        assertFalse(ishare.verifyClientToken("idp", sign(claims(), key, Algorithm.RS256)));
    }

    @Test
    public void verifiesRegistryPartyTokenSignature() throws Exception {
        Map<String, Object> claims = new java.util.HashMap<>(claims());
        claims.put("partyInfo", Map.of("id", "client", "claims", List.of(
                Map.of("type", "frameworkCompliance", "status", "active"),
                Map.of("type", "x509Certificate", "x5c", certificate))));
        Method validate = ISHARE.class.getDeclaredMethod("validatePartiesToken",
                String.class, String.class, String.class, String.class);
        validate.setAccessible(true);
        assertTrue((boolean) validate.invoke(ishare, sign(claims, key, Algorithm.RS256),
                "client", certificate, "idp"));
        assertFalse((boolean) validate.invoke(ishare, sign(claims, otherKey, Algorithm.RS256),
                "client", certificate, "idp"));
    }
}
