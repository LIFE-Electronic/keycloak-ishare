package org.keycloak.ishare;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.JsonWebToken;

import org.junit.Test;
import org.keycloak.util.JsonSerialization;

import static org.junit.Assert.*;

public class ISHARETest {
    private String party(String claims) {
        return "{\"id\":\"client\",\"claims\":[" + claims + "]}";
    }

    private boolean validate(String party, String clientId, String clientCert) throws Exception {
        ISHARE ishare = new ISHARE(null) {
            @Override
            protected boolean init() { return true; }
            @Override
            public boolean validateJwtCert(JWSInput jws) { return true; }
            @Override
            public boolean validateJwtToken(JsonWebToken token, String idpEORI) { return true; }
        };
        String payload = "{\"partyInfo\":" + party + "}";
        String jwt = Base64Url.encode("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8))
                + "." + Base64Url.encode(payload.getBytes(StandardCharsets.UTF_8)) + ".AA";
        Method method = ISHARE.class.getDeclaredMethod("validatePartiesToken",
                String.class, String.class, String.class, String.class);
        method.setAccessible(true);
        return (boolean) method.invoke(ishare, jwt, clientId, clientCert, "idp");
    }

    private String activeClaims() {
        return "{\"type\":\"frameworkCompliance\",\"status\":\"active\"},"
                + "{\"type\":\"x509Certificate\",\"x5c\":\"certificate\"}";
    }

    @Test
    public void acceptsV3PartyAndCertificateClaims() throws Exception {
        assertTrue(validate(party(activeClaims()), "client", "certificate"));
        ISHARESatellitePartiesResponse response = JsonSerialization.readValue(
                "{\"partyToken\":\"signed-token\"}", ISHARESatellitePartiesResponse.class);
        assertEquals("signed-token", response.party_token);
        ISHAREPartyToken token = JsonSerialization.readValue(
                "{\"partyInfo\":{\"id\":\"client\",\"claims\":[]}}", ISHAREPartyToken.class);
        assertEquals("client", token.party_info.party_id);
    }

    @Test
    public void rejectsMissingInactiveOrMismatchedParty() throws Exception {
        assertFalse(validate(null, "client", "certificate"));
        assertFalse(validate(party(""), "client", "certificate"));
        assertFalse(validate(party(activeClaims()), "other", "certificate"));
        assertFalse(validate(party(activeClaims()), "client", "other"));
        assertFalse(validate(party(activeClaims().replace("active", "inactive")),
                "client", "certificate"));
        assertFalse(validate("{}",
                "client", "certificate"));
    }

    @Test
    public void malformedAssertionFailsClosed() {
        ISHARE ishare = new ISHARE(null) {
            @Override
            protected boolean init() { return true; }
        };
        assertFalse(ishare.verifyClientToken("idp", "not-a-jwt"));
    }
}
