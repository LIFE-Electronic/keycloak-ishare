package org.keycloak.ishare;

import java.util.Arrays;

import org.junit.Test;
import org.keycloak.util.JsonSerialization;

import static org.junit.Assert.*;

public class ISHARETest {
    private ISHAREPartyInfo party(String claims) throws Exception {
        return JsonSerialization.readValue("{\"id\":\"client\",\"name\":\"Client\",\"claims\":["
                + claims + "]}", ISHAREPartyInfo.class);
    }

    private String activeClaims() {
        return "{\"type\":\"frameworkCompliance\",\"status\":\"active\"},"
                + "{\"type\":\"x509Certificate\",\"x5c\":\"certificate\"}";
    }

    @Test
    public void acceptsV3PartyAndCertificateClaims() throws Exception {
        assertTrue(ISHAREPartyValidation.validate(party(activeClaims()), "client", "certificate", null));
        ISHARESatellitePartiesResponse response = JsonSerialization.readValue(
                "{\"partyToken\":\"signed-token\"}", ISHARESatellitePartiesResponse.class);
        assertEquals("signed-token", response.party_token);
        ISHAREPartyToken token = JsonSerialization.readValue(
                "{\"partyInfo\":{\"id\":\"client\",\"claims\":[]}}", ISHAREPartyToken.class);
        assertEquals("client", token.party_info.party_id);
    }

    @Test
    public void rejectsMissingInactiveOrMismatchedParty() throws Exception {
        assertFalse(ISHAREPartyValidation.validate(null, "client", "certificate", null));
        assertFalse(ISHAREPartyValidation.validate(party(""), "client", "certificate", null));
        assertFalse(ISHAREPartyValidation.validate(party(activeClaims()), "other", "certificate", null));
        assertFalse(ISHAREPartyValidation.validate(party(activeClaims()), "client", "other", null));
        assertFalse(ISHAREPartyValidation.validate(party(activeClaims().replace("active", "inactive")),
                "client", "certificate", null));
        assertFalse(ISHAREPartyValidation.validate(JsonSerialization.readValue("{}", ISHAREPartyInfo.class),
                "client", "certificate", null));
    }

    @Test
    public void membershipAndAgreementsMustBelongToSameAllowedDataspace() throws Exception {
        ISHAREAllowedDataspaces allowed = new ISHAREAllowedDataspaces();
        allowed.dataspaceIds = Arrays.asList("space", "other");
        allowed.requiredAgreementTypes = Arrays.asList("TermsOfUse");
        String membership = ",{\"type\":\"dataspaceMembership\",\"status\":\"active\",\"dataspaceId\":\"space\"}";
        String agreement = ",{\"type\":\"dataspaceAgreement\",\"agreementType\":\"TermsOfUse\",\"dataspaceId\":\"space\"}";
        assertFalse(ISHAREPartyValidation.validate(party(activeClaims()), "client", "certificate", allowed));
        assertFalse(ISHAREPartyValidation.validate(party(activeClaims() + membership), "client", "certificate", allowed));
        assertFalse(ISHAREPartyValidation.validate(party(activeClaims() + membership + agreement.replace("space\"", "other\"")),
                "client", "certificate", allowed));
        assertTrue(ISHAREPartyValidation.validate(party(activeClaims() + membership + agreement),
                "client", "certificate", allowed));
        assertFalse(ISHAREPartyValidation.validate(party(activeClaims() + membership.replace("active", "inactive") + agreement),
                "client", "certificate", allowed));
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
