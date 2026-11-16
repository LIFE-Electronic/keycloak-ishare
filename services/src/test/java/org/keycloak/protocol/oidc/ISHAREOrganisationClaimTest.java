package org.keycloak.protocol.oidc;

import java.lang.reflect.Proxy;
import java.util.stream.Stream;

import org.junit.Test;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import static org.junit.Assert.*;

public class ISHAREOrganisationClaimTest {
    private final TokenManager manager = new TokenManager();
    private final KeycloakSession session = (KeycloakSession) Proxy.newProxyInstance(
            getClass().getClassLoader(), new Class<?>[]{KeycloakSession.class}, (proxy, method, args) -> null);

    private ClientSessionContext context(String scope) {
        return (ClientSessionContext) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{ClientSessionContext.class}, (proxy, method, args) -> {
                    if (method.getName().equals("getScopeString")) return scope;
                    if (method.getName().equals("getProtocolMappersStream")) return Stream.empty();
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private UserSessionModel userSession(String companyId) {
        UserModel user = (UserModel) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{UserModel.class}, (proxy, method, args) -> {
                    assertEquals("getFirstAttribute", method.getName());
                    assertEquals("companyId", args[0]);
                    return companyId;
                });
        return (UserSessionModel) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{UserSessionModel.class}, (proxy, method, args) -> user);
    }

    @Test
    public void mapsExistingCompanyIdIntoBothTokensForIshareScopes() {
        for (String scope : new String[]{"openid iSHARE", "openid ishare"}) {
            IDToken id = manager.transformIDToken(session, new IDToken(), userSession("NTRNL-12345678"), context(scope));
            AccessToken info = manager.transformUserInfoAccessToken(session, new AccessToken(), userSession("NTRNL-12345678"), context(scope));
            assertEquals("NTRNL-12345678", id.getOtherClaims().get("organisationIdentifier"));
            assertEquals("NTRNL-12345678", info.getOtherClaims().get("organisationIdentifier"));
        }
    }

    @Test
    public void retainsExplicitlyMappedOrganisation() {
        IDToken id = new IDToken();
        AccessToken info = new AccessToken();
        id.getOtherClaims().put("organisationIdentifier", "VATBE-123456789");
        info.getOtherClaims().put("organisationIdentifier", "VATBE-123456789");
        manager.transformIDToken(session, id, userSession("NTRNL-12345678"), context("openid iSHARE"));
        manager.transformUserInfoAccessToken(session, info, userSession("NTRNL-12345678"), context("openid iSHARE"));
        assertEquals("VATBE-123456789", id.getOtherClaims().get("organisationIdentifier"));
        assertEquals("VATBE-123456789", info.getOtherClaims().get("organisationIdentifier"));
    }

    @Test
    public void ordinaryOidcDoesNotRequireOrExposeCompanyId() {
        IDToken id = manager.transformIDToken(session, new IDToken(), userSession(null), context("openid profile"));
        AccessToken info = manager.transformUserInfoAccessToken(session, new AccessToken(), userSession(null), context("openid profile"));
        assertFalse(id.getOtherClaims().containsKey("organisationIdentifier"));
        assertFalse(info.getOtherClaims().containsKey("organisationIdentifier"));
    }

    @Test
    public void rejectsMissingOrMalformedOrganisationInBothTokens() {
        for (String companyId : new String[]{null, "", "NL.EORI.TEST", "NTRNL-has space"}) {
            assertThrows(IllegalStateException.class, () -> manager.transformIDToken(
                    session, new IDToken(), userSession(companyId), context("openid iSHARE")));
            assertThrows(IllegalStateException.class, () -> manager.transformUserInfoAccessToken(
                    session, new AccessToken(), userSession(companyId), context("openid iSHARE")));
        }
    }
}
