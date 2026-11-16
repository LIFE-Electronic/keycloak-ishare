package org.keycloak.protocol.oidc.endpoints;

import java.util.List;
import java.util.Map;

import org.junit.Test;

import static org.junit.Assert.*;

public class ISHARECapabilitiesEndpointTest {
    @Test
    @SuppressWarnings("unchecked")
    public void publishesV3ServicesWithTheirActualEndpoints() {
        Map<String, Object> capabilities = ISHARECapabilitiesEndpoint.createCapabilities(
                "http://idp/token", "http://idp/auth", "http://idp/userinfo", "http://idp/capabilities");
        List<Map<String, Object>> services = (List<Map<String, Object>>) capabilities.get("publicServices");
        assertEquals(4, services.size());
        assertFalse(capabilities.containsKey("supported_versions"));
        for (Map<String, Object> service : services) {
            assertEquals("active", service.get("status"));
            Map<String, Object> version = (Map<String, Object>) service.get("version");
            assertEquals(List.of("3.0"), version.get("compliesWithFrameworkVersions"));
            assertFalse(service.containsKey("url"));
        }
        assertEquals("http://idp/auth", services.get(1).get("endpointURL"));
        assertEquals("http://idp/token", services.get(2).get("tokenEndpoint"));
        assertEquals("http://idp/capabilities", services.get(3).get("endpointURL"));
        assertFalse(services.get(3).containsKey("tokenEndpoint"));
    }
}
