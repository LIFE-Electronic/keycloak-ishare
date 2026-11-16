/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.protocol.oidc.endpoints;

import org.jboss.resteasy.reactive.NoCache;
import org.keycloak.http.HttpRequest;
import org.keycloak.TokenCategory;
import org.keycloak.common.ClientConnection;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCWellKnownProviderFactory;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.services.Urls;
import org.keycloak.services.cors.Cors;
import org.keycloak.utils.MediaType;
import org.keycloak.utils.OAuth2Error;
import org.keycloak.wellknown.WellKnownProvider;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.ResponseBuilder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * @author pedroigor
 */
public class ISHARECapabilitiesEndpoint {

    private final HttpRequest request;

    private final KeycloakSession session;

    private final ClientConnection clientConnection;

    private final RealmModel realm;
    private final OAuth2Error error;
    private Cors cors;

    public ISHARECapabilitiesEndpoint(KeycloakSession session, org.keycloak.protocol.oidc.TokenManager tokenManager) {
        this.session = session;
        this.clientConnection = session.getContext().getConnection();
        this.realm = session.getContext().getRealm();
        //this.tokenManager = tokenManager;
        //this.appAuthManager = new AppAuthManager();
        this.error = new OAuth2Error().json(false).realm(realm);
        this.request = session.getContext().getHttpRequest();
    }

    @Path("/")
    @OPTIONS
    public Response issueUserInfoPreflight() {
        return Cors.add(this.request, Response.ok()).auth().preflight().build();
    }

    @Path("/")
    @GET
    @NoCache
    @Produces({MediaType.APPLICATION_JSON})
    public Response issueUserInfoGet() {
        setupCors();
        return issueCapabilities();
    }

    private Response issueCapabilities() {
        cors.allowAllOrigins();

        EventBuilder event = new EventBuilder(realm, session, clientConnection)
                .event(EventType.USER_INFO_REQUEST)
                .detail(Details.AUTH_METHOD, Details.VALIDATE_ACCESS_TOKEN);

        WellKnownProvider oidcProvider = session.getProvider(WellKnownProvider.class, OIDCWellKnownProviderFactory.PROVIDER_ID);
        OIDCConfigurationRepresentation oidcConfig = OIDCConfigurationRepresentation.class.cast(oidcProvider.getConfig());

        String issuer;
        if (realm.getIssuer().isEmpty()) {
            issuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        } else {
            issuer = realm.getIssuer();
        }

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", issuer);
        claims.put("aud", "public");
        claims.put("jti", UUID.randomUUID().toString());
        
        Instant now = Instant.now();
        claims.put("iat", now.getEpochSecond());
        claims.put("nbf", now.getEpochSecond());
        claims.put("exp", Date.from(now.plus(30L, ChronoUnit.SECONDS)).getTime() / 1000);

        // create own token category?
        String signatureAlgorithm = session.tokens().signatureAlgorithm(TokenCategory.USERINFO);

        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signatureAlgorithm);
        SignatureSignerContext signer = signatureProvider.signer();

        JWSBuilder jwsBuilder = new JWSBuilder();

        List<String> certs = signer.getCertificateChain();
        if (certs.size() > 0) {
            jwsBuilder = jwsBuilder.x5c(certs);
        } else {
            String cert = signer.getCertificate();
            if (cert != null) {
                certs.add(cert);
                jwsBuilder = jwsBuilder.x5c(certs);
            }
        }

        String userinfoEP = oidcConfig.getUserinfoEndpoint();
        String tokenEP = oidcConfig.getTokenEndpoint();
        String authEP = oidcConfig.getAuthorizationEndpoint();
        String capEP = userinfoEP.replace("userinfo", "capabilities");

        claims.put("capabilitiesInfo", createCapabilities(tokenEP, authEP, userinfoEP, capEP));

        String signedCapabilitiesInfo = jwsBuilder.type("JWT").jsonContent(claims).sign(signer);

        //ResponseBuilder responseBuilder = Response.ok(signedCapabilitiesInfo).header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JWT);
        
        Map<String, Object> capResponse = new HashMap<>();
        capResponse.put("capabilitiesToken", signedCapabilitiesInfo);
        //capResponse.put("version", "ishare-25.0.0");

        ResponseBuilder responseBuilder = Response.ok(capResponse).header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);

        event.success();

        return cors.builder(responseBuilder).build();
    }

    static Map<String, Object> createCapabilities(String tokenEP, String authEP, String userinfoEP, String capEP) {
        List<Object> services = new LinkedList<>();
        services.add(createService("request-oauth-token", "OIDC iSHARE Access Token",
                "Call to get access token for code", tokenEP, null, "POST"));
        services.add(createService("authorize", "OIDC iSHARE Authorization",
                "Initiates iSHARE OIDC Flow", authEP, null, "GET", "POST"));
        services.add(createService("get-user-info", "OIDC iSHARE User Info",
                "Obtains user info", userinfoEP, tokenEP, "GET", "POST"));
        services.add(createService("get-capabilities-token", "capabilities",
                "Retrieves iSHARE capabilities", capEP, null, "GET"));
        return Map.of("publicServices", services);
    }

    private static Map<String, Object> createService(String id, String name, String desc, String url,
            String tokenEndpoint, String... methods) {
        Map<String, Object> service = new HashMap<>();
        service.put("identifier", id);
        service.put("title", name);
        service.put("description", desc);
        service.put("endpointURL", url);
        service.put("status", "active");
        service.put("serviceType", "framework-defined");
        service.put("version", Map.of("compliesWithFrameworkVersions", List.of("3.0"),
                "capabilityVersion", "1.0"));
        service.put("methods", List.of(methods));
        if (tokenEndpoint != null) {
            service.put("tokenEndpoint", tokenEndpoint);
        }
        return service;
    }

    private void setupCors() {
        cors = Cors.add(request).auth().allowedMethods(request.getHttpMethod()).auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);
        error.cors(cors);
    }
}
