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

package org.keycloak.protocol.oidc.endpoints.request;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.Profile;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.par.endpoints.request.AuthzEndpointParParser;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.util.AuthorizationContextUtil;
import org.keycloak.util.TokenUtil;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.ishare.ISHARE;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Stream;
import java.util.Map;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthorizationEndpointRequestParserProcessor {

    private static final Logger logger = Logger.getLogger(AuthorizationEndpointRequestParserProcessor.class);

    public static AuthorizationEndpointRequest parseRequest(EventBuilder event, KeycloakSession session, ClientModel client, MultivaluedMap<String, String> requestParams, EndpointType endpointType) {
        try {

            // check if we have an iSHARE request
            boolean ishareRequest = AuthorizationEndpointRequestParserProcessor.hasScope(event, session, requestParams, "ishare") || 
                                    AuthorizationEndpointRequestParserProcessor.hasScope(event, session, requestParams, "iSHARE");;
            

            AuthorizationEndpointRequest request = new AuthorizationEndpointRequest();
            boolean isResponseTypeParameterRequired = isResponseTypeParameterRequired(requestParams, endpointType);
            AuthzEndpointQueryStringParser parser = new AuthzEndpointQueryStringParser(requestParams, isResponseTypeParameterRequired);
            parser.parseRequest(request);

            if (parser.getInvalidRequestMessage() != null) {
                request.invalidRequestMessage = parser.getInvalidRequestMessage();
            }
            if (request.getInvalidRequestMessage() != null) {
                return request;
            }

            String requestParam = requestParams.getFirst(OIDCLoginProtocol.REQUEST_PARAM);
            String requestUriParam = requestParams.getFirst(OIDCLoginProtocol.REQUEST_URI_PARAM);

            if (requestParam != null && requestUriParam != null) {
                throw new RuntimeException("Illegal to use both 'request' and 'request_uri' parameters together");
            }
            if (ishareRequest && requestParam == null) {
                throw new RuntimeException("Illegal to use 'ishare' scope without 'request' parameters");
            }

            String requestObjectRequired = OIDCAdvancedConfigWrapper.fromClientModel(client).getRequestObjectRequired();

            if (OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED_REQUEST_OR_REQUEST_URI.equals(requestObjectRequired)
                    && requestParam == null && requestUriParam == null) {
                throw new RuntimeException("Client is required to use 'request' or 'request_uri' parameter.");
            } else if (OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED_REQUEST.equals(requestObjectRequired)
                    && requestParam == null) {
                throw new RuntimeException("Client is required to use 'request' parameter.");
            } else if (OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED_REQUEST_URI.equals(requestObjectRequired)
                    && requestUriParam == null) {
                throw new RuntimeException("Client is required to use 'request_uri' parameter.");
            }

            if (!ishareRequest && requestParam != null) {
                new AuthzEndpointRequestObjectParser(session, requestParam, client).parseRequest(request);
            } else if (ishareRequest && requestParam != null) {

                ISHARE ishare = new ISHARE(session);

                Map<String, Object> claims = ishare.getClaimsFromClientAssertion(requestParam);
                Object redirectUri = claims.get("redirect_uri");
                if (redirectUri != null) {
                    request.redirectUriParam = redirectUri.toString();
                }
                Object nonce = claims.get("nonce");
                if (nonce != null) {
                    request.nonce = nonce.toString();
                }
                Object acr_values = claims.get("acr_values");
                if (acr_values != null) {
                    String[] acr_values_str = acr_values.toString().split(" ");
                    if (acr_values_str.length > 0 && !acr_values_str[0].isEmpty()) {
                        request.acr = acr_values_str[0];
                    }
                }
                
            } else if (requestUriParam != null) {
                // Define, if the request is `PAR` or usual `Request Object`.
                RequestUriType requestUriType = getRequestUriType(requestUriParam);
                if (requestUriType == RequestUriType.PAR) {
                    new AuthzEndpointParParser(session, client, requestUriParam).parseRequest(request);
                } else {
                    // Validate "requestUriParam" with allowed requestUris
                    List<String> requestUris = OIDCAdvancedConfigWrapper.fromClientModel(client).getRequestUris();
                    String requestUri = RedirectUtils.verifyRedirectUri(session, client.getRootUrl(), requestUriParam, new HashSet<>(requestUris), false);
                    if (requestUri == null) {
                        throw new RuntimeException("Specified 'request_uri' not allowed for this client.");
                    }
                    String retrievedRequest = session.getProvider(HttpClientProvider.class).getString(requestUri);
                    new AuthzEndpointRequestObjectParser(session, retrievedRequest, client).parseRequest(request);
                }
            }

            if (Profile.isFeatureEnabled(Profile.Feature.DYNAMIC_SCOPES)) {
                request.authorizationRequestContext = AuthorizationContextUtil.getAuthorizationRequestContextFromScopes(session, request.getScope());
            }

            return request;

        } catch (Exception e) {
            ServicesLogger.LOGGER.invalidRequest(e);
            event.error(Errors.INVALID_REQUEST);
            throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }
    }

    public static boolean hasScope(EventBuilder event, KeycloakSession session, MultivaluedMap<String, String> requestParams, String scope) {
        List<String> scopeParam = requestParams.get(OIDCLoginProtocol.SCOPE_PARAM);
        if (scopeParam != null && scopeParam.size() == 1) {
            String[] scopes = scopeParam.get(0).split(" ");
            return Stream.of(scopes).anyMatch(c -> {
                return c.toLowerCase().equals(scope);
            });
        } else {
            logger.warnf("Parameter 'scope' not present or present multiple times in the HTTP request parameters");
            event.error(Errors.INVALID_REQUEST);
            throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }
    }

    public static String getRequest(EventBuilder event, KeycloakSession session, MultivaluedMap<String, String> requestParams) {
        List<String> requestParam = requestParams.get(OIDCLoginProtocol.REQUEST_PARAM);
        if (requestParam != null && requestParam.size() == 1) {
            return requestParam.get(0);
        } else {
            logger.warnf("Parameter 'request' not present or present multiple times in the HTTP request parameters");
            event.error(Errors.INVALID_REQUEST);
            throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }
    }

    public static String getClientId(EventBuilder event, KeycloakSession session, MultivaluedMap<String, String> requestParams) {
        List<String> clientParam = requestParams.get(OIDCLoginProtocol.CLIENT_ID_PARAM);
        if (clientParam != null && clientParam.size() == 1) {
            return clientParam.get(0);
        } else {
            logger.warnf("Parameter 'client_id' not present or present multiple times in the HTTP request parameters");
            event.error(Errors.INVALID_REQUEST);
            throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }
    }

    public static RequestUriType getRequestUriType(String requestUri) {
        if (requestUri == null) {
            throw new RuntimeException("'request_uri' parameter is null");
        }

        return requestUri.toLowerCase().startsWith("urn:ietf:params:oauth:request_uri:")
                       ? RequestUriType.PAR
                       : RequestUriType.REQUEST_OBJECT;
    }


    // Parameter 'response_type' is mandatory parameter in the OIDC authentication endpoint request per OIDC Core specification.
    // The only exception when it is not mandatory is the case when request to authentication endpoint was sent after PAR request
    private static boolean isResponseTypeParameterRequired(MultivaluedMap<String, String> requestParams, EndpointType endpointType) {
        if (endpointType != EndpointType.OIDC_AUTH_ENDPOINT) return false;

        String scopeParam = requestParams.getFirst(OAuth2Constants.SCOPE);
        if (!TokenUtil.isOIDCRequest(scopeParam)) {
            return false;
        }

        String requestUriParam = requestParams.getFirst(OIDCLoginProtocol.REQUEST_URI_PARAM);
        if (requestUriParam != null && getRequestUriType(requestUriParam) == RequestUriType.PAR) {
            return false;
        }

        return true;
    }

    public enum EndpointType {
        OIDC_AUTH_ENDPOINT,
        OAUTH2_DEVICE_ENDPOINT,
        DOCKER_ENDPOINT
    }

}
