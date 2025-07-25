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

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.authenticators.client.ISHAREClientAuthenticator;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.common.Profile;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.crypto.Algorithm;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.ishare.ISHARE;
import org.keycloak.locale.LocaleSelectorProvider;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequestParserProcessor;
import org.keycloak.protocol.oidc.utils.AcrUtils;
import org.keycloak.protocol.oidc.grants.device.endpoints.DeviceEndpoint;
import org.keycloak.protocol.oidc.utils.OIDCRedirectUriBuilder;
import org.keycloak.protocol.oidc.utils.OIDCResponseMode;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.Urls;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.AuthorizationRequestContext;
import org.keycloak.services.clientpolicy.context.PreAuthorizationRequestContext;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.util.CacheControlUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.TokenUtil;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class AuthorizationEndpoint extends AuthorizationEndpointBase {

    private static final Logger logger = Logger.getLogger(AuthorizationEndpoint.class);

    public static final String CODE_AUTH_TYPE = "code";

    /**
     * Prefix used to store additional HTTP GET params from original client request into {@link AuthenticationSessionModel} note to be available later in Authenticators, RequiredActions etc. Prefix is used to
     * prevent collisions with internally used notes.
     *
     * @see AuthenticationSessionModel#getClientNote(String)
     */
    public static final String LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX = "client_request_param_";

    private enum Action {
        REGISTER, CODE, FORGOT_CREDENTIALS
    }

    private ClientModel client;
    private AuthenticationSessionModel authenticationSession;

    private Action action;
    private OIDCResponseType parsedResponseType;
    private OIDCResponseMode parsedResponseMode;

    private AuthorizationEndpointRequest request;
    private String redirectUri;

    public AuthorizationEndpoint(KeycloakSession session, EventBuilder event) {
        super(session, event);
        event.event(EventType.LOGIN);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response buildPost() {
        logger.trace("Processing @POST request");
        return process(httpRequest.getDecodedFormParameters());
    }

    @GET
    public Response buildGet() {
        logger.trace("Processing @GET request");
        return process(session.getContext().getUri().getQueryParameters());
    }

    /**
     * OAuth 2.0 Device Authorization endpoint
     */
    @Path("device")
    public Object authorizeDevice() {
        if (!Profile.isFeatureEnabled(Profile.Feature.DEVICE_FLOW)) {
            return null;
        }
        return new DeviceEndpoint(session, event);
    }

    private Response process(final MultivaluedMap<String, String> params) {
        String clientId = AuthorizationEndpointRequestParserProcessor.getClientId(event, session, params);

        checkSsl();
        checkRealm();

        try {
            session.clientPolicy().triggerOnEvent(new PreAuthorizationRequestContext(clientId, params));
        } catch (ClientPolicyException cpe) {
            throw new ErrorPageException(session, authenticationSession, cpe.getErrorStatus(), cpe.getErrorDetail());
        }

        boolean ishareRequest = AuthorizationEndpointRequestParserProcessor.hasScope(event, session, params, "ishare") ||
                                AuthorizationEndpointRequestParserProcessor.hasScope(event, session, params, "iSHARE");;

        if (ishareRequest && clientId != null) {
            // create client dynamically
            ISHARE iSHARE = new ISHARE(session);

            String requestParam = params.getFirst(OIDCLoginProtocol.REQUEST_PARAM);
            if (requestParam == null) {
                throw new RuntimeException("Request Param required with iSHARE flow");
            }
                    
            if (iSHARE.isProbablyJwe(requestParam)) {
                logger.debug("Got encrypted JWE");
                if (!iSHARE.decryptAndVerifyClientTokenAndParty(realm.getIssuer(), clientId, requestParam)) {
                    throw new RuntimeException("Error validating decrypted jwt claims");
                }
            }
            else {
                logger.debug("Got raw JWT");
                if (!iSHARE.verifyClientTokenAndParty(realm.getIssuer(), clientId, requestParam)) {
                    throw new RuntimeException("Error validating jwt claims");
                }
            }
            logger.infof("Client '%s' verified at iSHARE", clientId);

            client = realm.getClientByClientId(clientId);
            if (client == null) {
                logger.infof("Client '%s', exists on iSHARE and is active but does not exist on Keycloak. Auto create it!", clientId);

                client = realm.addClient(clientId);
                client.setClientId(clientId);

                Set<String> redirectUris = new HashSet<>();
                redirectUris.add("*");
                client.setRedirectUris(redirectUris);

                client.setBaseUrl("");
                client.setRootUrl("");
                client.setBearerOnly(false);
                client.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
                client.setClientAuthenticatorType(ISHAREClientAuthenticator.PROVIDER_ID);
                client.setConsentRequired(true);
                client.setAlwaysDisplayInConsole(false);

                OIDCAdvancedConfigWrapper oidc = OIDCAdvancedConfigWrapper.fromClientModel(client);
                oidc.setUseRefreshToken(false);
                oidc.setUserInfoSignedResponseAlg(Algorithm.RS256);
                List<String> acr_values = new LinkedList();
                acr_values.add("urn:http://eidas.europa.eu/LoA/NotNotified/substantial");
                oidc.setAttributeMultivalued(Constants.DEFAULT_ACR_VALUES, acr_values);

                client.setManagementUrl("");
                client.setPublicClient(false);
                client.setName("[iSHARE] " + clientId);
                client.setDescription("iSHARE client added via dynamic client discovery.");

                client.setFullScopeAllowed(true);
                client.setFrontchannelLogout(true);
                client.setEnabled(true);

                client.setDirectAccessGrantsEnabled(false);
                client.setStandardFlowEnabled(true);
                client.setImplicitFlowEnabled(false);
                client.setServiceAccountsEnabled(false);
                client.setSurrogateAuthRequired(false);

                
            
                client.updateClient();

                client = realm.getClientByClientId(clientId);
                
                logger.infof("Client '%s' created. ID: %s", clientId, client.getId());
            }
        }
        checkClient(clientId);

        request = AuthorizationEndpointRequestParserProcessor.parseRequest(event, session, client, params, AuthorizationEndpointRequestParserProcessor.EndpointType.OIDC_AUTH_ENDPOINT);

        AuthorizationEndpointChecker checker = new AuthorizationEndpointChecker()
                .event(event)
                .client(client)
                .realm(realm)
                .request(request)
                .session(session)
                .params(params);

        try {
            checker.checkRedirectUri();
            this.redirectUri = checker.getRedirectUri();
        } catch (AuthorizationEndpointChecker.AuthorizationCheckException ex) {
            ex.throwAsErrorPageException(authenticationSession);
        }

        try {
            checker.checkResponseType();
            this.parsedResponseType = checker.getParsedResponseType();
            this.parsedResponseMode = checker.getParsedResponseMode();
        } catch (AuthorizationEndpointChecker.AuthorizationCheckException ex) {
            OIDCResponseMode responseMode = null;
            if (checker.isInvalidResponseType(ex)) {
                responseMode = OIDCResponseMode.parseWhenInvalidResponseType(request.getResponseMode());
            } else {
                responseMode = checker.getParsedResponseMode() != null ? checker.getParsedResponseMode() : OIDCResponseMode.QUERY;
            }
            return redirectErrorToClient(responseMode, ex.getError(), ex.getErrorDescription());
        }
        if (action == null) {
            action = AuthorizationEndpoint.Action.CODE;
        }

        try {
            checker.checkParRequired();
            checker.checkInvalidRequestMessage();
            checker.checkOIDCRequest();
            checker.checkValidScope();
            checker.checkOIDCParams();
            checker.checkPKCEParams();
        } catch (AuthorizationEndpointChecker.AuthorizationCheckException ex) {
            return redirectErrorToClient(parsedResponseMode, ex.getError(), ex.getErrorDescription());
        }

        try {
            session.clientPolicy().triggerOnEvent(new AuthorizationRequestContext(parsedResponseType, request, redirectUri, params));
        } catch (ClientPolicyException cpe) {
            return redirectErrorToClient(parsedResponseMode, cpe.getError(), cpe.getErrorDetail());
        }

        authenticationSession = createAuthenticationSession(client, request.getState());
        updateAuthenticationSession();

        // So back button doesn't work
        CacheControlUtil.noBackButtonCacheControlHeader(session);
        switch (action) {
            case REGISTER:
                return buildRegister();
            case FORGOT_CREDENTIALS:
                return buildForgotCredential();
            case CODE:
                return buildAuthorizationCodeAuthorizationResponse(ishareRequest);
        }

        throw new RuntimeException("Unknown action " + action);
    }
 
    public AuthorizationEndpoint register() {
        event.event(EventType.REGISTER);
        action = Action.REGISTER;

        if (!realm.isRegistrationAllowed()) {
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.REGISTRATION_NOT_ALLOWED);
        }

        return this;
    }

    public AuthorizationEndpoint forgotCredentials() {
        event.event(EventType.RESET_PASSWORD);
        action = Action.FORGOT_CREDENTIALS;

        if (!realm.isResetPasswordAllowed()) {
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.RESET_CREDENTIAL_NOT_ALLOWED);
        }

        return this;
    }

    private void checkClient(String clientId) {
        if (clientId == null) {
            event.error(Errors.INVALID_REQUEST);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.MISSING_PARAMETER, OIDCLoginProtocol.CLIENT_ID_PARAM);
        }

        event.client(clientId);

        client = realm.getClientByClientId(clientId);
        if (client == null) {
            event.error(Errors.CLIENT_NOT_FOUND);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.CLIENT_NOT_FOUND);
        }

        if (!client.isEnabled()) {
            event.error(Errors.CLIENT_DISABLED);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.CLIENT_DISABLED);
        }

        if (client.isBearerOnly()) {
            event.error(Errors.NOT_ALLOWED);
            throw new ErrorPageException(session, authenticationSession, Response.Status.FORBIDDEN, Messages.BEARER_ONLY);
        }

        String protocol = client.getProtocol();
        if (protocol == null) {
            logger.warnf("Client '%s' doesn't have protocol set. Fallback to openid-connect. Please fix client configuration", clientId);
            protocol = OIDCLoginProtocol.LOGIN_PROTOCOL;
        }
        if (!protocol.equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            event.error(Errors.INVALID_CLIENT);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, "Wrong client protocol.");
        }

        session.getContext().setClient(client);
    }

    private Response redirectErrorToClient(OIDCResponseMode responseMode, String error, String errorDescription) {
        OIDCRedirectUriBuilder errorResponseBuilder = OIDCRedirectUriBuilder.fromUri(redirectUri, responseMode, session, null)
                .addParam(OAuth2Constants.ERROR, error);

        if (errorDescription != null) {
            errorResponseBuilder.addParam(OAuth2Constants.ERROR_DESCRIPTION, errorDescription);
        }

        if (request.getState() != null) {
            errorResponseBuilder.addParam(OAuth2Constants.STATE, request.getState());
        }

        OIDCAdvancedConfigWrapper clientConfig = OIDCAdvancedConfigWrapper.fromClientModel(client);
        if (!clientConfig.isExcludeIssuerFromAuthResponse()) {
            errorResponseBuilder.addParam(OAuth2Constants.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        }

        return errorResponseBuilder.build();
    }

    private void updateAuthenticationSession() {
        authenticationSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authenticationSession.setRedirectUri(redirectUri);
        authenticationSession.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());
        authenticationSession.setClientNote(OIDCLoginProtocol.RESPONSE_TYPE_PARAM, request.getResponseType());
        authenticationSession.setClientNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, request.getRedirectUriParam());
        //authenticationSession.setClientNote(OIDCLoginProtocol.ISSUER, "BLABLABLA");
        authenticationSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));

        performActionOnParameters(request, (paramName, paramValue) -> {if (paramValue != null) authenticationSession.setClientNote(paramName, paramValue);});
        if (request.getMaxAge() != null) authenticationSession.setClientNote(OIDCLoginProtocol.MAX_AGE_PARAM, String.valueOf(request.getMaxAge()));
        if (request.getUiLocales() != null) authenticationSession.setClientNote(LocaleSelectorProvider.CLIENT_REQUEST_LOCALE, request.getUiLocales());

        Map<String, Integer> acrLoaMap = AcrUtils.getAcrLoaMap(authenticationSession.getClient());
        List<String> acrValues = AcrUtils.getRequiredAcrValues(request.getClaims());

        if (acrValues.isEmpty()) {
            acrValues = AcrUtils.getAcrValues(request.getClaims(), request.getAcr(), authenticationSession.getClient());
        } else {
            authenticationSession.setClientNote(Constants.FORCE_LEVEL_OF_AUTHENTICATION, "true");
        }

        acrValues.stream().mapToInt(acr -> {
            try {
                Integer loa = acrLoaMap.get(acr);
                return loa == null ? Integer.parseInt(acr) : loa;
            } catch (NumberFormatException e) {
                // this is an unknown acr. In case of an essential claim, we directly reject authentication as we cannot met the specification requirement. Otherwise fallback to minimum LoA
                boolean essential = Boolean.parseBoolean(authenticationSession.getClientNote(Constants.FORCE_LEVEL_OF_AUTHENTICATION));
                if (essential) {
                    logger.errorf("Requested essential acr value '%s' is not a number and it is not mapped in the ACR-To-Loa mappings of realm or client. Please doublecheck ACR-to-LOA mapping or correct ACR passed in the 'claims' parameter.", acr);
                    event.error(Errors.INVALID_REQUEST);
                    throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.INVALID_PARAMETER, OIDCLoginProtocol.CLAIMS_PARAM);
                } else {
                    logger.warnf("Requested acr value '%s' is not a number and it is not mapped in the ACR-To-Loa mappings of realm or client. Please doublecheck ACR-to-LOA mapping or correct used ACR.", acr);
                    return Constants.MINIMUM_LOA;
                }
            }
        }).min().ifPresent(loa -> {
            authenticationSession.setClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION, String.valueOf(loa));
        });

        if (request.getAdditionalReqParams() != null) {
            for (String paramName : request.getAdditionalReqParams().keySet()) {
                authenticationSession.setClientNote(LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + paramName, request.getAdditionalReqParams().get(paramName));
            }
        }
    }

    private Response buildAuthorizationCodeAuthorizationResponse(boolean is_ishare_request) {
        this.event.event(EventType.LOGIN);
        authenticationSession.setAuthNote(Details.AUTH_TYPE, CODE_AUTH_TYPE);

        OIDCLoginProtocol oidc = new OIDCLoginProtocol(session, realm, session.getContext().getUri(), headers, event);
        boolean is_passive = TokenUtil.hasPrompt(request.getPrompt(), OIDCLoginProtocol.PROMPT_VALUE_NONE);
        boolean redirect_to_authentication = is_ishare_request; // iSHARE requires a redirect instead of a 200 OK
        return handleBrowserAuthenticationRequest(authenticationSession, oidc, is_passive, redirect_to_authentication);
    }

    private Response buildRegister() {
        authManager.expireIdentityCookie(session);

        AuthenticationFlowModel flow = realm.getRegistrationFlow();
        String flowId = flow.getId();

        AuthenticationProcessor processor = createProcessor(authenticationSession, flowId, LoginActionsService.REGISTRATION_PATH);
        authenticationSession.setClientNote(APP_INITIATED_FLOW, LoginActionsService.REGISTRATION_PATH);

        return processor.authenticate();
    }

    private Response buildForgotCredential() {
        authManager.expireIdentityCookie(session);

        AuthenticationFlowModel flow = realm.getResetCredentialsFlow();
        String flowId = flow.getId();

        AuthenticationProcessor processor = createProcessor(authenticationSession, flowId, LoginActionsService.RESET_CREDENTIALS_PATH);
        authenticationSession.setClientNote(APP_INITIATED_FLOW, LoginActionsService.RESET_CREDENTIALS_PATH);

        return processor.authenticate();
    }

    public static void performActionOnParameters(AuthorizationEndpointRequest request, BiConsumer<String, String> paramAction) {
        paramAction.accept(AdapterConstants.KC_IDP_HINT, request.getIdpHint());
        paramAction.accept(Constants.KC_ACTION, request.getAction());
        paramAction.accept(OAuth2Constants.DISPLAY, request.getDisplay());
        paramAction.accept(OIDCLoginProtocol.ACR_PARAM, request.getAcr());
        paramAction.accept(OIDCLoginProtocol.CLAIMS_PARAM, request.getClaims());
        paramAction.accept(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM, request.getCodeChallengeMethod());
        paramAction.accept(OIDCLoginProtocol.CODE_CHALLENGE_PARAM, request.getCodeChallenge());
        paramAction.accept(OIDCLoginProtocol.LOGIN_HINT_PARAM, request.getLoginHint());
        paramAction.accept(OIDCLoginProtocol.NONCE_PARAM, request.getNonce());
        paramAction.accept(OIDCLoginProtocol.PROMPT_PARAM, request.getPrompt());
        paramAction.accept(OIDCLoginProtocol.RESPONSE_MODE_PARAM, request.getResponseMode());
        paramAction.accept(OIDCLoginProtocol.SCOPE_PARAM, request.getScope());
        paramAction.accept(OIDCLoginProtocol.STATE_PARAM, request.getState());
    }
}
