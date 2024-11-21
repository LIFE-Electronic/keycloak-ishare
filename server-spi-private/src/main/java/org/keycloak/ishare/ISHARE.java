package org.keycloak.ishare;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import org.keycloak.util.JsonSerialization;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.models.KeycloakSession;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;

import org.jboss.logging.Logger;

import java.util.*;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.net.URL;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.io.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@JsonIgnoreProperties(ignoreUnknown = true)
class ISHAREAuthenticatorConfig implements Serializable {
    @JsonProperty(value="satellite-id", required=true)
    public String satelliteId;

    @JsonProperty(value="satellite-url", required=true)
    public String satelliteUrl;

    @JsonProperty(value="ishare-ca-file", required=true)
    public String ishareCaFile;
}

class ISHAREJWSHeader extends JWSHeader
{
    @JsonProperty("x5c")
    private String[] x5c;

    public String[] getX5C() {
        return x5c;
    }
}

class ISHARESatellitePartiesResponse implements Serializable {
    @JsonProperty("party_token")
    public String party_token;
}

class ISHARESatelliteResponse implements Serializable {
    @JsonProperty("status")
    public String status;

    @JsonProperty("message")
    public String message;

    @JsonProperty("access_token")
    public String access_token;

    @JsonProperty("token_type")
    public String token_type;

    @JsonProperty("expires_in")
    public int expires_in;

    public ISHARESatelliteResponse() {}
}

class ISHAREPartyToken extends JsonWebToken {
    @JsonProperty("party_info")
    public ISHAREPartyInfo party_info;
}

@JsonIgnoreProperties(ignoreUnknown = true)
class Adherence implements Serializable
{
    @JsonProperty("status")
    public String status;
}

@JsonIgnoreProperties(ignoreUnknown = true)
class ISHAREPartyInfo implements Serializable {
    @JsonProperty("party_id")
    public String party_id;

    @JsonProperty("registrar_id")
    public String registrar_id;

    @JsonProperty("adherence")
    public Adherence adherence;

    @JsonProperty("certificates")
    public List<ISHARECertificateInfo> certificates;
}

@JsonIgnoreProperties(ignoreUnknown = true)
class ISHARECertificateInfo implements Serializable {
    @JsonProperty("subject_name")
    public String subject_name;

    @JsonProperty("certificate_type")
    public String certificate_type;

    @JsonProperty("x5c")
    public String x5c;
}

public class ISHARE {

    private static final Logger logger = Logger.getLogger(ISHARE.class);

    String iSHARESatellitePartyId;
    String iSHARESatelliteBaseUrl;
    X509Certificate iSHARE_CA;
    KeycloakSession session;

    public ISHARE(KeycloakSession session) throws RuntimeException {
        if (!init()) {
            throw new RuntimeException("Error initializing iSHARE");
        }
        this.session = session;
    }

    protected boolean init() {
        // TO-DO: If someone can figure out how we can use Config.Scope here,
        // please leave an Issue on Github. For now, we slurp a config json.
        try {
            String keycloakHome = System.getenv("KEYCLOAK_HOME");
            
            String configFilePath = (keycloakHome != null ? keycloakHome : ".") + "/conf/ishare.json";
            logger.infof("use ishare config %s", configFilePath);
            
            String configFileContent = getFileContent(new FileInputStream(configFilePath), "utf-8");

            ISHAREAuthenticatorConfig cfg = JsonSerialization.readValue(configFileContent, ISHAREAuthenticatorConfig.class);

            iSHARESatellitePartyId = cfg.satelliteId;
            iSHARESatelliteBaseUrl = cfg.satelliteUrl;

            FileInputStream inStream = new FileInputStream(cfg.ishareCaFile);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            iSHARE_CA = (X509Certificate) cf.generateCertificate(inStream);
        } catch (Exception e) {
            logger.errorf("Exception during init %s", e.toString());
            return false;
        }

        logger.info("ISHAREAuthenticator init done");
        return true;
    }

    private String getFileContent(FileInputStream fis, String encoding ) throws IOException
    {
        try (BufferedReader br = new BufferedReader( new InputStreamReader(fis, encoding )))
            {
                StringBuilder sb = new StringBuilder();
                String line;
                while(( line = br.readLine()) != null ) {
                    sb.append( line );
                    sb.append( '\n' );
                }
                return sb.toString();
            }
    }

    public boolean verifyClientToken(String idpEORI, String incoming_token)
    {
        try {
            JWSInput jws = new JWSInput(incoming_token);
            if (!validateJwtCert(jws)) {
                return false;
            }

            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
            if (!validateJwtToken(token, idpEORI)) {
                return false;
            }

            return true;
        } catch (Exception e) {
            logger.errorf("Exception validating client_assertion: %s", e.toString());
        }        

        return true;
    }

    public boolean verifyClientTokenAndParty(String idpEORI, String clientId, String incoming_token)
    {
        try {
            JWSInput jws = new JWSInput(incoming_token);
            if (!validateJwtCert(jws)) {
                return false;
            }

            String[] x5c = getX5C(jws);

            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
            if (!validateJwtToken(token, idpEORI)) {
                return false;
            }

            String our_client_assertion = createSatelliteClientAssertion(idpEORI, this.session);
            
            return verifyClientAtSatellite(clientId, x5c[0], idpEORI, our_client_assertion);
        } catch (Exception e) {
            logger.errorf("Exception validating client_assertion: %s", e.toString());
        }        
        return false;
    }

    private String getParamsString(Map<String, String> params) throws java.io.UnsupportedEncodingException {
        StringBuilder result = new StringBuilder();

        for (Map.Entry<String, String> entry : params.entrySet()) {
          result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
          result.append("=");
          result.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
          result.append("&");
        }

        String resultString = result.toString();
        return resultString.length() > 0
          ? resultString.substring(0, resultString.length() - 1)
          : resultString;
    }

    private String createSatelliteClientAssertion(String idpEORI, KeycloakSession session)
    {
        Instant now = Instant.now();

        JWSBuilder jwsBuilder = new JWSBuilder();

        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, "RS256");
        SignatureSignerContext signer = signatureProvider.signer();

        Map<String, Object> claims = new HashMap<String, Object>();
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iss", idpEORI);
        claims.put("sub", idpEORI);
        claims.put("aud", iSHARESatellitePartyId);
        claims.put("iat", now.getEpochSecond());
        claims.put("nbf", now.getEpochSecond());
        claims.put("exp", Date.from(now.plus(30L, ChronoUnit.SECONDS)).getTime() / 1000);
        
    
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

        String client_assertion = jwsBuilder
            .type("JWT")
            .x5c(certs)
            .jsonContent(claims)
            .sign(signer);

        return client_assertion;
    }

    private String readBody(HttpURLConnection connection) throws Exception
    {
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuffer content = new StringBuffer();
        while ((inputLine = reader.readLine()) != null) {
            content.append(inputLine);
        }
        reader.close();
        return content.toString();
    }
    
    private String getAccessTokenFromSatellite(String idpEORI, String client_assertion) throws Exception
    {
        String tokenURL = iSHARESatelliteBaseUrl.concat("/connect/token");

        URL url = new URL(tokenURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");        
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setRequestProperty("Accept", "application/json");
        
        Map<String, String> parameters = new HashMap<>();
        parameters.put("grant_type", "client_credentials");
        parameters.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        parameters.put("client_assertion", client_assertion);
        parameters.put("scope", "iSHARE");
        parameters.put("client_id", idpEORI);

        connection.setDoOutput(true);
        DataOutputStream out = new DataOutputStream(connection.getOutputStream());
        out.writeBytes(getParamsString(parameters));
        out.flush();
        out.close();

        int status = connection.getResponseCode();
        logger.tracef("Satellite response status: %d", status);

        if (status == 200) {
            /* on success: 200 OK with { access_token, token_type, expires_in } */
            /* on missing client_assertion: 200 OK with { status: false, message } */
            String body = readBody(connection);

            ISHARESatelliteResponse resp = JsonSerialization.readValue(body, ISHARESatelliteResponse.class);
            if (resp.access_token == null || resp.access_token.isEmpty()) {
                // no access token means error
                logger.errorf("Couldn't obtain token from Satellite: %s", resp.message != null ? resp.message : "unknown error");
                return null;
            }
            logger.tracef("got access token: %s", resp.access_token);
            return resp.access_token;
        } else {
            logger.errorf("Satellite returned error. Statuscode: %d", status);
            return null;
        }
    }

    private boolean verifyClientAtSatellite(String clientId, String clientCert, String idpEORI, String client_assertion) throws Exception
    {
        String access_token = getAccessTokenFromSatellite(idpEORI, client_assertion);
        if (access_token == null) {
            return false;
        }

        //String tokenURL = iSHARESatelliteBaseUrl.concat(new String("/parties/").concat(callingPartyId));
        String tokenURL = iSHARESatelliteBaseUrl + "/parties/" + clientId;
        logger.tracef("call %s", tokenURL);

        URL url = new URL(tokenURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", "Bearer " + access_token);
        connection.setRequestProperty("Accept", "application/json");
        connection.connect();
        
        int status = connection.getResponseCode();
        if (status != 200) {
            logger.debugf("error getting parties: %d", status);
            return false;
        }

        String body = readBody(connection);

        ISHARESatellitePartiesResponse resp = JsonSerialization.readValue(body, ISHARESatellitePartiesResponse.class);

        if (!validatePartiesToken(resp.party_token, clientId, clientCert, idpEORI)) {
            logger.error("Error validating parties token");
            return false;
        }
        
        return true;
    }

    private boolean validatePartiesToken(String partiesToken, String clientId, String clientCert, String idpEORI) throws Exception
    {
        logger.tracef("validate parties token: %s", partiesToken);
        JWSInput jws = new JWSInput(partiesToken);
        if (!validateJwtCert(jws)) {
            logger.error("Invalid parties token cert");
            return false;
        }

        JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
        if (!validateJwtToken(token, idpEORI)) {
            logger.error("invalid parties token");
            return false;
        }

        byte[] contentBytes = Base64Url.decode(jws.getEncodedContent());

        logger.tracef("token content: %s", new String(contentBytes));
        
        ISHAREPartyToken partyInfoToken = JsonSerialization.readValue(contentBytes, ISHAREPartyToken.class);

        if (!partyInfoToken.party_info.party_id.equals(clientId)) {
            logger.errorf("invalid party_id in party token: %s. Should be: %s", partyInfoToken.party_info.party_id, clientId);
            return false;
        }

        if (!partyInfoToken.party_info.adherence.status.equals("Active")) {
            logger.error("party not active");
            return false;
        }

        List<ISHARECertificateInfo> storedCerts = partyInfoToken.party_info.certificates;
        boolean atLeastOneCert = storedCerts.stream().anyMatch(cert -> {
            return cert.x5c.equals(clientCert);
        });

        if (!atLeastOneCert) {
            logger.error("no matching certificate found in jwt");
            return false;
        }

        return atLeastOneCert;
    }

    public boolean validateJwtToken(JsonWebToken token, String idpEORI) throws Exception
    {
        if (!token.isActive()) {
            logger.error("token is not active anymore");
            return false; // skip for debugging
        }
            
        if (!token.hasAudience(idpEORI)) {
            logger.errorf("Invalid aud: %s. Should be: %s", token.audience(), idpEORI);
            return false;
        }

        return true;
    }
    
    private String[] getX5C(JWSInput jws) throws Exception
    {
        // unfortunately no way to get x5c otherwise
        String encodedHeader = jws.getEncodedHeader();
        byte[] headerBytes = Base64Url.decode(encodedHeader);

        ISHAREJWSHeader header = JsonSerialization.readValue(headerBytes, ISHAREJWSHeader.class);

        String[] x5c = header.getX5C();
        return x5c;
    }

    public boolean validateJwtCert(JWSInput jws) throws Exception
    {            
        String[] x5c = getX5C(jws);
        if (x5c.length == 0) {
            logger.error("x5c header value empty");
            return false;
        }
        logger.trace("--- certs ----");
        for (String s : x5c) {
            logger.tracef("x5c: %s", s);
        }
        logger.trace("----------------");

        X509Certificate cert = PemUtils.decodeCertificate(x5c[0]);

        // Note: This works only if iSHARE_CA has full chain to root.
            
        cert.verify(iSHARE_CA.getPublicKey());

        return true;
    }
}
