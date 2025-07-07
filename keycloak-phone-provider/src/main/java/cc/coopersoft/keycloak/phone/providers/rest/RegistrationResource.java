package cc.coopersoft.keycloak.phone.providers.rest;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.TokenManager.AccessTokenResponseBuilder;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.util.JsonSerialization;

import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.representations.TokenCodeRepresentation;
import cc.coopersoft.keycloak.phone.providers.spi.PhoneVerificationCodeProvider;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import jakarta.ws.rs.*;
import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;

public class RegistrationResource extends TokenCodeResource {

  RegistrationResource(KeycloakSession session) {
    super(session, TokenCodeType.REGISTRATION);
  }

  private PhoneVerificationCodeProvider getTokenCodeService() {
    return session.getProvider(PhoneVerificationCodeProvider.class);
  }
  
  @POST
  @NoCache
  @Path("")
  @Produces(APPLICATION_JSON)
  @Consumes(APPLICATION_JSON)
  public AccessTokenResponse registrationWithCode(InputStream requestBody) { // (MultivaluedMap<String, String> regitrationData) {
    RealmModel realm = session.getContext().getRealm();

    Map<String, Object> regitrationData;
    try {
      regitrationData = JsonSerialization.readValue(requestBody, Map.class);
      if (!regitrationData.containsKey("phoneNumber"))
        throw new BadRequestException("Must inform a phone number");
      if (!regitrationData.containsKey("code"))
        throw new BadRequestException("Must inform a token code");
      if (!regitrationData.containsKey("client_id"))
        throw new BadRequestException("Must inform a client id");  
      
      String username = regitrationData.get("phoneNumber").toString();
      TokenCodeRepresentation tokenCode = getTokenCodeService().ongoingProcess(username, TokenCodeType.REGISTRATION);

      if (!tokenCode.getCode().equals(regitrationData.get("code").toString()))
        throw new BadRequestException("Invalid token code");

      UserModel user = session.users().addUser(realm, username);
      user.setFirstName(regitrationData.get("firstName").toString());
      user.setLastName(regitrationData.get("lastName").toString());
      user.setEnabled(true);
      user.setSingleAttribute("phoneNumber", username);
      user.setEmail(String.format("%s@jrny.cn", username));
      user.setEmailVerified(true);

      user.setSingleAttribute("subscription_status", "NO_SUBSCRIPTION");
      
      if (regitrationData.containsKey("birthdate")) {
        user.setSingleAttribute("birthdate", regitrationData.get("birthdate").toString());
      } else {
        user.setSingleAttribute("birthdate", "1970-01-01");        
      }

      if (regitrationData.containsKey("gender"))
        user.setSingleAttribute("gender", regitrationData.get("gender").toString());
      if (regitrationData.containsKey("locale"))
        user.setSingleAttribute("locale", regitrationData.get("locale").toString());
      if (regitrationData.containsKey("height"))
        user.setSingleAttribute("height", regitrationData.get("height").toString());
      if (regitrationData.containsKey("weight"))
        user.setSingleAttribute("weight", regitrationData.get("weight").toString());

      ClientModel client = realm.getClientByClientId(regitrationData.get("client_id").toString());
      if (client == null)
        throw new BadRequestException("Client not found");
      session.getContext().setClient(client); 
      // 建立 user session
      @SuppressWarnings("deprecation")
      UserSessionModel userSession = session.sessions().createUserSession(
          realm,
          user,
          user.getUsername(),
          "127.0.0.1", // IP
          OIDCLoginProtocol.LOGIN_PROTOCOL,
          false,
          null,
          null
      );

      // 建立 client session
      
      AuthenticatedClientSessionModel clientSession = session.sessions()
          .createClientSession(realm, client, userSession);

      // 設定必要參數（模擬 OIDC login request）
      clientSession.setAction("AUTHENTICATE");
      clientSession.setRedirectUri("http://localhost"); // dummy URI
      clientSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
      clientSession.setNote(OIDCLoginProtocol.SCOPE_PARAM, "openid profile email");

      // 建立 ClientSessionContext
      ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionScopeParameter(clientSession, session); // .createClientSessionContext(clientSession);

      // 使用 TokenManager 建立完整 token response（包含 access、refresh、id token）
      TokenManager tokenManager = new TokenManager();
      EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());
      AccessTokenResponseBuilder builder = tokenManager.responseBuilder(realm, client, event, session, userSession, clientSessionCtx);
      builder.generateAccessToken();
      builder.generateIDToken();
      builder.generateRefreshToken();
      return builder.build();

    } catch (IOException e) {
      throw new BadRequestException("Invalid JSON input");
    }
  }
}
