package cc.coopersoft.keycloak.phone.providers.rest;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.util.JsonSerialization;

import cc.coopersoft.keycloak.phone.Utils;
import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.representations.TokenCodeRepresentation;
import cc.coopersoft.keycloak.phone.providers.spi.PhoneVerificationCodeProvider;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;

public class RegistrationResource extends TokenCodeResource {

  private final AuthResult auth;

  RegistrationResource(KeycloakSession session) {
    super(session, TokenCodeType.REGISTRATION);
    this.auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
  }

  private PhoneVerificationCodeProvider getTokenCodeService() {
    return session.getProvider(PhoneVerificationCodeProvider.class);
  }
  
  @POST
  @NoCache
  @Path("")
  @Produces(APPLICATION_JSON)
  @Consumes(APPLICATION_JSON)
  public Response registrationWithCode(InputStream requestBody) { // (MultivaluedMap<String, String> regitrationData) {
    RealmModel realm = session.getContext().getRealm();

    Map<String, Object> regitrationData;
    try {
      regitrationData = JsonSerialization.readValue(requestBody, Map.class);
      if (auth == null)
        throw new NotAuthorizedException("Bearer");
      if (!regitrationData.containsKey("phoneNumber"))
        throw new BadRequestException("Must inform a phone number");
      if (!regitrationData.containsKey("code"))
        throw new BadRequestException("Must inform a token code");
      
      String username = regitrationData.get("phoneNumber").toString();
      TokenCodeRepresentation tokenCode = getTokenCodeService().ongoingProcess(username, TokenCodeType.REGISTRATION);

      if (!tokenCode.getCode().equals(regitrationData.get("code").toString()))
        throw new BadRequestException("Invalid token code");

      UserModel user = session.users().addUser(realm, username);
      user.setFirstName(regitrationData.get("firstName").toString());
      user.setLastName(regitrationData.get("lastName").toString());
      user.setEnabled(true);
      user.setSingleAttribute("phoneNumber", username);
      String response = String.format("{\"message\":\"User created\", \"id\":\"%s\"}", user.getId());
      return Response.ok(response, APPLICATION_JSON).build();
      
    } catch (IOException e) {
      throw new BadRequestException("Invalid JSON input");
    }
  }
}
