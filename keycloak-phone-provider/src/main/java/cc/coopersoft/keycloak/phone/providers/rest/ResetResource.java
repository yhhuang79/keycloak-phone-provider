package cc.coopersoft.keycloak.phone.providers.rest;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.CredentialRepresentation;
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

public class ResetResource extends TokenCodeResource {

  private final AuthResult auth;

  ResetResource(KeycloakSession session) {
    super(session, TokenCodeType.RESET);
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
  public Response resetWithCode(InputStream requestBody) {
    RealmModel realm = session.getContext().getRealm();

    Map<String, Object> resetData;
    try {
      resetData = JsonSerialization.readValue(requestBody, Map.class);
      if (auth == null)
        throw new NotAuthorizedException("Bearer");
      if (!resetData.containsKey("phoneNumber"))
        throw new BadRequestException("Must inform a phone number");
      if (!resetData.containsKey("code"))
        throw new BadRequestException("Must inform a token code");
      if (!resetData.containsKey("password"))
        throw new BadRequestException("Must inform a new password");
      if (!resetData.containsKey("email"))
        throw new BadRequestException("Must inform a email");
      
      String username = Utils.standardizePhoneNumber(session, resetData.get("phoneNumber").toString());
      TokenCodeRepresentation tokenCode = getTokenCodeService().ongoingProcess(username, TokenCodeType.RESET);

      if (!tokenCode.getCode().equals(resetData.get("code").toString()))
        throw new BadRequestException("Invalid token code");

      UserModel user = session.users().getUserByUsername(realm, username);
      if (user == null)
        throw new NotFoundException("User not found");
      
      String email = resetData.get("email").toString();
      if (!email.matches("^.+@.+\\..+$"))
        throw new BadRequestException("Invalid email");
      user.setEmail(email);
      user.setEmailVerified(true);
      String newPassword = resetData.get("password").toString();
      CredentialRepresentation passwordCredential = new CredentialRepresentation();
      passwordCredential.setType(CredentialRepresentation.PASSWORD);
      passwordCredential.setValue(newPassword);
      passwordCredential.setTemporary(false);

      UserCredentialModel credential = UserCredentialModel.password(newPassword, false);
      user.credentialManager().updateCredential(credential);

      String response = "{\"message\":\"Password updated\"}";
      return Response.ok(response, APPLICATION_JSON).build();
      
    } catch (IOException e) {
      throw new BadRequestException("Invalid JSON input");
    }
  }
}
