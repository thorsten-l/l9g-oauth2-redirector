/*
 * Copyright 2025 Thorsten Ludewig (t.ludewig@gmail.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package l9g.oauth2.redirector.service;

import java.time.Instant;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;

/**
 * Liefert das Access-Token des interaktiv angemeldeten Users (Authorization
 * Code Flow) fuer Outbound-API-Calls.
 *
 * <p>
 * Der frueher hier vorhandene {@code adminServiceAccessToken()}
 * (Client-Credentials-Flow fuer die Keycloak-Admin-API) ist entfallen: das
 * verschluesselte Passwort kommt jetzt ueber den OIDC-UserInfo-Endpoint
 * (Scope {@code sonia-secret}), siehe {@code PasswordDecryptionService}.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class TokenService
{
  private final OAuth2AuthorizedClientManager authorizedClientManager;

  private final OAuth2AuthorizedClientService authorizedClientService;

  @Value("${app.oauth2.registration.name}")
  private String registrationName;

  public OAuth2AccessToken authClientAccessToken()
  {
    log.debug("authClientAccessToken");

    Authentication authentication =
      SecurityContextHolder.getContext().getAuthentication();

    OAuth2AuthorizedClient authorizedClient = authorizedClientService
      .loadAuthorizedClient(registrationName, authentication.getName());

    if(authorizedClient == null || authorizedClient.getAccessToken() == null
      || Instant.now().isAfter(authorizedClient.getAccessToken().getExpiresAt()))
    {
      OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.
        withClientRegistrationId(registrationName).principal(
        authentication).
        build();

      authorizedClient = authorizedClientManager.authorize(
        authorizeRequest);
    }

    if(authorizedClient != null && authorizedClient.getAccessToken() != null)
    {
      log.debug("access token expires={}",
        authorizedClient.getAccessToken().getExpiresAt());
    }

    return authorizedClient.getAccessToken();
  }

}
