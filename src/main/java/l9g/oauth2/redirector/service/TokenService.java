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
import java.util.Collections;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

/**
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class TokenService
{
  private final static String GRANT_TYPE = "client_credentials";

  private final RestTemplate restTemplate = new RestTemplate();

  private final ClientRegistrationRepository clientRegistrationRepository;

  private final OAuth2AuthorizedClientManager authorizedClientManager;

  private final OAuth2AuthorizedClientService authorizedClientService;

  @Value("${app.oauth2.registration.name}")
  private String registrationName;

  @Value("${spring.security.oauth2.client.registration.${app.oauth2.registration.name}.client-id}")
  private String clientId;

  @Value("${spring.security.oauth2.client.registration.${app.oauth2.registration.name}.client-secret}")
  private String clientSecret;

  private String tokenEndpoint()
  {
    String tokenEndpoint = null;

    ClientRegistration registration =
      clientRegistrationRepository.findByRegistrationId(registrationName);

    if(registration != null)
    {
      tokenEndpoint = registration.getProviderDetails().getTokenUri();
      log.debug("token endpoint uri = {}", tokenEndpoint);
    }
    else
    {
      log.warn("registration is null");
    }

    return tokenEndpoint;
  }

  public OAuth2AccessToken adminServiceAccessToken()
  {
    log.debug("adminServiceAccessToken");

    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

    MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
    body.add("grant_type", GRANT_TYPE);
    body.add("client_id", clientId);
    body.add("client_secret", clientSecret);

    HttpEntity<MultiValueMap<String, String>> requestEntity =
      new HttpEntity<>(body, headers);

    ResponseEntity<Map> responseEntity =
      restTemplate.postForEntity(tokenEndpoint(), requestEntity, Map.class);

    if(responseEntity.getStatusCode().is2xxSuccessful()
      && responseEntity.getBody() != null)
    {
      Map<String, Object> responseBody = responseEntity.getBody();
      String tokenValue = (String)responseBody.get("access_token");
      Integer expiresIn = (Integer)responseBody.get("expires_in");
      Instant issuedAt = Instant.now();
      Instant expiresAt = issuedAt.plusSeconds(
        expiresIn != null ? expiresIn.longValue() : 3600);

      log.debug("expiresAt = {}", expiresAt);

      return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
        tokenValue,
        issuedAt,
        expiresAt,
        Collections.emptySet());
    }
    else
    {
      throw new RuntimeException("Fehler beim Abruf des Access Tokens: "
        + responseEntity.getStatusCode());
    }
  }

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
