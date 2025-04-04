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
package l9g.oauth2.redirector.controller;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import l9g.oauth2.redirector.provider.RedirectorOAuth2AuthorizedClientProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.info.BuildProperties;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api",
                produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
@Slf4j
public class ApiController
{
  private final BuildProperties buildProperties;

  private final RedirectorOAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider;

  private final JwtDecoder jwtDecoder;

  @GetMapping("/principal")
  public OAuth2User principalGET(
    @AuthenticationPrincipal OAuth2User principal)
  {
    log.debug("principal.class={}", principal.getClass().getCanonicalName());
    log.debug("principal.name={}", principal.getName());
    return principal;
  }

  @GetMapping("/attributes")
  public Map<String, Object> principalAttributesGET(
    @AuthenticationPrincipal OAuth2User principal)
  {
    return principal.getAttributes();
  }

  @GetMapping("/userinfo")
  public OidcUserInfo principalUserinfoGET(
    @AuthenticationPrincipal OAuth2User principal)
  {
    return ((DefaultOidcUser)principal).getUserInfo();
  }

  @GetMapping("/idtoken")
  public OidcIdToken principalIdTokenGET(
    @AuthenticationPrincipal OAuth2User principal)
  {
    return ((DefaultOidcUser)principal).getIdToken();
  }

  @GetMapping("/accesstoken")
  public Jwt accessTokenGET()
  {
    log.debug("accessTokenGET");
    OAuth2AuthorizedClient client = oauth2AuthorizedClientProvider.getClient();
    return jwtDecoder.decode(client.getAccessToken().getTokenValue());
  }

  @GetMapping("/buildinfo")
  public Map<String, String> buildinfoGET()
  {
    log.debug("buildinfoGET");

    ArrayList<String> keys = new ArrayList<>();
    buildProperties.forEach(p -> keys.add(p.getKey()));
    Collections.sort(keys);
    LinkedHashMap<String, String> properties = new LinkedHashMap<>();
    for(String key : keys)
    {
      properties.put(key, buildProperties.get(key));
    }

    return properties;
  }

}
