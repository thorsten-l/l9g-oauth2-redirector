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

import l9g.oauth2.redirector.service.TokenService;
import l9g.oauth2.redirector.service.PasswordService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
@RequiredArgsConstructor
@Slf4j
public class RedirectController
{
  @Value("${app.password.keycloak-user-id}")
  private String appKeycloakUserId;

  private final JwtDecoder jwtDecoder;

  private final PasswordService passwordService;

  private final TokenService tokenService;

  @GetMapping("/r/{page}")
  public String redirectGET(
    @PathVariable String page,
    Model model,
    @AuthenticationPrincipal OAuth2User principal)
  {
    log.debug("redirectGET page={}", page);
    log.debug("principal={}", principal);

    if(principal != null)
    {
      DefaultOidcUser user = (DefaultOidcUser)principal;
      String kcuid = principal.getAttribute(appKeycloakUserId);

      log.debug("name/sub={}", user.getName());
      log.debug("preferred_username={}", user.getPreferredUsername());
      log.debug("issuer={}", user.getIdToken().getIssuer().toExternalForm());

      OAuth2AccessToken accessToken = tokenService.authClientAccessToken();
      model.addAttribute("fullname", user.getFullName());
      model.addAttribute("kcuid", kcuid);
      model.addAttribute("passwordService", passwordService);
      model.addAttribute("user", user);
      model.addAttribute("userinfo", user.getUserInfo());
      model.addAttribute("idtoken", user.getIdToken());
      model.addAttribute("issuer", user.getIdToken().getIssuer().toExternalForm());
      model.addAttribute("accesstoken", jwtDecoder.decode(accessToken.getTokenValue()));
    }

    return "r/" + page;
  }

}
