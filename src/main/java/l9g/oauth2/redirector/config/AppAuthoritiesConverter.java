/*
 * Copyright 2025 Thorsten Ludewig <t.ludewig@gmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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
package l9g.oauth2.redirector.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/**
 *
 * @author Thorsten Ludewig <t.ludewig@gmail.com>
 */
@Component
@RequiredArgsConstructor
public class AppAuthoritiesConverter
{
  
  @Value("${spring.security.oauth2.client.registration.${app.oauth2.registration.name}.client-id}")
  private String resourceAccessRoles;

  public Collection<GrantedAuthority> convert(OidcUser oidcUser, Jwt jwt)
  {
    List<String> realmRoles =
      (jwt.getClaimAsMap("realm_access") != null
      && jwt.getClaimAsMap("realm_access").get("roles") != null)
      ? (List<String>)jwt.getClaimAsMap("realm_access").get("roles")
      : new ArrayList<String>();

    List<String> resourceRoles =
      (jwt.getClaimAsMap("resource_access") != null
      && jwt.getClaimAsMap("resource_access")
        .get(resourceAccessRoles) != null
      && ((Map)jwt.getClaimAsMap("resource_access")
        .get(resourceAccessRoles)).get("roles") != null)
      ? ((Map<String, List<String>>)jwt
        .getClaimAsMap("resource_access")
        .get(resourceAccessRoles)).get("roles")
      : new ArrayList<String>();

    List<GrantedAuthority> authorities = realmRoles.stream()
      .map(role -> "ROLE_" + role)
      .map(SimpleGrantedAuthority :: new)
      .collect(Collectors.toList());

    authorities.addAll(
      resourceRoles.stream()
      .map(role -> "ROLE_RESOURCE_" + role)
      .map(SimpleGrantedAuthority :: new)
      .collect(Collectors.toList()));

    Object scopeClaim = jwt.getClaim("scope");
      if(scopeClaim instanceof String scopes)
      {
        Arrays.stream(scopes.split(" "))
          .map(String :: toUpperCase)
          .forEach(scope -> authorities.add(
            new SimpleGrantedAuthority("SCOPE_" + scope)));
      }    
    
    return authorities;
  }

}
