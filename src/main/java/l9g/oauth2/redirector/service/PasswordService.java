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

import l9g.oauth2.redirector.annotation.Base64Value;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class PasswordService
{
  private final RestTemplate restTemplate = new RestTemplate();

  private final TokenService tokenService;

  @Value("${app.password.attribute-name}")
  private String appPasswordAttributeName;

  @Base64Value("${app.password.private-key}")
  private byte[] appPasswordPrivateKeyBytes;

  @Value("${app.admin-users-uri}")
  private String adminUsersUri;

  public String getPassword(String kcuid)
  {
    String clearTextPassword = "";

    if(kcuid != null && kcuid.length() > 0)
    {
      String encryptedPassword = getEncryptedUserPassword(kcuid);

      if(appPasswordPrivateKeyBytes != null
        && encryptedPassword != null && encryptedPassword.length() > 0)
      {
        try
        {
          PKCS8EncodedKeySpec spec =
            new PKCS8EncodedKeySpec(appPasswordPrivateKeyBytes);
          KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
          PrivateKey privateKey = keyFactory.generatePrivate(spec);

          Cipher cipher = Cipher.getInstance("ECIES", "BC");
          cipher.init(Cipher.DECRYPT_MODE, privateKey,
            new IESParameterSpec(null, null, 256, 256, null, false));
          clearTextPassword =
            new String(cipher.doFinal(Base64.getDecoder()
              .decode(encryptedPassword)));
        }
        catch(Exception ex)
        {
          log.debug("decrypt failed", ex);
        }
      }
    }

    return clearTextPassword;
  }

  private String getEncryptedUserPassword(String userId)
  {
    String url = adminUsersUri + userId;

    ObjectMapper objectMapper = new ObjectMapper();

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(tokenService.adminServiceAccessToken().getTokenValue());
    headers.setContentType(MediaType.APPLICATION_JSON);

    HttpEntity<?> entity = new HttpEntity<>(headers);

    ResponseEntity<String> response = restTemplate.exchange(
      url, HttpMethod.GET, entity, String.class);

    String encryptedPassword = null;

    if(response.getStatusCode() == HttpStatus.OK)
    {
      try
      {
        JsonNode rootNode = objectMapper.readTree(response.getBody());
        JsonNode encryptedPasswordNode = rootNode.path("attributes")
          .path(appPasswordAttributeName);

        if(encryptedPasswordNode.isArray() && encryptedPasswordNode.size() > 0)
        {
          encryptedPassword = encryptedPasswordNode.get(0).asText();
        }
      }
      catch(JsonProcessingException ex)
      {
        log.error("json parsing error", ex);
      }
    }
    return encryptedPassword;
  }

}
