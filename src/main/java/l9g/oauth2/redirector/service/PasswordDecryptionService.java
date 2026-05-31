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
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import javax.crypto.Cipher;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

/**
 * Liefert das ECIES-entschluesselte Klartext-Passwort des angemeldeten Users.
 *
 * <p>
 * Der verschluesselte Wert ({@code ENCRYPTED_USER_PASSWORD}) wird seit
 * Einfuehrung des Client-Scopes {@code sonia-secret} ausschliesslich ueber den
 * OIDC-UserInfo-Endpoint geliefert und steht damit in den Principal-Attributen
 * bereit - es ist also kein Admin-API-Lookup (und damit keine
 * Service-Account-Rechte zum Suchen von Usern / Lesen aller Attribute) mehr
 * noetig.
 *
 * <p>
 * KeyCloak liefert den Wert weiterhin <b>verschluesselt</b>; den passenden
 * EC-Private-Key besitzt nur diese Anwendung. Diese Klasse uebernimmt daher
 * lediglich die clientseitige ECIES-Entschluesselung. Der BouncyCastle-Provider
 * wird in {@code RedirectorApplication} registriert.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Service
@Slf4j
public class PasswordDecryptionService
{
  @Value("${app.password.attribute-name}")
  private String appPasswordAttributeName;

  @Base64Value("${app.password.private-key}")
  private byte[] appPasswordPrivateKeyBytes;

  /**
   * Liest das verschluesselte Passwort-Attribut aus dem OIDC-Principal
   * (UserInfo) und entschluesselt es. Keycloak-User-Attribute sind
   * grundsaetzlich mehrwertig: je nach "Multivalued"-Einstellung des
   * Protocol-Mappers kommt der Wert als {@code String} oder als
   * {@code List}/Array an - beide Faelle werden behandelt.
   *
   * @param principal der angemeldete OIDC-Benutzer (darf {@code null} sein).
   *
   * @return das Klartext-Passwort oder ein Leerstring, wenn kein Wert vorhanden
   * ist oder die Entschluesselung fehlschlaegt (template-sicher).
   */
  public String getPassword(OAuth2User principal)
  {
    if(principal == null)
    {
      return "";
    }

    Object value = principal.getAttribute(appPasswordAttributeName);
    if(value instanceof Collection<?> collection)
    {
      value = collection.isEmpty() ? null : collection.iterator().next();
    }

    return value == null ? "" : decrypt(value.toString());
  }

  private String decrypt(String encryptedPassword)
  {
    if(appPasswordPrivateKeyBytes == null
      || encryptedPassword == null || encryptedPassword.isEmpty())
    {
      return "";
    }

    try
    {
      PKCS8EncodedKeySpec spec =
        new PKCS8EncodedKeySpec(appPasswordPrivateKeyBytes);
      KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
      PrivateKey privateKey = keyFactory.generatePrivate(spec);

      Cipher cipher = Cipher.getInstance("ECIES", "BC");
      cipher.init(Cipher.DECRYPT_MODE, privateKey,
        new IESParameterSpec(null, null, 256, 256, null, false));
      return new String(cipher.doFinal(Base64.getDecoder()
        .decode(encryptedPassword)));
    }
    catch(Exception ex)
    {
      log.debug("decrypt failed", ex);
      return "";
    }
  }

}
