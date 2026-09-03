/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import javax.xml.bind.DatatypeConverter;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

@Slf4j
public class CryptoUtilTest {

  @Test
  public void testSigningAssignment() {
    try {
      KeyPair keyPair = CryptoUtil.generateKeyPair();
      RSAPublicKey rsaPubKey = (RSAPublicKey) keyPair.getPublic();
      PrivateKey privateKey =
          CryptoUtil.getPrivateKeyFromPEM(CryptoUtil.getPrivateKeyInPEM(keyPair));
      String modulus = DatatypeConverter.printHexBinary(rsaPubKey.getModulus().toByteArray());
      String signature = CryptoUtil.signMessage(modulus, privateKey);
      log.debug("public exponent {}", rsaPubKey.getPublicExponent());
      assertThat(CryptoUtil.verifyAssignment(modulus, signature, keyPair.getPublic())).isTrue();
    } catch (Exception e) {
      fail("Signing failed");
    }
  }

  @Test
  public void malformedPemIsRejectedWithInvalidKeySpecException() {
    assertThatThrownBy(() -> CryptoUtil.getPrivateKeyFromPEM("not-a-pem-key"))
        .isInstanceOf(InvalidKeySpecException.class);
  }
}
