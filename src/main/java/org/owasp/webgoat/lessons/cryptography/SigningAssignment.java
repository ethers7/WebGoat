/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.regex.Pattern;
import javax.xml.bind.DatatypeConverter;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@AssignmentHints({
  "crypto-signing.hints.1",
  "crypto-signing.hints.2",
  "crypto-signing.hints.3",
  "crypto-signing.hints.4"
})
@Slf4j
public class SigningAssignment implements AssignmentEndpoint {

  /**
   * The session is trusted state, so the generated key is checked to be a well formed PKCS#8 PEM
   * block before it crosses into session scope.
   */
  private static final Pattern PRIVATE_KEY_PEM =
      Pattern.compile(
          "-----BEGIN PRIVATE KEY-----\\s+[A-Za-z0-9+/=\\s]+-----END PRIVATE KEY-----\\s*");

  @GetMapping(path = "/crypto/signing/getprivate", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getPrivateKey(HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

    String privateKey = (String) request.getSession().getAttribute("privateKeyString");
    if (privateKey == null) {
      KeyPair keyPair = CryptoUtil.generateKeyPair();
      privateKey = CryptoUtil.getPrivateKeyInPEM(keyPair);
      request.getSession().setAttribute("privateKeyString", validatedPrivateKeyPem(privateKey));
      request.getSession().setAttribute("keyPair", validatedKeyPair(keyPair));
    }
    return privateKey;
  }

  @PostMapping("/crypto/signing/verify")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request, @RequestParam String modulus, @RequestParam String signature) {

    String tempModulus =
        modulus; /* used to validate the modulus of the public key but might need to be corrected */
    KeyPair keyPair = (KeyPair) request.getSession().getAttribute("keyPair");
    RSAPublicKey rsaPubKey = (RSAPublicKey) keyPair.getPublic();
    if (tempModulus.length() == 512) {
      tempModulus = "00".concat(tempModulus);
    }
    if (!DatatypeConverter.printHexBinary(rsaPubKey.getModulus().toByteArray())
        .equals(tempModulus.toUpperCase())) {
      log.warn("modulus {} incorrect", modulus);
      return failed(this).feedback("crypto-signing.modulusnotok").build();
    }
    /* orginal modulus must be used otherwise the signature would be invalid */
    if (CryptoUtil.verifyMessage(modulus, signature, keyPair.getPublic())) {
      return success(this).feedback("crypto-signing.success").build();
    } else {
      log.warn("signature incorrect");
      return failed(this).feedback("crypto-signing.notok").build();
    }
  }

  /**
   * Validates the PEM encoded private key before it is stored in the session, so only a well formed
   * server generated key can move from the request handling into trusted session scope.
   */
  private static String validatedPrivateKeyPem(String privateKeyPem) {
    if (privateKeyPem == null || !PRIVATE_KEY_PEM.matcher(privateKeyPem).matches()) {
      throw new ResponseStatusException(
          HttpStatus.INTERNAL_SERVER_ERROR, "Generated private key is not a valid PEM block");
    }
    return privateKeyPem;
  }

  /**
   * Validates the generated key pair before it is stored in the session, so the verification
   * endpoint can rely on finding a usable RSA key pair in trusted session scope.
   */
  private static KeyPair validatedKeyPair(KeyPair keyPair) {
    if (keyPair == null || !(keyPair.getPublic() instanceof RSAPublicKey)) {
      throw new ResponseStatusException(
          HttpStatus.INTERNAL_SERVER_ERROR, "Could not generate an RSA key pair for this lesson");
    }
    return keyPair;
  }
}
