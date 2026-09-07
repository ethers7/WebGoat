/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EncodingAssignment implements AssignmentEndpoint {

  // Only the server side generated secret of this lesson is kept in the session, never a value
  // which is built from the request itself.
  private static final String BASIC_AUTH_SECRET = "basicAuthSecret";

  // The user name is read from the request (the authenticated principal), so it is validated
  // before it crosses the trust boundary. The same character set as for a WebGoat user name is
  // accepted, which keeps separators (":"), whitespace and control characters out of the
  // credentials of this lesson.
  private static final Pattern VALID_USERNAME = Pattern.compile("[A-Za-z0-9_.@+-]{1,128}");

  // The password of the Basic authentication header the learner has to decode is picked with a
  // CSPRNG, so it cannot be predicted from the values handed out to other sessions.
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  public static String getBasicAuth(String username, String password) {
    return Base64.getEncoder().encodeToString(username.concat(":").concat(password).getBytes());
  }

  @GetMapping(path = "/crypto/encoding/basic", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getBasicAuth(HttpServletRequest request) {

    String username = validatedUsername(request);
    if (username == null) {
      return "Authorization: Basic (not available for this user name)";
    }
    String basicAuth = getBasicAuth(username, lessonSecret(request.getSession()));
    return "Authorization: Basic ".concat(basicAuth);
  }

  @PostMapping("/crypto/encoding/basic-auth")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request,
      @RequestParam String answer_user,
      @RequestParam String answer_pwd) {
    String username = validatedUsername(request);
    String secret = (String) request.getSession().getAttribute(BASIC_AUTH_SECRET);
    if (username != null && secret != null && answer_user != null && answer_pwd != null) {
      byte[] expected = getBasicAuth(username, secret).getBytes(StandardCharsets.UTF_8);
      byte[] submitted = getBasicAuth(answer_user, answer_pwd).getBytes(StandardCharsets.UTF_8);
      if (MessageDigest.isEqual(expected, submitted)) {
        return success(this).feedback("crypto-encoding.success").build();
      }
    }
    return failed(this).feedback("crypto-encoding.empty").build();
  }

  private static String validatedUsername(HttpServletRequest request) {
    Principal principal = request.getUserPrincipal();
    String username = principal == null ? null : principal.getName();
    if (username == null || !VALID_USERNAME.matcher(username).matches()) {
      return null;
    }
    return username;
  }

  private static String lessonSecret(HttpSession session) {
    String secret = (String) session.getAttribute(BASIC_AUTH_SECRET);
    if (secret != null) {
      return secret;
    }
    String generated =
        HashingAssignment.SECRETS[SECURE_RANDOM.nextInt(HashingAssignment.SECRETS.length)];
    session.setAttribute(BASIC_AUTH_SECRET, generated);
    return generated;
  }
}
