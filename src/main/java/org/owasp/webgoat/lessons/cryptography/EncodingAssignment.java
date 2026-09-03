/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.security.SecureRandom;
import java.util.Base64;
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

  private static final String BASIC_AUTH_SECRET = "basicAuthSecret";
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  public static String getBasicAuth(String username, String password) {
    return Base64.getEncoder().encodeToString(username.concat(":").concat(password).getBytes());
  }

  @GetMapping(path = "/crypto/encoding/basic", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getBasicAuth(HttpServletRequest request) {

    // Only the server-chosen secret is stored in the session; the username is taken from
    // the authenticated principal on each request, so no request data becomes session state.
    String password = (String) request.getSession().getAttribute(BASIC_AUTH_SECRET);
    if (password == null) {
      String secret =
          HashingAssignment.SECRETS[SECURE_RANDOM.nextInt(HashingAssignment.SECRETS.length)];
      request.getSession().setAttribute(BASIC_AUTH_SECRET, secret);
      password = secret;
    }
    return "Authorization: Basic ".concat(getBasicAuth(currentUsername(request), password));
  }

  @PostMapping("/crypto/encoding/basic-auth")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request,
      @RequestParam String answer_user,
      @RequestParam String answer_pwd) {
    String password = (String) request.getSession().getAttribute(BASIC_AUTH_SECRET);
    String username = currentUsername(request);
    if (password != null
        && username != null
        && answer_user != null
        && answer_pwd != null
        && getBasicAuth(username, password).equals(getBasicAuth(answer_user, answer_pwd))) {
      return success(this).feedback("crypto-encoding.success").build();
    } else {
      return failed(this).feedback("crypto-encoding.empty").build();
    }
  }

  private static String currentUsername(HttpServletRequest request) {
    Principal principal = request.getUserPrincipal();
    return principal == null ? null : principal.getName();
  }
}
