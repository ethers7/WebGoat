/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Random;
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

  /**
   * The user name is supplied by the request, so it is validated against the same form WebGoat
   * accepts at registration before it is used to build the credential shown in this lesson.
   */
  private static final Pattern VALID_USERNAME = Pattern.compile("[a-zA-Z0-9_.@-]{1,64}");

  private static final String BASIC_AUTH_SECRET = "basicAuthSecret";

  public static String getBasicAuth(String username, String password) {
    return Base64.getEncoder().encodeToString(username.concat(":").concat(password).getBytes());
  }

  @GetMapping(path = "/crypto/encoding/basic", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getBasicAuth(HttpServletRequest request) {

    String password = (String) request.getSession().getAttribute(BASIC_AUTH_SECRET);
    if (password == null) {
      // Only server generated state is stored in the session, never request supplied data.
      password = HashingAssignment.SECRETS[new Random().nextInt(HashingAssignment.SECRETS.length)];
      request.getSession().setAttribute(BASIC_AUTH_SECRET, password);
    }
    return "Authorization: Basic ".concat(getBasicAuth(validatedUsername(request), password));
  }

  @PostMapping("/crypto/encoding/basic-auth")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request,
      @RequestParam String answer_user,
      @RequestParam String answer_pwd) {
    String password = (String) request.getSession().getAttribute(BASIC_AUTH_SECRET);
    if (password != null
        && answer_user != null
        && answer_pwd != null
        && getBasicAuth(validatedUsername(request), password)
            .equals(getBasicAuth(answer_user, answer_pwd))) {
      return success(this).feedback("crypto-encoding.success").build();
    } else {
      return failed(this).feedback("crypto-encoding.empty").build();
    }
  }

  private static String validatedUsername(HttpServletRequest request) {
    var principal = request.getUserPrincipal();
    String username = principal == null ? null : principal.getName();
    if (username == null || !VALID_USERNAME.matcher(username).matches()) {
      throw new IllegalArgumentException("Invalid user name");
    }
    return username;
  }
}
