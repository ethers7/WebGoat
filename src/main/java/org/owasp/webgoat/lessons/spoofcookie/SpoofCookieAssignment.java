/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.spoofcookie.encoders.EncDec;
import org.springframework.web.bind.UnsatisfiedServletRequestParameterException;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@AssignmentHints({"spoofcookie.hint1", "spoofcookie.hint2", "spoofcookie.hint3"})
@RestController
public class SpoofCookieAssignment implements AssignmentEndpoint {

  private static final String COOKIE_NAME = "spoof_auth";
  private static final String COOKIE_INFO =
      "Cookie details for user %s:<br />" + COOKIE_NAME + "=%s";
  private static final String ATTACK_USERNAME = "tom";

  private static final Map<String, String> users =
      Map.of("webgoat", "webgoat", "admin", "admin", ATTACK_USERNAME, "apasswordfortom");

  @PostMapping(path = "/SpoofCookie/login")
  @ResponseBody
  @ExceptionHandler(UnsatisfiedServletRequestParameterException.class)
  public AttackResult login(
      @RequestParam String username,
      @RequestParam String password,
      @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
      HttpServletResponse response) {

    if (StringUtils.isEmpty(cookieValue)) {
      return credentialsLoginFlow(username, password, response);
    } else {
      return cookieLoginFlow(cookieValue);
    }
  }

  @GetMapping(path = "/SpoofCookie/cleanup")
  public void cleanup(HttpServletRequest request, HttpServletResponse response) {
    Cookie cookie = new Cookie(COOKIE_NAME, "");
    cookie.setMaxAge(0);
    // Must repeat the path the cookie was issued with, otherwise the browser stores a second
    // cookie for /SpoofCookie instead of expiring the one on /WebGoat.
    cookie.setPath("/WebGoat");
    // The cookie is HttpOnly (see credentialsLoginFlow), so expiring it has to happen here on the
    // server; the lesson page calls this endpoint from its "Delete cookie" link.
    cookie.setHttpOnly(true);
    // Mirror the transport of the current request: WebGoat can be served over plain HTTP
    // (server.ssl.enabled=false), where a Secure cookie is rejected and the cookie would never
    // be erased, so the flag is only set for HTTPS requests.
    if (request.isSecure()) {
      cookie.setSecure(true);
    }
    response.addCookie(cookie);
  }

  private AttackResult credentialsLoginFlow(
      String username, String password, HttpServletResponse response) {
    String lowerCasedUsername = username.toLowerCase();
    if (ATTACK_USERNAME.equals(lowerCasedUsername)
        && matchesPassword(users.get(lowerCasedUsername), password)) {
      return informationMessage(this).feedback("spoofcookie.cheating").build();
    }

    String authPassword = users.getOrDefault(lowerCasedUsername, "");
    if (!authPassword.isBlank() && matchesPassword(authPassword, password)) {
      String newCookieValue = EncDec.encode(lowerCasedUsername);
      Cookie newCookie = new Cookie(COOKIE_NAME, newCookieValue);
      newCookie.setPath("/WebGoat");
      newCookie.setSecure(true);
      // Hide the cookie from JavaScript. The lesson still shows its value in the output below and
      // the attack is performed by sending a forged cookie in a request, which HttpOnly does not
      // prevent; the lesson page no longer reads document.cookie (see lessons/spoofcookie/js).
      newCookie.setHttpOnly(true);
      response.addCookie(newCookie);
      return informationMessage(this)
          .feedback("spoofcookie.login")
          .output(String.format(COOKIE_INFO, lowerCasedUsername, newCookie.getValue()))
          .build();
    }

    return informationMessage(this).feedback("spoofcookie.wrong-login").build();
  }

  // Compares a stored password with the submitted one in constant time. A plain equals returns
  // as soon as the first byte differs, so the response time of this login flow can leak the
  // stored password character by character.
  private static boolean matchesPassword(String storedPassword, String submittedPassword) {
    if (storedPassword == null || submittedPassword == null) {
      return false;
    }
    return MessageDigest.isEqual(
        storedPassword.getBytes(StandardCharsets.UTF_8),
        submittedPassword.getBytes(StandardCharsets.UTF_8));
  }

  private AttackResult cookieLoginFlow(String cookieValue) {
    String cookieUsername;
    try {
      cookieUsername = EncDec.decode(cookieValue).toLowerCase();
    } catch (Exception e) {
      // for providing some instructive guidance, we won't return 4xx error here
      return failed(this).output(e.getMessage()).build();
    }
    if (users.containsKey(cookieUsername)) {
      if (cookieUsername.equals(ATTACK_USERNAME)) {
        return success(this).build();
      }
      return failed(this)
          .feedback("spoofcookie.cookie-login")
          .output(String.format(COOKIE_INFO, cookieUsername, cookieValue))
          .build();
    }

    return failed(this).feedback("spoofcookie.wrong-cookie").build();
  }
}
