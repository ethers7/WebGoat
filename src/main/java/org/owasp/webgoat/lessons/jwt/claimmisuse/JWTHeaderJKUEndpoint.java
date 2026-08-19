/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

@RestController
@AssignmentHints({
  "jwt-jku-hint1",
  "jwt-jku-hint2",
  "jwt-jku-hint3",
  "jwt-jku-hint4",
  "jwt-jku-hint5"
})
public class JWTHeaderJKUEndpoint implements AssignmentEndpoint {

  private final List<String> allowedJkuHosts;

  public JWTHeaderJKUEndpoint(
      @Value("${webwolf.host:127.0.0.1}") String webWolfHost) {
    // Only allow JKU URLs pointing to localhost or the configured WebWolf host.
    // This prevents SSRF by rejecting arbitrary external hosts in the jku header.
    this.allowedJkuHosts = List.of("localhost", "127.0.0.1", webWolfHost);
  }

  @PostMapping("/JWT/jku/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    } else {
      return "You are now following Tom";
    }
  }

  @PostMapping("/JWT/jku/delete")
  public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
    if (StringUtils.isEmpty(token)) {
      return failed(this).feedback("jwt-invalid-token").build();
    } else {
      try {
        var decodedJWT = JWT.decode(token);
        var jku = decodedJWT.getHeaderClaim("jku");
        var jkuUrl = new URL(jku.asString()); // nosemgrep: java.spring.security.injection.tainted-url
        if (!allowedJkuHosts.contains(jkuUrl.getHost())) {
          return failed(this).feedback("jwt-jku-disallowed-host").build();
        }
        var jwkProvider = new JwkProviderBuilder(jkuUrl).build();
        var jwk = jwkProvider.get(decodedJWT.getKeyId());
        var algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey());
        JWT.require(algorithm).build().verify(decodedJWT);

        var username = decodedJWT.getClaims().get("username").asString();
        if ("Jerry".equals(username)) {
          return failed(this).feedback("jwt-final-jerry-account").build();
        }
        if ("Tom".equals(username)) {
          return success(this).build();
        } else {
          return failed(this).feedback("jwt-final-not-tom").build();
        }
      } catch (MalformedURLException | JWTVerificationException | JwkException e) {
        return failed(this).feedback("jwt-invalid-token").output(e.toString()).build();
      }
    }
  }
}
