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
import java.util.stream.Stream;

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

  private final List<String> approvedJwksHosts;

  public JWTHeaderJKUEndpoint(@Value("${webwolf.host}") String webWolfHost) {
    // The key set for this lesson is hosted in WebWolf, so only that host is approved.
    this.approvedJwksHosts =
        Stream.of(webWolfHost, "localhost", "127.0.0.1").filter(StringUtils::isNotEmpty).toList();
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
        var jwkProvider = new JwkProviderBuilder(allowedJwksUrl(jku.asString())).build();
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

  /**
   * Builds the URL of the key set, only accepting the hosts approved for this lesson.
   *
   * <p>The 'jku' header is taken from the token supplied by the user. Without an allowlist the
   * user decides which host WebGoat sends this request to, which allows probing internal
   * resources (server-side request forgery).
   */
  private URL allowedJwksUrl(String jku) throws MalformedURLException {
    if (StringUtils.isEmpty(jku)) {
      throw new MalformedURLException("jku header is missing");
    }
    var requested = new URL(jku);
    var protocol = requested.getProtocol();
    var approvedHost = approvedHostOrNull(requested.getHost());
    if (approvedHost == null || !("http".equals(protocol) || "https".equals(protocol))) {
      throw new MalformedURLException("jku header does not point to an approved host");
    }
    // Host taken from the allowlist, the user can only influence the port and the path.
    return new URL(protocol, approvedHost, requested.getPort(), requested.getFile());
  }

  private String approvedHostOrNull(String host) {
    if (StringUtils.isEmpty(host)) {
      return null;
    }
    return approvedJwksHosts.stream().filter(host::equalsIgnoreCase).findFirst().orElse(null);
  }
}
