/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

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

  /**
   * Hosts which are allowed to serve the JSON Web Key Set. The WebWolf instance belonging to this
   * WebGoat installation runs on the loopback interface, the configured WebWolf host is added to
   * this set as well.
   */
  private static final Set<String> DEFAULT_ALLOWED_JKU_HOSTS = Set.of("localhost", "127.0.0.1");

  private final Set<String> allowedJkuHosts;

  public JWTHeaderJKUEndpoint(@Value("${webwolf.host}") String webWolfHost) {
    var hosts = new HashSet<>(DEFAULT_ALLOWED_JKU_HOSTS);
    if (StringUtils.isNotBlank(webWolfHost)) {
      hosts.add(webWolfHost.trim().toLowerCase(Locale.ROOT));
    }
    this.allowedJkuHosts = Set.copyOf(hosts);
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
        var jwkProvider = new JwkProviderBuilder(jwkSetUrl(jku.asString())).build();
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
   * Determines the URL the JSON Web Key Set is fetched from. The "jku" header claim comes from a
   * token which is not verified yet, so it is attacker controlled. Only approved hosts may be
   * contacted and the host which is actually used is taken from the allowlist instead of from the
   * claim, so the claim can never decide which server WebGoat calls out to. Port, path and query
   * still come from the claim, they only address a resource on an approved host.
   *
   * @throws MalformedURLException when the claim is not a valid URL or refers to a host which is
   *     not approved
   */
  private URL jwkSetUrl(String jku) throws MalformedURLException {
    if (StringUtils.isBlank(jku)) {
      throw new MalformedURLException("The jku header claim is missing");
    }
    URI uri;
    try {
      uri = new URI(jku);
    } catch (URISyntaxException e) {
      throw new MalformedURLException("The jku header claim is not a valid URL");
    }
    if (uri.getHost() == null) {
      throw new MalformedURLException("The jku header claim does not contain a host");
    }
    var requestedHost = uri.getHost().toLowerCase(Locale.ROOT);
    var approvedHost =
        allowedJkuHosts.stream()
            .filter(allowedHost -> allowedHost.equals(requestedHost))
            .findFirst()
            .orElseThrow(
                () ->
                    new MalformedURLException(
                        "The host of the jku header claim is not an approved host"));
    var file = uri.getRawPath() == null ? "" : uri.getRawPath();
    if (uri.getRawQuery() != null) {
      file = file + "?" + uri.getRawQuery();
    }
    var scheme = "https".equalsIgnoreCase(uri.getScheme()) ? "https" : "http";
    return new URL(scheme, approvedHost, uri.getPort(), file);
  }
}
