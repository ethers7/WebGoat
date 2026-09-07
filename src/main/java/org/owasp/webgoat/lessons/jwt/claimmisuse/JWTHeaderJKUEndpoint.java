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
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

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
   * Strict pattern for the "jku" header claim: a plain http(s) URL without user info, so a host
   * cannot be smuggled past the allowlist below with constructs such as
   * "http://allowed@evil.example".
   */
  private static final Pattern JKU_PATTERN =
      Pattern.compile(
          "^(?<scheme>https?)://(?<host>[a-z0-9.-]+)(?::(?<port>\\d{1,5}))?"
              + "(?<path>/[^?#]*)?(?:\\?(?<query>[^#]*))?$",
          Pattern.CASE_INSENSITIVE);

  /**
   * Hosts which are allowed to serve the JSON Web Key Set referenced by the "jku" header claim,
   * being the WebWolf instance of this WebGoat deployment and its loopback aliases.
   */
  private final Set<String> allowedJwksHosts;

  public JWTHeaderJKUEndpoint(@Value("${webwolf.host}") String webWolfHost) {
    // Set.copyOf ignores duplicates, the configured WebWolf host is often a loopback host itself
    this.allowedJwksHosts =
        Set.copyOf(List.of(webWolfHost.toLowerCase(Locale.ROOT), "localhost", "127.0.0.1"));
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
        var jwkProvider = new JwkProviderBuilder(toAllowedJwksUrl(jku.asString())).build();
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
   * Resolves the location of the JSON Web Key Set from the untrusted "jku" header claim. The URL is
   * rebuilt from an allowlisted host instead of the host inside the token, so the token can only
   * influence the port, path and query of the URL and never the server which is contacted.
   *
   * @throws MalformedURLException when the claim is no http(s) URL or points to a host which is not
   *     allowed to serve a JSON Web Key Set
   */
  private URL toAllowedJwksUrl(String jku) throws MalformedURLException {
    var matcher = JKU_PATTERN.matcher(StringUtils.defaultString(jku));
    if (!matcher.matches()) {
      throw new MalformedURLException("The jku header claim is no supported http(s) URL");
    }
    var requestedHost = matcher.group("host").toLowerCase(Locale.ROOT);
    var allowedHost =
        allowedJwksHosts.stream()
            .filter(requestedHost::equals)
            .findFirst()
            .orElseThrow(
                () -> new MalformedURLException("The jku header claim host is not allowed"));
    var scheme = "https".equalsIgnoreCase(matcher.group("scheme")) ? "https" : "http";
    var port = matcher.group("port") == null ? -1 : Integer.parseInt(matcher.group("port"));
    if (port != -1 && (port < 1 || port > 65535)) {
      throw new MalformedURLException("The jku header claim port is invalid");
    }
    var path = StringUtils.defaultString(matcher.group("path"));
    var query = matcher.group("query");
    try {
      return new URI(scheme, null, allowedHost, port, path, query, null).toURL();
    } catch (URISyntaxException e) {
      throw new MalformedURLException("The jku header claim is no supported http(s) URL");
    }
  }
}
