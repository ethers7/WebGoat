/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint3"})
public class SSRFTask2 implements AssignmentEndpoint {

  // The submitted value may only select one of these fixed http(s) destinations, it never becomes
  // part of the outgoing request itself, so user input can no longer steer the server (CWE-918).
  private static final URI IFCONFIG_PRO = URI.create("http://ifconfig.pro");
  private static final List<URI> ALLOWED_DESTINATIONS = List.of(IFCONFIG_PRO);

  private static final int TIMEOUT_IN_MILLIS = 5000;

  private static final String CAT_HTML =
      "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">";

  private static final String SITE_DOWN_HTML =
      "<html><body>Although the http://ifconfig.pro site is down, you still managed to solve this"
          + " exercise the right way!</body></html>";

  // Returned when the allowlisted name resolves to an internal address, so nothing is fetched.
  private static final String BLOCKED_HTML = "<html><body>No request was sent.</body></html>";

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

  protected AttackResult furBall(String url) {
    var destination = allowedDestination(url);
    if (destination.isEmpty()) {
      // Anything outside the allowlist (internal hosts, cloud metadata, credentials in the
      // authority, other schemes, ...) is rejected before a connection is opened.
      return getFailedResult(CAT_HTML);
    }
    return success(this).feedback("ssrf.success").output(fetch(destination.get())).build();
  }

  /** Fetches an allowlisted destination, never a location derived from the request. */
  private String fetch(URI destination) {
    if (!resolvesToPublicAddress(destination.getHost())) {
      return BLOCKED_HTML;
    }
    try {
      var connection = destination.toURL().openConnection();
      connection.setConnectTimeout(TIMEOUT_IN_MILLIS);
      connection.setReadTimeout(TIMEOUT_IN_MILLIS);
      if (connection instanceof HttpURLConnection httpConnection) {
        // Redirects are not followed, they could point the server at an internal address.
        httpConnection.setInstanceFollowRedirects(false);
      }
      try (InputStream in = connection.getInputStream()) {
        // Otherwise the \n gets escaped in the response
        return new String(in.readAllBytes(), StandardCharsets.UTF_8).replaceAll("\n", "<br>");
      }
    } catch (IOException e) {
      // in case the external site is down, the test and lesson should still be ok
      return SITE_DOWN_HTML;
    }
  }

  /** Maps the submitted value onto an allowlisted destination, or empty when not allowed. */
  private static Optional<URI> allowedDestination(String requestedUrl) {
    if (requestedUrl == null) {
      return Optional.empty();
    }
    URI requested;
    try {
      requested = new URI(requestedUrl.trim());
    } catch (URISyntaxException e) {
      return Optional.empty();
    }
    if (!isSchemeAndHostOnly(requested)) {
      return Optional.empty();
    }
    for (URI allowed : ALLOWED_DESTINATIONS) {
      if (isSameDestination(allowed, requested)) {
        return Optional.of(allowed);
      }
    }
    return Optional.empty();
  }

  /** Positive specification: scheme and host only, no credentials, path, query or fragment. */
  private static boolean isSchemeAndHostOnly(URI uri) {
    var path = uri.getPath();
    return uri.getScheme() != null
        && uri.getHost() != null
        && uri.getUserInfo() == null
        && uri.getQuery() == null
        && uri.getFragment() == null
        && (path == null || path.isEmpty() || "/".equals(path));
  }

  private static boolean isSameDestination(URI allowed, URI requested) {
    return allowed.getScheme().equalsIgnoreCase(requested.getScheme())
        && allowed.getHost().equalsIgnoreCase(requested.getHost())
        && (requested.getPort() == -1 || requested.getPort() == allowed.getPort());
  }

  /** Guards against an allowlisted name that (still) points to an internal address. */
  private static boolean resolvesToPublicAddress(String host) {
    try {
      for (InetAddress address : InetAddress.getAllByName(host)) {
        if (isInternalAddress(address)) {
          return false;
        }
      }
      return true;
    } catch (UnknownHostException e) {
      // Fail closed when the destination cannot be resolved.
      return false;
    }
  }

  private static boolean isInternalAddress(InetAddress address) {
    return address.isAnyLocalAddress()
        || address.isLoopbackAddress()
        || address.isLinkLocalAddress()
        || address.isSiteLocalAddress()
        || address.isMulticastAddress()
        || isUniqueLocalIpv6(address);
  }

  /** Unique local IPv6 addresses (fc00::/7) are the IPv6 counterpart of a private range. */
  private static boolean isUniqueLocalIpv6(InetAddress address) {
    var bytes = address.getAddress();
    return bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc;
  }

  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
