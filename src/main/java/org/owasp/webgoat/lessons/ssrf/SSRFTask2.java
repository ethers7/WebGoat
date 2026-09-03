/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
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

  /**
   * The destinations this endpoint is allowed to contact. The value supplied by the user is only
   * used as a lookup key, so it can select one of these fixed destinations but it can never decide
   * the scheme, host, port or path of the outgoing request.
   */
  private static final Map<String, URI> ALLOWED_TARGETS =
      Map.of("http://ifconfig.pro", URI.create("http://ifconfig.pro"));

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

  protected AttackResult furBall(String url) {
    var target = url == null ? null : ALLOWED_TARGETS.get(url.strip());
    if (target == null) {
      // Not an approved destination, so no outgoing request is made at all
      var html = "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">";
      return getFailedResult(html);
    }
    if (resolvesToInternalAddress(target)) {
      return getFailedResult("The approved destination resolves to an internal address");
    }
    String html;
    try (InputStream in = target.toURL().openStream()) {
      html =
          new String(in.readAllBytes(), StandardCharsets.UTF_8)
              .replaceAll("\n", "<br>"); // Otherwise the \n gets escaped in the response
    } catch (IOException e) {
      // in case the external site is down, the test and lesson should still be ok
      html =
          "<html><body>Although the http://ifconfig.pro site is down, you still managed to solve"
              + " this exercise the right way!</body></html>";
    }
    return success(this).feedback("ssrf.success").output(html).build();
  }

  /**
   * Refuses a DNS answer which points at infrastructure that must never be reachable from this
   * application, such as the loopback interface, an internal RFC1918 network or the link-local
   * cloud metadata service on 169.254.169.254.
   */
  private static boolean resolvesToInternalAddress(URI target) {
    try {
      for (InetAddress address : InetAddress.getAllByName(target.getHost())) {
        if (isInternalAddress(address)) {
          return true;
        }
      }
      return false;
    } catch (UnknownHostException e) {
      // The name cannot be resolved, the fetch below reports the destination as unreachable
      return false;
    }
  }

  private static boolean isInternalAddress(InetAddress address) {
    if (address.isAnyLocalAddress()
        || address.isLoopbackAddress()
        || address.isLinkLocalAddress()
        || address.isSiteLocalAddress()
        || address.isMulticastAddress()) {
      return true;
    }
    // IPv6 unique local addresses (fc00::/7) are not covered by isSiteLocalAddress
    var bytes = address.getAddress();
    return bytes.length == 16 && (bytes[0] & 0xFE) == 0xFC;
  }

  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
