/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Set;
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

  /** The only destination WebGoat is allowed to fetch for this lesson. */
  private static final URI IFCONFIG_PRO = URI.create("http://ifconfig.pro");

  /**
   * Server-side map of the destinations the user is allowed to select.
   *
   * <p>The user supplied value is only compared against this allowlist, it is never used to build
   * the request itself, so it cannot make WebGoat call out to link-local, metadata or other
   * internal addresses (server-side request forgery).
   */
  private static final Set<String> ALLOWED_URLS = Set.of(IFCONFIG_PRO.toString());

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

  protected AttackResult furBall(String url) {
    if (ALLOWED_URLS.contains(url)) {
      String html;
      try (InputStream in = IFCONFIG_PRO.toURL().openStream()) {
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
    var html = "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">";
    return getFailedResult(html);
  }

  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
