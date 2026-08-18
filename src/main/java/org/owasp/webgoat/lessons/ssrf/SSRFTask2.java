/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
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

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

  private static boolean isAllowedUrl(String url) {
    try {
      String host = new URL(url).getHost();
      return "localhost".equals(host) || "127.0.0.1".equals(host);
    } catch (MalformedURLException e) {
      return false;
    }
  }

  protected AttackResult furBall(String url) {
    if (!isAllowedUrl(url)) {
      return getFailedResult("Access to this URL is not allowed. Only localhost is permitted.");
    }
    if (url.matches("http://ifconfig\\.pro")) {
      String html;
      try (InputStream in = new URL(url).openStream()) {
        html =
            new String(in.readAllBytes(), StandardCharsets.UTF_8)
                .replaceAll("\n", "<br>"); // Otherwise the \n gets escaped in the response
      } catch (MalformedURLException e) {
        return getFailedResult(e.getMessage());
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
