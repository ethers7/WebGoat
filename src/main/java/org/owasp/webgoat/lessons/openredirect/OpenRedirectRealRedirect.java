/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.openredirect;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

/**
 * Provides a real 302 redirect for experimentation separate from assignment scoring.
 *
 * <p>The destination is confined to this origin: only a relative path is accepted. Values carrying
 * a scheme or an authority (absolute and protocol-relative URLs) are rejected and replaced by a
 * known-good internal destination, so the endpoint can no longer send a user to an attacker
 * controlled site.
 *
 * <p>The scored assignments of this lesson (task1 - task4, the mitigation check and the quiz)
 * simulate redirects and report on the supplied URL instead of following it, so this control does
 * not change how the lesson is solved.
 */
@Controller
public class OpenRedirectRealRedirect {

  /** Internal destination used whenever the requested value is not a safe relative path. */
  private static final String DEFAULT_DESTINATION = "/welcome.mvc";

  /**
   * Backslashes and control characters are normalised inconsistently by browsers and are used to
   * smuggle an authority past path validation, so they are never accepted.
   */
  private static final Pattern UNSAFE_CHARACTERS = Pattern.compile("[\\\\\\p{Cntrl}]");

  /**
   * Redirects to a validated same-origin relative path.
   *
   * @param url the requested destination, which must be a relative path such as /welcome.mvc
   * @return a redirect to the validated path, or to the internal default when it is not accepted
   */
  @GetMapping("/OpenRedirect/realRedirect")
  public ModelAndView real(@RequestParam("url") String url) {
    return new ModelAndView("redirect:" + safeRelativePath(url));
  }

  private static String safeRelativePath(String requested) {
    if (requested == null || requested.isBlank() || UNSAFE_CHARACTERS.matcher(requested).find()) {
      return DEFAULT_DESTINATION;
    }

    URI candidate;
    try {
      candidate = new URI(requested).normalize();
    } catch (URISyntaxException e) {
      return DEFAULT_DESTINATION;
    }

    // A scheme or an authority means the destination can leave this origin.
    if (candidate.isAbsolute() || candidate.getRawAuthority() != null) {
      return DEFAULT_DESTINATION;
    }

    // Exactly one leading slash keeps the redirect on this origin, "//host" would not.
    String path = candidate.getRawPath();
    if (path == null || !path.startsWith("/") || path.startsWith("//")) {
      return DEFAULT_DESTINATION;
    }

    String query = candidate.getRawQuery();
    return query == null ? path : path + "?" + query;
  }
}
