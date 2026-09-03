/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.openredirect;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

/**
 * Provides a real 302 redirect for experimentation separate from assignment scoring.
 *
 * <p>The request value is never used as the redirect target. It must be a relative, in-application
 * path, which is canonicalized and then resolved against a fixed allow list of internal
 * destinations; the redirect is issued to the matching allow list entry. Absolute URLs,
 * scheme-relative {@code //host} forms, backslash variants and values escaping the application base
 * path are rejected with HTTP 400.
 */
@Controller
public class OpenRedirectRealRedirect {

  /** Known internal destinations this endpoint may redirect to. */
  private static final List<String> ALLOWED_TARGETS = List.of("/welcome.mvc", "/login", "/logout");

  /** Relative path without scheme, authority or other host denoting characters. */
  private static final Pattern SAFE_RELATIVE_PATH = Pattern.compile("/[A-Za-z0-9._~/-]{0,200}");

  @GetMapping("/OpenRedirect/realRedirect")
  public ModelAndView real(@RequestParam("url") String url) {
    return new ModelAndView("redirect:" + resolveAllowedTarget(url));
  }

  /** Resolves the requested value to one of the allow-listed internal paths, or fails closed. */
  private static String resolveAllowedTarget(String requested) {
    if (requested == null || requested.isBlank()) {
      throw badRequest();
    }
    String candidate = requested.trim();
    // Reject scheme relative (//host, /\host) and backslash variants before any parsing.
    if (candidate.startsWith("//") || candidate.contains("\\")) {
      throw badRequest();
    }
    if (!SAFE_RELATIVE_PATH.matcher(candidate).matches()) {
      throw badRequest();
    }
    String canonical;
    try {
      canonical = new URI(candidate).normalize().getPath();
    } catch (URISyntaxException e) {
      throw badRequest();
    }
    if (canonical == null) {
      throw badRequest();
    }
    for (String allowed : ALLOWED_TARGETS) {
      if (allowed.equals(canonical)) {
        // Redirect to the allow list entry itself, never to the request supplied value.
        return allowed;
      }
    }
    throw badRequest();
  }

  private static ResponseStatusException badRequest() {
    return new ResponseStatusException(
        HttpStatus.BAD_REQUEST, "Only allow-listed internal paths are valid redirect targets");
  }
}
