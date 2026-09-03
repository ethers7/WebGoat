/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.openredirect;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Set;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

/**
 * Provides a real 302 redirect for experimentation separate from assignment scoring.
 */
@Controller
public class OpenRedirectRealRedirect {

  private static final String FALLBACK_DESTINATION = "/welcome.mvc";

  // RFC 2606 reserves these documentation domains, so no third party can ever register them
  // and they cannot become attacker-controlled.
  private static final Set<String> ALLOWED_HOSTS =
      Set.of("example.com", "example.org", "example.net");

  @GetMapping("/OpenRedirect/realRedirect")
  public ModelAndView real(@RequestParam("url") String url) {
    String destination = isAllowedDestination(url) ? url : FALLBACK_DESTINATION;
    return new ModelAndView("redirect:" + destination);
  }

  private static boolean isAllowedDestination(String url) {
    if (url == null || url.isBlank()) {
      return false;
    }
    for (int i = 0; i < url.length(); i++) {
      char c = url.charAt(i);
      if (c == '\\' || c < 0x20 || c == 0x7F || Character.isWhitespace(c)) {
        return false;
      }
    }
    URI uri;
    try {
      uri = new URI(url);
    } catch (URISyntaxException e) {
      return false;
    }
    String scheme = uri.getScheme();
    if (scheme != null) {
      if (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https")) {
        return false;
      }
      if (uri.getUserInfo() != null || uri.getHost() == null) {
        return false;
      }
      return ALLOWED_HOSTS.contains(canonicalHost(uri.getHost()));
    }
    return uri.getAuthority() == null && uri.getHost() == null && url.startsWith("/");
  }

  private static String canonicalHost(String host) {
    String lowered = host.toLowerCase(Locale.ROOT);
    return lowered.endsWith(".") ? lowered.substring(0, lowered.length() - 1) : lowered;
  }
}
