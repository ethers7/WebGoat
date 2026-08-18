/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.openredirect;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

/**
 * Provides a real 302 redirect for experimentation separate from assignment scoring.
 */
@Controller
public class OpenRedirectRealRedirect {

  @GetMapping("/OpenRedirect/realRedirect")
  public ModelAndView real(@RequestParam("url") String url) {
    // Only permit same-origin relative redirects (must start with "/" but not "//").
    // Protocol-relative ("//evil.com") and absolute ("https://evil.com") URLs are rejected
    // to prevent open redirect abuse. Rotate any exposed credentials and load from env.
    if (url == null || !url.startsWith("/") || url.startsWith("//")) {
      return new ModelAndView("redirect:/");
    }
    return new ModelAndView("redirect:" + url);
  }
}
