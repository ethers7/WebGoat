/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.openredirect;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.lessons.Category;
import org.springframework.web.servlet.ModelAndView;

class OpenRedirectLessonMetadataTest {

  private final OpenRedirect lesson = new OpenRedirect();
  private final OpenRedirectSecureController secureController = new OpenRedirectSecureController();
  private final OpenRedirectRealRedirect realRedirect = new OpenRedirectRealRedirect();

  @Test
  void lessonMetadataMatchesRegistration() {
    assertThat(lesson.getDefaultCategory()).isEqualTo(Category.GENERAL);
    assertThat(lesson.getTitle()).isEqualTo("openredirect.title");
  }

  @Test
  void safeRedirectUsesMappedDestinationWhenKnown() {
    ModelAndView response = secureController.safe(3);

    assertThat(response.getViewName()).isEqualTo("redirect:/logout");
  }

  @Test
  void safeRedirectFallsBackToWelcomeWhenUnknownId() {
    ModelAndView response = secureController.safe(99);

    assertThat(response.getViewName()).isEqualTo("redirect:/welcome.mvc");
  }

  @Test
  void realRedirectAllowsRelativeUrl() {
    ModelAndView response = realRedirect.real("/OpenRedirect/start.mvc");

    assertThat(response.getViewName()).isEqualTo("redirect:/OpenRedirect/start.mvc");
  }

  @Test
  void realRedirectBlocksAbsoluteExternalUrl() {
    ModelAndView response = realRedirect.real("https://attacker.example");

    assertThat(response.getViewName()).isEqualTo("redirect:/");
  }

  @Test
  void realRedirectBlocksProtocolRelativeUrl() {
    ModelAndView response = realRedirect.real("//attacker.example");

    assertThat(response.getViewName()).isEqualTo("redirect:/");
  }

  @Test
  void realRedirectBlocksNullUrl() {
    ModelAndView response = realRedirect.real(null);

    assertThat(response.getViewName()).isEqualTo("redirect:/");
  }
}
