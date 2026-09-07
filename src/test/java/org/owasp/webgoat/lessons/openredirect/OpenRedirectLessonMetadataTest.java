/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.openredirect;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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
  void realRedirectFollowsValidatedRelativePath() {
    ModelAndView response = realRedirect.real("/welcome.mvc");

    assertThat(response.getViewName()).isEqualTo("redirect:/welcome.mvc");
  }

  @Test
  void realRedirectKeepsQueryStringOfRelativePath() {
    ModelAndView response = realRedirect.real("/OpenRedirect/safe?destId=2");

    assertThat(response.getViewName()).isEqualTo("redirect:/OpenRedirect/safe?destId=2");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "https://attacker.example",
        "http://attacker.example/login",
        "//attacker.example/login",
        "/\\attacker.example",
        "javascript:alert(1)",
        "welcome.mvc",
        " "
      })
  void realRedirectRefusesDestinationsThatCanLeaveTheOrigin(String url) {
    ModelAndView response = realRedirect.real(url);

    assertThat(response.getViewName()).isEqualTo("redirect:/welcome.mvc");
  }
}
