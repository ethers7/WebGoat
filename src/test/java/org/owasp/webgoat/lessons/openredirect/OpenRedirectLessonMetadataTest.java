/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.openredirect;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.container.lessons.Category;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
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
  void realRedirectAllowsAllowListedInternalPath() {
    ModelAndView response = realRedirect.real("/login");

    assertThat(response.getViewName()).isEqualTo("redirect:/login");
  }

  @Test
  void realRedirectNormalizesBeforeMatchingAllowList() {
    ModelAndView response = realRedirect.real("/webgoat/../welcome.mvc");

    assertThat(response.getViewName()).isEqualTo("redirect:/welcome.mvc");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "https://attacker.example",
        "http://attacker.example/login",
        "//attacker.example",
        "/\\attacker.example",
        "\\\\attacker.example",
        "javascript:alert(1)",
        "/../../etc/passwd",
        "/login?next=https://attacker.example",
        "/unknown-internal-path",
        " "
      })
  void realRedirectRejectsEverythingOutsideTheAllowList(String url) {
    assertThatThrownBy(() -> realRedirect.real(url))
        .isInstanceOf(ResponseStatusException.class)
        .extracting(e -> ((ResponseStatusException) e).getStatusCode())
        .isEqualTo(HttpStatus.BAD_REQUEST);
  }
}
