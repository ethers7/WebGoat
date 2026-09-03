/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class VerifyAccountTest {

  private static final String USER_ID = "1223445";

  private MockMvc mockMvc;

  @BeforeEach
  void setupEndpoint() {
    mockMvc = MockMvcBuilders.standaloneSetup(new VerifyAccount(new LessonSession())).build();
  }

  @Test
  @DisplayName("Wrong answers to the security questions do not verify the account")
  void shouldNotVerifyAccountWithWrongAnswers() throws Exception {
    mockMvc
        .perform(
            verifyAccount()
                .param("secQuestion0", "Dr. Who")
                .param("secQuestion1", "Downing Street"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.feedback").value("verify-account.failed"));
  }

  @Test
  @DisplayName("Renaming the security questions still bypasses the verification (lesson goal)")
  void shouldVerifyAccountWithRenamedSecurityQuestions() throws Exception {
    mockMvc
        .perform(verifyAccount().param("secQuestion2", "John").param("secQuestion3", "Main"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.feedback").value("verify-account.success"));
  }

  @Test
  @DisplayName("A security question parameter which is not well formed is rejected")
  void shouldRejectMalformedSecurityQuestionParameter() throws Exception {
    mockMvc
        .perform(verifyAccount().param("secQuestion0[]", "Dr. Watson"))
        .andExpect(status().isBadRequest());

    mockMvc
        .perform(verifyAccount().param("mysecQuestion", "Dr. Watson"))
        .andExpect(status().isBadRequest());
  }

  @Test
  @DisplayName("An answer to a security question which is too long is rejected")
  void shouldRejectTooLongAnswer() throws Exception {
    mockMvc
        .perform(verifyAccount().param("secQuestion0", "a".repeat(101)))
        .andExpect(status().isBadRequest());
  }

  private MockHttpServletRequestBuilder verifyAccount() {
    return post("/auth-bypass/verify-account")
        .param("userId", USER_ID)
        .param("verifyMethod", "SEC_QUESTIONS");
  }
}
