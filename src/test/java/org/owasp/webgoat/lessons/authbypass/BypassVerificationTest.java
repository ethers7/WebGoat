/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class BypassVerificationTest extends LessonTest {

  // The flaw this lesson teaches lives in the verification logic: renaming the security question
  // parameters skips the answer comparison. That attack must keep working.
  @Test
  void renamedSecurityQuestionsStillBypassVerification() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/auth-bypass/verify-account")
                .param("secQuestion2", "John")
                .param("secQuestion3", "Main")
                .param("jsEnabled", "1")
                .param("verifyMethod", "SEC_QUESTIONS")
                .param("userId", "12309746"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("verify-account.success"))));
  }

  // Parameter names that merely contain "secQuestion", or that are longer or use other characters
  // than the expected shape, are not collected anymore and cannot fill the answer map.
  @Test
  void parametersOutsideTheExpectedShapeAreIgnored() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/auth-bypass/verify-account")
                .param("mysecQuestion1", "John")
                .param("secQuestion_1", "Main")
                .param("secQuestion12345", "Baker Street")
                .param("jsEnabled", "1")
                .param("verifyMethod", "SEC_QUESTIONS")
                .param("userId", "12309746"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("verify-account.failed"))));
  }

  @Test
  void tooManySecurityQuestionsAreRejected() throws Exception {
    var request =
        MockMvcRequestBuilders.post("/auth-bypass/verify-account")
            .param("jsEnabled", "1")
            .param("verifyMethod", "SEC_QUESTIONS")
            .param("userId", "12309746");
    for (int i = 10; i <= 20; i++) {
      request.param("secQuestion" + i, "John");
    }

    mockMvc
        .perform(request)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("verify-account.failed"))));
  }

  @Test
  void oversizedAnswersAreRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/auth-bypass/verify-account")
                .param("secQuestion2", "J".repeat(101))
                .param("secQuestion3", "Main")
                .param("jsEnabled", "1")
                .param("verifyMethod", "SEC_QUESTIONS")
                .param("userId", "12309746"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("verify-account.failed"))));
  }

  // The expected parameter names are still accepted, so submitting the stored answers is still
  // reported as having looked them up in the source code.
  @Test
  void expectedSecurityQuestionsAreStillAccepted() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/auth-bypass/verify-account")
                .param("secQuestion0", "Dr. Watson")
                .param("secQuestion1", "Baker Street")
                .param("jsEnabled", "1")
                .param("verifyMethod", "SEC_QUESTIONS")
                .param("userId", "12309746"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("verify-account.cheated"))));
  }
}
