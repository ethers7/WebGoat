/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlOnlyInputValidationTest extends LessonTest {

  /**
   * Bypassing the space validation is still possible, but the underlying query binds the account
   * name as a parameter, so the appended statement is searched for as a last name instead of being
   * executed.
   */
  @Test
  public void injectionIsTreatedAsData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidation/attack")
                .param(
                    "userid_sql_only_input_validation",
                    "Smith';SELECT/**/*/**/from/**/user_system_data;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", containsString("last_name = ?")))
        .andExpect(content().string(not(containsString("passW0rD"))));
  }

  @Test
  public void containsSpace() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidation/attack")
                .param(
                    "userid_sql_only_input_validation", "Smith' ;SELECT from user_system_data;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", containsString("Using spaces is not allowed!")));
  }
}
