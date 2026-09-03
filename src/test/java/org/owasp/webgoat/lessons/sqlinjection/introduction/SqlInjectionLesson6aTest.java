/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson6aTest extends LessonTest {

  @Test
  public void wrongSolution() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "John"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /** An existing last name still returns the employees, but does not solve the assignment. */
  @Test
  public void existingAccountNameDoesNotSolveTheAssignment() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(content().string(not(containsString("passW0rD"))));
  }

  /**
   * The account name is bound as a query parameter, so the appended UNION is searched for as a last
   * name and the passwords of the other table are never returned.
   */
  @Test
  public void unionSelectIsTreatedAsData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param(
                    "userid_6a",
                    "Smith' union select userid,user_name, password,cookie,cookie, cookie,userid"
                        + " from user_system_data --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", containsString("last_name = ?")))
        .andExpect(content().string(not(containsString("passW0rD"))));
  }

  /**
   * The account name is bound as a query parameter, so the appended statement is searched for as a
   * last name and is never executed.
   */
  @Test
  public void appendedSelectStatementIsTreatedAsData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith'; SELECT * from user_system_data; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(content().string(not(containsString("passW0rD"))));
  }

  @Test
  public void noResultsReturned() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith' and 1 = 2 --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(
            jsonPath(
                "$.feedback", is(messages.getMessage("sql-injection.advanced.6a.no.results"))));
  }
}
