/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * The assignment only accepts a select on the employees table and runs it as a parameterized
 * statement, so the payloads below can no longer read another table or append a statement. They are
 * kept as regression cases and have to be rejected.
 */
public class SqlInjectionLesson2Test extends LessonTest {

  @Test
  public void solution() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack2")
                .param("query", "SELECT department FROM employees WHERE userid=96134;"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  public void solutionByName() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack2")
                .param(
                    "query",
                    "SELECT * FROM employees WHERE first_name='Bob' AND last_name='Franco'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  public void selectingAnotherTableIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack2")
                .param("query", "SELECT password FROM user_system_data WHERE user_name='dave'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", not(containsString("passW0rD"))));
  }

  @Test
  public void appendedStatementIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack2")
                .param(
                    "query",
                    "SELECT department FROM employees WHERE userid='96134'; DROP TABLE employees;"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void tautologyIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack2")
                .param("query", "SELECT * FROM employees WHERE last_name='Franco' or '1'='1'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}
