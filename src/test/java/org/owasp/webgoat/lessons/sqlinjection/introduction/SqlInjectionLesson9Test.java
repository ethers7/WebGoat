/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson9Test extends LessonTest {

  /** A valid name and TAN still queries the employee, but does not solve the assignment. */
  @Test
  public void validInputDoesNotSolveTheAssignment() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.9.one"))));
  }

  /** Unbalanced quotes are bound as data and can no longer break out of the query. */
  @Test
  public void quotesInTheTanAreTreatedAsData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A' OR '1' = '1'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  @Test
  public void SmithIsNotMostEarning() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param(
                    "auth_tan",
                    "3SL99A'; UPDATE employees SET salary = 9999 WHERE last_name = 'Smith"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  @Test
  public void OnlySmithSalaryMustBeUpdated() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A'; UPDATE employees SET salary = 9999 -- "))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  @Test
  public void OnlySmithMustMostEarning() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "'; UPDATE employees SET salary = 999999 -- ")
                .param("auth_tan", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * The name and the TAN are bound as query parameters, so the appended UPDATE statement is stored
   * as data and never executed: the salary is not raised and the assignment stays unsolved.
   */
  @Test
  public void appendedUpdateStatementDoesNotChangeTheSalary() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param(
                    "auth_tan",
                    "3SL99A'; UPDATE employees SET salary = '300000' WHERE last_name = 'Smith"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(content().string(not(containsString("300000"))));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.9.one"))))
        .andExpect(content().string(not(containsString("300000"))));
  }
}
