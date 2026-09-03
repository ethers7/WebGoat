/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson5aTest extends LessonTest {

  @Test
  public void knownAccountShouldDisplayData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("assignment.not.solved"))))
        .andExpect(jsonPath("$.output", containsString("<p>USERID, FIRST_NAME")));
  }

  @Disabled
  @Test
  public void unknownAccount() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("NoResultsMatched"))))
        .andExpect(jsonPath("$.output").doesNotExist());
  }

  /**
   * The account name is bound as a query parameter, so the always true condition is compared as
   * data and no longer returns every row.
   */
  @Test
  public void sqlInjectionDoesNotSolveTheAssignment() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "'")
                .param("operator", "OR")
                .param("injection", "'1' = '1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.5a.no.results"))));
  }

  /** Unbalanced quotes are data now, they can no longer produce a malformed query. */
  @Test
  public void sqlInjectionWithUnbalancedQuotesIsTreatedAsData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith'")
                .param("operator", "OR")
                .param("injection", "'1' = '1'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.5a.no.results"))))
        .andExpect(
            jsonPath(
                "$.output",
                is(
                    "Your query was: SELECT * FROM user_data WHERE first_name = 'John' and"
                        + " last_name = ?")));
  }
}
