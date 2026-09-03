/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson10Test extends LessonTest {

  @Test
  public void tableExistsIsFailure() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/SqlInjection/attack10").param("action_string", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.entries"))));
  }

  /**
   * The search string is bound as a query parameter, so the appended DROP TABLE statement is
   * searched for as data and never executed: the table survives and the assignment stays unsolved.
   */
  @Test
  public void appendedDropTableStatementDoesNotRemoveTheTable() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "%'; DROP TABLE access_log;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.entries"))));

    // the access_log table is still there, so the lesson still reports entries
    mockMvc
        .perform(MockMvcRequestBuilders.post("/SqlInjection/attack10").param("action_string", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.entries"))));
  }
}
