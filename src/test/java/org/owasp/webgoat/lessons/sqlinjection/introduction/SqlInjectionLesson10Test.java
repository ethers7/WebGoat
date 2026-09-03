/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.containsString;
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
   * The search term is bound as a LIKE parameter, so the chained DROP TABLE is only compared as
   * text. The lesson keeps working and the access_log table survives, which the follow up search
   * below proves: a dropped table would raise a SQL error and report the lesson as solved.
   */
  @Test
  public void dropTablePayloadNoLongerRemovesTheTable() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "%'; DROP TABLE access_log;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.entries"))));

    mockMvc
        .perform(MockMvcRequestBuilders.post("/SqlInjection/attack10").param("action_string", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.entries"))))
        .andExpect(jsonPath("$.output", containsString("<table>")));
  }
}
