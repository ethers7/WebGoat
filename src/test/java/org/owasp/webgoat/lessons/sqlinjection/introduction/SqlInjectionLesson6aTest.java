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
 * The lesson binds the account name as a parameter, so none of the payloads below reaches the SQL
 * parser any more. They are kept as regression cases: every one of them must be treated as a plain
 * last name, which matches no row, and must never return data from user_system_data.
 */
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

  @Test
  public void knownAccountShouldDisplayData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", containsString("USERID")))
        .andExpect(jsonPath("$.output", not(containsString("passW0rD"))));
  }

  @Test
  public void unionWithWrongNumberOfColumnsIsTreatedAsData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param(
                    "userid_6a",
                    "Smith' union select userid,user_name, password,cookie from user_system_data"
                        + " --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.6a.no.results"))))
        .andExpect(jsonPath("$.output", not(containsString("passW0rD"))));
  }

  @Test
  public void unionWithWrongDataTypeOfColumnsIsTreatedAsData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param(
                    "userid_6a",
                    "Smith' union select 1,password, 1,'2','3', '4',1 from user_system_data --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.6a.no.results"))))
        .andExpect(jsonPath("$.output", not(containsString("passW0rD"))));
  }

  /** The payload which used to solve the assignment by appending a second statement. */
  @Test
  public void chainedStatementNoLongerReturnsSystemData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith'; SELECT * from user_system_data; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.6a.no.results"))))
        .andExpect(jsonPath("$.output", not(containsString("passW0rD"))));
  }

  @Test
  public void noResultsReturned() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith' and 1 = 2 --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.6a.no.results"))));
  }

  /** The payload which used to solve the assignment without using a UNION. */
  @Test
  public void chainedSelectNoLongerReturnsSystemData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "S'; Select * from user_system_data; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.6a.no.results"))))
        .andExpect(jsonPath("$.output", not(containsString("passW0rD"))));
  }
}
