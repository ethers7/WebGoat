/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

public class SSRFTest2 extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  public void modifyUrlIfconfigPro() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/SSRF/task2").param("url", "http://ifconfig.pro"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  public void modifyUrlCat() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/SSRF/task2").param("url", "images/cat.jpg"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /** Only allowlisted destinations are fetched, every other request is rejected up front. */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/WebGoat/",
        "http://localhost/",
        "http://10.0.0.1/",
        "http://ifconfig.pro@127.0.0.1/",
        "http://ifconfig.pro.attacker.tld",
        "http://attacker.tld/?next=http://ifconfig.pro",
        "file:///etc/passwd"
      })
  public void requestsOutsideTheAllowlistAreRejected(String url) throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/SSRF/task2").param("url", url))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", containsString("images/cat.jpg")));
  }
}
