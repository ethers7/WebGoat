/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.File;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@WithWebGoatUser
class ProfileUploadTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void solve() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFile", "../picture.jpg", "text/plain", "an image".getBytes());

    // Path traversal in fullName is now rejected by canonical path validation in the base class.
    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload")
                .file(profilePicture)
                .param("fullName", "../John Doe"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.assignment", CoreMatchers.equalTo("ProfileUpload")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  @WithWebGoatUser
  void attemptWithWrongDirectory() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFile", "../picture.jpg", "text/plain", "an image".getBytes());

    // Path traversal in fullName is now rejected by canonical path validation in the base class.
    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload")
                .file(profilePicture)
                .param("fullName", "../../" + "test"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.assignment", CoreMatchers.equalTo("ProfileUpload")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  @WithWebGoatUser
  void shouldNotOverrideExistingFile() throws Exception {
    var profilePicture =
        new MockMultipartFile("uploadedFile", "picture.jpg", "text/plain", "an image".getBytes());
    // Path traversal in fullName is rejected by canonical path validation before any file I/O.
    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload")
                .file(profilePicture)
                .param("fullName", ".." + File.separator + "test"))
        .andExpect(
            jsonPath(
                "$.output",
                CoreMatchers.containsString("Path traversal attempt detected in filename")))
        .andExpect(status().is(200));
  }

  @Test
  void normalUpdate() throws Exception {
    var profilePicture =
        new MockMultipartFile("uploadedFile", "picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload")
                .file(profilePicture)
                .param("fullName", "John Doe"))
        .andExpect(status().is(200))
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.containsStringIgnoringCase(
                    "PathTraversal\\" + File.separator + "test\\" + File.separator + "John Doe")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
