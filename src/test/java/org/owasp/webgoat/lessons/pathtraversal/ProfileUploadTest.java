/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.File;
import java.util.Base64;
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

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload")
                .file(profilePicture)
                .param("fullName", "../John Doe"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.assignment", CoreMatchers.equalTo("ProfileUpload")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  @Test
  @WithWebGoatUser
  void attemptWithWrongDirectory() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFile", "../picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload")
                .file(profilePicture)
                .param("fullName", "../../" + "test"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.assignment", CoreMatchers.equalTo("ProfileUpload")))
        .andExpect(jsonPath("$.feedback", CoreMatchers.containsString("Nice try")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  @WithWebGoatUser
  void shouldNotWriteOutsideOfTheDirectoryOfTheUser() throws Exception {
    var profilePicture =
        new MockMultipartFile("uploadedFile", "picture.jpg", "text/plain", "an image".getBytes());
    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload")
                .file(profilePicture)
                .param("fullName", ".." + File.separator + "picture.jpg"))
        .andExpect(status().is(200));

    // The traversal is contained, the file is written inside the directory of the user itself and
    // is therefore served as the profile picture of that user. Before the fix the file was written
    // one directory up and the default image was returned here.
    mockMvc
        .perform(MockMvcRequestBuilders.get("/PathTraversal/profile-picture"))
        .andExpect(status().is(200))
        .andExpect(content().bytes(Base64.getEncoder().encode("an image".getBytes())));
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
