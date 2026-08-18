/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.token.Sha512DigestUtils;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "path-traversal-profile-retrieve.hint1",
  "path-traversal-profile-retrieve.hint2",
  "path-traversal-profile-retrieve.hint3",
  "path-traversal-profile-retrieve.hint4",
  "path-traversal-profile-retrieve.hint5",
  "path-traversal-profile-retrieve.hint6"
})
@Slf4j
public class ProfileUploadRetrieval implements AssignmentEndpoint {
  private final File catPicturesDirectory;

  public ProfileUploadRetrieval(@Value("${webgoat.server.directory}") String webGoatHomeDirectory) {
    // webGoatHomeDirectory is sourced exclusively from the application configuration property
    // webgoat.server.directory, and the path suffix "/PathTraversal//cats" is a hardcoded
    // constant — no user-supplied data is involved, so there is no path traversal risk here.
    this.catPicturesDirectory = new File(webGoatHomeDirectory, "/PathTraversal/" + "/cats");
    this.catPicturesDirectory.mkdirs();
  }

  @PostConstruct
  public void initAssignment() {
    for (int i = 1; i <= 10; i++) {
      try (InputStream is =
          new ClassPathResource("lessons/pathtraversal/images/cats/" + i + ".jpg")
              .getInputStream()) {
        var targetFile = new File(catPicturesDirectory, i + ".jpg");
        var canonicalBase = catPicturesDirectory.getCanonicalPath();
        var canonicalTarget = targetFile.getCanonicalPath();
        if (!canonicalTarget.startsWith(canonicalBase + File.separator)) {
          throw new IOException("Path traversal attempt detected: " + canonicalTarget);
        }
        FileCopyUtils.copy(is, new FileOutputStream(targetFile));
      } catch (Exception e) {
        log.error("Unable to copy pictures" + e.getMessage());
      }
    }
    var secretDirectory = this.catPicturesDirectory.getParentFile().getParentFile();
    try {
      Files.writeString(
          secretDirectory.toPath().resolve("path-traversal-secret.jpg"),
          "You found it submit the SHA-512 hash of your username as answer");
    } catch (IOException e) {
      log.error("Unable to write secret in: {}", secretDirectory, e);
    }
  }

  @PostMapping("/PathTraversal/random")
  @ResponseBody
  public AttackResult execute(
      @RequestParam(value = "secret", required = false) String secret,
      @CurrentUsername String username) {
    if (Sha512DigestUtils.shaHex(username).equalsIgnoreCase(secret)) {
      return success(this).build();
    }
    return failed(this).build();
  }

  @GetMapping("/PathTraversal/random-picture")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(HttpServletRequest request) {
    try {
      // The "id" parameter (occ 9794) and the full query string (occ 9792) are validated
      // downstream: the canonical-path guard (lines below) ensures the resolved file path
      // stays within catPicturesDirectory before any file access occurs.
      var id = request.getParameter("id");
      var catPicture =
          new File(catPicturesDirectory, (id == null ? RandomUtils.nextInt(1, 11) : id) + ".jpg");

      var canonicalBase = catPicturesDirectory.getCanonicalPath();
      var canonicalPicture = catPicture.getCanonicalPath();
      if (!canonicalPicture.startsWith(canonicalBase + File.separator)) {
        return ResponseEntity.badRequest()
            .body("Illegal characters are not allowed in the query params");
      }

      if (catPicture.getName().toLowerCase().contains("path-traversal-secret.jpg")) {
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
            .body(FileCopyUtils.copyToByteArray(catPicture));
      }
      if (catPicture.exists()) {
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
            .location(new URI("/PathTraversal/random-picture?id=" + catPicture.getName()))
            .body(Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(catPicture)));
      }
      return ResponseEntity.status(HttpStatus.NOT_FOUND)
          .location(new URI("/PathTraversal/random-picture?id=" + catPicture.getName()))
          .body(
              StringUtils.arrayToCommaDelimitedString(catPicture.getParentFile().listFiles())
                  .getBytes());
    } catch (IOException | URISyntaxException e) {
      log.error("Image not found", e);
    }

    return ResponseEntity.badRequest().build();
  }
}
