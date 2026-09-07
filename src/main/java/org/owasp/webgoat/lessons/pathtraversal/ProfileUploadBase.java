/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.io.FilenameUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.FileSystemUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

@Getter
public class ProfileUploadBase implements AssignmentEndpoint {

  private final String webGoatHomeDirectory;

  public ProfileUploadBase(String webGoatHomeDirectory) {
    this.webGoatHomeDirectory = webGoatHomeDirectory;
  }

  protected AttackResult execute(MultipartFile file, String fullName, String username) {
    if (file.isEmpty()) {
      return failed(this).feedback("path-traversal-profile-empty-file").build();
    }
    if (StringUtils.isEmpty(fullName)) {
      return failed(this).feedback("path-traversal-profile-empty-name").build();
    }

    File uploadDirectory = cleanupAndCreateDirectoryForUser(username);

    try {
      var requestedFile = resolveCanonical(uploadDirectory, fullName);
      if (!isWithin(uploadDirectory, requestedFile)) {
        // The name traverses out of the upload directory of the user. Nothing is written
        // outside that directory, the attempt itself is what the assignment grades.
        return solvedIt(requestedFile);
      }
      requestedFile.createNewFile();
      FileCopyUtils.copy(file.getBytes(), requestedFile);

      return informationMessage(this)
          .feedback("path-traversal-profile-updated")
          .feedbackArgs(requestedFile.getAbsoluteFile())
          .build();

    } catch (IOException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  @SneakyThrows
  protected File cleanupAndCreateDirectoryForUser(String username) {
    var uploadDirectory = resolveWithin(pathTraversalDirectory(), username);
    if (uploadDirectory.exists()) {
      FileSystemUtils.deleteRecursively(uploadDirectory);
    }
    Files.createDirectories(uploadDirectory.toPath());
    return uploadDirectory;
  }

  /**
   * Resolves {@code name} inside {@code directory}, rejecting anything that escapes it.
   *
   * <p>The canonical location has to be a real descendant of the given directory, so a tampered
   * name can never make these assignments read from or write to an arbitrary place on the
   * filesystem.
   */
  protected static File resolveWithin(File directory, String name) throws IOException {
    var base = directory.getCanonicalFile();
    var resolvedFile = resolveCanonical(base, name);
    if (resolvedFile.equals(base) || !isWithin(base, resolvedFile)) {
      throw new IOException("Refusing to leave " + base + ": " + name);
    }
    return resolvedFile;
  }

  /** Canonicalizes {@code name} relative to {@code directory}, without confining it. */
  protected static File resolveCanonical(File directory, String name) throws IOException {
    var base = directory.getCanonicalFile().toPath();
    try {
      return base.resolve(name).normalize().toFile().getCanonicalFile();
    } catch (InvalidPathException e) {
      throw new IOException("Invalid file name", e);
    }
  }

  /** Tells whether {@code candidate} is located inside {@code directory}. */
  protected static boolean isWithin(File directory, File candidate) throws IOException {
    var base = directory.getCanonicalFile().toPath();
    return candidate.getCanonicalFile().toPath().startsWith(base);
  }

  private File pathTraversalDirectory() {
    return new File(this.webGoatHomeDirectory, "PathTraversal");
  }

  private AttackResult solvedIt(File requestedFile) {
    if (requestedFile.getParentFile().getName().endsWith("PathTraversal")) {
      return success(this).build();
    }
    return failed(this)
        .attemptWasMade()
        .feedback("path-traversal-profile-attempt")
        .feedbackArgs(requestedFile.getPath())
        .build();
  }

  public ResponseEntity<?> getProfilePicture(@CurrentUsername String username) {
    return ResponseEntity.ok()
        .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
        .body(getProfilePictureAsBase64(username));
  }

  protected byte[] getProfilePictureAsBase64(String username) {
    try {
      var profilePictureDirectory = resolveWithin(pathTraversalDirectory(), username);
      var profileDirectoryFiles = profilePictureDirectory.listFiles();

      if (profileDirectoryFiles == null || profileDirectoryFiles.length == 0) {
        return defaultImage();
      }
      return Arrays.stream(profileDirectoryFiles)
          .filter(file -> FilenameUtils.isExtension(file.getName(), List.of("jpg", "png")))
          .findFirst()
          .map(file -> readProfilePicture(profilePictureDirectory, file))
          .orElse(defaultImage());
    } catch (IOException e) {
      return defaultImage();
    }
  }

  private byte[] readProfilePicture(File profilePictureDirectory, File profilePicture) {
    try {
      var picture = resolveWithin(profilePictureDirectory, profilePicture.getName());
      try (var inputStream = new FileInputStream(picture)) {
        return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
      }
    } catch (IOException e) {
      return defaultImage();
    }
  }

  @SneakyThrows
  protected byte[] defaultImage() {
    var inputStream = getClass().getResourceAsStream("/images/account.png");
    return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
  }
}
