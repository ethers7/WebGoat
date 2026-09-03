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
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.io.FilenameUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.SafePaths;
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
      // The name supplied by the caller is reduced to a bare file name and the result is verified
      // to stay inside the directory of the user, so a name like '../../file' can no longer write
      // outside of that directory.
      var uploadedFile = SafePaths.resolveWithin(uploadDirectory, fullName);
      uploadedFile.createNewFile();
      FileCopyUtils.copy(file.getBytes(), uploadedFile);

      // The unsanitized name is only used to report back whether an attack was attempted, it is
      // never handed to a file API.
      var requestedLocation = toRequestedLocation(uploadDirectory, fullName);
      if (attemptWasMade(uploadDirectory, requestedLocation)) {
        return solvedIt(requestedLocation);
      }
      return informationMessage(this)
          .feedback("path-traversal-profile-updated")
          .feedbackArgs(uploadedFile.getAbsoluteFile())
          .build();

    } catch (IOException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  @SneakyThrows
  protected File cleanupAndCreateDirectoryForUser(String username) {
    var uploadDirectory = directoryForUser(username);
    if (uploadDirectory.exists()) {
      FileSystemUtils.deleteRecursively(uploadDirectory);
    }
    Files.createDirectories(uploadDirectory.toPath());
    return uploadDirectory;
  }

  /**
   * Returns the upload directory of the given user, the user name is reduced to a single path
   * segment so it cannot point to a directory outside of the WebGoat home directory.
   */
  private File directoryForUser(String username) throws IOException {
    return SafePaths.resolveWithin(new File(this.webGoatHomeDirectory), "PathTraversal", username);
  }

  /** Location the caller asked for, used to give feedback only, never to open a file. */
  private Path toRequestedLocation(File uploadDirectory, String fullName) throws IOException {
    try {
      return uploadDirectory.getCanonicalFile().toPath().resolve(fullName).normalize();
    } catch (InvalidPathException e) {
      throw new IOException("Illegal file name");
    }
  }

  private boolean attemptWasMade(File expectedUploadDirectory, Path requestedLocation)
      throws IOException {
    return !expectedUploadDirectory
        .getCanonicalFile()
        .toPath()
        .equals(requestedLocation.getParent());
  }

  private AttackResult solvedIt(Path requestedLocation) {
    var parent = requestedLocation.getParent();
    if (parent != null
        && parent.getFileName() != null
        && parent.getFileName().toString().endsWith("PathTraversal")) {
      return success(this).build();
    }
    return failed(this)
        .attemptWasMade()
        .feedback("path-traversal-profile-attempt")
        .feedbackArgs(requestedLocation.toString())
        .build();
  }

  public ResponseEntity<?> getProfilePicture(@CurrentUsername String username) {
    return ResponseEntity.ok()
        .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
        .body(getProfilePictureAsBase64(username));
  }

  protected byte[] getProfilePictureAsBase64(String username) {
    File[] profileDirectoryFiles;
    try {
      profileDirectoryFiles = directoryForUser(username).listFiles();
    } catch (IOException e) {
      return defaultImage();
    }

    if (profileDirectoryFiles != null && profileDirectoryFiles.length > 0) {
      // Read the file which passed the extension check instead of the first file in the directory,
      // otherwise that check can be bypassed.
      return Arrays.stream(profileDirectoryFiles)
          .filter(file -> FilenameUtils.isExtension(file.getName(), List.of("jpg", "png")))
          .findFirst()
          .map(
              file -> {
                try (var inputStream = new FileInputStream(file)) {
                  return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
                } catch (IOException e) {
                  return defaultImage();
                }
              })
          .orElse(defaultImage());
    } else {
      return defaultImage();
    }
  }

  @SneakyThrows
  protected byte[] defaultImage() {
    var inputStream = getClass().getResourceAsStream("/images/account.png");
    return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
  }
}
