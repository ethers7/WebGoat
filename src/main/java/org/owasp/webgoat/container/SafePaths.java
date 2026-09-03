/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import org.apache.commons.io.FilenameUtils;

/**
 * Helpers which keep file system access confined to the directory the application owns.
 *
 * <p>Values which originate from a request (user names, uploaded file names, request parameters)
 * must never be used as a path directly. A value such as {@code ../../etc} would otherwise allow a
 * caller to read or write files outside of the intended directory.
 */
public final class SafePaths {

  /** Matches control characters, a NUL byte in a name confuses the underlying file system calls. */
  private static final String CONTROL_CHARACTERS = "\\p{Cntrl}";

  private SafePaths() {}

  /**
   * Reduces a value which originates from a request to a single file system segment.
   *
   * <p>All directory information is dropped, so the result can never contain a path separator or a
   * reference to a parent directory. An empty string is returned when nothing usable remains.
   */
  public static String segment(String name) {
    if (name == null) {
      return "";
    }
    var candidate = FilenameUtils.getName(name).replaceAll(CONTROL_CHARACTERS, "").trim();
    if (candidate.isEmpty() || ".".equals(candidate) || "..".equals(candidate)) {
      return "";
    }
    return candidate;
  }

  /**
   * Resolves the given segments inside {@code baseDirectory} and verifies the outcome really stays
   * inside that directory.
   *
   * <p>Every segment is first reduced with {@link #segment(String)} and the canonical result is
   * compared against the canonical base directory afterwards, which also rejects an escape through
   * a symbolic link.
   *
   * @throws IOException when a segment is unusable or when the result is outside {@code
   *     baseDirectory}
   */
  public static File resolveWithin(File baseDirectory, String... segments) throws IOException {
    Path base = baseDirectory.getCanonicalFile().toPath();
    Path resolved = base;
    for (String segment : segments) {
      var safeSegment = segment(segment);
      if (safeSegment.isEmpty()) {
        throw new IOException("Illegal file name");
      }
      resolved = resolved.resolve(safeSegment);
    }
    var canonical = resolved.toFile().getCanonicalFile();
    if (!canonical.toPath().startsWith(base)) {
      throw new IOException("Resolved path is outside of the expected directory");
    }
    return canonical;
  }
}
