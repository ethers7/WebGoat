/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.deserialization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.io.InvalidClassException;
import java.util.HashMap;
import org.junit.jupiter.api.Test;

class SerializationHelperTest {

  @Test
  void allowedClassIsDeserialized() throws Exception {
    String token = SerializationHelper.toString("hello");

    assertThat(SerializationHelper.fromString(token)).isEqualTo("hello");
  }

  @Test
  void classWhichIsNotOnTheAllowListIsRejected() throws Exception {
    String token = SerializationHelper.toString(new HashMap<String, String>());

    assertThatExceptionOfType(InvalidClassException.class)
        .isThrownBy(() -> SerializationHelper.fromString(token));
  }
}
