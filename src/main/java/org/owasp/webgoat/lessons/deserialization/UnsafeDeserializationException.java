/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.deserialization;

import java.io.InvalidClassException;

/** Signals that a stream contained data which this application refuses to deserialize. */
public class UnsafeDeserializationException extends InvalidClassException {

  private static final long serialVersionUID = 1;

  public UnsafeDeserializationException(String cname, String reason) {
    super(cname, reason);
  }
}
