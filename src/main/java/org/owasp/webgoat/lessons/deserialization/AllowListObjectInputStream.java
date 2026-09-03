/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.deserialization;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Set;

/** Object input stream which only deserializes an explicit allow list of classes. */
public class AllowListObjectInputStream extends ObjectInputStream {

  /** Maximum number of serialized bytes which is accepted for deserialization. */
  public static final int MAX_BYTES = 4096;

  // Only the task holder used by this lesson and the types it serializes are accepted. Any other
  // class, for instance a gadget chain, is rejected before the class is loaded and before any
  // readObject() implementation is invoked.
  private static final Set<String> ALLOWED_CLASSES =
      Set.of(
          "org.dummy.insecure.framework.VulnerableTaskHolder",
          "java.time.Ser",
          "java.time.LocalDateTime",
          "java.lang.String");

  // Second line of defence: bound the size, depth and number of references of the stream so that a
  // small payload cannot exhaust memory while being deserialized.
  private static final ObjectInputFilter LIMITS_FILTER =
      ObjectInputFilter.Config.createFilter("maxdepth=10;maxrefs=64;maxbytes=4096;maxarray=16");

  public AllowListObjectInputStream(InputStream in) throws IOException {
    super(in);
    setObjectInputFilter(LIMITS_FILTER);
  }

  /** Creates a stream for the given serialized data, rejecting oversized payloads up front. */
  public static AllowListObjectInputStream from(byte[] data) throws IOException {
    if (data.length > MAX_BYTES) {
      throw new UnsafeDeserializationException("byte[]", "payload is larger than allowed");
    }
    return new AllowListObjectInputStream(new ByteArrayInputStream(data));
  }

  @Override
  protected Class<?> resolveClass(ObjectStreamClass desc)
      throws IOException, ClassNotFoundException {
    if (!ALLOWED_CLASSES.contains(desc.getName())) {
      throw new UnsafeDeserializationException(desc.getName(), "class is not on the allow list");
    }
    return super.resolveClass(desc);
  }

  @Override
  protected Class<?> resolveProxyClass(String[] interfaces)
      throws IOException, ClassNotFoundException {
    throw new UnsafeDeserializationException(
        "java.lang.reflect.Proxy", "dynamic proxies are not allowed");
  }
}
