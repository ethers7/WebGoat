/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.deserialization;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;

public class SerializationHelper {

  private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

  // Allow-list limiting deserialization to the classes this lesson exchanges (CWE-502): the task
  // class in org.dummy.insecure.framework plus the String and java.time values it holds. Any
  // other class is rejected before it is instantiated, so a crafted stream cannot reach a
  // gadget class on the class path, and the depth/byte limits cap a hostile stream.
  private static final String SERIAL_FILTER_PATTERN =
      "maxdepth=10;maxbytes=8192;org.dummy.insecure.framework.*;java.lang.String;java.time.*;!*";

  private static final ObjectInputFilter SERIAL_FILTER =
      ObjectInputFilter.Config.createFilter(SERIAL_FILTER_PATTERN);

  /** Returns the allow-list filter to install on every stream this lesson deserializes. */
  static ObjectInputFilter lessonObjectInputFilter() {
    return SERIAL_FILTER;
  }

  public static Object fromString(String s) throws IOException, ClassNotFoundException {
    byte[] data = Base64.getDecoder().decode(s);
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
      ois.setObjectInputFilter(SERIAL_FILTER);
      return ois.readObject();
    }
  }

  public static String toString(Serializable o) throws IOException {

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(baos);
    oos.writeObject(o);
    oos.close();
    return Base64.getEncoder().encodeToString(baos.toByteArray());
  }

  public static String show() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    dos.writeLong(-8699352886133051976L);
    dos.close();
    byte[] longBytes = baos.toByteArray();
    return bytesToHex(longBytes);
  }

  public static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }
}
