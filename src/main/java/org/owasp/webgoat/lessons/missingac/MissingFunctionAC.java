/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import org.owasp.webgoat.container.lessons.Category;
import org.owasp.webgoat.container.lessons.Lesson;
import org.springframework.stereotype.Component;

@Component
public class MissingFunctionAC extends Lesson {

  // Not keys or credentials: these are the password salts of this lesson. They are deliberately
  // static and predictable because that is the weakness the lesson demonstrates (see
  // DisplayUser#genUserHash), and the hashes derived from them are handed out by the lesson's own
  // endpoints. A salt does not have to be secret, so there is nothing to hide or to rotate.
  public static final String PASSWORD_SALT_SIMPLE = "DeliberatelyInsecure1234";
  public static final String PASSWORD_SALT_ADMIN = "DeliberatelyInsecure1235";

  @Override
  public Category getDefaultCategory() {
    return Category.A1;
  }

  @Override
  public String getTitle() {
    return "missing-function-access-control.title";
  }
}
