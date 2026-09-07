/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

public interface SolutionConstants {

  // TODO should be random generated when starting the server
  // Not a credential: the answer template of challenge 1. Assignment1 replaces its digits with
  // ImageServlet.PINCODE, which is generated randomly on every server start, so this literal on
  // its own authenticates nothing and there is nothing to rotate.
  String PASSWORD = "!!webgoat_admin_1234!!";
}
