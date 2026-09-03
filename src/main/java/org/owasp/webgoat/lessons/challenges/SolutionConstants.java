/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

public interface SolutionConstants {

  // TODO should be random generated when starting the server
  // Non-production challenge fixture: the sample password students recover while solving the
  // challenges, it grants no access outside these lessons, nothing to rotate.
  String PASSWORD = "!!webgoat_admin_1234!!";
}
