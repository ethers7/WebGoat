/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

// Allow lists for the 'employees' table used by the SQL introduction assignments.
//
// Those assignments let the student submit a complete statement, but the submitted text is never
// sent to the database. The assignment matches it against a fixed statement shape, resolves the
// table and column names with this class (an identifier cannot be bound as a parameter) and binds
// every literal as a parameter. A statement which does not resolve is rejected, not executed.
final class EmployeesSchema {

  private static final String TABLE = "employees";

  private static final Set<String> COLUMNS =
      Set.of("userid", "first_name", "last_name", "department", "salary", "auth_tan", "phone");

  private static final Set<String> NUMERIC_COLUMNS = Set.of("salary");

  private EmployeesSchema() {}

  // Checks the table name of a submitted statement, only the employees table is allowed.
  static boolean isTable(String table) {
    return TABLE.equalsIgnoreCase(table.trim());
  }

  // Resolves a column name of a submitted statement to a known column of the employees table.
  static Optional<String> column(String column) {
    var candidate = column.trim().toLowerCase(Locale.ROOT);
    return COLUMNS.contains(candidate) ? Optional.of(candidate) : Optional.empty();
  }

  // Resolves the select list of a submitted statement, either an asterisk or known columns.
  static Optional<String> columnList(String columns) {
    if ("*".equals(columns.trim())) {
      return Optional.of("*");
    }
    var resolved = new LinkedHashSet<String>();
    for (String column : columns.split(",")) {
      var known = column(column);
      if (known.isEmpty()) {
        return Optional.empty();
      }
      resolved.add(known.get());
    }
    return Optional.of(String.join(", ", resolved));
  }

  // Binds a literal of a submitted statement as a parameter, so it always stays a value.
  static void bindLiteral(PreparedStatement statement, int index, String column, String literal)
      throws SQLException {
    var value = unquote(literal);
    if (NUMERIC_COLUMNS.contains(column)) {
      try {
        statement.setInt(index, Integer.parseInt(value));
      } catch (NumberFormatException e) {
        throw new SQLException("The value for column " + column + " must be a number");
      }
    } else {
      statement.setString(index, value);
    }
  }

  private static String unquote(String literal) {
    var value = literal.trim();
    if (value.length() > 1 && value.startsWith("'") && value.endsWith("'")) {
      return value.substring(1, value.length() - 1).replace("''", "'");
    }
    return value;
  }
}
