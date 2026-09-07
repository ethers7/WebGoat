/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {"SqlStringInjectionHint4-1", "SqlStringInjectionHint4-2", "SqlStringInjectionHint4-3"})
public class SqlInjectionLesson4 implements AssignmentEndpoint {

  // A submitted statement is only executed when it adds a single column to the employees table. A
  // column name and a data type cannot be bound as parameters, so they are only accepted when they
  // match the pattern below and the data type is one of the allow listed types.
  private static final Pattern ADD_COLUMN_STATEMENT =
      Pattern.compile(
          "(?i)\\s*alter\\s+table\\s+(?<table>\\w+)\\s+add\\s+(?:column\\s+)?"
              + "(?<column>[a-z]\\w{0,29})\\s+(?<type>[a-z]+)"
              + "(?:\\s*\\(\\s*(?<size>\\d{1,4})\\s*\\))?\\s*;?\\s*");

  private static final Set<String> DATA_TYPES =
      Set.of("varchar", "char", "int", "integer", "bigint", "smallint", "boolean", "date");

  private static final String REJECTED = "Only adding a column to employees is executed.";

  private final LessonDataSource dataSource;

  public SqlInjectionLesson4(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack4")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    var matcher = ADD_COLUMN_STATEMENT.matcher(query);
    if (!matcher.matches() || !EmployeesSchema.isTable(matcher.group("table"))) {
      return failed(this).output(REJECTED).build();
    }
    var column = matcher.group("column").toLowerCase(Locale.ROOT);
    var type = matcher.group("type").toLowerCase(Locale.ROOT);
    if (!DATA_TYPES.contains(type)) {
      return failed(this).output(REJECTED).build();
    }
    var size = matcher.group("size");
    var dataType = size == null ? type : type + "(" + size + ")";
    // Only the validated column name and data type end up in the statement below.
    var safeQuery = "ALTER TABLE employees ADD COLUMN %s %s".formatted(column, dataType);

    try (Connection connection = dataSource.getConnection()) {
      try (var statement = connection.prepareStatement(safeQuery)) {
        statement.execute();
      }
      connection.commit();
      return checkSolution(connection, safeQuery);
    } catch (SQLException sqle) {
      return failed(this).output(sqle.getMessage()).build();
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }

  private AttackResult checkSolution(Connection connection, String safeQuery) throws SQLException {
    // The user completes the lesson if the column phone exists.
    try (var statement =
        connection.prepareStatement(
            "SELECT phone FROM employees", TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
      ResultSet results = statement.executeQuery();
      StringBuilder output = new StringBuilder();
      if (results.first()) {
        output.append("<span class='feedback-positive'>" + safeQuery + "</span>");
        return success(this).output(output.toString()).build();
      } else {
        return failed(this).output(output.toString()).build();
      }
    }
  }
}
