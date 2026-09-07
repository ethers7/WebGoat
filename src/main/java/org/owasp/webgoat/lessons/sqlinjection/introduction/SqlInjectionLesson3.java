/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
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
@AssignmentHints(value = {"SqlStringInjectionHint3-1", "SqlStringInjectionHint3-2"})
public class SqlInjectionLesson3 implements AssignmentEndpoint {

  // A submitted statement is only executed when it updates a single column of a single row. The
  // identifiers are resolved with an allow list and both values are bound as parameters, so the
  // submitted text can never change the structure of the statement.
  private static final Pattern UPDATE_STATEMENT =
      Pattern.compile(
          "(?i)\\s*update\\s+(?<table>\\w+)\\s+set\\s+(?<column>\\w+)\\s*=\\s*"
              + "(?<value>'[^']*'|-?\\d+)\\s+where\\s+(?<key>\\w+)\\s*=\\s*"
              + "(?<keyvalue>'[^']*'|-?\\d+)\\s*;?\\s*");

  private static final String REJECTED = "Only a simple UPDATE on employees is executed.";

  private final LessonDataSource dataSource;

  public SqlInjectionLesson3(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack3")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    var matcher = UPDATE_STATEMENT.matcher(query);
    if (!matcher.matches() || !EmployeesSchema.isTable(matcher.group("table"))) {
      return failed(this).output(REJECTED).build();
    }
    var column = EmployeesSchema.column(matcher.group("column"));
    var key = EmployeesSchema.column(matcher.group("key"));
    if (column.isEmpty() || key.isEmpty()) {
      return failed(this).output(REJECTED).build();
    }
    // Only allow listed identifiers are used, both values are bound below.
    var safeQuery = "UPDATE employees SET %s = ? WHERE %s = ?".formatted(column.get(), key.get());

    try (Connection connection = dataSource.getConnection()) {
      try (var statement = connection.prepareStatement(safeQuery)) {
        EmployeesSchema.bindLiteral(statement, 1, column.get(), matcher.group("value"));
        EmployeesSchema.bindLiteral(statement, 2, key.get(), matcher.group("keyvalue"));
        statement.executeUpdate();
      }
      return checkSolution(connection, safeQuery);
    } catch (SQLException sqle) {
      return failed(this).output(sqle.getMessage()).build();
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }

  private AttackResult checkSolution(Connection connection, String safeQuery) throws SQLException {
    // The user completes the lesson if the department of Tobi Barnett now is 'Sales'.
    try (var statement =
        connection.prepareStatement(
            "SELECT * FROM employees WHERE last_name = ?",
            TYPE_SCROLL_INSENSITIVE,
            CONCUR_READ_ONLY)) {
      statement.setString(1, "Barnett");
      ResultSet results = statement.executeQuery();
      StringBuilder output = new StringBuilder();
      results.first();
      if (results.getString("department").equals("Sales")) {
        output.append("<span class='feedback-positive'>" + safeQuery + "</span>");
        output.append(SqlInjectionLesson8.generateTable(results));
        return success(this).output(output.toString()).build();
      } else {
        return failed(this).output(output.toString()).build();
      }
    }
  }
}
