/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

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
@AssignmentHints(
    value = {
      "SqlStringInjectionHint2-1",
      "SqlStringInjectionHint2-2",
      "SqlStringInjectionHint2-3",
      "SqlStringInjectionHint2-4"
    })
public class SqlInjectionLesson2 implements AssignmentEndpoint {

  // A submitted statement is only executed when it selects from a single table with one equals
  // condition. The identifiers are resolved with an allow list and the value is bound as a
  // parameter, so the submitted text can never change the structure of the query.
  private static final Pattern SELECT_STATEMENT =
      Pattern.compile(
          "(?i)\\s*select\\s+(?<columns>\\*|[\\w,\\s]+?)\\s+from\\s+(?<table>\\w+)"
              + "\\s+where\\s+(?<column>\\w+)\\s*=\\s*(?<value>'[^']*'|-?\\d+)\\s*;?\\s*");

  private final LessonDataSource dataSource;

  public SqlInjectionLesson2(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack2")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    var matcher = SELECT_STATEMENT.matcher(query);
    if (!matcher.matches() || !EmployeesSchema.isTable(matcher.group("table"))) {
      return failed(this).feedback("sql-injection.2.failed").build();
    }
    var columns = EmployeesSchema.columnList(matcher.group("columns"));
    var column = EmployeesSchema.column(matcher.group("column"));
    if (columns.isEmpty() || column.isEmpty()) {
      return failed(this).feedback("sql-injection.2.failed").build();
    }
    // Only allow listed identifiers are used, the value of the condition is bound below.
    var safeQuery = "SELECT %s FROM employees WHERE %s = ?".formatted(columns.get(), column.get());

    try (var connection = dataSource.getConnection();
        var statement =
            connection.prepareStatement(safeQuery, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
      EmployeesSchema.bindLiteral(statement, 1, column.get(), matcher.group("value"));
      ResultSet results = statement.executeQuery();
      StringBuilder output = new StringBuilder();

      if (!results.first()) {
        return failed(this).feedback("sql-injection.2.failed").build();
      }

      if ("Marketing".equals(results.getString("department"))) {
        output.append("<span class='feedback-positive'>").append(safeQuery).append("</span>");
        output.append(SqlInjectionLesson8.generateTable(results));
        return success(this).feedback("sql-injection.2.success").output(output.toString()).build();
      } else {
        return failed(this).feedback("sql-injection.2.failed").output(output.toString()).build();
      }
    } catch (SQLException sqle) {
      return failed(this).feedback("sql-injection.2.failed").output(sqle.getMessage()).build();
    }
  }
}
