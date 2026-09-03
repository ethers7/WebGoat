/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
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

  private static final List<String> EMPLOYEE_COLUMNS =
      List.of("userid", "first_name", "last_name", "department", "salary", "auth_tan");

  /**
   * Matches a simple {@code SELECT <columns> FROM employees WHERE <column> = <value>} statement.
   * The column names are resolved against {@link #EMPLOYEE_COLUMNS} and the value is bound as a
   * parameter, so the submitted text can never change the meaning of the executed query.
   */
  private static final Pattern SELECT_STATEMENT =
      Pattern.compile(
          "\\s*select\\s+(?<columns>\\*|[\\w\\s,]+?)\\s+from\\s+employees\\s+where\\s+"
              + "(?<column>\\w+)\\s*=\\s*'?(?<value>[^';]*?)'?\\s*;?\\s*",
          Pattern.CASE_INSENSITIVE);

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
    Matcher matcher = SELECT_STATEMENT.matcher(query == null ? "" : query);
    if (!matcher.matches()) {
      return failed(this).feedback("sql-injection.2.failed").build();
    }
    Optional<String> columns = resolveColumns(matcher.group("columns"));
    Optional<String> filterColumn = resolveColumn(matcher.group("column"));
    if (columns.isEmpty() || filterColumn.isEmpty()) {
      return failed(this).feedback("sql-injection.2.failed").build();
    }
    // Only allow-listed column names end up in the query, the value is bound as a parameter.
    String safeQuery =
        "SELECT " + columns.get() + " FROM employees WHERE " + filterColumn.get() + " = ?";

    try (var connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement(safeQuery, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
      statement.setString(1, matcher.group("value"));
      ResultSet results = statement.executeQuery();

      if (!results.first()) {
        return failed(this).feedback("sql-injection.2.failed").build();
      }

      StringBuilder output = new StringBuilder();
      if ("Marketing".equals(results.getString("department"))) {
        output.append("<span class='feedback-positive'>").append(query).append("</span>");
        output.append(SqlInjectionLesson8.generateTable(results));
        return success(this).feedback("sql-injection.2.success").output(output.toString()).build();
      } else {
        return failed(this).feedback("sql-injection.2.failed").output(output.toString()).build();
      }
    } catch (SQLException sqle) {
      return failed(this).feedback("sql-injection.2.failed").output(sqle.getMessage()).build();
    }
  }

  private static Optional<String> resolveColumns(String columns) {
    if ("*".equals(columns.trim())) {
      return Optional.of("*");
    }
    List<String> resolved = new ArrayList<>();
    for (String column : columns.split(",")) {
      Optional<String> allowed = resolveColumn(column);
      if (allowed.isEmpty()) {
        return Optional.empty();
      }
      resolved.add(allowed.get());
    }
    return Optional.of(String.join(", ", resolved));
  }

  private static Optional<String> resolveColumn(String column) {
    return EMPLOYEE_COLUMNS.stream()
        .filter(allowed -> allowed.equalsIgnoreCase(column.trim()))
        .findFirst();
  }
}
