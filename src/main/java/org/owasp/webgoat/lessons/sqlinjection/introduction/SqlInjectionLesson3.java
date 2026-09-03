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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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
@AssignmentHints(value = {"SqlStringInjectionHint3-1", "SqlStringInjectionHint3-2"})
public class SqlInjectionLesson3 implements AssignmentEndpoint {

  private static final List<String> EMPLOYEE_COLUMNS =
      List.of("userid", "first_name", "last_name", "department", "salary", "auth_tan");

  /**
   * Matches a simple {@code UPDATE employees SET <column> = <value> WHERE <column> = <value>}
   * statement. The column names are resolved against {@link #EMPLOYEE_COLUMNS} and both values are
   * bound as parameters, so the submitted text can never change the meaning of the statement which
   * is executed.
   */
  private static final Pattern UPDATE_STATEMENT =
      Pattern.compile(
          "\\s*update\\s+employees\\s+set\\s+(?<column>\\w+)\\s*=\\s*'?(?<value>[^';]*?)'?"
              + "\\s+where\\s+(?<filterColumn>\\w+)\\s*=\\s*'?(?<filterValue>[^';]*?)'?\\s*;?\\s*",
          Pattern.CASE_INSENSITIVE);

  private static final String CHECK_QUERY = "SELECT * FROM employees WHERE last_name = ?";

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
    Matcher matcher = UPDATE_STATEMENT.matcher(query == null ? "" : query);
    if (!matcher.matches()) {
      return failed(this).output(rejected(query)).build();
    }
    Optional<String> column = resolveColumn(matcher.group("column"));
    Optional<String> filterColumn = resolveColumn(matcher.group("filterColumn"));
    if (column.isEmpty() || filterColumn.isEmpty()) {
      return failed(this).output(rejected(query)).build();
    }
    // Only allow-listed column names end up in the statement, the values are bound as parameters.
    String updateStatement =
        "UPDATE employees SET " + column.get() + " = ? WHERE " + filterColumn.get() + " = ?";

    try (Connection connection = dataSource.getConnection()) {
      try {
        try (PreparedStatement statement = connection.prepareStatement(updateStatement)) {
          statement.setString(1, matcher.group("value"));
          statement.setString(2, matcher.group("filterValue"));
          statement.executeUpdate();
        }
        try (PreparedStatement checkStatement =
            connection.prepareStatement(CHECK_QUERY, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
          checkStatement.setString(1, "Barnett");
          ResultSet results = checkStatement.executeQuery();
          StringBuilder output = new StringBuilder();
          // user completes lesson if the department of Tobi Barnett now is 'Sales'
          results.first();
          if (results.getString("department").equals("Sales")) {
            output.append("<span class='feedback-positive'>" + query + "</span>");
            output.append(SqlInjectionLesson8.generateTable(results));
            return success(this).output(output.toString()).build();
          } else {
            return failed(this).output(output.toString()).build();
          }
        }
      } catch (SQLException sqle) {
        return failed(this).output(sqle.getMessage()).build();
      }
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }

  private static Optional<String> resolveColumn(String column) {
    return EMPLOYEE_COLUMNS.stream()
        .filter(allowed -> allowed.equalsIgnoreCase(column.trim()))
        .findFirst();
  }

  private static String rejected(String query) {
    return "Only a simple UPDATE on the employees table with known column names is accepted."
        + "<br> Your query was: "
        + query;
  }
}
