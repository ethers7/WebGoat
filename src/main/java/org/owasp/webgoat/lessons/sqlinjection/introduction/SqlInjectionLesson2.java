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
import java.util.Locale;
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

  // The text the student submits is never executed. It only has to match the shape this assignment
  // asks for: a SELECT on the employees table with one of the allowed conditions. The statement
  // which is executed is hardcoded below, the column names are resolved from an allowlist and the
  // values the student typed are bound as parameters, so the submitted text can never change the
  // structure of the query.
  private static final Pattern SELECT_STATEMENT =
      Pattern.compile(
          "select\\s+(?<columns>[\\w*]+(?:\\s*,\\s*[\\w*]+)*)\\s+from\\s+employees\\s+where\\s+"
              + "(?<condition>.+?)\\s*;?",
          Pattern.CASE_INSENSITIVE);

  private static final Pattern BY_USERID =
      Pattern.compile("userid\\s*=\\s*'?(?<userid>\\d{1,6})'?", Pattern.CASE_INSENSITIVE);

  private static final Pattern BY_LAST_NAME =
      Pattern.compile("last_name\\s*=\\s*'(?<lastName>[\\w ]{1,20})'", Pattern.CASE_INSENSITIVE);

  private static final Pattern BY_FULL_NAME =
      Pattern.compile(
          "first_name\\s*=\\s*'(?<firstName>[\\w ]{1,20})'\\s+and\\s+last_name\\s*=\\s*'"
              + "(?<lastName>[\\w ]{1,20})'",
          Pattern.CASE_INSENSITIVE);

  private static final String REJECTED =
      "Only a SELECT on the employees table with a userid or a name condition is accepted, for"
          + " example: SELECT department FROM employees WHERE last_name='Franco'";

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
    var parsed = parse(query);
    if (parsed.isEmpty()) {
      return failed(this).feedback("sql-injection.2.failed").output(REJECTED).build();
    }
    String sql = parsed.get().sql();
    List<String> parameters = parsed.get().parameters();
    StringBuilder output = new StringBuilder();

    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement(sql, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
      for (int i = 0; i < parameters.size(); i++) {
        statement.setString(i + 1, parameters.get(i));
      }
      ResultSet results = statement.executeQuery();

      if (!results.first()) {
        return failed(this).feedback("sql-injection.2.failed").build();
      }

      if ("Marketing".equals(results.getString("department"))) {
        output.append("<span class='feedback-positive'>").append(sql).append("</span>");
        output.append(SqlInjectionLesson8.generateTable(results));
        return success(this).feedback("sql-injection.2.success").output(output.toString()).build();
      } else {
        return failed(this).feedback("sql-injection.2.failed").output(output.toString()).build();
      }
    } catch (SQLException sqle) {
      return failed(this).feedback("sql-injection.2.failed").output(sqle.getMessage()).build();
    }
  }

  // Hardcoded SQL together with the values which have to be bound to it.
  private record PreparedQuery(String sql, List<String> parameters) {}

  private static Optional<PreparedQuery> parse(String submitted) {
    if (submitted == null) {
      return Optional.empty();
    }
    Matcher statement = SELECT_STATEMENT.matcher(submitted.trim());
    if (!statement.matches()) {
      return Optional.empty();
    }
    var columns = new StringBuilder();
    for (String submittedColumn : statement.group("columns").split(",")) {
      String resolved = column(submittedColumn);
      if (resolved == null) {
        return Optional.empty();
      }
      if (!columns.isEmpty()) {
        columns.append(", ");
      }
      columns.append(resolved);
    }
    String condition = statement.group("condition");
    Matcher byUserid = BY_USERID.matcher(condition);
    if (byUserid.matches()) {
      return Optional.of(
          new PreparedQuery(
              "SELECT " + columns + " FROM employees WHERE userid = ?",
              List.of(byUserid.group("userid"))));
    }
    Matcher byLastName = BY_LAST_NAME.matcher(condition);
    if (byLastName.matches()) {
      return Optional.of(
          new PreparedQuery(
              "SELECT " + columns + " FROM employees WHERE last_name = ?",
              List.of(byLastName.group("lastName"))));
    }
    Matcher byFullName = BY_FULL_NAME.matcher(condition);
    if (byFullName.matches()) {
      return Optional.of(
          new PreparedQuery(
              "SELECT " + columns + " FROM employees WHERE first_name = ? AND last_name = ?",
              List.of(byFullName.group("firstName"), byFullName.group("lastName"))));
    }
    return Optional.empty();
  }

  // A column name cannot be bound as a parameter, so the submitted name is used as a key to look up
  // the literal which ends up in the statement. Unknown names are rejected.
  private static String column(String submitted) {
    return switch (submitted.trim().toLowerCase(Locale.ROOT)) {
      case "*" -> "*";
      case "userid" -> "userid";
      case "first_name" -> "first_name";
      case "last_name" -> "last_name";
      case "department" -> "department";
      case "salary" -> "salary";
      case "auth_tan" -> "auth_tan";
      default -> null;
    };
  }
}
