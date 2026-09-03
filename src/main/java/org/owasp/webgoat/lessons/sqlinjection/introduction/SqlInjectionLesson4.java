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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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
    value = {"SqlStringInjectionHint4-1", "SqlStringInjectionHint4-2", "SqlStringInjectionHint4-3"})
public class SqlInjectionLesson4 implements AssignmentEndpoint {

  private static final Map<String, String> ALLOWED_ACTIONS =
      Map.of("add", "ADD COLUMN", "drop", "DROP COLUMN");

  private static final List<String> ALLOWED_COLUMN_TYPES =
      List.of("bigint", "boolean", "char", "date", "int", "integer", "timestamp", "varchar");

  /**
   * Matches a simple {@code ALTER TABLE employees ADD|DROP COLUMN <column> [<type>]} statement.
   * Identifiers cannot be bound as parameters, so the action and the column type are resolved
   * against the allow lists above and the column name may only consist of identifier characters.
   */
  private static final Pattern ALTER_STATEMENT =
      Pattern.compile(
          "\\s*alter\\s+table\\s+employees\\s+(?<action>\\w+)(\\s+column)?\\s+"
              + "(?<column>[a-z]\\w{0,29})(\\s+(?<type>[a-z]+)(\\((?<length>\\d{1,4})\\))?)?"
              + "\\s*;?\\s*",
          Pattern.CASE_INSENSITIVE);

  private static final String CHECK_QUERY = "SELECT phone FROM employees";

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
    Matcher matcher = ALTER_STATEMENT.matcher(query == null ? "" : query);
    if (!matcher.matches()) {
      return failed(this).output(rejected(query)).build();
    }
    String action = ALLOWED_ACTIONS.get(matcher.group("action").toLowerCase(Locale.ROOT));
    if (action == null) {
      return failed(this).output(rejected(query)).build();
    }
    String columnType = null;
    if (matcher.group("type") != null) {
      columnType = matcher.group("type").toLowerCase(Locale.ROOT);
      if (!ALLOWED_COLUMN_TYPES.contains(columnType)) {
        return failed(this).output(rejected(query)).build();
      }
    }
    // Identifiers cannot be bound as parameters, so the statement is built from allow-listed
    // keywords, a validated column name and a numeric length only.
    StringBuilder alterStatement = new StringBuilder("ALTER TABLE employees ");
    alterStatement.append(action).append(' ').append(matcher.group("column"));
    if (columnType != null) {
      alterStatement.append(' ').append(columnType);
      if (matcher.group("length") != null) {
        alterStatement.append('(').append(matcher.group("length")).append(')');
      }
    }

    try (Connection connection = dataSource.getConnection()) {
      try {
        try (PreparedStatement statement = connection.prepareStatement(alterStatement.toString())) {
          statement.execute();
        }
        connection.commit();
        try (PreparedStatement checkStatement =
            connection.prepareStatement(CHECK_QUERY, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
          ResultSet results = checkStatement.executeQuery();
          StringBuilder output = new StringBuilder();
          // user completes lesson if column phone exists
          if (results.first()) {
            output.append("<span class='feedback-positive'>" + query + "</span>");
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

  private static String rejected(String query) {
    return "Only a simple ALTER TABLE on the employees table is accepted."
        + "<br> Your query was: "
        + query;
  }
}
