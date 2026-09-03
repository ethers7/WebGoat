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
import java.sql.Statement;
import java.util.Locale;
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

  // The text the student submits is never executed. It only has to match the shape this assignment
  // asks for: adding a column to the employees table. A column name and a data type are identifiers
  // and can never be bound as statement parameters, so they are resolved from the allowlists in
  // columnDefinition and only those literals end up in the statement which is executed.
  private static final Pattern ALTER_STATEMENT =
      Pattern.compile(
          "alter\\s+table\\s+employees\\s+add\\s+(?:column\\s+)?(?<column>\\w{1,30})\\s+"
              + "(?<type>\\w{1,20}\\s*(?:\\(\\s*\\d{1,3}\\s*\\))?)\\s*;?",
          Pattern.CASE_INSENSITIVE);

  private static final Pattern SIZED_TYPE =
      Pattern.compile(
          "(?<type>\\w{1,20})\\s*\\(\\s*(?<size>\\d{1,3})\\s*\\)", Pattern.CASE_INSENSITIVE);

  private static final String REJECTED =
      "Only adding a column to the employees table is accepted, for example: ALTER TABLE employees"
          + " ADD phone varchar(20)";

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
    Matcher submitted = ALTER_STATEMENT.matcher(query == null ? "" : query.trim());
    if (!submitted.matches()) {
      return failed(this).output(REJECTED).build();
    }
    String definition = columnDefinition(submitted.group("column"), submitted.group("type"));
    if (definition == null) {
      return failed(this).output(REJECTED).build();
    }
    // every part of this statement is a literal coming from the allowlists, never from the request
    String alterTable = "ALTER TABLE employees ADD " + definition;

    try (Connection connection = dataSource.getConnection()) {
      try (Statement statement =
          connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        statement.executeUpdate(alterTable);
        connection.commit();
        ResultSet results = statement.executeQuery("SELECT phone from employees;");
        StringBuilder output = new StringBuilder();
        // user completes lesson if column phone exists
        if (results.first()) {
          output.append("<span class='feedback-positive'>").append(alterTable).append("</span>");
          return success(this).output(output.toString()).build();
        } else {
          return failed(this).output(output.toString()).build();
        }
      } catch (SQLException sqle) {
        return failed(this).output(sqle.getMessage()).build();
      }
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }

  // The submitted column name and data type are used as keys to look up the literals which are put
  // in the statement. A size is re-rendered from the parsed number, everything unknown is rejected.
  private static String columnDefinition(String column, String type) {
    String name =
        switch (column.toLowerCase(Locale.ROOT)) {
          case "phone" -> "phone";
          default -> null;
        };
    if (name == null) {
      return null;
    }
    Matcher sized = SIZED_TYPE.matcher(type.trim());
    if (sized.matches()) {
      String base =
          switch (sized.group("type").toLowerCase(Locale.ROOT)) {
            case "varchar" -> "varchar";
            case "char" -> "char";
            default -> null;
          };
      if (base == null) {
        return null;
      }
      int size = Integer.parseInt(sized.group("size"));
      return size >= 1 && size <= 255 ? name + " " + base + "(" + size + ")" : null;
    }
    String simple =
        switch (type.trim().toLowerCase(Locale.ROOT)) {
          case "int", "integer" -> "int";
          case "smallint" -> "smallint";
          case "bigint" -> "bigint";
          case "boolean" -> "boolean";
          case "date" -> "date";
          case "timestamp" -> "timestamp";
          default -> null;
        };
    return simple == null ? null : name + " " + simple;
  }
}
