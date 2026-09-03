/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.annotation.PostConstruct;
import java.sql.Connection;
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
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint5-1",
      "SqlStringInjectionHint5-2",
      "SqlStringInjectionHint5-3",
      "SqlStringInjectionHint5-4"
    })
public class SqlInjectionLesson5 implements AssignmentEndpoint {

  // The text the student submits is never executed. It only has to match the shape this assignment
  // asks for: granting a privilege on a table to a user. Privileges, table names and user names are
  // identifiers which can never be bound as parameters, so all three are resolved from the
  // allowlists below and only those literals end up in the statement which is executed.
  private static final Pattern GRANT_STATEMENT =
      Pattern.compile(
          "grant\\s+(?<privilege>\\w+(?:\\s+\\w+)?)\\s+on\\s+(?:table\\s+)?(?<table>\\w{1,30})"
              + "\\s+to\\s+(?<grantee>\\w{1,30})\\s*;?",
          Pattern.CASE_INSENSITIVE);

  private static final String REJECTED =
      "Only granting a privilege on the grant_rights table to unauthorized_user is accepted, for"
          + " example: grant select on grant_rights to unauthorized_user";

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostConstruct
  public void createUser() {
    // HSQLDB does not support CREATE USER with IF NOT EXISTS so we need to do it in code (using
    // DROP first will throw error if user does not exists)
    try (Connection connection = dataSource.getConnection()) {
      try (var statement =
          connection.prepareStatement("CREATE USER unauthorized_user PASSWORD test")) {
        statement.execute();
      }
    } catch (Exception e) {
      // user already exists continue
    }
  }

  @PostMapping("/SqlInjection/attack5")
  @ResponseBody
  public AttackResult completed(String query) {
    createUser();
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    Matcher submitted = GRANT_STATEMENT.matcher(query == null ? "" : query.trim());
    if (!submitted.matches()) {
      return failed(this).output(REJECTED).build();
    }
    String privilege = privilege(submitted.group("privilege"));
    String table = table(submitted.group("table"));
    String grantee = grantee(submitted.group("grantee"));
    if (privilege == null || table == null || grantee == null) {
      return failed(this).output(REJECTED).build();
    }
    // every part of this statement is a literal coming from the allowlists, never from the request
    String grant = "GRANT " + privilege + " ON " + table + " TO " + grantee;

    try (Connection connection = dataSource.getConnection();
        Statement statement = connection.createStatement()) {
      statement.execute(grant);
      if (checkSolution(connection)) {
        return success(this).build();
      }
      return failed(this).output("Your query was: " + grant).build();
    } catch (Exception e) {
      return failed(this)
          .output(
              this.getClass().getName() + " : " + e.getMessage() + "<br> Your query was: " + grant)
          .build();
    }
  }

  private static String privilege(String submitted) {
    return switch (submitted.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ")) {
      case "select" -> "SELECT";
      case "insert" -> "INSERT";
      case "update" -> "UPDATE";
      case "delete" -> "DELETE";
      case "all", "all privileges" -> "ALL";
      default -> null;
    };
  }

  private static String table(String submitted) {
    return switch (submitted.toLowerCase(Locale.ROOT)) {
      case "grant_rights" -> "grant_rights";
      default -> null;
    };
  }

  private static String grantee(String submitted) {
    return switch (submitted.toLowerCase(Locale.ROOT)) {
      case "unauthorized_user" -> "unauthorized_user";
      default -> null;
    };
  }

  private boolean checkSolution(Connection connection) {
    try {
      var stmt =
          connection.prepareStatement(
              "SELECT * FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE TABLE_NAME = ? AND GRANTEE ="
                  + " ?");
      stmt.setString(1, "GRANT_RIGHTS");
      stmt.setString(2, "UNAUTHORIZED_USER");
      var resultSet = stmt.executeQuery();
      return resultSet.next();
    } catch (SQLException throwables) {
      return false;
    }
  }
}
