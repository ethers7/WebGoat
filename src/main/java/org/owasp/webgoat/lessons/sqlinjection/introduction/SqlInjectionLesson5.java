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
import java.util.Locale;
import java.util.Set;
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

  // A submitted statement is only executed when it grants an allow listed privilege on the table
  // of this assignment to the user of this assignment. A privilege, a table and a grantee are
  // identifiers which cannot be bound as parameters, so they are resolved with the allow lists.
  private static final Pattern GRANT_STATEMENT =
      Pattern.compile(
          "(?i)\\s*grant\\s+(?<privilege>\\w+)\\s+on\\s+(?<table>\\w+)\\s+to\\s+"
              + "(?<grantee>\\w+)\\s*;?\\s*");

  private static final Set<String> PRIVILEGES =
      Set.of("select", "insert", "update", "delete", "references", "trigger", "all");

  private static final Set<String> TABLES = Set.of("grant_rights");

  private static final Set<String> GRANTEES = Set.of("unauthorized_user");

  private static final String REJECTED = "Only a GRANT on grant_rights is executed.";

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
    var matcher = GRANT_STATEMENT.matcher(query);
    if (!matcher.matches()) {
      return failed(this).output(REJECTED).build();
    }
    var privilege = matcher.group("privilege").toLowerCase(Locale.ROOT);
    var table = matcher.group("table").toLowerCase(Locale.ROOT);
    var grantee = matcher.group("grantee").toLowerCase(Locale.ROOT);
    var allowed =
        PRIVILEGES.contains(privilege) && TABLES.contains(table) && GRANTEES.contains(grantee);
    if (!allowed) {
      return failed(this).output(REJECTED).build();
    }
    // Only allow listed keywords and identifiers end up in the statement below.
    var safeQuery = "GRANT %s ON %s TO %s".formatted(privilege, table, grantee);

    try (Connection connection = dataSource.getConnection()) {
      try (var statement = connection.prepareStatement(safeQuery)) {
        statement.execute();
      }
      if (checkSolution(connection)) {
        return success(this).build();
      }
      return failed(this).output("Your query was: " + safeQuery).build();
    } catch (Exception e) {
      var message = this.getClass().getName() + " : " + e.getMessage();
      return failed(this).output(message + "<br> Your query was: " + safeQuery).build();
    }
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
