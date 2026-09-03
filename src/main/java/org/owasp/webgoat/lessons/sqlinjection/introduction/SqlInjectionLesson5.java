/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.annotation.PostConstruct;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;
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

  private static final List<String> ALLOWED_PRIVILEGES =
      List.of("all", "delete", "insert", "select", "update");

  /**
   * Matches a simple {@code GRANT <privilege> ON <table> TO <user>} statement. Privileges,
   * identifiers and user names cannot be bound as parameters, so the privilege is resolved against
   * {@link #ALLOWED_PRIVILEGES} and the table and the grantee may only consist of identifier
   * characters, which means the submitted text can never change the meaning of the statement.
   */
  private static final Pattern GRANT_STATEMENT =
      Pattern.compile(
          "\\s*grant\\s+(?<privilege>\\w+)\\s+on\\s+(?<table>[a-z]\\w{0,29})\\s+to\\s+"
              + "(?<grantee>[a-z]\\w{0,29})\\s*;?\\s*",
          Pattern.CASE_INSENSITIVE);

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
    Matcher matcher = GRANT_STATEMENT.matcher(query == null ? "" : query);
    if (!matcher.matches()) {
      return failed(this).output(rejected(query)).build();
    }
    String privilege = matcher.group("privilege").toLowerCase(Locale.ROOT);
    if (!ALLOWED_PRIVILEGES.contains(privilege)) {
      return failed(this).output(rejected(query)).build();
    }
    // Only an allow-listed privilege and validated identifiers are used in the statement.
    String table = matcher.group("table");
    String grantee = matcher.group("grantee");
    String grant = "GRANT " + privilege + " ON " + table + " TO " + grantee;

    try (Connection connection = dataSource.getConnection()) {
      try (PreparedStatement statement = connection.prepareStatement(grant)) {
        statement.execute();
      }
      if (checkSolution(connection)) {
        return success(this).build();
      }
      return failed(this).output("Your query was: " + query).build();
    } catch (Exception e) {
      return failed(this)
          .output(
              this.getClass().getName() + " : " + e.getMessage() + "<br> Your query was: " + query)
          .build();
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

  private static String rejected(String query) {
    return "Only a GRANT statement with a known privilege is accepted."
        + "<br> Your query was: "
        + query;
  }
}
