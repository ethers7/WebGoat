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
import java.sql.Statement;
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

  // The text the student submits is never executed. It only has to match the shape this assignment
  // asks for: an UPDATE of the department on the employees table with one of the allowed
  // conditions. The statement which is executed is hardcoded below and the values the student typed
  // are bound as parameters, so the submitted text can never add columns, rows or statements to it.
  private static final Pattern UPDATE_STATEMENT =
      Pattern.compile(
          "update\\s+employees\\s+set\\s+department\\s*=\\s*'(?<department>[\\w ]{1,20})'"
              + "\\s+where\\s+(?<condition>.+?)\\s*;?",
          Pattern.CASE_INSENSITIVE);

  private static final Pattern BY_USERID =
      Pattern.compile("userid\\s*=\\s*'?(?<userid>\\d{1,6})'?", Pattern.CASE_INSENSITIVE);

  private static final Pattern BY_LAST_NAME =
      Pattern.compile("last_name\\s*=\\s*'(?<lastName>[\\w ]{1,20})'", Pattern.CASE_INSENSITIVE);

  private static final String REJECTED =
      "Only an UPDATE of the department on the employees table with a userid or a last_name"
          + " condition is accepted, for example: UPDATE employees SET department='Sales' WHERE"
          + " last_name='Barnett'";

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
    Matcher submitted = UPDATE_STATEMENT.matcher(query == null ? "" : query.trim());
    if (!submitted.matches()) {
      return failed(this).output(REJECTED).build();
    }
    String condition = submitted.group("condition");
    Matcher byUserid = BY_USERID.matcher(condition);
    Matcher byLastName = BY_LAST_NAME.matcher(condition);
    String sql;
    String conditionValue;
    if (byUserid.matches()) {
      sql = "UPDATE employees SET department = ? WHERE userid = ?";
      conditionValue = byUserid.group("userid");
    } else if (byLastName.matches()) {
      sql = "UPDATE employees SET department = ? WHERE last_name = ?";
      conditionValue = byLastName.group("lastName");
    } else {
      return failed(this).output(REJECTED).build();
    }

    try (Connection connection = dataSource.getConnection()) {
      try (PreparedStatement statement = connection.prepareStatement(sql)) {
        statement.setString(1, submitted.group("department"));
        statement.setString(2, conditionValue);
        statement.executeUpdate();
        Statement checkStatement =
            connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY);
        ResultSet results =
            checkStatement.executeQuery("SELECT * FROM employees WHERE last_name='Barnett';");
        StringBuilder output = new StringBuilder();
        // user completes lesson if the department of Tobi Barnett now is 'Sales'
        if (results.first() && "Sales".equals(results.getString("department"))) {
          output.append("<span class='feedback-positive'>").append(sql).append("</span>");
          output.append(SqlInjectionLesson8.generateTable(results));
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
}
