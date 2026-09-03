/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.sql.*;
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
      "SqlStringInjectionHint5b1",
      "SqlStringInjectionHint5b2",
      "SqlStringInjectionHint5b3",
      "SqlStringInjectionHint5b4"
    })
public class SqlInjectionLesson5b implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5b(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/assignment5b")
  @ResponseBody
  public AttackResult completed(@RequestParam String userid, @RequestParam String login_count)
      throws IOException {
    return injectableQuery(login_count, userid);
  }

  protected AttackResult injectableQuery(String login_count, String accountName) {
    // Both the login count and the user id are bound as parameters, so neither of them can be
    // appended to the statement as SQL. The user id is a numeric column, so it is parsed as a
    // number and rejected when it is not one.
    String queryString = "SELECT * From user_data WHERE Login_Count = ? and userid = ?";
    int count;
    try {
      count = Integer.parseInt(login_count);
    } catch (NumberFormatException e) {
      return failed(this)
          .output(
              "Could not parse: "
                  + login_count
                  + " to a number"
                  + "<br> Your query was: "
                  + queryString)
          .build();
    }
    int userId;
    try {
      userId = Integer.parseInt(accountName.trim());
    } catch (NumberFormatException e) {
      return failed(this)
          .output("Could not parse the user id to a number<br> Your query was: " + queryString)
          .build();
    }
    // Only the parsed numbers are echoed back, never the raw input.
    String displayedQuery =
        "SELECT * From user_data WHERE Login_Count = " + count + " and userid = " + userId;
    try (Connection connection = dataSource.getConnection();
        PreparedStatement query =
            connection.prepareStatement(
                queryString, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
      query.setInt(1, count);
      query.setInt(2, userId);
      try {
        ResultSet results = query.executeQuery();

        if ((results != null) && (results.first() == true)) {
          ResultSetMetaData resultsMetaData = results.getMetaData();
          StringBuilder output = new StringBuilder();

          output.append(SqlInjectionLesson5a.writeTable(results, resultsMetaData));
          results.last();

          // If they get back more than one user they succeeded
          if (results.getRow() >= 6) {
            return success(this)
                .feedback("sql-injection.5b.success")
                .output("Your query was: " + displayedQuery)
                .feedbackArgs(output.toString())
                .build();
          } else {
            return failed(this)
                .output(output.toString() + "<br> Your query was: " + displayedQuery)
                .build();
          }

        } else {
          return failed(this)
              .feedback("sql-injection.5b.no.results")
              .output("Your query was: " + displayedQuery)
              .build();
        }
      } catch (SQLException sqle) {

        return failed(this)
            .output(sqle.getMessage() + "<br> Your query was: " + displayedQuery)
            .build();
      }
    } catch (Exception e) {
      return failed(this)
          .output(
              this.getClass().getName()
                  + " : "
                  + e.getMessage()
                  + "<br> Your query was: "
                  + displayedQuery)
          .build();
    }
  }
}
