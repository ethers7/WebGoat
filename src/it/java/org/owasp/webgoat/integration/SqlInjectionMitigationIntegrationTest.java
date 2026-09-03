/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import static org.hamcrest.CoreMatchers.containsString;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class SqlInjectionMitigationIntegrationTest extends IntegrationTest {

  @Test
  public void runTests() {
    startLesson("SqlInjectionMitigations");

    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("field1", "getConnection");
    params.put("field2", "PreparedStatement prep");
    params.put("field3", "prepareStatement");
    params.put("field4", "?");
    params.put("field5", "?");
    params.put("field6", "prep.setString(1,\"\")");
    params.put("field7", "prep.setString(2,\\\"\\\")");
      checkAssignment(webGoatUrlConfig.url("SqlInjectionMitigations/attack10a"), params, true);

    params.put(
        "editor",
        "try {\r\n"
            + "    Connection conn = DriverManager.getConnection(DBURL,DBUSER,DBPW);\r\n"
            + "    PreparedStatement prep = conn.prepareStatement(\"select id from users where name"
            + " = ?\");\r\n"
            + "    prep.setString(1,\"me\");\r\n"
            + "    prep.execute();\r\n"
            + "    System.out.println(conn);   //should output 'null'\r\n"
            + "} catch (Exception e) {\r\n"
            + "    System.out.println(\"Oops. Something went wrong!\");\r\n"
            + "}");
      checkAssignment(webGoatUrlConfig.url("SqlInjectionMitigations/attack10b"), params, true);

    params.clear();
    params.put(
        "userid_sql_only_input_validation", "Smith';SELECT/**/*/**/from/**/user_system_data;--");
      checkAssignment(webGoatUrlConfig.url("SqlOnlyInputValidation/attack"), params, true);

    params.clear();
    params.put(
        "userid_sql_only_input_validation_on_keywords",
        "Smith';SESELECTLECT/**/*/**/FRFROMOM/**/user_system_data;--");
      checkAssignment(webGoatUrlConfig.url("SqlOnlyInputValidationOnKeywords/attack"), params, true);

    // The sort column is validated against an allowlist of selectable columns, so an injected
    // expression is rejected instead of being executed.
    RestAssured.given()
        .when()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .contentType(ContentType.JSON)
        .get(
            webGoatUrlConfig.url(
                "SqlInjectionMitigations/servers?column=(case when (true) then hostname"
                    + " else id end)"))
        .then()
        .statusCode(400);

    RestAssured.given()
        .when()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .contentType(ContentType.JSON)
        .get(webGoatUrlConfig.url("SqlInjectionMitigations/servers?column=unknown"))
        .then()
        .statusCode(400);

    // Sorting on one of the allowed columns still works.
    RestAssured.given()
        .when()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .contentType(ContentType.JSON)
        .get(webGoatUrlConfig.url("SqlInjectionMitigations/servers?column=hostname"))
        .then()
        .statusCode(200)
        .body("[0].hostname", containsString("webgoat-acc"));

    params.clear();
    params.put("ip", "104.130.219.202");
      checkAssignment(webGoatUrlConfig.url("SqlInjectionMitigations/attack12a"), params, true);

    checkResults("SqlInjectionMitigations");
  }
}
