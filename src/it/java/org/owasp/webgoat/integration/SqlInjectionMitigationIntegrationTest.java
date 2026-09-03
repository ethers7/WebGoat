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

    // Both assignments below delegate to assignment 6a, which binds the account name as a query
    // parameter, so the injection payloads are handled as data and can no longer solve them.
    params.clear();
    params.put(
        "userid_sql_only_input_validation", "Smith';SELECT/**/*/**/from/**/user_system_data;--");
      checkAssignment(webGoatUrlConfig.url("SqlOnlyInputValidation/attack"), params, false);

    params.clear();
    params.put(
        "userid_sql_only_input_validation_on_keywords",
        "Smith';SESELECTLECT/**/*/**/FRFROMOM/**/user_system_data;--");
      checkAssignment(
              webGoatUrlConfig.url("SqlOnlyInputValidationOnKeywords/attack"), params, false);

      RestAssured.given()
        .when()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .contentType(ContentType.JSON)
        .get(webGoatUrlConfig.url("SqlInjectionMitigations/servers?column=hostname"))
        .then()
        .statusCode(200);

      RestAssured.given()
        .when()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .contentType(ContentType.JSON)
        .get(
                webGoatUrlConfig.url("SqlInjectionMitigations/servers?column=(case when (true) then hostname"
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
        .statusCode(400)
        .body("error", containsString("Bad Request"));

    params.clear();
    params.put("ip", "104.130.219.202");
      checkAssignment(webGoatUrlConfig.url("SqlInjectionMitigations/attack12a"), params, true);

    // checkResults("SqlInjectionMitigations") is intentionally not called: the two input validation
    // assignments of this lesson use bound parameters now and can therefore no longer be solved by
    // an injection.
  }
}
