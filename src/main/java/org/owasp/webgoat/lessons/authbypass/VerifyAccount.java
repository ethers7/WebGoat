/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "auth-bypass.hints.verify.1",
  "auth-bypass.hints.verify.2",
  "auth-bypass.hints.verify.3",
  "auth-bypass.hints.verify.4"
})
public class VerifyAccount implements AssignmentEndpoint {

  // Security question answers are the only request parameters this endpoint consumes, so their
  // names must match the expected shape as a whole instead of merely containing "secQuestion".
  private static final Pattern SEC_QUESTION_NAME = Pattern.compile("secQuestion[A-Za-z0-9]{1,4}");
  // Upper bounds on what a single request may put into the answer map.
  private static final int MAX_SEC_QUESTIONS = 10;
  private static final int MAX_ANSWER_LENGTH = 100;

  private final LessonSession userSessionData;

  public VerifyAccount(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @PostMapping(
      path = "/auth-bypass/verify-account",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(
      @RequestParam String userId, @RequestParam String verifyMethod, HttpServletRequest req)
      throws ServletException, IOException {
    AccountVerificationHelper verificationHelper = new AccountVerificationHelper();
    Map<String, String> submittedAnswers = parseSecQuestions(req);
    if (verificationHelper.didUserLikelylCheat((HashMap<String, String>) submittedAnswers)) {
      return failed(this)
          .feedback("verify-account.cheated")
          .output("Yes, you guessed correctly, but see the feedback message")
          .build();
    }

    // else
    if (verificationHelper.verifyAccount(
        Integer.valueOf(userId), (HashMap<String, String>) submittedAnswers)) {
      userSessionData.setValue("account-verified-id", userId);
      return success(this).feedback("verify-account.success").build();
    } else {
      return failed(this).feedback("verify-account.failed").build();
    }
  }

  private HashMap<String, String> parseSecQuestions(HttpServletRequest req) {
    Map<String, String> userAnswers = new HashMap<>();
    // Validate at the trust boundary: only parameter names matching the expected security question
    // shape are read, and at most MAX_SEC_QUESTIONS of them, so a request cannot fill the answer
    // map with an unbounded number of arbitrarily named keys.
    List<String> paramNames =
        Collections.list(req.getParameterNames()).stream()
            .filter(paramName -> SEC_QUESTION_NAME.matcher(paramName).matches())
            .limit(MAX_SEC_QUESTIONS)
            .toList();
    for (String paramName : paramNames) {
      String answer = req.getParameter(paramName);
      // Ignore missing or oversized answers instead of storing unbounded client input;
      // verification then fails closed because the expected number of answers is not reached.
      if (answer != null && answer.length() <= MAX_ANSWER_LENGTH) {
        userAnswers.put(paramName, answer);
      }
    }
    return (HashMap<String, String>) userAnswers;
  }
}
