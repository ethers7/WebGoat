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
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@AssignmentHints({
  "auth-bypass.hints.verify.1",
  "auth-bypass.hints.verify.2",
  "auth-bypass.hints.verify.3",
  "auth-bypass.hints.verify.4"
})
public class VerifyAccount implements AssignmentEndpoint {

  /**
   * The answers to the security questions are submitted as {@code secQuestion} followed by the
   * number of the question, any other parameter name is not a security question.
   */
  private static final Pattern SEC_QUESTION_PARAMETER = Pattern.compile("secQuestion\\d{1,2}");

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

  /**
   * Collects the submitted answers to the security questions. Parameters which are not a security
   * question are ignored, a security question which is not well formed or an answer which is too
   * long is rejected instead of being passed on to the verification.
   */
  private HashMap<String, String> parseSecQuestions(HttpServletRequest req) {
    Map<String, String> userAnswers = new HashMap<>();
    List<String> paramNames = Collections.list(req.getParameterNames());
    for (String paramName : paramNames) {
      if (!paramName.contains("secQuestion")) {
        continue;
      }
      if (!SEC_QUESTION_PARAMETER.matcher(paramName).matches()) {
        throw new ResponseStatusException(
            HttpStatus.BAD_REQUEST, "Invalid security question parameter");
      }
      if (userAnswers.size() >= MAX_SEC_QUESTIONS) {
        throw new ResponseStatusException(
            HttpStatus.BAD_REQUEST, "Too many security questions submitted");
      }
      var answer = req.getParameter(paramName);
      if (answer == null || answer.length() > MAX_ANSWER_LENGTH) {
        throw new ResponseStatusException(
            HttpStatus.BAD_REQUEST, "Invalid answer for security question " + paramName);
      }
      userAnswers.put(paramName, answer);
    }
    return (HashMap<String, String>) userAnswers;
  }
}
