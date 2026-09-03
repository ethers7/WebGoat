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
import java.util.OptionalInt;
import java.util.Set;
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

  // The security question parameters the verification form submits, see AuthBypass.html and the
  // questions stored in AccountVerificationHelper. Any other name is not an answer.
  private static final Set<String> SEC_QUESTION_PARAMS = Set.of("secQuestion0", "secQuestion1");

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

    if (hasUnexpectedSecQuestions(req)) {
      // The learner renamed the security question parameters, which is the flaw this lesson
      // teaches, so the assignment is graded as solved. The bypassed request deliberately does
      // not verify anything, hence no account is recorded as verified here.
      return success(this).feedback("verify-account.success").build();
    }

    OptionalInt verifiedUserId = parseUserId(userId);
    if (verifiedUserId.isEmpty()) {
      return failed(this).feedback("verify-account.failed").build();
    }

    // else
    if (verificationHelper.verifyAccount(
        verifiedUserId.getAsInt(), (HashMap<String, String>) submittedAnswers)) {
      userSessionData.setValue("account-verified-id", userId);
      return success(this).feedback("verify-account.success").build();
    } else {
      return failed(this).feedback("verify-account.failed").build();
    }
  }

  private HashMap<String, String> parseSecQuestions(HttpServletRequest req) {
    Map<String, String> userAnswers = new HashMap<>();
    List<String> paramNames = Collections.list(req.getParameterNames());
    for (String paramName : paramNames) {
      // Parameter names are supplied by the caller, so only the questions which were really
      // asked are accepted as answers, anything else must not take part in the verification.
      if (SEC_QUESTION_PARAMS.contains(paramName)) {
        userAnswers.put(paramName, req.getParameter(paramName));
      }
    }
    return (HashMap<String, String>) userAnswers;
  }

  // Whether the request carries security question parameters under names the form never submits.
  private boolean hasUnexpectedSecQuestions(HttpServletRequest req) {
    for (String paramName : Collections.list(req.getParameterNames())) {
      if (paramName.contains("secQuestion") && !SEC_QUESTION_PARAMS.contains(paramName)) {
        return true;
      }
    }
    return false;
  }

  private static OptionalInt parseUserId(String userId) {
    try {
      return OptionalInt.of(Integer.parseInt(userId));
    } catch (NumberFormatException e) {
      return OptionalInt.empty();
    }
  }
}
