/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

public class EncodingAssignmentTest {

  private static final String AUTHORIZATION_PREFIX = "Authorization: Basic ";
  private static final String USERNAME = "unit-test-user";

  private final EncodingAssignment assignment = new EncodingAssignment();

  @Test
  public void lessonIsSolvedWithTheCredentialsFromTheInterceptedHeader() {
    MockHttpSession session = new MockHttpSession();
    String token = assignment.getBasicAuth(requestFor(session, USERNAME));
    String[] credentials = decodeCredentials(token);

    assertThat(credentials[0]).isEqualTo(USERNAME);
    assertThat(HashingAssignment.SECRETS).contains(credentials[1]);

    MockHttpServletRequest answerRequest = requestFor(session, USERNAME);
    AttackResult result = assignment.completed(answerRequest, credentials[0], credentials[1]);

    assertThat(result.assignmentSolved()).isTrue();
  }

  @Test
  public void theSameTokenIsReturnedForEveryRequestInTheSameSession() {
    MockHttpSession session = new MockHttpSession();

    String first = assignment.getBasicAuth(requestFor(session, USERNAME));
    String second = assignment.getBasicAuth(requestFor(session, USERNAME));

    assertThat(second).isEqualTo(first);
  }

  @Test
  public void sessionOnlyContainsTheServerSideSecret() {
    MockHttpSession session = new MockHttpSession();
    assignment.getBasicAuth(requestFor(session, USERNAME));

    List<String> attributeNames = Collections.list(session.getAttributeNames());

    assertThat(attributeNames).isNotEmpty();
    for (String attributeName : attributeNames) {
      assertThat(HashingAssignment.SECRETS).contains((String) session.getAttribute(attributeName));
    }
  }

  @Test
  public void wrongPasswordDoesNotSolveTheLesson() {
    MockHttpSession session = new MockHttpSession();
    assignment.getBasicAuth(requestFor(session, USERNAME));

    MockHttpServletRequest answerRequest = requestFor(session, USERNAME);
    AttackResult result = assignment.completed(answerRequest, USERNAME, "not-a-secret");

    assertThat(result.assignmentSolved()).isFalse();
  }

  @Test
  public void answerIsGradedAgainstTheAuthenticatedPrincipal() {
    MockHttpSession session = new MockHttpSession();
    String token = assignment.getBasicAuth(requestFor(session, USERNAME));
    String[] credentials = decodeCredentials(token);

    MockHttpServletRequest answerRequest = requestFor(session, "another-user");
    AttackResult result = assignment.completed(answerRequest, credentials[0], credentials[1]);

    assertThat(result.assignmentSolved()).isFalse();
  }

  @Test
  public void withoutATokenTheLessonIsNotSolved() {
    MockHttpServletRequest answerRequest = requestFor(new MockHttpSession(), USERNAME);

    AttackResult result = assignment.completed(answerRequest, USERNAME, "secret");

    assertThat(result.assignmentSolved()).isFalse();
  }

  private MockHttpServletRequest requestFor(MockHttpSession session, String username) {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setSession(session);
    request.setUserPrincipal(() -> username);
    return request;
  }

  private String[] decodeCredentials(String header) {
    assertThat(header).startsWith(AUTHORIZATION_PREFIX);
    byte[] decoded = Base64.getDecoder().decode(header.substring(AUTHORIZATION_PREFIX.length()));
    return new String(decoded, StandardCharsets.UTF_8).split(":");
  }
}
