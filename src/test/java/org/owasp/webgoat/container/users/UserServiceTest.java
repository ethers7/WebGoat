/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.function.Function;
import org.assertj.core.api.Assertions;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.webgoat.container.mailbox.MailboxRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

  @Mock private UserRepository userRepository;
  @Mock private UserProgressRepository userTrackerRepository;
  @Mock private JdbcTemplate jdbcTemplate;
  @Mock private Function<String, Flyway> flywayLessons;
  @Mock private MailboxRepository mailboxRepository;

  @Test
  void shouldThrowExceptionWhenUserIsNotFound() {
    when(userRepository.findByUsername(any())).thenReturn(null);
    UserService userService =
        new UserService(
            userRepository,
            userTrackerRepository,
            jdbcTemplate,
            flywayLessons,
            List.of(),
            mailboxRepository);
    Assertions.assertThatThrownBy(() -> userService.loadUserByUsername("unknown"))
        .isInstanceOf(UsernameNotFoundException.class);
  }

  /**
   * The user name becomes the name of the database schema which holds the lessons of that user. A
   * schema name is an identifier and can never be bound as a statement parameter, so a name which
   * carries SQL syntax has to be rejected before anything is stored or executed.
   */
  @Test
  void shouldRejectUserNameWhichIsNotAValidSchemaName() {
    UserService userService =
        new UserService(
            userRepository,
            userTrackerRepository,
            jdbcTemplate,
            flywayLessons,
            List.of(),
            mailboxRepository);

    Assertions.assertThatThrownBy(
            () -> userService.addUser("guest\" authorization dba; DROP SCHEMA \"guest", "password"))
        .isInstanceOf(IllegalArgumentException.class);

    verifyNoInteractions(userRepository, jdbcTemplate, flywayLessons);
  }
}
