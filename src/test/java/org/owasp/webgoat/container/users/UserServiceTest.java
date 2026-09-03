/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
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
  @Mock private Flyway flyway;
  @Mock private MailboxRepository mailboxRepository;

  private UserService userService() {
    return new UserService(
        userRepository,
        userTrackerRepository,
        jdbcTemplate,
        flywayLessons,
        List.of(),
        mailboxRepository);
  }

  @Test
  void shouldThrowExceptionWhenUserIsNotFound() {
    when(userRepository.findByUsername(any())).thenReturn(null);

    Assertions.assertThatThrownBy(() -> userService().loadUserByUsername("unknown"))
        .isInstanceOf(UsernameNotFoundException.class);
  }

  @Test
  void shouldCreateSchemaForAValidUsername() {
    when(userRepository.save(any())).thenReturn(new WebGoatUser("someuser", "password"));
    when(flywayLessons.apply("someuser")).thenReturn(flyway);

    userService().addUser("someuser", "password");

    verify(jdbcTemplate).execute("CREATE SCHEMA \"someuser\" authorization dba");
    verify(flyway).migrate();
  }

  /**
   * A schema name is an identifier and can therefore not be bound as a parameter, so a username
   * which could change the meaning of the statement is rejected before it is used.
   */
  @Test
  void shouldRejectUsernameWhichCannotBeUsedAsSchemaName() {
    String maliciousUsername = "webgoat\" authorization dba; drop schema \"webgoat";
    when(userRepository.save(any())).thenReturn(new WebGoatUser(maliciousUsername, "password"));

    Assertions.assertThatThrownBy(() -> userService().addUser(maliciousUsername, "password"))
        .isInstanceOf(IllegalArgumentException.class);

    verify(jdbcTemplate, never()).execute(anyString());
  }
}
