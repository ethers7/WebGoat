/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
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
    UserService userService = userService();
    Assertions.assertThatThrownBy(() -> userService.loadUserByUsername("unknown"))
        .isInstanceOf(UsernameNotFoundException.class);
  }

  @Test
  void shouldCreateSchemaForNewUser() {
    when(userRepository.existsByUsername("tom")).thenReturn(false);
    when(userRepository.save(any())).thenReturn(new WebGoatUser("tom", "password"));
    when(flywayLessons.apply("tom")).thenReturn(flyway);

    userService().addUser("tom", "password");

    verify(jdbcTemplate).execute("CREATE SCHEMA \"tom\" authorization dba");
    verify(flyway).migrate();
  }

  @Test
  void shouldRejectUsernameWhichCannotBeUsedAsSchemaName() {
    UserService userService = userService();

    Assertions.assertThatThrownBy(() -> userService.addUser("tom\" authorization dba--", "pw"))
        .isInstanceOf(IllegalArgumentException.class);

    verifyNoInteractions(jdbcTemplate, userRepository, userTrackerRepository, mailboxRepository);
  }
}
