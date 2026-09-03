/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Seeds default accounts on first startup so that the platform is immediately usable
 * without manual database intervention.
 *
 * <p>If the users already exist, their credentials are left untouched (for normal users)
 * or re-ensured (for admins), making this bean idempotent across restarts.
 *
 * <p>The password for these accounts is never kept in the source: it is read from the
 * {@code webgoat.default.user.password} property (environment variable
 * {@code WEBGOAT_DEFAULT_USER_PASSWORD}). When it is not configured no account is seeded,
 * so no deployment ends up with a well-known password.
 */
@Component
@Slf4j
public class DefaultUserInitializer implements ApplicationRunner {

  private static final String ADMIN_USERNAME = "webgoat-admin";
  private static final String DEFAULT_USER_USERNAME = "webgoat-user";

  private final UserRepository userRepository;
  private final UserService userService;
  private final String defaultPassword;

  public DefaultUserInitializer(
      UserRepository userRepository,
      UserService userService,
      @Value("${webgoat.default.user.password:}") String defaultPassword) {
    this.userRepository = userRepository;
    this.userService = userService;
    this.defaultPassword = defaultPassword;
  }

  @Override
  public void run(ApplicationArguments args) {
    if (!StringUtils.hasText(defaultPassword)) {
      log.info(
          "No password configured in 'webgoat.default.user.password'"
              + " (WEBGOAT_DEFAULT_USER_PASSWORD); skipping creation of the '{}' and '{}'"
              + " accounts. Register an account or configure the property to seed them.",
          ADMIN_USERNAME,
          DEFAULT_USER_USERNAME);
      return;
    }

    // 1. Seed the default admin
    if (userRepository.existsByUsername(ADMIN_USERNAME)) {
      // Always ensure the admin has the correct role AND the configured password so that
      // the credentials remain predictable after every restart regardless of mid-session resets.
      userRepository.save(
          new WebGoatUser(ADMIN_USERNAME, defaultPassword, WebGoatUser.ROLE_ADMIN));
      log.info(
          "Ensured '{}' account is WEBGOAT_ADMIN with the configured default password.",
          ADMIN_USERNAME);
    } else {
      userRepository.save(
          new WebGoatUser(ADMIN_USERNAME, defaultPassword, WebGoatUser.ROLE_ADMIN));
      log.info(
          "Created default admin account '{}' with role {}.",
          ADMIN_USERNAME,
          WebGoatUser.ROLE_ADMIN);
    }

    // 2. Seed the default regular user
    if (!userRepository.existsByUsername(DEFAULT_USER_USERNAME)) {
      // Use UserService here because it properly provisions lessons and progress trackers
      // for a normal user, which is required for them to actually play the game.
      userService.addUser(DEFAULT_USER_USERNAME, defaultPassword);
      log.info(
          "Created default regular user account '{}' and provisioned lessons.",
          DEFAULT_USER_USERNAME);
    } else {
      log.info(
          "Default regular user account '{}' already exists. Skipping initialization.",
          DEFAULT_USER_USERNAME);
    }
  }
}
