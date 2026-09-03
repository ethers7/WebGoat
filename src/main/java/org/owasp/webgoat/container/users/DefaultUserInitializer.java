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
 * Seeds default accounts on startup so that the platform can be made usable without manual database
 * intervention.
 *
 * <p>Seeding is opt-in and driven by configuration: the seed password is read from {@code
 * webgoat.default.admin.password} (environment variable {@code WEBGOAT_DEFAULT_ADMIN_PASSWORD}) and
 * no credential is shipped with the source. When that property is blank, nothing is seeded and a
 * warning is logged; accounts can then be created through self-registration.
 *
 * <p>When a seed password is configured and the users already exist, their credentials are left
 * untouched (for normal users) or re-ensured (for admins), making this bean idempotent across
 * restarts.
 */
@Component
@Slf4j
public class DefaultUserInitializer implements ApplicationRunner {

  private static final String ADMIN_USERNAME = "webgoat-admin";
  private static final String DEFAULT_USER_USERNAME = "webgoat-user";
  private static final String SEED_PASSWORD_PROPERTY = "webgoat.default.admin.password";
  private static final String SEED_PASSWORD_ENV_VARIABLE = "WEBGOAT_DEFAULT_ADMIN_PASSWORD";

  private final UserRepository userRepository;
  private final UserService userService;

  /** Seed password, supplied by configuration. Empty means "do not seed any account". */
  private final String seedPassword;

  public DefaultUserInitializer(
      UserRepository userRepository,
      UserService userService,
      @Value("${webgoat.default.admin.password:}") String seedPassword) {
    this.userRepository = userRepository;
    this.userService = userService;
    this.seedPassword = seedPassword;
  }

  @Override
  public void run(ApplicationArguments args) {
    if (!StringUtils.hasText(seedPassword)) {
      log.warn(
          "Default account seeding skipped: no seed password is configured, so neither '{}' nor"
              + " '{}' was created. Set '{}' (environment variable {}) to enable seeding, or"
              + " create an account through self-registration.",
          ADMIN_USERNAME,
          DEFAULT_USER_USERNAME,
          SEED_PASSWORD_PROPERTY,
          SEED_PASSWORD_ENV_VARIABLE);
      return;
    }

    // 1. Seed the default admin
    if (userRepository.existsByUsername(ADMIN_USERNAME)) {
      // Always ensure the admin has the correct role AND the configured password so that
      // the credentials remain predictable after every restart regardless of mid-session resets.
      userRepository.save(new WebGoatUser(ADMIN_USERNAME, seedPassword, WebGoatUser.ROLE_ADMIN));
      log.info(
          "Ensured '{}' account is WEBGOAT_ADMIN with the configured seed password.",
          ADMIN_USERNAME);
    } else {
      userRepository.save(new WebGoatUser(ADMIN_USERNAME, seedPassword, WebGoatUser.ROLE_ADMIN));
      log.info(
          "Created default admin account '{}' with role {}.",
          ADMIN_USERNAME,
          WebGoatUser.ROLE_ADMIN);
    }

    // 2. Seed the default regular user
    if (!userRepository.existsByUsername(DEFAULT_USER_USERNAME)) {
      // Use UserService here because it properly provisions lessons and progress trackers
      // for a normal user, which is required for them to actually play the game.
      userService.addUser(DEFAULT_USER_USERNAME, seedPassword);
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
