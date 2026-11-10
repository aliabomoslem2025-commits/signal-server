/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.workers;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import com.google.common.annotations.VisibleForTesting;
import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Environment;
import io.micrometer.core.instrument.Metrics;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.inf.Subparser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.WhisperServerConfiguration;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.SandboxAccounts;

/// Deletes sandbox accounts that are past [#MAX_SANDBOX_ACCOUNT_AGE]
public class RemoveExpiredSandboxAccountsCommand extends AbstractCommandWithDependencies {
  private static final Logger log = LoggerFactory.getLogger(RemoveExpiredSandboxAccountsCommand.class);
  public static final Duration MAX_SANDBOX_ACCOUNT_AGE = Duration.ofDays(1);

  private static final String RELEASED_ACI_COUNTER_NAME =
      name(RemoveExpiredSandboxAccountsCommand.class, "releasedAci");

  @VisibleForTesting
  static final String DRY_RUN_ARGUMENT = "dry-run";

  private final Clock clock;

  public RemoveExpiredSandboxAccountsCommand(final Clock clock) {
    super(new Application<>() {
      @Override
      public void run(final WhisperServerConfiguration configuration, final Environment environment) {
      }
    }, "remove-expired-sandbox-accounts", "Removes expired sandbox accounts and returns their ACIs to the pool");
    this.clock = clock;
  }

  @Override
  public void configure(final Subparser subparser) {
    super.configure(subparser);

    subparser.addArgument("--dry-run")
        .type(Boolean.class)
        .dest(DRY_RUN_ARGUMENT)
        .required(false)
        .setDefault(true)
        .help("If true, don't actually delete accounts or release ACIs");
  }

  @Override
  protected void run(final Environment environment, final Namespace namespace,
      final WhisperServerConfiguration configuration, final CommandDependencies commandDependencies) throws Exception {
    final boolean isDryRun = namespace.getBoolean(DRY_RUN_ARGUMENT);
    final AccountsManager accountsManager = commandDependencies.accountsManager();
    final SandboxAccounts sandboxAccounts = commandDependencies.sandboxAccounts();
    final Instant expirationThreshold = clock.instant().minus(MAX_SANDBOX_ACCOUNT_AGE);

    for (final SandboxAccounts.SandboxAccountReservation sandboxAccount : sandboxAccounts.getAll()) {
      if (sandboxAccount.registeredAt().isEmpty()) {
        continue;
      }
      final Instant registeredAt = sandboxAccount.registeredAt().get();
      final boolean expired = registeredAt.isBefore(expirationThreshold);
      if (!expired) {
        log.info("Skipping unexpired sandbox account {}", sandboxAccount);
        continue;
      }

      try {
        final Optional<Account> account = accountsManager.getByAccountIdentifier(sandboxAccount.uuid());
        if (!isDryRun) {
          account.ifPresent(_ -> accountsManager.delete(sandboxAccount.uuid(), AccountsManager.DeletionReason.EXPIRED));
          if (!sandboxAccounts.releaseAci(sandboxAccount.uuid(), registeredAt)) {
            log.warn("Registration for sandbox ACI {} changed before it could be released", sandboxAccount.uuid());
            continue;
          }
        }

        log.info("Released sandbox ACI {} registered at {} (exists: {}, dry run: {})",
            sandboxAccount.uuid(), registeredAt, account.isPresent(), isDryRun);
        Metrics.counter(RELEASED_ACI_COUNTER_NAME,
                "exists", String.valueOf(account.isPresent()),
                "dryRun", String.valueOf(isDryRun))
            .increment();
      } catch (final Exception e) {
        log.warn("Failed to remove sandbox account {}", sandboxAccount.uuid(), e);
      }
    }
  }
}
