/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.workers;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.dropwizard.core.setup.Environment;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import javax.annotation.Nullable;
import net.sourceforge.argparse4j.inf.Namespace;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.whispersystems.textsecuregcm.WhisperServerConfiguration;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.SandboxAccounts;
import org.whispersystems.textsecuregcm.util.TestClock;
import org.whispersystems.textsecuregcm.storage.SandboxAccounts.SandboxAccountReservation;

class RemoveExpiredSandboxAccountsCommandTest {

  private static final Instant NOW = Instant.now();
  private static final Instant EXPIRED_REGISTRATION = NOW
      .minus(RemoveExpiredSandboxAccountsCommand.MAX_SANDBOX_ACCOUNT_AGE)
      .minusSeconds(1);
  private static final Instant FRESH_REGISTRATION = NOW.minus(Duration.ofHours(1));

  private AccountsManager accountsManager;
  private SandboxAccounts sandboxAccounts;

  @BeforeEach
  void setUp() {
    accountsManager = mock(AccountsManager.class);
    sandboxAccounts = mock(SandboxAccounts.class);
    when(sandboxAccounts.releaseAci(any(), any())).thenReturn(true);
  }


  static Stream<Arguments> processSandboxAccounts() {
    final Account account = mock(Account.class);
    return Stream.of(
        Arguments.argumentSet("stale-account", account, EXPIRED_REGISTRATION, true, true),
        Arguments.argumentSet("stale-deleted-account", null, EXPIRED_REGISTRATION, true, false),
        Arguments.argumentSet("fresh-account", account, FRESH_REGISTRATION, false, false),
        Arguments.argumentSet("fresh-deleted-account", null, FRESH_REGISTRATION, false, false),
        Arguments.argumentSet("untracked-account", account, null, false, false)
    );
  }

  @ParameterizedTest
  @MethodSource
  void processSandboxAccounts(final @Nullable Account account, @Nullable final Instant registrationTime, final boolean expectRelease, final boolean expectDelete) throws Exception {
    final UUID aci = UUID.randomUUID();
    when(sandboxAccounts.getAll())
        .thenReturn(List.of(new SandboxAccountReservation(aci, Optional.ofNullable(registrationTime))));
    when(accountsManager.getByAccountIdentifier(aci))
        .thenReturn(Optional.ofNullable(account));

    runCommand(false);

    verify(sandboxAccounts, times(expectRelease ? 1 : 0)).releaseAci(aci, registrationTime);
    verify(accountsManager, times(expectDelete ? 1 : 0)).delete(any(), any());
  }

  @Test
  void dryRun() throws Exception {
    final UUID aci = UUID.randomUUID();
    when(sandboxAccounts.getAll())
        .thenReturn(List.of(new SandboxAccountReservation(aci, Optional.of(EXPIRED_REGISTRATION))));
    when(accountsManager.getByAccountIdentifier(aci))
        .thenReturn(Optional.of(mock(Account.class)));

    runCommand(true);

    verify(accountsManager, never()).delete(any(), any());
    verify(sandboxAccounts, never()).releaseAci(any(), any());
  }

  private void runCommand(final boolean isDryRun) throws Exception {
    final CommandDependencies commandDependencies = mock(CommandDependencies.class);
    when(commandDependencies.accountsManager()).thenReturn(accountsManager);
    when(commandDependencies.sandboxAccounts()).thenReturn(sandboxAccounts);

    final Namespace namespace = mock(Namespace.class);
    when(namespace.getBoolean(RemoveExpiredSandboxAccountsCommand.DRY_RUN_ARGUMENT)).thenReturn(isDryRun);

    new RemoveExpiredSandboxAccountsCommand(TestClock.pinned(NOW))
        .run(mock(Environment.class), namespace, mock(WhisperServerConfiguration.class), commandDependencies);
  }
}
