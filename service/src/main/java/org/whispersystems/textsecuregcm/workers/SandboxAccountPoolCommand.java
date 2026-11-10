/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.workers;

import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Environment;
import java.util.UUID;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.inf.Subparser;
import net.sourceforge.argparse4j.inf.Subparsers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.WhisperServerConfiguration;
import org.whispersystems.textsecuregcm.storage.SandboxAccounts;

/// Manages the pool of ACIs available for sandbox accounts
public class SandboxAccountPoolCommand extends AbstractCommandWithDependencies {

  private static final Logger log = LoggerFactory.getLogger(SandboxAccountPoolCommand.class);

  private static final String SUBCOMMAND_ARGUMENT = "subcommand";
  private static final String COUNT_ARGUMENT = "count";

  @FunctionalInterface
  private interface Subcommand {
    void run(SandboxAccounts sandboxAccounts, Namespace namespace);
  }

  public SandboxAccountPoolCommand() {
    super(new Application<>() {
      @Override
      public void run(final WhisperServerConfiguration configuration, final Environment environment) {
      }
    }, "sandbox-account-pool", "Adds, removes, or lists the ACIs available for sandbox accounts");
  }

  @Override
  public void configure(final Subparser subparser) {
    super.configure(subparser);

    final Subparsers subparsers = subparser.addSubparsers();

    final Subparser addParser = subparsers.addParser("add")
        .help("Add random ACIs to the pool")
        .setDefault(SUBCOMMAND_ARGUMENT, (Subcommand) SandboxAccountPoolCommand::add);
    addCountArgument(addParser, "The number of ACIs to add");

    final Subparser removeParser = subparsers.addParser("remove")
        .help("Remove unclaimed ACIs from the pool")
        .setDefault(SUBCOMMAND_ARGUMENT, (Subcommand) SandboxAccountPoolCommand::remove);
    addCountArgument(removeParser, "The number of ACIs to remove");

    subparsers.addParser("list")
        .help("List all ACIs in the pool")
        .setDefault(SUBCOMMAND_ARGUMENT, (Subcommand) SandboxAccountPoolCommand::list);
  }

  private static void addCountArgument(final Subparser subparser, final String help) {
    subparser.addArgument("count")
        .type(Integer.class)
        .dest(COUNT_ARGUMENT)
        .choices(Arguments.range(1, Integer.MAX_VALUE))
        .help(help);
  }

  @Override
  protected void run(final Environment environment, final Namespace namespace,
      final WhisperServerConfiguration configuration, final CommandDependencies commandDependencies) throws Exception {
    final Subcommand subcommand = namespace.get(SUBCOMMAND_ARGUMENT);
    subcommand.run(commandDependencies.sandboxAccounts(), namespace);
  }

  private static void add(final SandboxAccounts sandboxAccounts, final Namespace namespace) {
    final int count = namespace.getInt(COUNT_ARGUMENT);
    for (int i = 0; i < count; i++) {
      final UUID aci = UUID.randomUUID();
      sandboxAccounts.add(aci);
      log.info("Added sandbox ACI {}", aci);
    }
  }

  private static void remove(final SandboxAccounts sandboxAccounts, final Namespace namespace) {
    final int count = namespace.getInt(COUNT_ARGUMENT);
    int removed = 0;
    for (final UUID aci : sandboxAccounts.getAvailable()) {
      if (removed == count) {
        break;
      }
      if (sandboxAccounts.removeIfAvailable(aci)) {
        log.info("Removed sandbox ACI {}", aci);
        removed++;
      } else {
        log.info("Not removing sandbox ACI {} because it is currently claimed", aci);
      }
    }

    if (removed < count) {
      throw new RuntimeException(
          "Requested removal of %d sandbox ACIs, but only %d were unclaimed".formatted(count, removed));
    }
  }

  private static void list(final SandboxAccounts sandboxAccounts, final Namespace namespace) {
    for (final SandboxAccounts.SandboxAccountReservation sandboxAccount : sandboxAccounts.getAll()) {
      log.info("{} {}", sandboxAccount.uuid(), sandboxAccount.registeredAt()
          .map(registeredAt -> "expires " + registeredAt.plus(RemoveExpiredSandboxAccountsCommand.MAX_SANDBOX_ACCOUNT_AGE))
          .orElse("available"));
    }
  }
}
