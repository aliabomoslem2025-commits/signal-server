/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.whispersystems.textsecuregcm.storage.DynamoDbExtensionSchema.Tables;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;

class SandboxAccountsTest {

  @RegisterExtension
  static final DynamoDbExtension DYNAMO_DB_EXTENSION = new DynamoDbExtension(Tables.SANDBOX_ACCOUNTS);

  private SandboxAccounts sandboxAccounts;

  @BeforeEach
  void setUp() {
    sandboxAccounts = new SandboxAccounts(Tables.SANDBOX_ACCOUNTS.tableName(), DYNAMO_DB_EXTENSION.getDynamoDbClient());
  }

  @Test
  void addClaimRelease() {
    final Instant now = Instant.now();

    final UUID first = UUID.randomUUID();
    final UUID second = UUID.randomUUID();
    sandboxAccounts.add(first);
    sandboxAccounts.add(second);

    assertThat(sandboxAccounts.getAvailable()).containsExactlyInAnyOrder(first, second);
    assertThat(sandboxAccounts.getAll()).containsExactlyInAnyOrder(
        new SandboxAccounts.SandboxAccountReservation(first, Optional.empty()),
        new SandboxAccounts.SandboxAccountReservation(second, Optional.empty()));

    claim(first, now);
    assertThat(sandboxAccounts.getAvailable()).containsExactly(second);
    assertThat(sandboxAccounts.getAll()).containsExactlyInAnyOrder(
        new SandboxAccounts.SandboxAccountReservation(first, Optional.of(now.truncatedTo(ChronoUnit.SECONDS))),
        new SandboxAccounts.SandboxAccountReservation(second, Optional.empty()));

    assertThat(sandboxAccounts.releaseAci(first, now.truncatedTo(ChronoUnit.SECONDS))).isTrue();
    assertThat(sandboxAccounts.releaseAci(first, now.truncatedTo(ChronoUnit.SECONDS))).isFalse();
    assertThat(sandboxAccounts.getAvailable()).containsExactlyInAnyOrder(first, second);
  }

  @Test
  void claimFailure() {
    final Instant now = Instant.now();
    final UUID notInPool = UUID.randomUUID();
    final UUID alreadyClaimed = UUID.randomUUID();

    sandboxAccounts.add(alreadyClaimed);
    claim(alreadyClaimed, now);

    assertThrows(TransactionCanceledException.class, () -> claim(alreadyClaimed, now));
    assertThrows(TransactionCanceledException.class, () -> claim(notInPool, now));
  }

  @Test
  void removeIfAvailable() {
    final UUID available = UUID.randomUUID();
    final UUID claimed = UUID.randomUUID();
    sandboxAccounts.add(available);
    sandboxAccounts.add(claimed);
    claim(claimed, Instant.now());

    assertThat(sandboxAccounts.removeIfAvailable(available)).isTrue();
    assertThat(sandboxAccounts.removeIfAvailable(available)).isFalse();
    assertThat(sandboxAccounts.removeIfAvailable(claimed)).isFalse();
    assertThat(sandboxAccounts.getAll()).extracting(SandboxAccounts.SandboxAccountReservation::uuid).containsExactly(claimed);
  }

  private void claim(final UUID aci, final Instant registeredAt) {
    DYNAMO_DB_EXTENSION.getDynamoDbClient().transactWriteItems(TransactWriteItemsRequest.builder()
        .transactItems(sandboxAccounts.buildClaimWriteItem(aci, registeredAt))
        .build());
  }
}
