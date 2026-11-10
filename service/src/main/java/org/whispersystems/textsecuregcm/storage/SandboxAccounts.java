/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.whispersystems.textsecuregcm.util.AttributeValues;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ReturnValue;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.Update;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;

/// The pool of account identifiers available for short-lived sandbox accounts and whether they are currently in use.
public class SandboxAccounts {

  // B: uuid; primary key
  static final String KEY_ACCOUNT_UUID = "U";
  // N: registration timestamp in epoch seconds. Only present if there is an active account with this ACI
  static final String ATTR_REGISTERED_AT = "R";

  private final String tableName;
  private final DynamoDbClient dynamoDbClient;

  /// @param uuid         the sandbox ACI
  /// @param registeredAt when an account registered with this ACI, or empty if the ACI is available
  public record SandboxAccountReservation(UUID uuid, Optional<Instant> registeredAt) {}

  public SandboxAccounts(final String tableName, final DynamoDbClient dynamoDbClient) {
    this.tableName = tableName;
    this.dynamoDbClient = dynamoDbClient;
  }

  /// Get sandbox ACIs that no account currently holds
  public List<UUID> getAvailable() {
    return dynamoDbClient.scanPaginator(ScanRequest.builder()
            .tableName(tableName)
            .filterExpression("attribute_not_exists(#registeredAt)")
            .expressionAttributeNames(Map.of("#registeredAt", ATTR_REGISTERED_AT))
            .build())
        .items()
        .stream()
        .map(item -> AttributeValues.getUUID(item, KEY_ACCOUNT_UUID, null))
        .toList();
  }

  /// Get every ACI in the pool along with its registration timestamp, if any.
  public List<SandboxAccountReservation> getAll() {
    return dynamoDbClient.scanPaginator(ScanRequest.builder().tableName(tableName).build())
        .items()
        .stream()
        .map(item -> new SandboxAccountReservation(
            AttributeValues.getUUID(item, KEY_ACCOUNT_UUID, null),
            AttributeValues.get(item, ATTR_REGISTERED_AT)
                .map(AttributeValue::n)
                .map(Long::parseLong)
                .map(Instant::ofEpochSecond)))
        .toList();
  }

  /// Build a [TransactWriteItem] that claims a pool ACI for a new account. The transaction fails if the ACI is not in
  /// the pool or is already claimed.
  ///
  /// @param uuid         the pool ACI to claim
  /// @param registeredAt the registration time of the new account
  public TransactWriteItem buildClaimWriteItem(final UUID uuid, final Instant registeredAt) {
    return TransactWriteItem.builder()
        .update(Update.builder()
            .tableName(tableName)
            .key(Map.of(KEY_ACCOUNT_UUID, AttributeValues.fromUUID(uuid)))
            .updateExpression("SET #registeredAt = :registeredAt")
            .conditionExpression("attribute_exists(#uuid) AND attribute_not_exists(#registeredAt)")
            .expressionAttributeNames(Map.of(
                "#uuid", KEY_ACCOUNT_UUID,
                "#registeredAt", ATTR_REGISTERED_AT))
            .expressionAttributeValues(Map.of(
                ":registeredAt", AttributeValues.fromLong(registeredAt.getEpochSecond())))
            .build())
        .build();
  }

  /// Mark a previously used ACI as available. The corresponding account must be deleted first.
  ///
  /// @param uuid                 the ACI to release
  /// @param expectedRegisteredAt the registration timestamp the caller observed
  /// @return true if the registration was cleared, or false if the ACI's registration timestamp no longer matches
  /// `expectedRegisteredAt`
  public boolean releaseAci(final UUID uuid, final Instant expectedRegisteredAt) {
    try {
      dynamoDbClient.updateItem(UpdateItemRequest.builder()
          .tableName(tableName)
          .key(Map.of(KEY_ACCOUNT_UUID, AttributeValues.fromUUID(uuid)))
          .updateExpression("REMOVE #registeredAt")
          .conditionExpression("#registeredAt = :expectedRegisteredAt")
          .expressionAttributeNames(Map.of("#registeredAt", ATTR_REGISTERED_AT))
          .expressionAttributeValues(Map.of(
              ":expectedRegisteredAt", AttributeValues.fromLong(expectedRegisteredAt.getEpochSecond())))
          .build());
      return true;
    } catch (final ConditionalCheckFailedException _) {
      return false;
    }
  }

  /// Add an ACI to the pool. Adding an ACI that is already in the pool has no effect.
  public void add(final UUID uuid) {
    try {
      dynamoDbClient.putItem(PutItemRequest.builder()
          .tableName(tableName)
          .item(Map.of(KEY_ACCOUNT_UUID, AttributeValues.fromUUID(uuid)))
          .conditionExpression("attribute_not_exists(#uuid)")
          .expressionAttributeNames(Map.of("#uuid", KEY_ACCOUNT_UUID))
          .build());
    } catch (final ConditionalCheckFailedException _) {
      // Already in the pool
    }
  }

  /// Remove an ACI from the pool if no account currently holds it
  ///
  /// @return true if the ACI was removed, or false if it is currently claimed or did not exist
  public boolean removeIfAvailable(final UUID uuid) {
    try {
      final DeleteItemResponse resp = dynamoDbClient.deleteItem(DeleteItemRequest.builder()
          .tableName(tableName)
          .key(Map.of(KEY_ACCOUNT_UUID, AttributeValues.fromUUID(uuid)))
          .conditionExpression("attribute_not_exists(#registeredAt)")
          .expressionAttributeNames(Map.of("#registeredAt", ATTR_REGISTERED_AT))
          .returnValues(ReturnValue.ALL_OLD)
          .build());
      return resp.hasAttributes();
    } catch (final ConditionalCheckFailedException _) {
      return false;
    }
  }
}
