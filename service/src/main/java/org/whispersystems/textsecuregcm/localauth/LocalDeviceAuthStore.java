/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.localauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.whispersystems.textsecuregcm.util.Pair;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;

/**
 * Durable storage for pre-authorized LAN devices, short-lived challenges, and registration sessions.
 *
 * The backing DynamoDB table must have string partition/sort keys named PK and SK. Keep this table
 * separate from Signal's account and message tables.
 */
public final class LocalDeviceAuthStore {
  public static final String DEFAULT_TABLE_NAME = "signal_local_device_auth";
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final DateTimeFormatter EVENT_MONTH = DateTimeFormatter.ofPattern("uuuu-MM").withZone(ZoneOffset.UTC);

  private final DynamoDbClient dynamoDb;
  private final String tableName;
  private final Clock clock;

  public LocalDeviceAuthStore(final DynamoDbClient dynamoDb, final String tableName) {
    this(dynamoDb, tableName, Clock.systemUTC());
  }

  LocalDeviceAuthStore(final DynamoDbClient dynamoDb, final String tableName, final Clock clock) {
    this.dynamoDb = dynamoDb;
    this.tableName = tableName;
    this.clock = clock;
  }

  public record Device(
      String phoneNumber,
      String androidId,
      String publicKey,
      String displayName,
      boolean enabled,
      long createdAt,
      long updatedAt,
      long lastSeenAt) { }

  public record Challenge(
      String challengeId,
      String phoneNumber,
      String androidId,
      String nonce,
      long expiresAt,
      boolean used) { }

  public record DevicePage(List<Device> devices, String nextCursor) { }

  public record Event(
      String id,
      String type,
      String phoneNumber,
      String androidId,
      boolean success,
      long createdAt) { }

  public Optional<Device> findDevice(final String phoneNumber, final String androidId) {
    final Map<String, AttributeValue> item = get(devicePk(phoneNumber), deviceSk(androidId));
    if (item.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(toDevice(item));
  }

  public void createDevice(
      final String phoneNumber,
      final String androidId,
      final String publicKey,
      final String displayName) {
    final long now = clock.instant().getEpochSecond();
    final Map<String, AttributeValue> item = key(devicePk(phoneNumber), deviceSk(androidId));
    item.put("phoneNumber", s(phoneNumber));
    item.put("androidId", s(androidId));
    item.put("publicKey", s(publicKey));
    item.put("displayName", s(displayName == null ? "" : displayName));
    item.put("enabled", bool(true));
    item.put("createdAt", n(now));
    item.put("updatedAt", n(now));
    item.put("lastSeenAt", n(0));
    dynamoDb.putItem(PutItemRequest.builder()
        .tableName(tableName)
        .item(item)
        .conditionExpression("attribute_not_exists(PK) AND attribute_not_exists(SK)")
        .build());
    recordEvent("DEVICE_CREATED", phoneNumber, androidId, true);
  }

  public boolean updateDevice(
      final String phoneNumber,
      final String androidId,
      final Boolean enabled,
      final String displayName) {
    final Map<String, AttributeValue> values = new HashMap<>();
    values.put(":now", n(clock.instant().getEpochSecond()));
    final StringBuilder expression = new StringBuilder("SET updatedAt = :now");
    if (enabled != null) {
      expression.append(", enabled = :enabled");
      values.put(":enabled", bool(enabled));
    }
    if (displayName != null) {
      expression.append(", displayName = :displayName");
      values.put(":displayName", s(displayName));
    }
    try {
      dynamoDb.updateItem(UpdateItemRequest.builder()
          .tableName(tableName)
          .key(key(devicePk(phoneNumber), deviceSk(androidId)))
          .updateExpression(expression.toString())
          .conditionExpression("attribute_exists(PK)")
          .expressionAttributeValues(values)
          .build());
      recordEvent("DEVICE_UPDATED", phoneNumber, androidId, true);
      return true;
    } catch (ConditionalCheckFailedException e) {
      return false;
    }
  }

  public boolean deleteDevice(final String phoneNumber, final String androidId) {
    try {
      dynamoDb.deleteItem(DeleteItemRequest.builder()
          .tableName(tableName)
          .key(key(devicePk(phoneNumber), deviceSk(androidId)))
          .conditionExpression("attribute_exists(PK)")
          .build());
      recordEvent("DEVICE_REVOKED", phoneNumber, androidId, true);
      return true;
    } catch (ConditionalCheckFailedException e) {
      return false;
    }
  }

  public DevicePage listDevices(final int requestedLimit, final String cursor, final String query) {
    final int limit = Math.max(1, Math.min(100, requestedLimit));
    final Map<String, AttributeValue> exclusiveStartKey = decodeCursor(cursor);
    final ScanResponse response = dynamoDb.scan(ScanRequest.builder()
        .tableName(tableName)
        .limit(limit)
        .exclusiveStartKey(exclusiveStartKey)
        .filterExpression("begins_with(SK, :devicePrefix)")
        .expressionAttributeValues(Map.of(":devicePrefix", s("DEVICE#")))
        .build());

    final String normalizedQuery = query == null ? "" : query.trim().toLowerCase();
    final List<Device> devices = response.items().stream()
        .map(LocalDeviceAuthStore::toDevice)
        .filter(device -> normalizedQuery.isEmpty()
            || device.phoneNumber().toLowerCase().contains(normalizedQuery)
            || device.androidId().toLowerCase().contains(normalizedQuery)
            || device.displayName().toLowerCase().contains(normalizedQuery))
        .toList();

    return new DevicePage(devices, encodeCursor(response.lastEvaluatedKey()));
  }

  public void createChallenge(
      final String challengeId,
      final String phoneNumber,
      final String androidId,
      final String nonce,
      final long expiresAt) {
    final Map<String, AttributeValue> item = key("CHALLENGE#" + challengeId, "NONCE");
    item.put("phoneNumber", s(phoneNumber));
    item.put("androidId", s(androidId));
    item.put("nonce", s(nonce));
    item.put("expiresAt", n(expiresAt));
    item.put("used", bool(false));
    dynamoDb.putItem(PutItemRequest.builder().tableName(tableName).item(item).build());
  }

  public Optional<Challenge> findChallenge(final String challengeId) {
    final Map<String, AttributeValue> item = get("CHALLENGE#" + challengeId, "NONCE");
    if (item.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(new Challenge(
        challengeId,
        value(item, "phoneNumber"),
        value(item, "androidId"),
        value(item, "nonce"),
        number(item, "expiresAt"),
        booleanValue(item, "used")));
  }

  /** Atomically prevents the same challenge from being redeemed twice. */
  public boolean consumeChallenge(final String challengeId) {
    try {
      dynamoDb.updateItem(UpdateItemRequest.builder()
          .tableName(tableName)
          .key(key("CHALLENGE#" + challengeId, "NONCE"))
          .updateExpression("SET used = :true")
          .conditionExpression("used = :false AND expiresAt > :now")
          .expressionAttributeValues(Map.of(
              ":true", bool(true),
              ":false", bool(false),
              ":now", n(clock.instant().getEpochSecond())))
          .build());
      return true;
    } catch (ConditionalCheckFailedException e) {
      return false;
    }
  }

  public String createRegistrationSession(
      final String phoneNumber,
      final String androidId,
      final String code,
      final long expiresAt) {
    final byte[] randomBytes = new byte[32];
    RANDOM.nextBytes(randomBytes);
    final String sessionId = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    final Map<String, AttributeValue> item = key("SESSION#" + sessionId, "VERIFIED");
    item.put("phoneNumber", s(phoneNumber));
    item.put("androidId", s(androidId));
    item.put("codeHash", s(hash(sessionId + ":" + code)));
    item.put("codeVerified", bool(false));
    item.put("expiresAt", n(expiresAt));
    item.put("createdAt", n(clock.instant().getEpochSecond()));
    dynamoDb.putItem(PutItemRequest.builder().tableName(tableName).item(item).build());
    recordEvent("AUTH_CODE_ISSUED", phoneNumber, androidId, true);
    return sessionId;
  }

  /** Verifies the six-digit code returned through the authenticated LAN response. */
  public boolean verifyRegistrationCode(final String phoneNumber, final String sessionId, final String code) {
    final Map<String, AttributeValue> item = get("SESSION#" + sessionId, "VERIFIED");
    if (item.isEmpty()
        || !phoneNumber.equals(value(item, "phoneNumber"))
        || booleanValue(item, "codeVerified")
        || number(item, "expiresAt") <= clock.instant().getEpochSecond()) {
      return false;
    }

    final String expectedHash = value(item, "codeHash");
    final String actualHash = hash(sessionId + ":" + code);
    if (!MessageDigest.isEqual(expectedHash.getBytes(StandardCharsets.US_ASCII),
        actualHash.getBytes(StandardCharsets.US_ASCII))) {
      recordEvent("AUTH_CODE_REJECTED", phoneNumber, value(item, "androidId"), false);
      return false;
    }

    try {
      dynamoDb.updateItem(UpdateItemRequest.builder()
          .tableName(tableName)
          .key(key("SESSION#" + sessionId, "VERIFIED"))
          .updateExpression("SET codeVerified = :true")
          .conditionExpression("codeVerified = :false AND expiresAt > :now")
          .expressionAttributeValues(Map.of(
              ":true", bool(true),
              ":false", bool(false),
              ":now", n(clock.instant().getEpochSecond())))
          .build());
      recordEvent("AUTH_CODE_ACCEPTED", phoneNumber, value(item, "androidId"), true);
      return true;
    } catch (ConditionalCheckFailedException e) {
      return false;
    }
  }

  /** Returns true only for a valid, unexpired local registration session whose code was submitted. */
  public boolean isVerifiedRegistrationSession(final String phoneNumber, final byte[] sessionIdBytes) {
    final String sessionId = Base64.getUrlEncoder().withoutPadding().encodeToString(sessionIdBytes);
    final Map<String, AttributeValue> item = get("SESSION#" + sessionId, "VERIFIED");
    return !item.isEmpty()
        && phoneNumber.equals(value(item, "phoneNumber"))
        && booleanValue(item, "codeVerified")
        && number(item, "expiresAt") > clock.instant().getEpochSecond();
  }

  public List<Event> listRecentEvents(final int requestedLimit) {
    final int limit = Math.max(1, Math.min(200, requestedLimit));
    final ScanResponse response = dynamoDb.scan(ScanRequest.builder()
        .tableName(tableName)
        .limit(limit)
        .filterExpression("begins_with(PK, :eventPrefix)")
        .expressionAttributeValues(Map.of(":eventPrefix", s("EVENT#")))
        .build());
    return response.items().stream()
        .map(item -> new Event(
            value(item, "SK"),
            value(item, "type"),
            value(item, "phoneNumber"),
            value(item, "androidId"),
            booleanValue(item, "success"),
            number(item, "createdAt")))
        .sorted((left, right) -> Long.compare(right.createdAt(), left.createdAt()))
        .limit(limit)
        .toList();
  }

  public void recordEvent(final String type, final String phoneNumber, final String androidId, final boolean success) {
    final long now = clock.instant().getEpochSecond();
    final String id = UUID.randomUUID().toString();
    final Map<String, AttributeValue> item = key("EVENT#" + EVENT_MONTH.format(Instant.ofEpochSecond(now)), id);
    item.put("type", s(type));
    item.put("phoneNumber", s(phoneNumber == null ? "" : phoneNumber));
    item.put("androidId", s(androidId == null ? "" : androidId));
    item.put("success", bool(success));
    item.put("createdAt", n(now));
    dynamoDb.putItem(PutItemRequest.builder().tableName(tableName).item(item).build());
  }

  private Map<String, AttributeValue> get(final String pk, final String sk) {
    return dynamoDb.getItem(GetItemRequest.builder()
        .tableName(tableName)
        .key(key(pk, sk))
        .consistentRead(true)
        .build()).item();
  }

  private static Device toDevice(final Map<String, AttributeValue> item) {
    return new Device(
        value(item, "phoneNumber"),
        value(item, "androidId"),
        value(item, "publicKey"),
        value(item, "displayName"),
        booleanValue(item, "enabled"),
        number(item, "createdAt"),
        number(item, "updatedAt"),
        number(item, "lastSeenAt"));
  }

  private static Map<String, AttributeValue> key(final String pk, final String sk) {
    return new HashMap<>(Map.of("PK", s(pk), "SK", s(sk)));
  }

  private static String devicePk(final String phoneNumber) {
    return "PHONE#" + phoneNumber;
  }

  private static String deviceSk(final String androidId) {
    return "DEVICE#" + hash(androidId);
  }

  private static AttributeValue s(final String value) {
    return AttributeValue.builder().s(value).build();
  }

  private static AttributeValue n(final long value) {
    return AttributeValue.builder().n(Long.toString(value)).build();
  }

  private static AttributeValue bool(final boolean value) {
    return AttributeValue.builder().bool(value).build();
  }

  private static String value(final Map<String, AttributeValue> item, final String name) {
    final AttributeValue value = item.get(name);
    return value == null || value.s() == null ? "" : value.s();
  }

  private static long number(final Map<String, AttributeValue> item, final String name) {
    final AttributeValue value = item.get(name);
    if (value == null || value.n() == null) {
      return 0;
    }
    try {
      return Long.parseLong(value.n());
    } catch (NumberFormatException e) {
      return 0;
    }
  }

  private static boolean booleanValue(final Map<String, AttributeValue> item, final String name) {
    final AttributeValue value = item.get(name);
    return value != null && Boolean.TRUE.equals(value.bool());
  }

  private static String hash(final String value) {
    try {
      return Base64.getUrlEncoder().withoutPadding()
          .encodeToString(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (Exception e) {
      throw new IllegalStateException("SHA-256 is unavailable", e);
    }
  }

  private static String encodeCursor(final Map<String, AttributeValue> lastKey) {
    if (lastKey == null || lastKey.isEmpty()) {
      return null;
    }
    final String raw = value(lastKey, "PK") + "\n" + value(lastKey, "SK");
    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
  }

  private static Map<String, AttributeValue> decodeCursor(final String cursor) {
    if (cursor == null || cursor.isBlank()) {
      return Map.of();
    }
    try {
      final String raw = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
      final int separator = raw.indexOf('\n');
      if (separator <= 0 || separator == raw.length() - 1) {
        throw new IllegalArgumentException("Invalid cursor");
      }
      return key(raw.substring(0, separator), raw.substring(separator + 1));
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid pagination cursor", e);
    }
  }
}
