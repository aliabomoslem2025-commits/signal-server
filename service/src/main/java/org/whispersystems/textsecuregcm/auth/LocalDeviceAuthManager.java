/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.auth;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.whispersystems.textsecuregcm.configuration.LocalDeviceAuthConfiguration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;
import org.whispersystems.textsecuregcm.entities.LocalDeviceAuthSession;
import org.whispersystems.textsecuregcm.registration.VerificationSession;
import org.whispersystems.textsecuregcm.util.AttributeValues;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;

/**
 * Validates administrator-enrolled phone/device pairs and creates single-use local registration sessions.
 *
 * The DynamoDB table must use partition key "P" and sort key "S". Enrollment rows use
 * P="ENROLLMENT#<E164>", S="DEVICE#<HMAC(AndroidID)>". Session rows use
 * P="SESSION#<encoded-session-id>", S="LOCAL_AUTH".
 */
public final class LocalDeviceAuthManager {

  private static final byte[] SESSION_MARKER = new byte[] { 'L', 'A', 'N', '1' };
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final String ATTR_P = "P";
  private static final String ATTR_S = "S";

  private final DynamoDbClient dynamoDbClient;
  private final String tableName;
  private final byte[] hmacKey;
  private final int maxCodeAttempts;
  private final long sessionTtlSeconds;
  private final Clock clock;

  public LocalDeviceAuthManager(
      final DynamoDbClient dynamoDbClient,
      final LocalDeviceAuthConfiguration configuration,
      final Clock clock) {
    this.dynamoDbClient = dynamoDbClient;
    this.tableName = configuration.getTableName();
    this.hmacKey = configuration.getAndroidIdHmacKey().value().getBytes(StandardCharsets.UTF_8);
    this.maxCodeAttempts = configuration.getMaxCodeAttempts();
    this.sessionTtlSeconds = configuration.getSessionTtl().toSeconds();
    this.clock = clock;
  }

  public void enroll(final String number, final String androidId, final boolean enabled) {
    final String normalizedNumber = normalizeNumber(number);
    final String deviceHash = hashAndroidId(androidId);
    dynamoDbClient.putItem(PutItemRequest.builder()
        .tableName(tableName)
        .item(Map.of(
            ATTR_P, s("ENROLLMENT#" + normalizedNumber),
            ATTR_S, s("DEVICE#" + deviceHash),
            "number", s(normalizedNumber),
            "deviceHash", s(deviceHash),
            "enabled", bool(enabled),
            "createdAt", n(clock.instant().getEpochSecond())))
        .build());
  }

  public List<Enrollment> listEnrollments() {
    final List<Enrollment> enrollments = new ArrayList<>();
    dynamoDbClient.scanPaginator(ScanRequest.builder()
            .tableName(tableName)
            .filterExpression("begins_with(#p, :prefix)")
            .expressionAttributeNames(Map.of("#p", ATTR_P))
            .expressionAttributeValues(Map.of(":prefix", s("ENROLLMENT#")))
            .build())
        .items()
        .forEach(item -> enrollments.add(new Enrollment(
            value(item, "number"),
            value(item, "deviceHash"),
            Boolean.parseBoolean(value(item, "enabled")),
            longValue(item, "createdAt"))));
    return List.copyOf(enrollments);
  }

  public void revoke(final String number, final String androidId) {
    final String normalizedNumber = normalizeNumber(number);
    final String deviceHash = hashAndroidId(androidId);
    dynamoDbClient.deleteItem(DeleteItemRequest.builder()
        .tableName(tableName)
        .key(key("ENROLLMENT#" + normalizedNumber, "DEVICE#" + deviceHash))
        .build());
  }

  public LocalDeviceAuthSession createSession(final String number, final String androidId) {
    final String normalizedNumber = normalizeNumber(number);
    final String deviceHash = hashAndroidId(androidId);
    final Map<String, AttributeValue> enrollment = dynamoDbClient.getItem(GetItemRequest.builder()
        .tableName(tableName)
        .key(key("ENROLLMENT#" + normalizedNumber, "DEVICE#" + deviceHash))
        .consistentRead(true)
        .build()).item();

    if (enrollment == null || enrollment.isEmpty() || !Boolean.parseBoolean(value(enrollment, "enabled"))) {
      throw new LocalDeviceNotEnrolledException();
    }

    final byte[] rawSessionId = new byte[32];
    RANDOM.nextBytes(rawSessionId);
    System.arraycopy(SESSION_MARKER, 0, rawSessionId, 0, SESSION_MARKER.length);
    final String encodedSessionId = Base64.getUrlEncoder().withoutPadding().encodeToString(rawSessionId);
    final String code = String.format("%06d", RANDOM.nextInt(1_000_000));
    final long expiresAt = clock.instant().getEpochSecond() + sessionTtlSeconds;

    dynamoDbClient.putItem(PutItemRequest.builder()
        .tableName(tableName)
        .item(Map.of(
            ATTR_P, s("SESSION#" + encodedSessionId),
            ATTR_S, s("LOCAL_AUTH"),
            "number", s(normalizedNumber),
            "deviceHash", s(deviceHash),
            "codeHash", s(hashCode(encodedSessionId, code)),
            "verified", bool(false),
            "attempts", n(0),
            "expiresAt", n(expiresAt),
            "ttl", n(expiresAt)))
        .build());

    return new LocalDeviceAuthSession(encodedSessionId, code, false, expiresAt);
  }

  public LocalDeviceAuthSession verifyCode(final String encodedSessionId, final String code) {
    final SessionRecord session = findSession(encodedSessionId).orElseThrow(LocalDeviceSessionNotFoundException::new);
    final long now = clock.instant().getEpochSecond();

    if (session.expiresAt() <= now || session.verified()) {
      throw new LocalDeviceSessionNotFoundException();
    }

    if (session.attempts() >= maxCodeAttempts) {
      throw new LocalDeviceSessionLockedException();
    }

    if (!MessageDigest.isEqual(
        hashCode(encodedSessionId, code).getBytes(StandardCharsets.US_ASCII),
        session.codeHash().getBytes(StandardCharsets.US_ASCII))) {
      dynamoDbClient.updateItem(UpdateItemRequest.builder()
          .tableName(tableName)
          .key(key("SESSION#" + encodedSessionId, "LOCAL_AUTH"))
          .updateExpression("SET #attempts = #attempts + :one")
          .conditionExpression("attribute_exists(#p) AND #expires > :now AND #verified = :false")
          .expressionAttributeNames(Map.of(
              "#p", ATTR_P,
              "#attempts", "attempts",
              "#expires", "expiresAt",
              "#verified", "verified"))
          .expressionAttributeValues(Map.of(
              ":one", n(1),
              ":now", n(now),
              ":false", bool(false)))
          .build());
      throw new LocalDeviceCodeInvalidException();
    }

    dynamoDbClient.updateItem(UpdateItemRequest.builder()
        .tableName(tableName)
        .key(key("SESSION#" + encodedSessionId, "LOCAL_AUTH"))
        .updateExpression("SET #verified = :true REMOVE #codeHash")
        .conditionExpression("attribute_exists(#p) AND #expires > :now AND #verified = :false AND #attempts < :max")
        .expressionAttributeNames(Map.of(
            "#p", ATTR_P,
            "#verified", "verified",
            "#codeHash", "codeHash",
            "#expires", "expiresAt",
            "#attempts", "attempts"))
        .expressionAttributeValues(Map.of(
            ":true", bool(true),
            ":false", bool(false),
            ":now", n(now),
            ":max", n(maxCodeAttempts)))
        .build());

    return new LocalDeviceAuthSession(encodedSessionId, null, true, session.expiresAt());
  }

  public void verifyRegistrationSession(final String number, final byte[] sessionId) {
    if (!isLocalSessionId(sessionId)) {
      throw new InvalidLocalSessionIdException();
    }
    final String encodedSessionId = Base64.getUrlEncoder().withoutPadding().encodeToString(sessionId);
    final SessionRecord session = findSession(encodedSessionId).orElseThrow(LocalDeviceSessionNotFoundException::new);

    if (!session.verified() || session.expiresAt() <= clock.instant().getEpochSecond()) {
      throw new LocalDeviceSessionNotVerifiedException();
    }

    if (!MessageDigest.isEqual(normalizeNumber(number).getBytes(StandardCharsets.UTF_8),
        session.number().getBytes(StandardCharsets.UTF_8))) {
      throw new InvalidLocalSessionIdException();
    }
  }

  public boolean isLocalSessionId(final byte[] sessionId) {
    if (sessionId == null || sessionId.length != 32) {
      return false;
    }
    for (int i = 0; i < SESSION_MARKER.length; i++) {
      if (sessionId[i] != SESSION_MARKER[i]) {
        return false;
      }
    }
    return true;
  }

  private Optional<SessionRecord> findSession(final String encodedSessionId) {
    final Map<String, AttributeValue> item = dynamoDbClient.getItem(GetItemRequest.builder()
        .tableName(tableName)
        .key(key("SESSION#" + encodedSessionId, "LOCAL_AUTH"))
        .consistentRead(true)
        .build()).item();
    if (item == null || item.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(new SessionRecord(
        value(item, "number"),
        value(item, "deviceHash"),
        value(item, "codeHash"),
        Boolean.parseBoolean(value(item, "verified")),
        (int) longValue(item, "attempts"),
        longValue(item, "expiresAt")));
  }

  private String hashAndroidId(final String androidId) {
    if (androidId == null || androidId.isBlank()) {
      throw new IllegalArgumentException("androidId must not be blank");
    }
    return hmac("android-id:" + androidId.trim());
  }

  private String hashCode(final String sessionId, final String code) {
    return hmac("local-auth-code:" + sessionId + ":" + code);
  }

  private String hmac(final String value) {
    try {
      final Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("Could not calculate local authentication HMAC", e);
    }
  }

  private static String normalizeNumber(final String number) {
    if (number == null || !number.matches("^\\+[1-9][0-9]{7,14}$")) {
      throw new IllegalArgumentException("number must be in E.164 format");
    }
    return number;
  }

  private static Map<String, AttributeValue> key(final String p, final String s) {
    return Map.of(ATTR_P, s(p), ATTR_S, s(s));
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

  private static String value(final Map<String, AttributeValue> item, final String key) {
    final AttributeValue attribute = item.get(key);
    if (attribute == null) return "";
    if (attribute.s() != null) return attribute.s();
    if (attribute.bool() != null) return attribute.bool().toString();
    return "";
  }

  private static long longValue(final Map<String, AttributeValue> item, final String key) {
    final AttributeValue attribute = item.get(key);
    if (attribute == null || attribute.n() == null) return 0;
    return Long.parseLong(attribute.n());
  }

  public record Enrollment(String number, String deviceHash, boolean enabled, long createdAt) {}
  private record SessionRecord(String number, String deviceHash, String codeHash, boolean verified, int attempts, long expiresAt) {}

  public static class LocalDeviceNotEnrolledException extends RuntimeException {}
  public static class LocalDeviceSessionNotFoundException extends RuntimeException {}
  public static class LocalDeviceSessionNotVerifiedException extends RuntimeException {}
  public static class LocalDeviceSessionLockedException extends RuntimeException {}
  public static class LocalDeviceCodeInvalidException extends RuntimeException {}
  public static class InvalidLocalSessionIdException extends RuntimeException {}
}
