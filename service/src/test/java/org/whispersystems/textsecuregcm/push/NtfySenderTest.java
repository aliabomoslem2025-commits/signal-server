/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.push;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.configuration.NtfyConfiguration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

class NtfySenderTest {

  private static PushNotification notification(
      final PushNotification.NotificationType type,
      final Object data) {
    return new PushNotification(
        "signal-0123456789abcdefghijklmnopqrstuv",
        PushNotification.TokenType.NTFY,
        type,
        data,
        null,
        null,
        type == PushNotification.NotificationType.ATTEMPT_LOGIN_NOTIFICATION_HIGH_PRIORITY,
        null);
  }

  @Test
  void ordinaryNotificationsContainOnlyOpaqueWakeHint() {
    assertEquals("wake", NtfySender.toNtfyMessage(
        notification(PushNotification.NotificationType.NOTIFICATION, Map.of("private", "must-not-leak"))));
  }

  @Test
  void attemptLoginNotificationsContainOnlyOpaqueWakeHint() {
    assertEquals("wake", NtfySender.toNtfyMessage(
        notification(PushNotification.NotificationType.ATTEMPT_LOGIN_NOTIFICATION_HIGH_PRIORITY, "private")));
  }

  @Test
  void registrationChallengeIsDeliveredAsControlEvent() {
    final String payload = NtfySender.toNtfyMessage(
        notification(PushNotification.NotificationType.CHALLENGE, "short-lived-token"));

    assertTrue(payload.contains("\"type\":\"CHALLENGE\""));
    assertTrue(payload.contains("\"data\":\"short-lived-token\""));
  }

  @Test
  void rateLimitChallengeIsDeliveredAsControlEvent() {
    final String payload = NtfySender.toNtfyMessage(
        notification(PushNotification.NotificationType.RATE_LIMIT_CHALLENGE, "rate-limit-token"));

    assertTrue(payload.contains("\"type\":\"RATE_LIMIT_CHALLENGE\""));
    assertTrue(payload.contains("\"data\":\"rate-limit-token\""));
  }

  @Test
  void verificationRequestDoesNotContainAccountOrMessageData() {
    final String payload = NtfySender.toNtfyMessage(
        notification(PushNotification.NotificationType.VERIFICATION_CODE_REQUESTED, Map.of("timestamp", 1234)));

    assertEquals("{\"type\":\"VERIFICATION_CODE_REQUESTED\",\"data\":{\"timestamp\":1234}}", payload);
    assertFalse(payload.contains("phoneNumber"));
    assertFalse(payload.contains("message"));
  }

  @Test
  void rejectsTopicsOutsideThePrivateSignalNamespace() {
    final NtfySender sender = new NtfySender(
        new NtfyConfiguration(URI.create("https://push.example.test"), new SecretString("test-token")));

    final PushNotification invalid = new PushNotification(
        "not-a-signal-topic",
        PushNotification.TokenType.NTFY,
        PushNotification.NotificationType.NOTIFICATION,
        null,
        null,
        null,
        true,
        null);

    final SendPushNotificationResult result = sender.sendNotification(invalid).join();

    assertFalse(result.accepted());
    assertEquals(Optional.of("invalid_topic"), result.errorCode());
  }
}
