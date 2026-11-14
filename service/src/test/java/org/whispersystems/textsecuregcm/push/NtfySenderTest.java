/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.push;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.net.URI;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.configuration.NtfyConfiguration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;
import org.whispersystems.textsecuregcm.tests.util.SynchronousExecutorService;

class NtfySenderTest {

  @Test
  void rejectsNonNtfyTopicsWithoutMakingARequest() {
    final NtfySender sender = new NtfySender(
        new SynchronousExecutorService(),
        new NtfyConfiguration(URI.create("https://push.example.test"), new SecretString("test-token")));

    final PushNotification notification = new PushNotification(
        "not-a-signal-topic",
        PushNotification.TokenType.NTFY,
        PushNotification.NotificationType.NOTIFICATION,
        null,
        null,
        null,
        true,
        null);

    final SendPushNotificationResult result = sender.sendNotification(notification).join();

    assertFalse(result.accepted());
    assertEquals(Optional.of("invalid-topic"), result.errorCode());
  }
}
