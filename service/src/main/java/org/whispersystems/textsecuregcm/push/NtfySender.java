/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.push;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.configuration.NtfyConfiguration;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/**
 * Sends an opaque wake-up hint only. Signal message envelopes are fetched from the authenticated
 * Signal receive channel and remain end-to-end encrypted; they are never placed on ntfy.
 */
public final class NtfySender implements PushNotificationSender {
  private static final Logger logger = LoggerFactory.getLogger(NtfySender.class);
  private static final Timer SEND_TIMER = Metrics.timer(name(NtfySender.class, "sendNotification"));

  private final URI baseUrl;
  private final String publisherToken;
  private final HttpClient httpClient;

  public NtfySender(final NtfyConfiguration configuration) {
    this(configuration, HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build());
  }

  NtfySender(final NtfyConfiguration configuration, final HttpClient httpClient) {
    this.baseUrl = URI.create(configuration.baseUrl().toString().replaceAll("/+$", ""));
    this.publisherToken = configuration.publisherToken().value();
    this.httpClient = httpClient;
  }

  /**
   * Preserve Signal's control-plane push events while keeping message contents out of ntfy.
   * Ordinary message and attempt-login pushes are only wake-up hints; the app fetches the
   * authenticated, end-to-end encrypted Signal payload through its normal receive channel.
   */
  static String toNtfyMessage(final PushNotification notification) {
    return switch (notification.notificationType()) {
      case NOTIFICATION, ATTEMPT_LOGIN_NOTIFICATION_HIGH_PRIORITY -> "wake";
      case CHALLENGE, RATE_LIMIT_CHALLENGE, VERIFICATION_CODE_REQUESTED -> {
        final Map<String, Object> event = new LinkedHashMap<>();
        event.put("type", notification.notificationType().name());
        event.put("data", notification.data());
        try {
          yield SystemMapper.jsonMapper().writeValueAsString(event);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
          throw new IllegalArgumentException("Unable to serialize ntfy control event", e);
        }
      }
    };
  }

  @Override
  public CompletableFuture<SendPushNotificationResult> sendNotification(final PushNotification notification) {
    final String topic = notification.deviceToken();
    if (topic == null || !topic.matches("signal-[A-Za-z0-9_-]{32,64}")) {
      return CompletableFuture.completedFuture(new SendPushNotificationResult(
          false, Optional.of("invalid_topic"), false, Optional.empty()));
    }

    final String message;
    try {
      message = toNtfyMessage(notification);
    } catch (final IllegalArgumentException e) {
      logger.warn("Unable to encode Signal ntfy control event", e);
      return CompletableFuture.completedFuture(new SendPushNotificationResult(
          false, Optional.of("invalid_payload"), false, Optional.empty()));
    }

    final URI target = baseUrl.resolve(baseUrl.getPath().endsWith("/") ? topic : baseUrl.getPath() + "/" + topic);
    final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(target)
        .timeout(Duration.ofSeconds(8))
        .header("Authorization", "Bearer " + publisherToken)
        .header("Content-Type", "text/plain; charset=utf-8")
        // Explicitly suppress ntfy's optional Firebase bridge. This project uses the direct LAN stream.
        .header("X-Firebase", "no")
        // Retain the opaque wake/control event on the ntfy server so a reconnecting handset can resume by message ID.
        .header("Cache", "yes")
        .header("X-Title", "Signal")
        .header("Priority", notification.urgent() ? "5" : "3");
    notification.ttl().ifPresent(ttl -> requestBuilder.header("X-Message-TTL", Long.toString(ttl.toSeconds())));
    final HttpRequest request = requestBuilder
        .POST(HttpRequest.BodyPublishers.ofString(message, StandardCharsets.UTF_8))
        .build();

    final Timer.Sample sample = Timer.start();
    return httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding())
        .whenComplete((ignored, error) -> sample.stop(SEND_TIMER))
        .handle((response, error) -> {
          if (error != null) {
            logger.warn("Unable to publish Signal wake-up hint to ntfy", error);
            return new SendPushNotificationResult(false, Optional.of(error.getClass().getSimpleName()), false, Optional.empty());
          }
          final int status = response.statusCode();
          if (status >= 200 && status < 300) {
            return new SendPushNotificationResult(true, Optional.empty(), false, Optional.empty());
          }
          logger.warn("ntfy rejected a Signal wake-up hint with HTTP {}", status);
          return new SendPushNotificationResult(false, Optional.of("http" + status), false, Optional.empty());
        });
  }
}
