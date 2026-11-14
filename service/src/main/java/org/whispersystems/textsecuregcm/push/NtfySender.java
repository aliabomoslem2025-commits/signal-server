/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.push;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.configuration.NtfyConfiguration;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/**
 * Publishes opaque wake-up hints to a private ntfy instance. Signal message bodies are never sent to ntfy;
 * clients use the hint only to fetch authenticated, end-to-end encrypted envelopes from Signal Server.
 */
public class NtfySender implements PushNotificationSender {

  private static final Logger logger = LoggerFactory.getLogger(NtfySender.class);
  private static final Timer SEND_NOTIFICATION_TIMER = Metrics.timer(name(NtfySender.class, "sendNotification"));

  private final NtfyConfiguration configuration;
  private final HttpClient httpClient;

  public NtfySender(final ExecutorService executor, final NtfyConfiguration configuration) {
    this.configuration = configuration;
    this.httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .executor(executor)
        .version(HttpClient.Version.HTTP_1_1)
        .build();
  }

  private static String toNtfyMessage(final PushNotification pushNotification) {
    if (pushNotification.notificationType() == PushNotification.NotificationType.NOTIFICATION
        || pushNotification.notificationType() == PushNotification.NotificationType.ATTEMPT_LOGIN_NOTIFICATION_HIGH_PRIORITY) {
      return "wake";
    }

    // Registration/rate-limit challenges are control messages rather than chat content. Keep their
    // existing semantics while never publishing message text or attachment data.
    final Map<String, Object> event = new LinkedHashMap<>();
    event.put("type", pushNotification.notificationType().name());
    event.put("data", pushNotification.data());
    try {
      return SystemMapper.jsonMapper().writeValueAsString(event);
    } catch (final JsonProcessingException e) {
      throw new IllegalArgumentException("Unable to serialize ntfy control event", e);
    }
  }

  @Override
  public CompletableFuture<SendPushNotificationResult> sendNotification(final PushNotification pushNotification) {
    final String topic = pushNotification.deviceToken();
    if (topic == null || !topic.matches("signal-[A-Za-z0-9_-]{32,64}")) {
      return CompletableFuture.completedFuture(
          new SendPushNotificationResult(false, Optional.of("invalid-topic"), false, Optional.empty()));
    }

    final URI endpoint = URI.create(configuration.normalizedBaseUrl() + "/" +
        URLEncoder.encode(topic, StandardCharsets.UTF_8));
    final HttpRequest request = HttpRequest.newBuilder(endpoint)
        .timeout(Duration.ofSeconds(10))
        .header("Authorization", "Bearer " + configuration.publisherToken().value())
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("X-Firebase", "no")
        .header("Cache", "no")
        .header("X-Title", "Signal")
        .header("X-Priority", pushNotification.urgent() ? "5" : "3")
        .POST(HttpRequest.BodyPublishers.ofString(toNtfyMessage(pushNotification), StandardCharsets.UTF_8))
        .build();

    final Timer.Sample sample = Timer.start();
    return httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding())
        .whenComplete((ignored, throwable) -> sample.stop(SEND_NOTIFICATION_TIMER))
        .thenApply(response -> {
          final int status = response.statusCode();
          if (status >= 200 && status < 300) {
            return new SendPushNotificationResult(true, Optional.empty(), false, Optional.empty());
          }
          logger.warn("ntfy rejected a push notification with HTTP status {}", status);
          return new SendPushNotificationResult(false, Optional.of("http" + status), false, Optional.empty());
        });
  }
}
