/*
 * Copyright 2026 Signal LAN customization
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validates and consumes short-lived tickets minted by the LAN-only Local Device Authentication service.
 *
 * The service validates the device proof before issuing a ticket. This adapter keeps that proof separate from
 * Signal's ACI/PNI identity and pre-key generation: it only replaces the proof-of-control check for a phone number.
 */
public final class LocalAuthTicketClient {
  private static final Logger logger = LoggerFactory.getLogger(LocalAuthTicketClient.class);
  private static final String PREFIX = "LAN1.";
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final URI baseUri;
  private final String bearerToken;
  private final HttpClient httpClient;

  private LocalAuthTicketClient(final URI baseUri, final String bearerToken) {
    this.baseUri = baseUri;
    this.bearerToken = bearerToken;
    this.httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(4))
        .version(HttpClient.Version.HTTP_1_1)
        .build();
  }

  /**
   * Local-auth integration is opt-in until the sidecar and client have been deployed together.
   * A partial configuration is a startup error; silently falling back could re-enable external SMS.
   */
  public static Optional<LocalAuthTicketClient> fromEnvironment() {
    final String endpoint = System.getenv("LOCAL_AUTH_INTERNAL_URL");
    final String token = System.getenv("LOCAL_AUTH_INTERNAL_TOKEN");
    if ((endpoint == null || endpoint.isBlank()) && (token == null || token.isBlank())) {
      return Optional.empty();
    }
    if (endpoint == null || endpoint.isBlank() || token == null || token.length() < 32) {
      throw new IllegalStateException("LOCAL_AUTH_INTERNAL_URL and a 32+ character LOCAL_AUTH_INTERNAL_TOKEN must be configured together");
    }

    final URI uri = URI.create(endpoint.trim());
    final String scheme = uri.getScheme();
    final String host = uri.getHost();
    final boolean loopbackHttp = "http".equalsIgnoreCase(scheme)
        && ("127.0.0.1".equals(host) || "localhost".equalsIgnoreCase(host) || "::1".equals(host));
    if (!"https".equalsIgnoreCase(scheme) && !loopbackHttp) {
      throw new IllegalStateException("LOCAL_AUTH_INTERNAL_URL must use HTTPS (HTTP is allowed only on loopback)");
    }
    return Optional.of(new LocalAuthTicketClient(uri, token));
  }

  public static boolean isLocalAuthSession(final byte[] sessionId) {
    return sessionId != null && new String(sessionId, java.nio.charset.StandardCharsets.UTF_8).startsWith(PREFIX);
  }

  public void validate(final String number, final byte[] sessionId)
      throws IOException, InterruptedException, InvalidRegistrationSessionException {
    call("validate-ticket", number, extractTicket(sessionId));
  }

  public void consume(final String number, final byte[] sessionId)
      throws IOException, InterruptedException, InvalidRegistrationSessionException {
    call("consume-ticket", number, extractTicket(sessionId));
  }

  private String extractTicket(final byte[] sessionId) throws InvalidRegistrationSessionException {
    if (!isLocalAuthSession(sessionId)) {
      throw new InvalidRegistrationSessionException("invalid local authentication session");
    }
    final String wrapped = new String(sessionId, java.nio.charset.StandardCharsets.UTF_8);
    final String ticket = wrapped.substring(PREFIX.length());
    if (!ticket.startsWith("lan1.") || ticket.length() > 4096) {
      throw new InvalidRegistrationSessionException("invalid local authentication ticket");
    }
    return ticket;
  }

  private void call(final String action, final String expectedNumber, final String ticket)
      throws IOException, InterruptedException, InvalidRegistrationSessionException {
    final URI endpoint = baseUri.resolve("/v1/local-auth/internal/" + action);
    final String body = OBJECT_MAPPER.writeValueAsString(java.util.Map.of("ticket", ticket));
    final HttpRequest request = HttpRequest.newBuilder(endpoint)
        .timeout(Duration.ofSeconds(6))
        .header("Authorization", "Bearer " + bearerToken)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();

    final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() == 401 || response.statusCode() == 403 || response.statusCode() == 404) {
      throw new InvalidRegistrationSessionException("local authentication ticket is invalid, expired, or already used");
    }
    if (response.statusCode() != 200) {
      logger.warn("Local authentication service returned HTTP {} for {}", response.statusCode(), action);
      throw new IOException("local authentication service unavailable");
    }

    final JsonNode json;
    try {
      json = OBJECT_MAPPER.readTree(response.body());
    } catch (final Exception e) {
      throw new IOException("invalid response from local authentication service", e);
    }
    if (!expectedNumber.equals(json.path("phone").asText())) {
      throw new InvalidRegistrationSessionException("local authentication ticket does not match the requested phone number");
    }
  }
}
