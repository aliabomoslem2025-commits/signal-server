package org.whispersystems.textsecuregcm.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.whispersystems.textsecuregcm.configuration.LocalTurnConfiguration;

/**
 * Generates coturn TURN REST API credentials. The shared secret is never returned to clients;
 * only an account-scoped username and short-lived HMAC credential leave the server.
 */
public final class LocalTurnCredentialsManager implements TurnCredentialsProvider {
  private static final String HMAC_ALGORITHM = "HmacSHA1";

  private final byte[] sharedSecret;
  private final List<String> urls;
  private final long ttlSeconds;
  private final Clock clock;

  public LocalTurnCredentialsManager(final LocalTurnConfiguration configuration, final Clock clock) {
    this.sharedSecret = configuration.sharedSecret().value().getBytes(StandardCharsets.UTF_8);
    this.urls = List.copyOf(configuration.urls());
    this.ttlSeconds = configuration.credentialTtl().toSeconds();
    this.clock = clock;
    if (sharedSecret.length < 32) {
      throw new IllegalArgumentException("TURN REST shared secret must contain at least 32 UTF-8 bytes");
    }
    if (ttlSeconds <= 0 || ttlSeconds > 86_400) {
      throw new IllegalArgumentException("TURN credential TTL must be between 1 second and 24 hours");
    }
  }

  @Override
  public TurnToken retrieve(final UUID accountUuid) throws IOException {
    final long expiresAt = clock.instant().getEpochSecond() + ttlSeconds;
    final String username = expiresAt + ":" + accountUuid;
    try {
      final Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(new SecretKeySpec(sharedSecret, HMAC_ALGORITHM));
      final byte[] digest = mac.doFinal(username.getBytes(StandardCharsets.UTF_8));
      final String credential = Base64.getEncoder().encodeToString(digest);
      return new TurnToken(username, credential, ttlSeconds, urls, List.of(), null);
    } catch (Exception e) {
      throw new IOException("Unable to generate local TURN credentials", e);
    }
  }
}
