/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.localauth;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.ServiceUnavailableException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.whispersystems.textsecuregcm.localauth.LocalDeviceAuthStore.Challenge;
import org.whispersystems.textsecuregcm.localauth.LocalDeviceAuthStore.Device;
import org.whispersystems.textsecuregcm.localauth.LocalDeviceAuthStore.DevicePage;
import org.whispersystems.textsecuregcm.localauth.LocalDeviceAuthStore.Event;

/**
 * LAN device authentication and device allow-list administration.
 *
 * Admin endpoints require Authorization: Bearer <LOCAL_AUTH_ADMIN_TOKEN>. The browser dashboard
 * must never embed this token in its build; an administrator enters it at runtime.
 */
@Path("/v1/local-auth")
@Produces(MediaType.APPLICATION_JSON)
public final class LocalDeviceAuthController {
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final long CHALLENGE_TTL_SECONDS = 180;
  private static final long REGISTRATION_SESSION_TTL_SECONDS = 900;
  private static final String ADMIN_TOKEN_ENV = "LOCAL_AUTH_ADMIN_TOKEN";

  private final LocalDeviceAuthStore store;
  private final Clock clock;
  private final String adminToken;

  public LocalDeviceAuthController(final LocalDeviceAuthStore store) {
    this(store, Clock.systemUTC(), System.getenv(ADMIN_TOKEN_ENV));
  }

  LocalDeviceAuthController(final LocalDeviceAuthStore store, final Clock clock, final String adminToken) {
    this.store = store;
    this.clock = clock;
    this.adminToken = adminToken;
  }

  public record ChallengeRequest(
      @NotBlank @Size(max = 32) @Pattern(regexp = "^\\+[1-9][0-9]{7,14}$") String phoneNumber,
      @NotBlank @Size(min = 1, max = 128) String androidId) { }

  public record ChallengeResponse(String challengeId, String nonce, long expiresAt) { }

  public record VerifyChallengeRequest(
      @NotBlank String challengeId,
      @NotBlank String signature) { }

  public record VerifyChallengeResponse(
      String code,
      String registrationSessionId,
      long expiresInSeconds) { }

  public record SubmitCodeRequest(
      @NotBlank String phoneNumber,
      @NotBlank String registrationSessionId,
      @NotBlank @Pattern(regexp = "^[0-9]{6}$") String code) { }

  public record SubmitCodeResponse(boolean verified) { }

  public record CreateDeviceRequest(
      @NotBlank @Size(max = 32) @Pattern(regexp = "^\\+[1-9][0-9]{7,14}$") String phoneNumber,
      @NotBlank @Size(max = 128) String androidId,
      @NotBlank @Size(max = 4096) String publicKey,
      @Size(max = 100) String displayName) { }

  public record UpdateDeviceRequest(Boolean enabled, @Size(max = 100) String displayName) { }

  public record DevicePageResponse(List<Device> devices, String nextCursor) { }

  public record EventsResponse(List<Event> events) { }

  @POST
  @Path("/challenge")
  @Consumes(MediaType.APPLICATION_JSON)
  public ChallengeResponse createChallenge(@NotNull @Valid final ChallengeRequest request) {
    final String phoneNumber = request.phoneNumber().trim();
    final String androidId = request.androidId().trim();
    final Device device = store.findDevice(phoneNumber, androidId)
        .filter(Device::enabled)
        .orElseThrow(() -> new NotFoundException("No pre-authorized device"));

    validateStoredPublicKey(device.publicKey());

    final byte[] nonceBytes = new byte[32];
    RANDOM.nextBytes(nonceBytes);
    final String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
    final String challengeId = UUID.randomUUID().toString();
    final long expiresAt = clock.instant().getEpochSecond() + CHALLENGE_TTL_SECONDS;

    store.createChallenge(challengeId, phoneNumber, androidId, nonce, expiresAt);
    return new ChallengeResponse(challengeId, nonce, expiresAt);
  }

  /**
   * Verifies the Android Keystore ECDSA signature and returns a one-time code inside this TLS-protected
   * response. The code is not sent through SMS, email, FCM, or any other external service.
   */
  @POST
  @Path("/verify")
  @Consumes(MediaType.APPLICATION_JSON)
  public VerifyChallengeResponse verifyChallenge(@NotNull @Valid final VerifyChallengeRequest request) {
    final Challenge challenge = store.findChallenge(request.challengeId())
        .orElseThrow(() -> new NotFoundException("Challenge not found"));

    if (challenge.used() || challenge.expiresAt() <= clock.instant().getEpochSecond()) {
      throw new NotAuthorizedException("Challenge expired or already used");
    }

    final Device device = store.findDevice(challenge.phoneNumber(), challenge.androidId())
        .filter(Device::enabled)
        .orElseThrow(() -> new NotAuthorizedException("Device is no longer authorized"));

    final boolean validSignature = verifySignature(device.publicKey(), challenge.nonce(), request.signature());
    if (!validSignature) {
      store.recordEvent("CHALLENGE_SIGNATURE_REJECTED", challenge.phoneNumber(), challenge.androidId(), false);
      throw new NotAuthorizedException("Device proof failed");
    }

    if (!store.consumeChallenge(challenge.challengeId())) {
      throw new NotAuthorizedException("Challenge was already consumed");
    }

    final String code = "%06d".formatted(RANDOM.nextInt(1_000_000));
    final long expiresAt = clock.instant().getEpochSecond() + REGISTRATION_SESSION_TTL_SECONDS;
    final String sessionId = store.createRegistrationSession(
        challenge.phoneNumber(), challenge.androidId(), code, expiresAt);
    return new VerifyChallengeResponse(code, sessionId, REGISTRATION_SESSION_TTL_SECONDS);
  }

  /**
   * The Android client calls this after the six-digit code has been placed in the existing Signal
   * verification-code field. A successful result marks the local registration session as verified.
   */
  @POST
  @Path("/submit-code")
  @Consumes(MediaType.APPLICATION_JSON)
  public SubmitCodeResponse submitCode(@NotNull @Valid final SubmitCodeRequest request) {
    final boolean verified = store.verifyRegistrationCode(
        request.phoneNumber(), request.registrationSessionId(), request.code());
    if (!verified) {
      throw new NotAuthorizedException("Invalid or expired local verification code");
    }
    return new SubmitCodeResponse(true);
  }

  @GET
  @Path("/admin/devices")
  public DevicePageResponse listDevices(
      @HeaderParam("Authorization") final String authorization,
      @QueryParam("q") @DefaultValue("") final String query,
      @QueryParam("limit") @DefaultValue("50") final int limit,
      @QueryParam("cursor") final String cursor) {
    requireAdmin(authorization);
    final DevicePage page = store.listDevices(limit, cursor, query);
    return new DevicePageResponse(page.devices(), page.nextCursor());
  }

  @POST
  @Path("/admin/devices")
  @Consumes(MediaType.APPLICATION_JSON)
  public Device createDevice(
      @HeaderParam("Authorization") final String authorization,
      @NotNull @Valid final CreateDeviceRequest request) {
    requireAdmin(authorization);
    final String phoneNumber = request.phoneNumber().trim();
    final String androidId = request.androidId().trim();
    validatePublicKey(request.publicKey());
    try {
      store.createDevice(phoneNumber, androidId, request.publicKey(), request.displayName());
    } catch (software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException e) {
      throw new WebApplicationException("This phone number and Android ID are already registered", 409);
    }
    return store.findDevice(phoneNumber, androidId).orElseThrow(() -> new ServiceUnavailableException("Device record was not created"));
  }

  @PUT
  @Path("/admin/devices/{phoneNumber}/{androidId}")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response updateDevice(
      @HeaderParam("Authorization") final String authorization,
      @PathParam("phoneNumber") final String phoneNumber,
      @PathParam("androidId") final String androidId,
      @NotNull @Valid final UpdateDeviceRequest request) {
    requireAdmin(authorization);
    if (request.enabled() == null && request.displayName() == null) {
      throw new BadRequestException("No device fields were supplied");
    }
    if (!store.updateDevice(phoneNumber, androidId, request.enabled(), request.displayName())) {
      throw new NotFoundException("Device not found");
    }
    return Response.noContent().build();
  }

  @DELETE
  @Path("/admin/devices/{phoneNumber}/{androidId}")
  public Response deleteDevice(
      @HeaderParam("Authorization") final String authorization,
      @PathParam("phoneNumber") final String phoneNumber,
      @PathParam("androidId") final String androidId) {
    requireAdmin(authorization);
    if (!store.deleteDevice(phoneNumber, androidId)) {
      throw new NotFoundException("Device not found");
    }
    return Response.noContent().build();
  }

  @GET
  @Path("/admin/events")
  public EventsResponse listEvents(
      @HeaderParam("Authorization") final String authorization,
      @QueryParam("limit") @DefaultValue("100") final int limit) {
    requireAdmin(authorization);
    return new EventsResponse(store.listRecentEvents(limit));
  }

  private void requireAdmin(final String authorization) {
    if (adminToken == null || adminToken.isBlank()) {
      throw new ServiceUnavailableException("LOCAL_AUTH_ADMIN_TOKEN is not configured");
    }
    if (authorization == null || !authorization.startsWith("Bearer ")) {
      throw new NotAuthorizedException("Admin bearer token required");
    }
    final byte[] expected = adminToken.getBytes(StandardCharsets.UTF_8);
    final byte[] actual = authorization.substring("Bearer ".length()).getBytes(StandardCharsets.UTF_8);
    if (!MessageDigest.isEqual(expected, actual)) {
      throw new ForbiddenException("Invalid admin token");
    }
  }

  private static boolean verifySignature(final String encodedPublicKey, final String encodedNonce, final String encodedSignature) {
    try {
      final PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(
          new X509EncodedKeySpec(Base64.getDecoder().decode(encodedPublicKey)));
      final Signature verifier = Signature.getInstance("SHA256withECDSA");
      verifier.initVerify(publicKey);
      verifier.update(Base64.getUrlDecoder().decode(encodedNonce));
      return verifier.verify(Base64.getUrlDecoder().decode(encodedSignature));
    } catch (Exception e) {
      return false;
    }
  }

  private static void validateStoredPublicKey(final String encodedPublicKey) {
    validatePublicKey(encodedPublicKey);
  }

  private static void validatePublicKey(final String encodedPublicKey) {
    try {
      final PublicKey key = KeyFactory.getInstance("EC").generatePublic(
          new X509EncodedKeySpec(Base64.getDecoder().decode(encodedPublicKey)));
      if (!"EC".equalsIgnoreCase(key.getAlgorithm())) {
        throw new IllegalArgumentException("An EC public key is required");
      }
      final java.security.interfaces.ECPublicKey ecKey = (java.security.interfaces.ECPublicKey) key;
      if (ecKey.getParams().getCurve().getField().getFieldSize() != 256) {
        throw new IllegalArgumentException("Only P-256 public keys are accepted");
      }
    } catch (Exception e) {
      throw new BadRequestException("publicKey must be a Base64-encoded X.509 EC P-256 public key", e);
    }
  }
}
