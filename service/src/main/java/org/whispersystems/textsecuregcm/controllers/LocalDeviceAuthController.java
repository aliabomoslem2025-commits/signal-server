/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.auth.LocalDeviceAuthManager;
import org.whispersystems.textsecuregcm.configuration.LocalDeviceAuthConfiguration;
import org.whispersystems.textsecuregcm.entities.LocalDeviceAuthSession;

/**
 * LAN-only device enrollment and local registration authentication.
 *
 * Protect the administrator routes with a firewall or private management network in addition to the
 * bearer token. The client routes must only be exposed over TLS.
 */
@Path("/")
public final class LocalDeviceAuthController {

  private static final String ADMIN_HEADER = "X-Local-Admin-Token";

  private final LocalDeviceAuthManager manager;
  private final LocalDeviceAuthConfiguration configuration;

  public LocalDeviceAuthController(
      final LocalDeviceAuthManager manager,
      final LocalDeviceAuthConfiguration configuration) {
    this.manager = manager;
    this.configuration = configuration;
  }

  @POST
  @Path("/v1/local-auth/sessions")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "Start local device authentication using an administrator-enrolled phone/device pair")
  public LocalDeviceAuthSession createSession(@NotBlank @Valid final CreateSessionRequest request) {
    try {
      return manager.createSession(request.number(), request.androidId());
    } catch (final LocalDeviceAuthManager.LocalDeviceNotEnrolledException e) {
      // Deliberately do not reveal whether the phone number or Android ID was the mismatching value.
      throw new NotAuthorizedException("Device authentication failed");
    }
  }

  @POST
  @Path("/v1/local-auth/sessions/{sessionId}/verify")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "Consume the one-time local authentication value")
  public LocalDeviceAuthSession verifyCode(
      @jakarta.ws.rs.PathParam("sessionId") final String sessionId,
      @NotBlank @Valid final VerifyCodeRequest request) {
    try {
      return manager.verifyCode(sessionId, request.code());
    } catch (final LocalDeviceAuthManager.LocalDeviceCodeInvalidException e) {
      throw new NotAuthorizedException("Device authentication failed");
    } catch (final LocalDeviceAuthManager.LocalDeviceSessionLockedException e) {
      throw new jakarta.ws.rs.ClientErrorException(Response.Status.TOO_MANY_REQUESTS);
    } catch (final LocalDeviceAuthManager.LocalDeviceSessionNotFoundException e) {
      throw new jakarta.ws.rs.NotFoundException();
    }
  }

  @POST
  @Path("/v1/admin/device-enrollments")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "Create or update an administrator-provisioned phone/device enrollment")
  public Response enroll(
      @HeaderParam(ADMIN_HEADER) final String adminToken,
      @NotBlank @Valid final EnrollmentRequest request) {
    requireAdministrator(adminToken);
    manager.enroll(request.number(), request.androidId(), request.enabled());
    return Response.noContent().build();
  }

  @GET
  @Path("/v1/admin/device-enrollments")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "List administrator-provisioned phone/device enrollments")
  public List<LocalDeviceAuthManager.Enrollment> listEnrollments(
      @HeaderParam(ADMIN_HEADER) final String adminToken) {
    requireAdministrator(adminToken);
    return manager.listEnrollments();
  }

  @DELETE
  @Path("/v1/admin/device-enrollments")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "Revoke an administrator-provisioned phone/device enrollment")
  public Response revoke(
      @HeaderParam(ADMIN_HEADER) final String adminToken,
      @NotBlank @Valid final EnrollmentRequest request) {
    requireAdministrator(adminToken);
    manager.revoke(request.number(), request.androidId());
    return Response.noContent().build();
  }

  private void requireAdministrator(@Nullable final String suppliedToken) {
    final String expectedToken = configuration.getAdminApiToken().value();
    if (suppliedToken == null || !MessageDigest.isEqual(
        expectedToken.getBytes(StandardCharsets.UTF_8),
        suppliedToken.getBytes(StandardCharsets.UTF_8))) {
      throw new NotAuthorizedException("Administrator authentication required");
    }
  }

  public record CreateSessionRequest(
      @Schema(requiredMode = Schema.RequiredMode.REQUIRED) @JsonProperty("number") String number,
      @Schema(requiredMode = Schema.RequiredMode.REQUIRED) @JsonProperty("androidId") String androidId) {}

  public record VerifyCodeRequest(
      @Schema(requiredMode = Schema.RequiredMode.REQUIRED) @JsonProperty("code") String code) {}

  public record EnrollmentRequest(
      @Schema(requiredMode = Schema.RequiredMode.REQUIRED) @JsonProperty("number") String number,
      @Schema(requiredMode = Schema.RequiredMode.REQUIRED) @JsonProperty("androidId") String androidId,
      @JsonProperty("enabled") boolean enabled) {}
}
