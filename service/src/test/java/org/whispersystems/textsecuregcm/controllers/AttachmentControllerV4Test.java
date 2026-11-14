/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import jakarta.ws.rs.core.Response;
import java.util.Base64;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.attachments.TusAttachmentGenerator;
import org.whispersystems.textsecuregcm.attachments.TusConfiguration;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes;
import org.whispersystems.textsecuregcm.entities.AttachmentDescriptorV3;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.textsecuregcm.tests.util.AuthHelper;
import org.whispersystems.textsecuregcm.util.MockUtils;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.TestRandomUtil;

@ExtendWith(DropwizardExtensionsSupport.class)
class AttachmentControllerV4Test {

  private static final RateLimiter COUNT_RATE_LIMITER = mock(RateLimiter.class);
  private static final RateLimiter BYTE_RATE_LIMITER = mock(RateLimiter.class);

  private static final RateLimiters RATE_LIMITERS = MockUtils.buildMock(RateLimiters.class, rateLimiters -> {
    when(rateLimiters.getAttachmentLimiter()).thenReturn(COUNT_RATE_LIMITER);
    when(rateLimiters.getAttachmentBytesLimiter()).thenReturn(BYTE_RATE_LIMITER);
  });

  private static final String CDN3_ENABLED_CREDS = AuthHelper.getAuthHeader(AuthHelper.VALID_UUID, AuthHelper.VALID_PASSWORD);
  private static final String CDN3_DISABLED_CREDS = AuthHelper.getAuthHeader(AuthHelper.VALID_UUID_TWO, AuthHelper.VALID_PASSWORD_TWO);
  private static final byte[] TUS_SECRET = TestRandomUtil.nextBytes(32);
  private static final String TUS_URL = "https://example.com/uploads";
  private static final long MAX_UPLOAD_LENGTH = 1000;

  private static final ResourceExtension resources;

  static {
    final TusAttachmentGenerator tusAttachmentGenerator =
        new TusAttachmentGenerator(new TusConfiguration(new SecretBytes(TUS_SECRET), TUS_URL, TusConfiguration.DEFAULT_TOKEN_EXPIRATION));
    resources = ResourceExtension.builder()
        .addProvider(AuthHelper.getAuthFilter())
        .addProvider(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
        .setMapper(SystemMapper.jsonMapper())
        .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
        .addProvider(new RateLimitExceededExceptionMapper())
        .addProvider(new AttachmentControllerV4(RATE_LIMITERS, tusAttachmentGenerator, MAX_UPLOAD_LENGTH))
        .build();
  }

  @AfterEach
  public void tearDown() {
    reset(COUNT_RATE_LIMITER, BYTE_RATE_LIMITER);
  }

  @ParameterizedTest
  @ValueSource(longs = {-1, 0})
  void testInvalidUploadLength(final long uploadLength) {
    assertThat(resources.getJerseyTest()
        .target("/v4/attachments/form/upload")
        .queryParam("uploadLength", uploadLength)
        .request()
        .header("Authorization", CDN3_ENABLED_CREDS)
        .get().getStatus())
        .isEqualTo(Response.Status.BAD_REQUEST.getStatusCode());
  }

  @Test
  void testUploadTooLarge() {
    assertThat(resources.getJerseyTest()
        .target("/v4/attachments/form/upload")
        .queryParam("uploadLength", MAX_UPLOAD_LENGTH + 1)
        .request()
        .header("Authorization", CDN3_ENABLED_CREDS)
        .get().getStatus())
        .isEqualTo(Response.Status.REQUEST_ENTITY_TOO_LARGE.getStatusCode());
  }

  @Test
  void countRateLimitExceeded() throws RateLimitExceededException {
    doThrow(RateLimitExceededException.class).when(COUNT_RATE_LIMITER).validate(AuthHelper.VALID_UUID);
    assertThat(resources.getJerseyTest()
        .target("/v4/attachments/form/upload")
        .queryParam("uploadLength", MAX_UPLOAD_LENGTH)
        .request()
        .header("Authorization", CDN3_ENABLED_CREDS)
        .get().getStatus())
        .isEqualTo(Response.Status.TOO_MANY_REQUESTS.getStatusCode());
  }

  @Test
  void rollbackRateLimit() throws RateLimitExceededException {
    doThrow(RateLimitExceededException.class).when(BYTE_RATE_LIMITER)
        .validate(AuthHelper.VALID_UUID, MAX_UPLOAD_LENGTH);
    assertThat(resources.getJerseyTest()
        .target("/v4/attachments/form/upload")
        .queryParam("uploadLength", MAX_UPLOAD_LENGTH)
        .request()
        .header("Authorization", CDN3_ENABLED_CREDS)
        .get().getStatus())
        .isEqualTo(Response.Status.TOO_MANY_REQUESTS.getStatusCode());

    verify(COUNT_RATE_LIMITER).validate(AuthHelper.VALID_UUID);
    verify(COUNT_RATE_LIMITER).restorePermits(AuthHelper.VALID_UUID, 1);
  }

  @Test
  void testV4TusForm() {
    AttachmentDescriptorV3 descriptor = resources.getJerseyTest()
        .target("/v4/attachments/form/upload")
        .queryParam("uploadLength", MAX_UPLOAD_LENGTH)
        .request()
        .header("Authorization", CDN3_ENABLED_CREDS)
        .get(AttachmentDescriptorV3.class);
    assertThat(descriptor.cdn()).isEqualTo(3);
    assertThat(descriptor.key()).isNotBlank();
    assertThat(descriptor.signedUploadLocation()).isEqualTo(TUS_URL + "/" + "attachments");
    final String filenameb64 = descriptor.headers().get("Upload-Metadata").split(" ")[1];
    final String filename = new String(Base64.getDecoder().decode(filenameb64));
    assertThat(descriptor.key()).isEqualTo(filename);
  }

  @Test
  void testLanDeploymentAlwaysUsesTusForEveryDevice() {
    AttachmentDescriptorV3 descriptor = resources.getJerseyTest()
        .target("/v4/attachments/form/upload")
        .queryParam("uploadLength", MAX_UPLOAD_LENGTH)
        .request()
        .header("Authorization", CDN3_DISABLED_CREDS)
        .get(AttachmentDescriptorV3.class);

    assertThat(descriptor.cdn()).isEqualTo(3);
    assertThat(descriptor.key()).isNotBlank();
    assertThat(descriptor.signedUploadLocation()).isEqualTo(TUS_URL + "/attachments");
  }

}
