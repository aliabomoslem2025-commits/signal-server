/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.grpc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.whispersystems.textsecuregcm.grpc.GrpcTestUtils.assertRateLimitExceeded;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.signal.chat.attachments.AttachmentsGrpc;
import org.signal.chat.attachments.GetStickerUploadFormRequest;
import org.signal.chat.attachments.GetStickerUploadFormResponse;
import org.signal.chat.attachments.GetUploadFormRequest;
import org.signal.chat.attachments.GetUploadFormResponse;
import org.signal.chat.common.S3UploadForm;
import org.signal.chat.common.UploadForm;
import org.whispersystems.textsecuregcm.attachments.TusAttachmentGenerator;
import org.whispersystems.textsecuregcm.attachments.TusConfiguration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes;
import org.whispersystems.textsecuregcm.controllers.RateLimitExceededException;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.s3.PostPolicyGenerator;
import org.whispersystems.textsecuregcm.util.MockUtils;
import org.whispersystems.textsecuregcm.util.TestRandomUtil;

class AttachmentsGrpcServiceTest extends
    SimpleBaseGrpcTest<AttachmentsGrpcService, AttachmentsGrpc.AttachmentsBlockingStub> {

  @Mock
  private static final byte[] TUS_SECRET = TestRandomUtil.nextBytes(32);
  private static final String TUS_URL = "https://example.com/uploads";
  private static final int MAX_UPLOAD_LENGTH = 1000;

  @Mock
  private RateLimiter countRateLimiter;
  @Mock
  private RateLimiter byteRateLimiter;
  @Mock
  @Mock
  private RateLimiter stickerRateLimiter;

  @Override
  protected AttachmentsGrpcService createServiceBeforeEachTest() {
    final TusAttachmentGenerator tusAttachmentGenerator =
        new TusAttachmentGenerator(new TusConfiguration(new SecretBytes(TUS_SECRET), TUS_URL, TusConfiguration.DEFAULT_TOKEN_EXPIRATION));

    return new AttachmentsGrpcService(
        MockUtils.buildMock(RateLimiters.class, rateLimiters -> {
          when(rateLimiters.getAttachmentLimiter()).thenReturn(countRateLimiter);
          when(rateLimiters.getAttachmentBytesLimiter()).thenReturn(byteRateLimiter);
          when(rateLimiters.getStickerPackLimiter()).thenReturn(stickerRateLimiter);
        }),
        tusAttachmentGenerator,
        new PostPolicyGenerator("wakonda-south-7", "test", "accessId", "accessSecret"),
        MAX_UPLOAD_LENGTH,
        Clock.systemUTC());
  }

  @ParameterizedTest
  @ValueSource(longs = {-1, 0})
  void invalidUploadLength(final long uploadLength) {
    GrpcTestUtils.assertStatusInvalidArgument(() -> authenticatedServiceStub()
        .getUploadForm(GetUploadFormRequest.newBuilder().setUploadLength(uploadLength).build()));
  }

  @Test
  void uploadLengthTooBig() {
    assertThat(authenticatedServiceStub()
        .getUploadForm(GetUploadFormRequest.newBuilder().setUploadLength(MAX_UPLOAD_LENGTH + 1).build())
        .hasExceedsMaxUploadLength()).isTrue();
  }

  @Test
  void countRateLimitExceeded() throws RateLimitExceededException {
    final Duration retryAfter = Duration.ofSeconds(17);
    doThrow(new RateLimitExceededException(retryAfter)).when(countRateLimiter).validate(AUTHENTICATED_ACI);
    GrpcTestUtils.assertRateLimitExceeded(retryAfter, () -> authenticatedServiceStub()
        .getUploadForm(GetUploadFormRequest.newBuilder().setUploadLength(123).build()));
  }

  @Test
  void rollbackRateLimit() throws RateLimitExceededException {
    final Duration retryAfter = Duration.ofSeconds(17);
    doThrow(new RateLimitExceededException(retryAfter)).when(byteRateLimiter)
        .validate(AUTHENTICATED_ACI, 123);
    GrpcTestUtils.assertRateLimitExceeded(retryAfter, () -> authenticatedServiceStub()
        .getUploadForm(GetUploadFormRequest.newBuilder().setUploadLength(123).build()));

    verify(countRateLimiter).validate(AUTHENTICATED_ACI);
    verify(countRateLimiter).restorePermits(AUTHENTICATED_ACI, 1);
  }


  @Test
  void getUploadFormAlwaysUsesLanTus() {
    final GetUploadFormResponse response = authenticatedServiceStub()
        .getUploadForm(GetUploadFormRequest.newBuilder().setUploadLength(1).build());

    final UploadForm uploadForm = response.getUploadForm();
    assertThat(uploadForm.getCdn()).isEqualTo(3);
    assertThat(uploadForm.getKey()).isNotBlank();
    assertThat(uploadForm.getSignedUploadLocation()).isEqualTo(TUS_URL + "/attachments");

    final String filenameb64 = uploadForm.getHeadersMap().get("Upload-Metadata").split(" ")[1];
    final String filename = new String(Base64.getDecoder().decode(filenameb64));
    assertThat(uploadForm.getKey()).isEqualTo(filename);
  }


  @ParameterizedTest
  @ValueSource(booleans =  {true, false})
  void getUploadFormRateLimited(boolean useByteRateLimiter) throws RateLimitExceededException {
    final Duration retryAfter = Duration.ofMinutes(5);
    if (useByteRateLimiter) {
      doThrow(new RateLimitExceededException(retryAfter)).when(byteRateLimiter).validate(any(UUID.class), anyLong());
    } else {
      doThrow(new RateLimitExceededException(retryAfter)).when(countRateLimiter).validate(any(UUID.class));
    }

    assertRateLimitExceeded(retryAfter, () ->
        authenticatedServiceStub().getUploadForm(GetUploadFormRequest.newBuilder().setUploadLength(1).build()));
  }

  @Test
  void getStickerUploadForm() {
    final int stickerCount = 7;

    final GetStickerUploadFormResponse response =
        authenticatedServiceStub().getStickerUploadForm(GetStickerUploadFormRequest.newBuilder()
            .setStickerCount(stickerCount)
            .build());

    assertThat(response.getPackId()).isNotBlank();
    assertThat(response.getManifestUploadForm()).satisfies(AttachmentsGrpcServiceTest::s3UploadFormValid);
    assertThat(response.getStickerUploadFormsCount()).isEqualTo(stickerCount);
    assertThat(response.getStickerUploadFormsList()).allSatisfy(AttachmentsGrpcServiceTest::s3UploadFormValid);
  }

  private static void s3UploadFormValid(final S3UploadForm s3UploadForm) {
    assertThat(s3UploadForm.getAcl()).isEqualTo("private");
    assertThat(s3UploadForm.getAlgorithm()).isEqualTo("AWS4-HMAC-SHA256");
    assertThat(s3UploadForm.getKey()).startsWith("stickers/");
    assertThat(s3UploadForm.getCredential()).endsWith("/s3/aws4_request");
    assertThat(s3UploadForm.getDate()).isNotBlank();
    assertThat(s3UploadForm.getPolicy()).isNotBlank();
    assertThat(s3UploadForm.getSignature()).isNotBlank();
  }

  @Test
  void getStickerUploadFormRateLimited() throws RateLimitExceededException {
    final Duration retryAfter = Duration.ofMinutes(13);
    doThrow(new RateLimitExceededException(retryAfter)).when(stickerRateLimiter).validate(any(UUID.class));

    //noinspection ResultOfMethodCallIgnored
    GrpcTestUtils.assertRateLimitExceeded(retryAfter,
        () -> authenticatedServiceStub().getStickerUploadForm(GetStickerUploadFormRequest.newBuilder()
            .setStickerCount(7)
            .build()));
  }
}
