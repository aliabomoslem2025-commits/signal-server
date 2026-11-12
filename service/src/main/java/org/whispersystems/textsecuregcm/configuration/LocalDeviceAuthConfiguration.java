/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.AssertTrue;
import java.time.Duration;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

/**
 * Configuration for administrator-provisioned device authentication on private LAN deployments.
 */
public class LocalDeviceAuthConfiguration {

  @JsonProperty
  private boolean enabled = false;

  @JsonProperty
  @Nullable
  private String tableName;

  @JsonProperty
  @Nullable
  private SecretString adminApiToken;

  @JsonProperty
  @Nullable
  private SecretString androidIdHmacKey;

  @JsonProperty
  private Duration sessionTtl = Duration.ofMinutes(5);

  @JsonProperty
  private int maxCodeAttempts = 5;

  public boolean isEnabled() {
    return enabled;
  }

  public String getTableName() {
    return tableName;
  }

  public SecretString getAdminApiToken() {
    return adminApiToken;
  }

  public SecretString getAndroidIdHmacKey() {
    return androidIdHmacKey;
  }

  public Duration getSessionTtl() {
    return sessionTtl;
  }

  public int getMaxCodeAttempts() {
    return maxCodeAttempts;
  }

  @AssertTrue(message = "When localDeviceAuth is enabled, tableName, adminApiToken, androidIdHmacKey, a positive sessionTtl, and maxCodeAttempts >= 1 are required")
  public boolean isValidWhenEnabled() {
    return !enabled || (tableName != null && !tableName.isBlank()
        && adminApiToken != null && androidIdHmacKey != null
        && sessionTtl != null && !sessionTtl.isNegative() && !sessionTtl.isZero()
        && maxCodeAttempts >= 1);
  }
}
