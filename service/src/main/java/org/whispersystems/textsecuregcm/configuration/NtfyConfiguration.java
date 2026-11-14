/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.configuration;

import jakarta.validation.constraints.NotNull;
import java.net.URI;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

/** Configuration for the private, self-hosted ntfy push transport. */
public record NtfyConfiguration(@NotNull URI baseUrl,
                                @NotNull SecretString publisherToken) {
  public NtfyConfiguration {
    if (baseUrl == null || !"https".equalsIgnoreCase(baseUrl.getScheme()) || baseUrl.getHost() == null) {
      throw new IllegalArgumentException("ntfy.baseUrl must be an absolute HTTPS URL");
    }
    if (baseUrl.getUserInfo() != null || baseUrl.getQuery() != null || baseUrl.getFragment() != null) {
      throw new IllegalArgumentException("ntfy.baseUrl must not contain credentials, query, or fragment");
    }
  }

  public String normalizedBaseUrl() {
    final String value = baseUrl.toString();
    return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
  }
}
