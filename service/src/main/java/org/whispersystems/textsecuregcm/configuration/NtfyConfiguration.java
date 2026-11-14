/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.configuration;

import jakarta.validation.constraints.NotNull;
import java.net.URI;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

public record NtfyConfiguration(@NotNull URI baseUrl, @NotNull SecretString publisherToken) {
  public NtfyConfiguration {
    if (!"https".equalsIgnoreCase(baseUrl.getScheme()) || baseUrl.getHost() == null
        || baseUrl.getUserInfo() != null || baseUrl.getQuery() != null || baseUrl.getFragment() != null) {
      throw new IllegalArgumentException("ntfy.baseUrl must be an HTTPS origin or base path without credentials, query, or fragment");
    }
  }
}
