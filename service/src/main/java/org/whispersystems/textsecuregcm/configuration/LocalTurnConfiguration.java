package org.whispersystems.textsecuregcm.configuration;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

/** Credentials and advertised relay URIs for an on-premises coturn REST deployment. */
public record LocalTurnConfiguration(
    @NotNull SecretString sharedSecret,
    @NotNull @NotEmpty List<String> urls,
    @NotNull Duration credentialTtl) {

  @AssertTrue
  @Schema(hidden = true)
  public boolean isCredentialTtlValid() {
    return credentialTtl != null
        && !credentialTtl.isNegative()
        && !credentialTtl.isZero()
        && credentialTtl.compareTo(Duration.ofHours(24)) <= 0;
  }

  @AssertTrue
  @Schema(hidden = true)
  public boolean areUrlsValid() {
    if (urls == null || urls.isEmpty()) return false;
    return urls.stream().allMatch(value -> {
      try {
        final String trimmed = value.trim();
        final int separator = trimmed.indexOf(':');
        if (separator <= 0) return false;
        final String scheme = trimmed.substring(0, separator).toLowerCase();
        if (!scheme.equals("turn") && !scheme.equals("turns")) return false;
        final URI uri = URI.create("https://" + trimmed.substring(separator + 1));
        final String query = uri.getRawQuery();
        return uri.getHost() != null
            && uri.getUserInfo() == null
            && uri.getFragment() == null
            && (uri.getRawPath() == null || uri.getRawPath().isEmpty())
            && (query == null || query.equals("transport=udp") || query.equals("transport=tcp"))
            && (uri.getPort() == -1 || (uri.getPort() >= 1 && uri.getPort() <= 65535));
      } catch (RuntimeException e) {
        return false;
      }
    });
  }
}
