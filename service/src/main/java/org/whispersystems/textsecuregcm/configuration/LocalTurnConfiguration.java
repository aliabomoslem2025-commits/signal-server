package org.whispersystems.textsecuregcm.configuration;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import java.net.URI;
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
        URI uri = URI.create(value);
        String scheme = uri.getScheme();
        return uri.getHost() != null
            && ("turn".equalsIgnoreCase(scheme) || "turns".equalsIgnoreCase(scheme))
            && uri.getUserInfo() == null
            && uri.getFragment() == null;
      } catch (RuntimeException e) {
        return false;
      }
    });
  }
}
