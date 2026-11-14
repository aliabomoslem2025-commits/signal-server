package org.whispersystems.textsecuregcm.configuration;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import javax.annotation.Nullable;

/** Exactly one TURN credential provider must be configured. */
public record TurnConfiguration(
    @Nullable @Valid CloudflareTurnConfiguration cloudflare,
    @Nullable @Valid LocalTurnConfiguration local) {

  @AssertTrue
  @Schema(hidden = true)
  public boolean isExactlyOneProviderConfigured() {
    return (cloudflare == null) != (local == null);
  }
}
