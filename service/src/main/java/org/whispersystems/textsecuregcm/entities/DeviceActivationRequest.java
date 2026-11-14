package org.whispersystems.textsecuregcm.entities;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.Optional;

public record DeviceActivationRequest(
    @NotNull
    @Valid
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = """
        A signed EC pre-key to be associated with this account's ACI.
        """)
    ECSignedPreKey aciSignedPreKey,

    @Schema(requiredMode = Schema.RequiredMode.NOT_REQUIRED, description = """
        An APNs token set for an Apple device. Android ntfy topics are provisioned after
        registration through the authenticated account API.
        """)
    Optional<@Valid ApnRegistrationId> apnToken) {
}
