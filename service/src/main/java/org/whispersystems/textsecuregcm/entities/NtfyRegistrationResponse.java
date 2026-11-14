/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.entities;

import jakarta.validation.constraints.NotBlank;

/** Topic capability assigned to the authenticated device. */
public record NtfyRegistrationResponse(@NotBlank String topic) {
}
