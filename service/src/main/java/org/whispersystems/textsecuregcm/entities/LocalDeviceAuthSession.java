/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.entities;

import javax.annotation.Nullable;

/** Response for the administrator-enrolled, local-LAN authentication flow. */
public record LocalDeviceAuthSession(
    String id,
    @Nullable String localVerificationCode,
    boolean verified,
    long expiresAt) {}
