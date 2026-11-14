package org.whispersystems.textsecuregcm.auth;

import java.io.IOException;
import java.util.UUID;

/** Supplies short-lived TURN credentials to authenticated Signal devices. */
public interface TurnCredentialsProvider {
  TurnToken retrieve(UUID accountUuid) throws IOException;
}
