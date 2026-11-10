/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.storage;

/// One of the provided transaction write items to an account creation operation failed
class AccountCreationConditionException extends Exception {

  private final int index;

  AccountCreationConditionException(final int index) {
    this.index = index;
  }

  /// @return The index of the item that caused a conditional check failure
  public int getIndex() {
    return index;
  }
}
