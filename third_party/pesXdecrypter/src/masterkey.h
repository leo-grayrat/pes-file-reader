/*
    This is free and unencumbered software released into the public domain.

    For more information, please refer to <http://unlicense.org>
 */

#ifndef _MASTERKEY_H
#define _MASTERKEY_H

#include <stdint.h>

#include "crypt.h"

#define MASTER_KEY_LENGTH 64

// Empty master key for default usage.
CRYPTER_EXPORT extern const uint8_t MasterKeyZero[MASTER_KEY_LENGTH];

// Expose master keys for library usage.
CRYPTER_EXPORT extern const uint8_t MasterKeyPes16[MASTER_KEY_LENGTH];
CRYPTER_EXPORT extern const uint8_t MasterKeyPes16MyClub[MASTER_KEY_LENGTH];
CRYPTER_EXPORT extern const uint8_t MasterKeyPes17[MASTER_KEY_LENGTH];
CRYPTER_EXPORT extern const uint8_t MasterKeyPes18[MASTER_KEY_LENGTH];
CRYPTER_EXPORT extern const uint8_t MasterKeyPes19[MASTER_KEY_LENGTH];
CRYPTER_EXPORT extern const uint8_t MasterKeyPes20[MASTER_KEY_LENGTH];
CRYPTER_EXPORT extern const uint8_t MasterKeyPes21[MASTER_KEY_LENGTH];

// Old global master key, maintained for backwards compatibility.
extern uint8_t const *MasterKey;

#endif /* _MASTERKEY_H */