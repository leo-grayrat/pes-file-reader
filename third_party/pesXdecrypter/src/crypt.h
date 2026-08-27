/*
    This is free and unencumbered software released into the public domain.

    For more information, please refer to <http://unlicense.org>
 */

#ifndef _CRYPT_H
#define _CRYPT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BUILDING_LIBRARY

#ifdef _WIN32
#define CRYPTER_EXPORT __declspec(dllexport)
#else
#define CRYPTER_EXPORT __attribute__ ((visibility ("protected")))
#endif

#else

#define CRYPTER_EXPORT

#endif /* BUILDING_LIBRARY */

struct FileHeader
{
    uint8_t mysteryData[64];
    uint32_t dataSize;
    uint32_t logoSize;
    uint32_t descSize;
    uint32_t serialLength;
    uint8_t hash[64];
    uint8_t fileTypeString[32];
    #if USE_PES18_MASTER_KEY || USE_PES19_MASTER_KEY || USE_PES20_MASTER_KEY || USE_PES21_MASTER_KEY
    uint8_t gameVersionString[32];
    #endif
};

struct FileDescriptor
{
    uint8_t *encryptionHeader;
    struct FileHeader *fileHeader;

    uint8_t *description;
    uint8_t *logo;
    uint8_t *data;
    uint8_t *serial;
};

struct FileDescriptor CRYPTER_EXPORT *createFileDescriptor();
void CRYPTER_EXPORT destroyFileDescriptor(struct FileDescriptor *desc);

void CRYPTER_EXPORT decryptWithKey(struct FileDescriptor *descriptor, const uint8_t *input, const char *masterKey);
uint8_t CRYPTER_EXPORT *encryptWithKey(const struct FileDescriptor *descriptor, int *size, const char *masterKey);

void CRYPTER_EXPORT decryptWithKey_ex(const char *pathIn, const char *pathOut, const char *masterKey);
void CRYPTER_EXPORT encryptWithKey_ex(const char *pathIn, const char *pathOut, const char *masterKey);

uint8_t *readFile(const char *path, uint32_t *sizePtr);

// *** Old functions, maintained for backwards compatibility ***
void CRYPTER_EXPORT decrypt(struct FileDescriptor *descriptor, const uint8_t *input);
uint8_t CRYPTER_EXPORT *encrypt(const struct FileDescriptor *descriptor, int *size);

void CRYPTER_EXPORT decrypt_ex(const char *pathIn, const char *pathOut);
void CRYPTER_EXPORT encrypt_ex(const char *pathIn, const char *pathOut);

#ifdef __cplusplus
}
#endif

#endif /* _CRYPT_H */