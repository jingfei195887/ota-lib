#ifndef _PLATFORM_SOFTWARE_H
#define _PLATFORM_SOFTWARE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "system_cfg.h"


typedef unsigned int __u32;

/* Size in bytes of a SHA-256 digest. */
#define MD5_DIGEST_SIZE 16
/* Size in bytes of a SHA-1 digest. */
#define SHA1_DIGEST_SIZE 20
/* Size in bytes of a SHA-256 digest. */
#define SHA256_DIGEST_SIZE 32
/* Size in bytes of a SHA-512 digest. */
#define SHA512_DIGEST_SIZE 64

/* Block size in bytes of a md5 digest. */
#define MD5_BLOCK_SIZE 64
/* Block size in bytes of a SHA-256 digest. */
#define SHA256_BLOCK_SIZE 64
/* Block size in bytes of a SHA-512 digest. */
#define SHA512_BLOCK_SIZE 128

struct MD5Context {
    __u32 buf[4];
    __u32 bits[2];
    union {
        unsigned char in[MD5_BLOCK_SIZE] __attribute__((aligned(CACHE_LINE)));
        __u32 in32[16];
    };
    unsigned char state[16] __attribute__((aligned(CACHE_LINE)));
};

/* Data structure used for SHA-256. */
typedef struct {
    uint32_t h[8];
    uint64_t tot_len;
    size_t len;
    uint8_t block[2 * SHA256_BLOCK_SIZE]__attribute__((aligned(CACHE_LINE)));
    uint8_t state[SHA256_DIGEST_SIZE]__attribute__((aligned(CACHE_LINE)));
    uint8_t buf[SHA256_DIGEST_SIZE]__attribute__((aligned(
                CACHE_LINE))); /* Used for storing the final digest. */
} SHA256Ctx;

/* Data structure used for SHA-512. */
typedef struct {
    uint64_t h[8];
    uint64_t tot_len;
    size_t len;
    uint8_t block[2 * SHA512_BLOCK_SIZE]__attribute__((aligned(CACHE_LINE)));
    uint8_t state[SHA512_DIGEST_SIZE]__attribute__((aligned(CACHE_LINE)));
    uint8_t buf[SHA512_DIGEST_SIZE]__attribute__((aligned(
                CACHE_LINE))); /* Used for storing the final digest. */
} SHA512Ctx;

void MD5Init(struct MD5Context *ctx);
void MD5Update(struct MD5Context *ctx, unsigned char const *buf, unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *ctx);

/*
 * Calculate and store in 'output' the MD5 digest of 'len' bytes at
 * 'input'. 'output' must have enough space to hold 16 bytes.
 */
void md5(const unsigned char *input, const int len, unsigned char output[16]);

/*
 * Calculate and store in 'output' the MD5 digest of 'len' bytes at 'input'.
 * 'output' must have enough space to hold 16 bytes. If 'chunk' Trigger the
 * watchdog every 'chunk_sz' bytes of input processed.
 */
void md5_wd(const unsigned char *input, const int len,
            unsigned char output[16],
            const unsigned int chunk_sz);


/* Initializes the SHA-256 context. */
void sha256_init(SHA256Ctx *ctx);

/* Updates the SHA-256 context with |len| bytes from |data|. */
void sha256_update(SHA256Ctx *ctx, const uint8_t *data, size_t len);

/* Returns the SHA-256 digest. */
void sha256_final(unsigned char digest[32], SHA256Ctx *ctx);

void sha256(const unsigned char *input, const size_t len,
            unsigned char output[32]);

/* Initializes the SHA-512 context. */
void sha512_init(SHA512Ctx *ctx);

/* Updates the SHA-512 context with |len| bytes from |data|. */
void sha512_update(SHA512Ctx *ctx, const uint8_t *data, size_t len);

/* Returns the SHA-512 digest. */
void sha512_final(unsigned char digest[64], SHA512Ctx *ctx);

void sha512(const unsigned char *input, const size_t len,
            unsigned char output[64]);

#ifdef __cplusplus
extern "C" {
#endif

#endif /* _MD5_H */
