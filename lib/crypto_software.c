#define _LARGEFILE64_SOURCE
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#if !RUN_IN_QNX
#include <linux/fs.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include <time.h>
#include <assert.h>
#include "system_cfg.h"
#include "crypto_software.h"

static void
MD5Transform(__u32 buf[4], __u32 const in[16]);

/*
 * Note: this code is harmless on little-endian machines.
 */
static void
byteReverse(unsigned char *buf, unsigned longs)
{
    __u32 t;

    do {
        t = (__u32) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
            ((unsigned) buf[1] << 8 | buf[0]);
        *(__u32 *) buf = t;
        buf += 4;
    }
    while (--longs);
}

/* --------------------------------------------md5--------------------------------------------*/

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void
MD5Init(struct MD5Context *ctx)
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;

    ctx->bits[0] = 0;
    ctx->bits[1] = 0;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void
MD5Update(struct MD5Context *ctx, unsigned char const *buf, unsigned len)
{
    register __u32 t;

    /* Update bitcount */

    t = ctx->bits[0];

    if ((ctx->bits[0] = t + ((__u32) len << 3)) < t)
        ctx->bits[1]++; /* Carry from low to high */

    ctx->bits[1] += len >> 29;

    t = (t >> 3) & 0x3f;    /* Bytes already in shsInfo->data */

    /* Handle any leading odd-sized chunks */

    if (t) {
        unsigned char *p = (unsigned char *) ctx->in + t;

        t = 64 - t;

        if (len < t) {
            memmove(p, buf, len);
            return;
        }

        memmove(p, buf, t);
        byteReverse(ctx->in, 16);
        MD5Transform(ctx->buf, (__u32 *) ctx->in);
        buf += t;
        len -= t;
    }

    /* Process data in 64-byte chunks */

    while (len >= 64) {
        memmove(ctx->in, buf, 64);
        byteReverse(ctx->in, 16);
        MD5Transform(ctx->buf, (__u32 *) ctx->in);
        buf += 64;
        len -= 64;
    }

    /* Handle any remaining bytes of data. */

    memmove(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void
MD5Final(unsigned char digest[16], struct MD5Context *ctx)
{
    unsigned int count;
    unsigned char *p;

    /* Compute number of bytes mod 64 */
    count = (ctx->bits[0] >> 3) & 0x3F;

    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    p = ctx->in + count;
    *p++ = 0x80;

    /* Bytes of padding needed to make 64 bytes */
    count = 64 - 1 - count;

    /* Pad out to 56 mod 64 */
    if (count < 8) {
        /* Two lots of padding:  Pad the first block to 64 bytes */
        memset(p, 0, count);
        byteReverse(ctx->in, 16);
        MD5Transform(ctx->buf, (__u32 *) ctx->in);

        /* Now fill the next block with 56 bytes */
        memset(ctx->in, 0, 56);
    }
    else {
        /* Pad block to 56 bytes */
        memset(p, 0, count - 8);
    }

    byteReverse(ctx->in, 14);

    /* Append length in bits and transform */
    ctx->in32[14] = ctx->bits[0];
    ctx->in32[15] = ctx->bits[1];

    MD5Transform(ctx->buf, (__u32 *) ctx->in);
    byteReverse((unsigned char *) ctx->buf, 4);
    memmove(digest, ctx->buf, 16);
    memset(ctx, 0, sizeof(*ctx));   /* In case it's sensitive */
}

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
    ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void
MD5Transform(__u32 buf[4], __u32 const in[16])
{
    register __u32 a, b, c, d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}

/*
 * Calculate and store in 'output' the MD5 digest of 'len' bytes at
 * 'input'. 'output' must have enough space to hold 16 bytes.
 */
void
md5(const unsigned char *input, const int len, unsigned char output[16])
{
    struct MD5Context context;

    MD5Init(&context);
    MD5Update(&context, input, len);
    MD5Final(output, &context);
}

/* --------------------------------------------sha256--------------------------------------------*/

#define SHFR(x, n) (x >> n)
#define ROTR(x, n) ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define ROTL(x, n) ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define SHA256_F1(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SHA256_F2(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SHA256_F3(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHFR(x, 3))
#define SHA256_F4(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHFR(x, 10))

#define UNPACK32(x, str)                 \
  {                                      \
    *((str) + 3) = (uint8_t)((x));       \
    *((str) + 2) = (uint8_t)((x) >> 8);  \
    *((str) + 1) = (uint8_t)((x) >> 16); \
    *((str) + 0) = (uint8_t)((x) >> 24); \
  }

#define UNPACK64(x, str)                         \
  {                                              \
    *((str) + 7) = (uint8_t)x;                   \
    *((str) + 6) = (uint8_t)((uint64_t)x >> 8);  \
    *((str) + 5) = (uint8_t)((uint64_t)x >> 16); \
    *((str) + 4) = (uint8_t)((uint64_t)x >> 24); \
    *((str) + 3) = (uint8_t)((uint64_t)x >> 32); \
    *((str) + 2) = (uint8_t)((uint64_t)x >> 40); \
    *((str) + 1) = (uint8_t)((uint64_t)x >> 48); \
    *((str) + 0) = (uint8_t)((uint64_t)x >> 56); \
  }

#define PACK32(str, x)                                                    \
  {                                                                       \
    *(x) = ((uint32_t) * ((str) + 3)) | ((uint32_t) * ((str) + 2) << 8) | \
           ((uint32_t) * ((str) + 1) << 16) |                             \
           ((uint32_t) * ((str) + 0) << 24);                              \
  }

/* Macros used for loops unrolling */

#define SHA256_SCR(i) \
  { w[i] = SHA256_F4(w[i - 2]) + w[i - 7] + SHA256_F3(w[i - 15]) + w[i - 16]; }

#define SHA256_EXP(a, b, c, d, e, f, g, h, j)                               \
  {                                                                         \
    t1 = wv[h] + SHA256_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) + sha256_k[j] + \
         w[j];                                                              \
    t2 = SHA256_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);                       \
    wv[d] += t1;                                                            \
    wv[h] = t1 + t2;                                                        \
  }

static const uint32_t sha256_h0[8] = {0x6a09e667,
                                      0xbb67ae85,
                                      0x3c6ef372,
                                      0xa54ff53a,
                                      0x510e527f,
                                      0x9b05688c,
                                      0x1f83d9ab,
                                      0x5be0cd19
                                     };

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void SHA256_transform(SHA256Ctx *ctx,
                             const uint8_t *message,
                             size_t block_nb)
{
    uint32_t w[64];
    uint32_t wv[8];
    uint32_t t1, t2;
    const unsigned char *sub_block;
    size_t i;

#ifndef UNROLL_LOOPS
    size_t j;
#endif

    for (i = 0; i < block_nb; i++) {
        sub_block = message + (i << 6);

#ifndef UNROLL_LOOPS

        for (j = 0; j < 16; j++) {
            PACK32(&sub_block[j << 2], &w[j]);
        }

        for (j = 16; j < 64; j++) {
            SHA256_SCR(j);
        }

        for (j = 0; j < 8; j++) {
            wv[j] = ctx->h[j];
        }

        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6]) + sha256_k[j] +
                 w[j];
            t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }

        for (j = 0; j < 8; j++) {
            ctx->h[j] += wv[j];
        }

#else
        PACK32(&sub_block[0], &w[0]);
        PACK32(&sub_block[4], &w[1]);
        PACK32(&sub_block[8], &w[2]);
        PACK32(&sub_block[12], &w[3]);
        PACK32(&sub_block[16], &w[4]);
        PACK32(&sub_block[20], &w[5]);
        PACK32(&sub_block[24], &w[6]);
        PACK32(&sub_block[28], &w[7]);
        PACK32(&sub_block[32], &w[8]);
        PACK32(&sub_block[36], &w[9]);
        PACK32(&sub_block[40], &w[10]);
        PACK32(&sub_block[44], &w[11]);
        PACK32(&sub_block[48], &w[12]);
        PACK32(&sub_block[52], &w[13]);
        PACK32(&sub_block[56], &w[14]);
        PACK32(&sub_block[60], &w[15]);

        SHA256_SCR(16);
        SHA256_SCR(17);
        SHA256_SCR(18);
        SHA256_SCR(19);
        SHA256_SCR(20);
        SHA256_SCR(21);
        SHA256_SCR(22);
        SHA256_SCR(23);
        SHA256_SCR(24);
        SHA256_SCR(25);
        SHA256_SCR(26);
        SHA256_SCR(27);
        SHA256_SCR(28);
        SHA256_SCR(29);
        SHA256_SCR(30);
        SHA256_SCR(31);
        SHA256_SCR(32);
        SHA256_SCR(33);
        SHA256_SCR(34);
        SHA256_SCR(35);
        SHA256_SCR(36);
        SHA256_SCR(37);
        SHA256_SCR(38);
        SHA256_SCR(39);
        SHA256_SCR(40);
        SHA256_SCR(41);
        SHA256_SCR(42);
        SHA256_SCR(43);
        SHA256_SCR(44);
        SHA256_SCR(45);
        SHA256_SCR(46);
        SHA256_SCR(47);
        SHA256_SCR(48);
        SHA256_SCR(49);
        SHA256_SCR(50);
        SHA256_SCR(51);
        SHA256_SCR(52);
        SHA256_SCR(53);
        SHA256_SCR(54);
        SHA256_SCR(55);
        SHA256_SCR(56);
        SHA256_SCR(57);
        SHA256_SCR(58);
        SHA256_SCR(59);
        SHA256_SCR(60);
        SHA256_SCR(61);
        SHA256_SCR(62);
        SHA256_SCR(63);

        wv[0] = ctx->h[0];
        wv[1] = ctx->h[1];
        wv[2] = ctx->h[2];
        wv[3] = ctx->h[3];
        wv[4] = ctx->h[4];
        wv[5] = ctx->h[5];
        wv[6] = ctx->h[6];
        wv[7] = ctx->h[7];

        SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 0);
        SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 1);
        SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 2);
        SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 3);
        SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 4);
        SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 5);
        SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 6);
        SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 7);
        SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 8);
        SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 9);
        SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 10);
        SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 11);
        SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 12);
        SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 13);
        SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 14);
        SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 15);
        SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 16);
        SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 17);
        SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 18);
        SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 19);
        SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 20);
        SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 21);
        SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 22);
        SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 23);
        SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 24);
        SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 25);
        SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 26);
        SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 27);
        SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 28);
        SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 29);
        SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 30);
        SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 31);
        SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 32);
        SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 33);
        SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 34);
        SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 35);
        SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 36);
        SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 37);
        SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 38);
        SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 39);
        SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 40);
        SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 41);
        SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 42);
        SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 43);
        SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 44);
        SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 45);
        SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 46);
        SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 47);
        SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 48);
        SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 49);
        SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 50);
        SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 51);
        SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 52);
        SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 53);
        SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 54);
        SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 55);
        SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 56);
        SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 57);
        SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 58);
        SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 59);
        SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 60);
        SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 61);
        SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 62);
        SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 63);

        ctx->h[0] += wv[0];
        ctx->h[1] += wv[1];
        ctx->h[2] += wv[2];
        ctx->h[3] += wv[3];
        ctx->h[4] += wv[4];
        ctx->h[5] += wv[5];
        ctx->h[6] += wv[6];
        ctx->h[7] += wv[7];
#endif /* !UNROLL_LOOPS */
    }
}

void sha256_update(SHA256Ctx *ctx, const uint8_t *data, size_t len)
{
    size_t block_nb;
    size_t new_len, rem_len, tmp_len;
    const uint8_t *shifted_data;

    tmp_len = SHA256_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], data, rem_len);

    if (ctx->len + len < SHA256_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA256_BLOCK_SIZE;

    shifted_data = data + rem_len;

    SHA256_transform(ctx, ctx->block, 1);
    SHA256_transform(ctx, shifted_data, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    memcpy(ctx->block, &shifted_data[block_nb << 6], rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}

void sha256_final(unsigned char digest[32], SHA256Ctx *ctx)
{
    size_t block_nb;
    size_t pm_len;
    uint64_t len_b;
#ifndef UNROLL_LOOPS
    size_t i;
#endif

    block_nb =
        (1 + ((SHA256_BLOCK_SIZE - 9) < (ctx->len % SHA256_BLOCK_SIZE)));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK64(len_b, ctx->block + pm_len - 8);

    SHA256_transform(ctx, ctx->block, block_nb);

#ifndef UNROLL_LOOPS

    for (i = 0; i < 8; i++) {
        UNPACK32(ctx->h[i], &ctx->buf[i << 2]);
    }

#else
    UNPACK32(ctx->h[0], &ctx->buf[0]);
    UNPACK32(ctx->h[1], &ctx->buf[4]);
    UNPACK32(ctx->h[2], &ctx->buf[8]);
    UNPACK32(ctx->h[3], &ctx->buf[12]);
    UNPACK32(ctx->h[4], &ctx->buf[16]);
    UNPACK32(ctx->h[5], &ctx->buf[20]);
    UNPACK32(ctx->h[6], &ctx->buf[24]);
    UNPACK32(ctx->h[7], &ctx->buf[28]);
#endif /* !UNROLL_LOOPS */

    memmove(digest, ctx->buf, SHA256_DIGEST_SIZE);
    memset(ctx, 0, sizeof(*ctx));   /* In case it's sensitive */
    return;
}

void sha256(const unsigned char *input, const size_t len,
            unsigned char output[32])
{
    SHA256Ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, input, len);
    sha256_final(output, &ctx);
}

/* --------------------------------------------sha512--------------------------------------------*/

#define SHA512_F1(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define SHA512_F2(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define SHA512_F3(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHFR(x, 7))
#define SHA512_F4(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHFR(x, 6))

#define PACK64(str, x)                                                        \
  {                                                                           \
    *(x) =                                                                    \
        ((uint64_t) * ((str) + 7)) | ((uint64_t) * ((str) + 6) << 8) |        \
        ((uint64_t) * ((str) + 5) << 16) | ((uint64_t) * ((str) + 4) << 24) | \
        ((uint64_t) * ((str) + 3) << 32) | ((uint64_t) * ((str) + 2) << 40) | \
        ((uint64_t) * ((str) + 1) << 48) | ((uint64_t) * ((str) + 0) << 56);  \
  }

/* Macros used for loops unrolling */

#define SHA512_SCR(i) \
  { w[i] = SHA512_F4(w[i - 2]) + w[i - 7] + SHA512_F3(w[i - 15]) + w[i - 16]; }

#define SHA512_EXP(a, b, c, d, e, f, g, h, j)                               \
  {                                                                         \
    t1 = wv[h] + SHA512_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) + sha512_k[j] + \
         w[j];                                                              \
    t2 = SHA512_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);                       \
    wv[d] += t1;                                                            \
    wv[h] = t1 + t2;                                                        \
  }

static const uint64_t sha512_h0[8] = {0x6a09e667f3bcc908ULL,
                                      0xbb67ae8584caa73bULL,
                                      0x3c6ef372fe94f82bULL,
                                      0xa54ff53a5f1d36f1ULL,
                                      0x510e527fade682d1ULL,
                                      0x9b05688c2b3e6c1fULL,
                                      0x1f83d9abfb41bd6bULL,
                                      0x5be0cd19137e2179ULL
                                     };

static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};


/* SHA-256 implementation */
void sha256_init(SHA256Ctx *ctx)
{
#ifndef UNROLL_LOOPS
    int i;

    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha256_h0[i];
    }

#else
    ctx->h[0] = sha256_h0[0];
    ctx->h[1] = sha256_h0[1];
    ctx->h[2] = sha256_h0[2];
    ctx->h[3] = sha256_h0[3];
    ctx->h[4] = sha256_h0[4];
    ctx->h[5] = sha256_h0[5];
    ctx->h[6] = sha256_h0[6];
    ctx->h[7] = sha256_h0[7];
#endif /* !UNROLL_LOOPS */

    ctx->len = 0;
    ctx->tot_len = 0;
}

/* SHA-512 implementation */

void sha512_init(SHA512Ctx *ctx)
{
#ifdef UNROLL_LOOPS_SHA512
    ctx->h[0] = sha512_h0[0];
    ctx->h[1] = sha512_h0[1];
    ctx->h[2] = sha512_h0[2];
    ctx->h[3] = sha512_h0[3];
    ctx->h[4] = sha512_h0[4];
    ctx->h[5] = sha512_h0[5];
    ctx->h[6] = sha512_h0[6];
    ctx->h[7] = sha512_h0[7];
#else
    int i;

    for (i = 0; i < 8; i++)
        ctx->h[i] = sha512_h0[i];

#endif /* UNROLL_LOOPS_SHA512 */

    ctx->len = 0;
    ctx->tot_len = 0;
}

static void SHA512_transform(SHA512Ctx *ctx,
                             const uint8_t *message,
                             size_t block_nb)
{
    uint64_t w[80];
    uint64_t wv[8];
    uint64_t t1, t2;
    const uint8_t *sub_block;
    size_t i, j;

    for (i = 0; i < block_nb; i++) {
        sub_block = message + (i << 7);

#ifdef UNROLL_LOOPS_SHA512
        PACK64(&sub_block[0], &w[0]);
        PACK64(&sub_block[8], &w[1]);
        PACK64(&sub_block[16], &w[2]);
        PACK64(&sub_block[24], &w[3]);
        PACK64(&sub_block[32], &w[4]);
        PACK64(&sub_block[40], &w[5]);
        PACK64(&sub_block[48], &w[6]);
        PACK64(&sub_block[56], &w[7]);
        PACK64(&sub_block[64], &w[8]);
        PACK64(&sub_block[72], &w[9]);
        PACK64(&sub_block[80], &w[10]);
        PACK64(&sub_block[88], &w[11]);
        PACK64(&sub_block[96], &w[12]);
        PACK64(&sub_block[104], &w[13]);
        PACK64(&sub_block[112], &w[14]);
        PACK64(&sub_block[120], &w[15]);

        SHA512_SCR(16);
        SHA512_SCR(17);
        SHA512_SCR(18);
        SHA512_SCR(19);
        SHA512_SCR(20);
        SHA512_SCR(21);
        SHA512_SCR(22);
        SHA512_SCR(23);
        SHA512_SCR(24);
        SHA512_SCR(25);
        SHA512_SCR(26);
        SHA512_SCR(27);
        SHA512_SCR(28);
        SHA512_SCR(29);
        SHA512_SCR(30);
        SHA512_SCR(31);
        SHA512_SCR(32);
        SHA512_SCR(33);
        SHA512_SCR(34);
        SHA512_SCR(35);
        SHA512_SCR(36);
        SHA512_SCR(37);
        SHA512_SCR(38);
        SHA512_SCR(39);
        SHA512_SCR(40);
        SHA512_SCR(41);
        SHA512_SCR(42);
        SHA512_SCR(43);
        SHA512_SCR(44);
        SHA512_SCR(45);
        SHA512_SCR(46);
        SHA512_SCR(47);
        SHA512_SCR(48);
        SHA512_SCR(49);
        SHA512_SCR(50);
        SHA512_SCR(51);
        SHA512_SCR(52);
        SHA512_SCR(53);
        SHA512_SCR(54);
        SHA512_SCR(55);
        SHA512_SCR(56);
        SHA512_SCR(57);
        SHA512_SCR(58);
        SHA512_SCR(59);
        SHA512_SCR(60);
        SHA512_SCR(61);
        SHA512_SCR(62);
        SHA512_SCR(63);
        SHA512_SCR(64);
        SHA512_SCR(65);
        SHA512_SCR(66);
        SHA512_SCR(67);
        SHA512_SCR(68);
        SHA512_SCR(69);
        SHA512_SCR(70);
        SHA512_SCR(71);
        SHA512_SCR(72);
        SHA512_SCR(73);
        SHA512_SCR(74);
        SHA512_SCR(75);
        SHA512_SCR(76);
        SHA512_SCR(77);
        SHA512_SCR(78);
        SHA512_SCR(79);

        wv[0] = ctx->h[0];
        wv[1] = ctx->h[1];
        wv[2] = ctx->h[2];
        wv[3] = ctx->h[3];
        wv[4] = ctx->h[4];
        wv[5] = ctx->h[5];
        wv[6] = ctx->h[6];
        wv[7] = ctx->h[7];

        j = 0;

        do {
            SHA512_EXP(0, 1, 2, 3, 4, 5, 6, 7, j);
            j++;
            SHA512_EXP(7, 0, 1, 2, 3, 4, 5, 6, j);
            j++;
            SHA512_EXP(6, 7, 0, 1, 2, 3, 4, 5, j);
            j++;
            SHA512_EXP(5, 6, 7, 0, 1, 2, 3, 4, j);
            j++;
            SHA512_EXP(4, 5, 6, 7, 0, 1, 2, 3, j);
            j++;
            SHA512_EXP(3, 4, 5, 6, 7, 0, 1, 2, j);
            j++;
            SHA512_EXP(2, 3, 4, 5, 6, 7, 0, 1, j);
            j++;
            SHA512_EXP(1, 2, 3, 4, 5, 6, 7, 0, j);
            j++;
        }
        while (j < 80);

        ctx->h[0] += wv[0];
        ctx->h[1] += wv[1];
        ctx->h[2] += wv[2];
        ctx->h[3] += wv[3];
        ctx->h[4] += wv[4];
        ctx->h[5] += wv[5];
        ctx->h[6] += wv[6];
        ctx->h[7] += wv[7];
#else

        for (j = 0; j < 16; j++) {
            PACK64(&sub_block[j << 3], &w[j]);
        }

        for (j = 16; j < 80; j++) {
            SHA512_SCR(j);
        }

        for (j = 0; j < 8; j++) {
            wv[j] = ctx->h[j];
        }

        for (j = 0; j < 80; j++) {
            t1 = wv[7] + SHA512_F2(wv[4]) + CH(wv[4], wv[5], wv[6]) + sha512_k[j] +
                 w[j];
            t2 = SHA512_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }

        for (j = 0; j < 8; j++)
            ctx->h[j] += wv[j];

#endif /* UNROLL_LOOPS_SHA512 */
    }
}

void sha512_update(SHA512Ctx *ctx, const uint8_t *data, size_t len)
{
    size_t block_nb;
    size_t new_len, rem_len, tmp_len;
    const uint8_t *shifted_data;

    tmp_len = SHA512_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], data, rem_len);

    if (ctx->len + len < SHA512_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA512_BLOCK_SIZE;

    shifted_data = data + rem_len;

    SHA512_transform(ctx, ctx->block, 1);
    SHA512_transform(ctx, shifted_data, block_nb);

    rem_len = new_len % SHA512_BLOCK_SIZE;

    memcpy(ctx->block, &shifted_data[block_nb << 7], rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 7;
}

void sha512_final(unsigned char digest[64], SHA512Ctx *ctx)
{
    size_t block_nb;
    size_t pm_len;
    uint64_t len_b;

#ifndef UNROLL_LOOPS_SHA512
    size_t i;
#endif

    block_nb =
        1 + ((SHA512_BLOCK_SIZE - 17) < (ctx->len % SHA512_BLOCK_SIZE));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 7;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK64(len_b, ctx->block + pm_len - 8);

    SHA512_transform(ctx, ctx->block, block_nb);

#ifdef UNROLL_LOOPS_SHA512
    UNPACK64(ctx->h[0], &ctx->buf[0]);
    UNPACK64(ctx->h[1], &ctx->buf[8]);
    UNPACK64(ctx->h[2], &ctx->buf[16]);
    UNPACK64(ctx->h[3], &ctx->buf[24]);
    UNPACK64(ctx->h[4], &ctx->buf[32]);
    UNPACK64(ctx->h[5], &ctx->buf[40]);
    UNPACK64(ctx->h[6], &ctx->buf[48]);
    UNPACK64(ctx->h[7], &ctx->buf[56]);
#else

    for (i = 0; i < 8; i++)
        UNPACK64(ctx->h[i], &ctx->buf[i << 3]);

#endif /* UNROLL_LOOPS_SHA512 */

    memmove(digest, ctx->buf, SHA512_DIGEST_SIZE);
    memset(ctx, 0, sizeof(*ctx));   /* In case it's sensitive */
    return;
}

void sha512(const unsigned char *input, const size_t len,
            unsigned char output[64])
{
    SHA512Ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, input, len);
    sha512_final(output, &ctx);
}

