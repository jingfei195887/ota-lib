/*
 * SEMIDRIVE Copyright Statement
 * Copyright (c) SEMIDRIVE. All rights reserved
 *
 * This software and all rights therein are owned by SEMIDRIVE, and are
 * protected by copyright law and other relevant laws, regulations and
 * protection. Without SEMIDRIVE's prior written consent and/or related rights,
 * please do not use this software or any potion thereof in any form or by any
 * means. You may not reproduce, modify or distribute this software except in
 * compliance with the License. Unless required by applicable law or agreed to
 * in writing, software distributed under the License is distributed on
 * an "AS IS" basis, WITHOUT WARRANTIES OF ANY KIND, either express or implied.
 *
 * You should have received a copy of the License along with this program.
 * If not, see <http://www.semidrive.com/licenses/>.
 */

#define _LARGEFILE64_SOURCE
#include <stdint.h>
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

#if RUN_IN_QNX
#include <qcrypto/qcrypto.h>

#elif RUN_IN_ANDROID
#include <openssl/evp.h>

struct digest_table {
    const char *name;
    size_t digest_len;
    const EVP_MD *(*md_func)(void);
};

#define TABLE_LEN 5
const struct digest_table digest_table[TABLE_LEN] = {
    { "md5",     16,    EVP_md5    },
    { "sha1",    20,    EVP_sha1   },
    { "sha256",  32,    EVP_sha256 },
    { "sha384",  48,    EVP_sha384 },
    { "sha512",  64,    EVP_sha512 },
};
#else
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

typedef void (*hash_fn)(const uint8_t *input, uint32_t input_size,
                        uint8_t *output);
struct hash_map_entry {
    const char *name;
    hash_fn fn;
    uint32_t digest_size;
};

void digest_openssl(const char* dig, const uint8_t *input, uint32_t input_size, uint8_t *output)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *method = NULL;
    ctx = EVP_MD_CTX_new();
    uint32_t len = 0;
    if (ctx == NULL)
        goto err;

    method = EVP_MD_fetch(NULL, dig, NULL);
    if (method == NULL)
        goto err;

    if (!EVP_DigestInit_ex(ctx, method, NULL))
        goto err;

    if (!EVP_DigestUpdate(ctx, input, input_size))
            goto err;

    if (!EVP_DigestFinal_ex(ctx, output, &len))
        goto err;

err:
    EVP_MD_free(method);
    EVP_MD_CTX_free(ctx);
}
void md5_openssl(const uint8_t *input, uint32_t input_size, uint8_t *output)
{
#if 0
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, input, input_size);
    MD5_Final(output, &ctx);
#endif
    digest_openssl("MD5", input, input_size, output);
}
void sha256_openssl(const uint8_t *input, uint32_t input_size, uint8_t *output)
{
#if 0
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input, input_size);
    SHA256_Final(output, &ctx);
#endif
    digest_openssl("SHA256", input, input_size, output);

}
void sha512_openssl(const uint8_t *input, uint32_t input_size, uint8_t *output)
{
#if 0
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, input, input_size);
    SHA512_Final(output, &ctx);
#endif
    digest_openssl("SHA512", input, input_size, output);
}
const struct hash_map_entry hash_map[] = {
    {"md5",    md5_openssl,    MD5_DIGEST_LENGTH},
    {"sha256", sha256_openssl, SHA256_DIGEST_LENGTH},
    {"sha512", sha512_openssl, SHA512_DIGEST_LENGTH}
};
const size_t num_methods = sizeof(hash_map) / sizeof(hash_map[0]);

#endif

int crypto_init(void)
{
#if RUN_IN_QNX
    int ret;
    ret = qcrypto_init(QCRYPTO_INIT_LAZY, NULL);

    if (ret != QCRYPTO_R_EOK) {
        PRINTF_CRITICAL("qcrypto_init() failed (%d:%s)\n", ret, qcrypto_strerror(ret));
        return -1;
    }

#endif
    return 0;
}


void crypto_uninit(void)
{
#if RUN_IN_QNX
    qcrypto_uninit();
#endif
}

int crypto_digest_buffer(const char *method, uint8_t *input,
                         uint32_t input_size, uint8_t *output, uint32_t output_size)
{
#if RUN_IN_QNX
    const char *digest_method = method;
    int ret = -1;
    qcrypto_ctx_t *ctx = NULL;
    size_t dsize;
    const char *input_buffer = (const char *)input;
    size_t calc_size = input_size;
    uint8_t *output_buffer = NULL;

    /* check para */
    if (!digest_method || !output || !input || !input_size || !output_size) {
        PRINTF_CRITICAL("para error\n");
        ret = -1;
        goto done;
    }

    /* Checking if a digest is supported */
    ret = qcrypto_digest_supported(digest_method, NULL, 0);

    if (ret != QCRYPTO_R_EOK) {
        PRINTF_CRITICAL("qcrypto_digest_supported() failed (%d:%s)\n", ret,
                        qcrypto_strerror(ret));
        ret = -1;
        goto done;
    }

    /* Requesting the digest */
    ret = qcrypto_digest_request(digest_method, NULL, 0, &ctx);

    if (ret != QCRYPTO_R_EOK) {
        PRINTF_CRITICAL("qcrypto_digest_request() failed (%d:%s)\n", ret,
                        qcrypto_strerror(ret));
        ret = -1;
        goto done;
    }

    /* Querying the digest size */
    dsize = qcrypto_digestsize(ctx);
#if DEBUGMODE
    PRINTF_CRITICAL("%s digest size =  %d\n", digest_method, (int)dsize);
    PRINTF_CRITICAL("output_size size =  %d\n", output_size);
#endif

    if (output_size < dsize) {
        PRINTF_CRITICAL("need digest size =  %d, but output buffer size is %d\n",
                        (int)dsize, output_size);
        ret = -1;
        goto done;
    }

    output_buffer = malloc(dsize);

    if (output_buffer == NULL) {
        PRINTF_CRITICAL("output size not defined (%d:%s)\n", ret,
                        qcrypto_strerror(ret));
        ret = -1;
        goto done;
    }

    /* Initializing, updating, and finalizing the digest */
    ret = qcrypto_digest(ctx, (const uint8_t *)input_buffer, calc_size,
                         output_buffer, &dsize);

    if (ret != QCRYPTO_R_EOK) {
        PRINTF_CRITICAL("qcrypto_digest() failed (%d:%s)\n", ret,
                        qcrypto_strerror(ret));
        ret = -1;
        goto done;
    }

#if DEBUGMODE
    PRINTF_CRITICAL("digest_method = %s\n", digest_method);

    for (int i = 0; i < dsize; i++) {
        PRINTF("%02x", output_buffer[i]);
    }

    PRINTF_CRITICAL("\n");
#endif

    memcpy(output, output_buffer, dsize);
    ret = 0;

done:

    if (output_buffer) {
        free(output_buffer);
        output_buffer = NULL;
    }

    /* Releasing the context */
    qcrypto_release_ctx(ctx);

    return ret;

#elif RUN_IN_ANDROID
    const char *digest_method = method;
    const char *input_buffer = (const char *)input;
    uint32_t calc_size = input_size;
    int i = 0;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    uint32_t dsize = 0;
    const EVP_MD* (*md_func)(void);

    /* check para */
    if (!digest_method || !output || !input || !input_size || !output_size) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    for (i = 0; i < TABLE_LEN; i++) {
        if (!strcmp(digest_table[i].name, digest_method)) {
            dsize = digest_table[i].digest_len;
            md_func = digest_table[i].md_func;
            break;
        }
    }

    if (i == TABLE_LEN) {
        PRINTF_CRITICAL("digest %s not supported\n", digest_method);
        return -1;
    }

    if (output_size < dsize) {
        PRINTF_CRITICAL("need digest size =  %d, but output buffer size is %d\n",
                        (int)dsize, output_size);
        return -1;
    }

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md_func(), NULL);
    EVP_DigestUpdate(mdctx, input_buffer, calc_size);
    EVP_DigestFinal_ex(mdctx, md_value, &dsize);
    memcpy(output, md_value, dsize);

#if DEBUGMODE
    PRINTF_CRITICAL("digest_method = %s\n", digest_method);

    for (int i = 0; i < dsize; i++) {
        PRINTF("%02x", md_value[i]);
    }

    PRINTF_CRITICAL("\n");
#endif

    EVP_MD_CTX_free(mdctx);

    return 0;
#else
    const char *digest_method = method;
    hash_fn hash_func = NULL;
    uint32_t dsize = 0;

    for (size_t i = 0; i < num_methods; ++i) {
        if (strcmp(hash_map[i].name, digest_method) == 0) {
            hash_func = hash_map[i].fn;
            dsize = hash_map[i].digest_size;
            break;
        }
    }

    if (!hash_func) {
        fprintf(stderr, "Invalid hash method\n");
        return -1;
    }

    if (output_size < dsize) {
        fprintf(stderr, "Output buffer size is too small for %s\n", digest_method);
        return -1;
    }

    hash_func(input, input_size, output);

#if DEBUGMODE
    PRINTF_CRITICAL("digest_method = %s\n", digest_method);

    for (int i = 0; i < dsize; i++) {
        PRINTF("%02x", output[i]);
    }

    PRINTF_CRITICAL("\n");
#endif

    return 0;
#endif
}

