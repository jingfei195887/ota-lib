#ifndef _PLATFORM_CRYPTO_H
#define _PLATFORM_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

extern int crypto_init(void);
extern void crypto_uninit(void);
extern int crypto_digest_buffer(const char *method, uint8_t *input,
                                uint32_t input_size, uint8_t *output, uint32_t output_size);

#ifdef __cplusplus
extern "C" {
#endif

#endif /* _MD5_H */
