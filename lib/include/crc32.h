#ifndef CRC32_H_
#define CRC32_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define CRC_BUFFER_SIZE  8192

unsigned long Crc32_ComputeBuf(unsigned long inCrc32, const void *buf,
                               size_t bufLen);

uint32_t sd_crc32(uint32_t crc, const uint8_t *buffer, uint32_t len);
#define crc32 Crc32_ComputeBuf

#ifdef __cplusplus
extern "C" {
#endif

#endif
