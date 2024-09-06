#ifndef BPT_H_
#define BPT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>

#define BPT_V1 0x42505401
#define BPT_V2 0x42505402

#define BPT_V1_SZ 0x800
#define BPT_V2_SZ 0x1000

#define BPT_V1_CRC_OFF  0x7FC
#define BPT_V2_CRC_OFF  0xFEC

#define BPT_PSN_OFF     0xFF0
#define BPT_PSN_INV_OFF 0xFF4

#define BPT_SEC_VER_OFF 0x8

#ifdef __cplusplus
extern "C" {
#endif

#endif
