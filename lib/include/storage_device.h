/*
 * Copyright (c) 2019 Semidrive Semiconductor.
 * All rights reserved.
 */
#ifndef __STORAGE_DEV_H__
#define __STORAGE_DEV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#if RUN_IN_ANDROID && !RUN_IN_HOST
#include <sdrv_rpmsg_channel.h>
#endif

#ifndef RUN_IN_QNX
#define MONITOR_CHANNEL_SAFETY "soc:ipcc@0.update-monitor.-1.81"
#define MONITOR_CHANNEL_SECURE "soc:ipcc@1.update-monitor.-1.81"
#define MONITOR_CHANNEL_MP     "soc:ipcc@2.update-monitor.-1.81"
//#define MONITOR_CHANNEL_SAFETY "virtio0.update-monitor.-1.81"
//#define MONITOR_CHANNEL_SECURE "virtio1.update-monitor.-1.81"
//#define MONITOR_CHANNEL_MP     "virtio2.update-monitor.-1.81"
#else
#define MONITOR_CHANNEL_SAFETY "/dev/rpmsg10"
#define MONITOR_CHANNEL_SECURE "/dev/rpmsg11"
#define MONITOR_CHANNEL_MP     "/dev/rpmsg12"
#endif

#define FILE_PATH_LEN 256
#define FILE_PATH_LEN_L 512

#ifndef STORAGE_NAME_LEN
#define STORAGE_NAME_LEN 256
#endif

#define SELECT_BOOT0    0
#define SELECT_BOOT1    1
#define SELECT_USERDATA 2
#define SELECT_PEERLOAD_BOOT    3

#define LBA_SIZE 512
typedef enum storage_inst_id {
    STORAGE_LOCAL,
    STORAGE_REMOTE,
    STORAGE_REMOTE_LOCAL,
    STORAGE_ERROR = -1,
} storage_type_id_e;

typedef struct storage_device storage_device_t;

typedef struct chunk_header {
    uint16_t  chunk_type; /* 0xCAC1 -> raw; 0xCAC2 -> fill; 0xCAC3 -> don't care */
    uint16_t  reserved1;
    uint32_t  chunk_sz;   /* in blocks in output image */
    uint32_t  total_sz;   /* in bytes of chunk input file including chunk header and data */
} chunk_header_t;

#define SPARSE_HEADER_MAGIC     0xed26ff3a
#define CHUNK_TYPE_RAW          0xCAC1
#define CHUNK_TYPE_FILL         0xCAC2
#define CHUNK_TYPE_DONT_CARE    0xCAC3
#define CHUNK_TYPE_CRC          0xCAC4

typedef struct sparse_header_struct {
    uint32_t  magic;           /* 0xed26ff3a */
    uint16_t  major_version;  /* (0x1) - reject images with higher major versions */
    uint16_t  minor_version;  /* (0x0) - allow images with higer minor versions */
    uint16_t  file_hdr_sz;    /* 28 bytes for first revision of the file format */
    uint16_t  chunk_hdr_sz;   /* 12 bytes for first revision of the file format */
    uint32_t  blk_sz;     /* block size in bytes, must be a multiple of 4 (4096) */
    uint32_t  total_blks; /* total blocks in the non-sparse output image */
    uint32_t  total_chunks;   /* total chunks in the sparse input image */
    uint32_t  image_checksum; /* CRC32 checksum of the original data, counting "don't care" */
    /* as 0. Standard 802.3 polynomial, use a Public Domain */
    /* table implementation */
} sparse_header_t;


#if RUN_IN_QNX
#include "rpmsg/rpmsg.h"
#include <sys/neutrino.h>
#define RP_EVENT_PRIORITY   (21)
#define RP_EVENT_CODE       (SI_NOTIFY)
#define RP_ENDPOINT         (81)
typedef struct rpmsg_op {
    unsigned ept_id;
    int chid;
    int coid;
    rpmsg_endpoint_t *ept_hdl;
} rpmsg_op_t;

typedef struct rpmsg_handle {
    int ctl_fd;
    int ept_fd;
    uint32_t count;
    rpmsg_op_t rp_op;
} rpmsg_handle_t;
#endif

typedef enum shared_memory_digest_mode_enum {
    DIGEST_MODE_NONE = 0,
    DIGEST_MODE_CRC32,
    DIGEST_MODE_CRC32_WITH_RAMDOM,
    DIGEST_MODE_MD5,
    DIGEST_MODE_SHA256,
} shared_memory_digest_mode_e;

struct shared_memory_mode_struct {
    uint8_t digest_mode;
    uint8_t reserved[7];
} __attribute__((packed));

typedef struct shared_memory_mode_struct shared_memory_mode_t;

struct storage_device {
    char dev_name[STORAGE_NAME_LEN];
    storage_type_id_e type;
    int dev_fd;
    int cnt;
    bool mapped;
    bool use_shared_memory;
    int memfd;
    uint8_t *shared_mem_ptr;
    uint64_t capacity;
    uint32_t erase_size;
    uint32_t block_size;
    uint32_t shared_memory_read_data_offset;
    uint32_t shared_memory_write_data_offset;
    uint32_t shared_memory_read_crc_offset;
    uint32_t shared_memory_write_crc_offset;
    uint32_t max_shared_memory_length;
    uint32_t max_shared_memory_read_data_length;
    uint32_t max_shared_memory_write_data_length;
    uint32_t max_shared_memory_crc_length;
    uint32_t thread_read_size;
    uint32_t thread_read_crc_size;
    const char* shared_memory_name;
    int64_t (*read_direct)(storage_device_t *storage_dev, uint8_t *dst,
                           uint64_t size);
    int64_t (*write_direct)(storage_device_t *storage_dev, const uint8_t *buf,
                            uint64_t data_len);
    int64_t (*seek)(storage_device_t *storage_dev, off_t offset, int whence);
    int (*init) (storage_device_t *storage_dev);
    int (*read) (storage_device_t *storage_dev, uint64_t src, uint8_t *dst,
                 uint64_t size);
    int (*write) (storage_device_t *storage_dev, uint64_t dst,
                  const uint8_t *buf, uint64_t data_len);
    int (*write_with_check) (storage_device_t *storage_dev, uint64_t dst,
                             const uint8_t *buf, uint64_t data_len);
    int (*erase) (storage_device_t *storage_dev, uint64_t dst, uint64_t len);
    int (*switch_part) (storage_device_t *storage_dev, uint32_t part);
    uint64_t (*get_capacity) (storage_device_t *storage_dev);
    uint32_t (*get_erase_group_size) (storage_device_t *storage_dev);
    uint32_t (*get_block_size) (storage_device_t *storage_dev);
    int (*need_erase) (storage_device_t *storage_dev);
    int (*release) (storage_device_t *storage_dev);
    int (*copy) (storage_device_t *storage_dev, uint64_t src, uint64_t dst,
                 uint64_t size);
    int (*write_file)(storage_device_t *storage_dev, uint64_t dst, uint64_t size,
                      char *file, uint8_t write_check);
    int (*setup_ptdev)(storage_device_t *storage_dev, const char *ptdev_name);
    int (*destroy_ptdev)(storage_device_t *storage_dev, const char *ptdev_name);
    int (*get_partition_index)(storage_device_t *storage_dev,
                               const char *ptdev_name, const char *partition_name);
    uint64_t (*get_partition_offset)(storage_device_t *storage_dev,
                                     const char *ptdev_name, const char *partition_name);
    uint64_t (*get_partition_size)(storage_device_t *storage_dev,
                                   const char *ptdev_name, const char *partition_name);
    int (*get_slot_number)(storage_device_t *storage_dev, const char *ptdev_name);
    int (*update_slot_attr)(storage_device_t *storage_dev, const char *ptdev_name);
    int (*set_slot_attr)(storage_device_t *storage_dev, const char *ptdev_name,
                         uint8_t slot, uint8_t attr, uint8_t set_value);
    int (*get_slot_attr)(storage_device_t *storage_dev, const char *ptdev_name,
                         uint8_t slot, uint8_t attr);
    int (*get_current_slot)(storage_device_t *storage_dev, const char *ptdev_name);
    int (*get_partition_info)(storage_device_t *storage_dev, const char *ptdev_name,
                              uint8_t partition_index, void *entry);
    int (*get_partition_number)(storage_device_t *storage_dev,
                                const char *ptdev_name);
    int (*set_readonly) (storage_device_t *storage_dev, bool read_only);
    int (*get_readonly) (storage_device_t *storage_dev);

    shared_memory_mode_t shared_mem_mode;
    bool support_switch_part;
    uint64_t boot0_capacity;
    uint64_t boot1_capacity;
    int boot0_dev_fd;
    int boot1_dev_fd;
    int user_data_dev_fd;
    int part;
#if RUN_IN_ANDROID && !RUN_IN_HOST
    channel_handle_t *rpmsg_handler;
#elif RUN_IN_QNX
    rpmsg_handle_t *rpmsg_handler;
#endif
};

extern int init_storage(storage_device_t *storage,
                        storage_device_t *base_storage);
extern int uninit_storage(storage_device_t *storage);

extern storage_device_t mmc1;
extern storage_device_t sec_update_monitor;
extern storage_device_t saf_update_monitor;
extern storage_device_t mp_update_monitor;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __STORAGE_DEV_H__ */
