/*
  SEMIDRIVE Copyright Statement
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

#ifndef SDRV_OSPI_MIGRATE_H
#define SDRV_OSPI_MIGRATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
struct rpmsg_endpoint_info {
    char name[32];
    uint32_t src;
    uint32_t dst;
};

typedef enum ota_cmd {
    OTA_CMD_START,
    OTA_CMD_START_OK,
    OTA_CMD_START_FAIL,
    OTA_CMD_SEEK,
    OTA_CMD_SEEK_OK,
    OTA_CMD_SEEK_FAIL,
    OTA_CMD_READ,
    OTA_CMD_READ_OK,
    OTA_CMD_READ_FAIL,
    OTA_CMD_WRITE,
    OTA_CMD_WRITE_OK,
    OTA_CMD_WRITE_FAIL,
    OTA_CMD_WRITE_INFO,
    OTA_CMD_WRITE_INFO_OK,
    OTA_CMD_WRITE_INFO_FAIL,
    OTA_CMD_GET_CAPACITY,
    OTA_CMD_GET_CAPACITY_OK,
    OTA_CMD_GET_CAPACITY_FAIL,
    OTA_CMD_GET_BLOCK,
    OTA_CMD_GET_BLOCK_OK,
    OTA_CMD_GET_BLOCK_FAIL,
    OTA_CMD_GET_ERASESIZE,
    OTA_CMD_GET_ERASESIZE_OK,
    OTA_CMD_GET_ERASESIZE_FAIL,
    OTA_CMD_COPY,
    OTA_CMD_COPY_OK,
    OTA_CMD_COPY_FAIL,
    OTA_CMD_HANDOVER,
    OTA_CMD_HANDOVER_OK,
    OTA_CMD_HANDOVER_FAIL,
    OTA_CMD_CLOSE,
    OTA_CMD_CLOSE_OK,
    OTA_CMD_CLOSE_FAIL,
    OTA_CMD_PRIORITY,
    OTA_CMD_PRIORITY_OK,
    OTA_CMD_PRIORITY_FAIL,
    OTA_CMD_STOP_WDT,
    OTA_CMD_STOP_WDT_OK,
    OTA_CMD_STOP_WDT_FAIL,
    OTA_CMD_SETUP_PTDEV,
    OTA_CMD_SETUP_PTDEV_OK,
    OTA_CMD_SETUP_PTDEV_FAIL,
    OTA_CMD_DESTROY_PTDEV,
    OTA_CMD_DESTROY_PTDEV_OK,
    OTA_CMD_DESTROY_PTDEV_FAIL,
    OTA_CMD_GET_PARTITION_INDEX,
    OTA_CMD_GET_PARTITION_INDEX_OK,
    OTA_CMD_GET_PARTITION_INDEX_FAIL,
    OTA_CMD_GET_PARTITION_SIZE,
    OTA_CMD_GET_PARTITION_SIZE_OK,
    OTA_CMD_GET_PARTITION_SIZE_FAIL,
    OTA_CMD_GET_PARTITION_OFFSET,
    OTA_CMD_GET_PARTITION_OFFSET_OK,
    OTA_CMD_GET_PARTITION_OFFSET_FAIL,
    OTA_CMD_GET_NUMBER_SLOTS,
    OTA_CMD_GET_NUMBER_SLOTS_OK,
    OTA_CMD_GET_NUMBER_SLOTS_FAIL,
    OTA_CMD_GET_CURRENT_SLOTS,
    OTA_CMD_GET_CURRENT_SLOTS_OK,
    OTA_CMD_GET_CURRENT_SLOTS_FAIL,
    OTA_CMD_GET_SLOT_ATTR,
    OTA_CMD_GET_SLOT_ATTR_OK,
    OTA_CMD_GET_SLOT_ATTR_FAIL,
    OTA_CMD_SET_SLOT_ATTR,
    OTA_CMD_SET_SLOT_ATTR_OK,
    OTA_CMD_SET_SLOT_ATTR_FAIL,
    OTA_CMD_UPDATE_SLOT_ATTR,
    OTA_CMD_UPDATE_SLOT_ATTR_OK,
    OTA_CMD_UPDATE_SLOT_ATTR_FAIL,
    OTA_CMD_GET_NUMBER_PARTITION,
    OTA_CMD_GET_NUMBER_PARTITION_OK,
    OTA_CMD_GET_NUMBER_PARTITION_FAIL,
    OTA_CMD_GET_PARTITION_INFO,
    OTA_CMD_GET_PARTITION_INFO_OK,
    OTA_CMD_GET_PARTITION_INFO_FAIL,
    OTA_CMD_GET_BOOT_INFO,
    OTA_CMD_GET_BOOT_INFO_OK,
    OTA_CMD_GET_BOOT_INFO_FAIL,
    OTA_CMD_SEEK_MAPPED,
    OTA_CMD_SEEK_MAPPED_OK,
    OTA_CMD_SEEK_MAPPED_FAIL,
    OTA_CMD_GET_CAPACITY_MAPPED,
    OTA_CMD_GET_CAPACITY_MAPPED_OK,
    OTA_CMD_GET_CAPACITY_MAPPED_FAIL,
    OTA_CMD_COPY_MAPPED,
    OTA_CMD_COPY_MAPPED_OK,
    OTA_CMD_COPY_MAPPED_FAIL,
    OTA_CMD_SETUP_MAPPED_STORAGE,
    OTA_CMD_SETUP_MAPPED_STORAGE_OK,
    OTA_CMD_SETUP_MAPPED_STORAGE_FAIL,
    OTA_CMD_CHECK_AP,
    OTA_CMD_CHECK_AP_OK,
    OTA_CMD_CHECK_AP_FAIL,
    OTA_CMD_HOLDUP_AP2,
    OTA_CMD_HOLDUP_AP2_OK,
    OTA_CMD_HOLDUP_AP2_FAIL,
    OTA_CMD_MAX,
} ota_cmd_enum;


struct ota_msg_head_struct {
    uint16_t flag1;
    uint16_t len;
    uint16_t cmd;
    uint32_t resv;
    uint32_t crc;
    uint16_t flag2;
} __attribute__((packed));

typedef struct ota_msg_head_struct ota_msg_head_struct_t;

typedef struct ota_op {
    ota_cmd_enum cmd;
    int fd;
    uint32_t timeout_ms;
    ota_cmd_enum expect_recv_cmd;
} ota_op_t;

#define OTA_START_MAGIC 0x7E7E
#define OTA_END_MAGIC   0x7B7B
#define MAX_DATA_LENGTH 448
#define MSG_HEAD_SIZE (sizeof(ota_msg_head_struct_t))
#define MAX_SEND_LENGTH (MAX_DATA_LENGTH + MSG_HEAD_SIZE)
#define MAX_RECV_LENGTH (MAX_DATA_LENGTH + MSG_HEAD_SIZE)
#define OSPI_HANDOVER_MODE 0xAA55
#define OSPI_REMOTE_MODE   0x55AA
#define SHARED_MEMORY_BASE_AP_OFFSET 0x10000000

extern int remote_init(storage_device_t *storage_dev);
extern int remote_read(storage_device_t *storage_dev, uint64_t src,
                       uint8_t *dst, uint64_t size);
extern int remote_read_mapped(storage_device_t *storage_dev, uint64_t src,
                              uint8_t *dst, uint64_t size);
extern uint64_t remote_get_capacity(storage_device_t *storage_dev);
extern uint64_t remote_get_capacity_mapped(storage_device_t *storage_dev);
extern uint32_t remote_get_erase_group_size(storage_device_t *storage_dev);
extern uint32_t remote_get_block_size(storage_device_t *storage_dev);
extern int remote_write(storage_device_t *storage_dev, uint64_t dst,
                        const uint8_t *buf, uint64_t data_len);
extern int remote_write_mapped(storage_device_t *storage_dev, uint64_t dst,
                               const uint8_t *buf, uint64_t data_len);
extern int remote_copy(storage_device_t *storage_dev, uint64_t src,
                       uint64_t dst, uint64_t size);
extern int remote_copy_mapped(storage_device_t *storage_dev, uint64_t src,
                              uint64_t dst, uint64_t size);
extern int remote_release(storage_device_t *storage_dev);
extern int remote_release_mapped(storage_device_t *storage_dev);
extern int remote_stop_wdt(storage_device_t *storage_dev);
extern int remote_holdup_ap2(storage_device_t *storage_dev);
extern int remote_write_with_check(storage_device_t *storage_dev, uint64_t dst,
                                   const uint8_t *buf, uint64_t data_len);
extern int remote_write_with_check_mapped(storage_device_t *storage_dev,
        uint64_t dst,
        const uint8_t *buf, uint64_t data_len);
extern bool ospi_use_handover;
extern int64_t remote_read_direct(storage_device_t *storage_dev, uint8_t *dst,
                                  uint64_t size);
extern int64_t remote_write_direct(storage_device_t *storage_dev,
                                   const uint8_t *buf, uint64_t data_len);
extern int64_t remote_seek(storage_device_t *storage_dev, off_t offset,
                           int whence);
extern int64_t remote_seek_mapped(storage_device_t *storage_dev, off_t offset,
                                  int whence);
extern int remote_setup_ptdev(storage_device_t *storage_dev,
                              const char *ptdev_name);
extern int remote_destroy_ptdev(storage_device_t *storage_dev,
                                const char *ptdev_name);
extern int remote_get_partition_index(storage_device_t *storage_dev,
                                      const char  *ptdev_name, const char *partition_name);
extern uint64_t remote_get_partition_offset(storage_device_t *storage_dev,
        const char *ptdev_name, const char *partition_name);
extern uint64_t remote_get_partition_size(storage_device_t *storage_dev,
        const char *ptdev_name, const char *partition_name);
extern int remote_update_slot_attr(storage_device_t *storage_dev,
                                   const char *ptdev_name);
extern int remote_set_slot_attr(storage_device_t *storage_dev,
                                const char *ptdev_name, uint8_t slot, uint8_t attr, uint8_t set_value);
extern int remote_get_slot_attr(storage_device_t *storage_dev,
                                const char *ptdev_name, uint8_t slot, uint8_t attr);
extern int remote_get_current_slot(storage_device_t *storage_dev,
                                   const char *ptdev_name);
extern int remote_get_slot_number(storage_device_t *storage_dev,
                                  const char *ptdev_name);
extern int remote_get_partition_info(storage_device_t *storage_dev,
                                     const char  *ptdev_name, uint8_t partition_index, void *entry);
extern int remote_get_partition_number(storage_device_t *storage_dev,
                                       const char *ptdev_name);
extern int remote_get_boot_info(storage_device_t *storage_dev, char *boot_info);
extern int remote_init_mapped(storage_device_t *storage_dev);
extern const char  *get_ota_cmd_str(ota_cmd_enum num);

/* Read Write time */
extern uint64_t pure_read_time;
extern uint64_t pure_write_time;
extern uint64_t finish_read_time;

/* shared memory copy time */
extern uint64_t read_ddr_copy_time;
extern uint64_t write_ddr_copy_time;

/* shared memory Hash time */
extern uint64_t read_hash_time;
extern uint64_t write_hash_time;

/* seek time */
extern uint64_t seek_time;

/* write info time*/
extern uint64_t write_info_time;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
