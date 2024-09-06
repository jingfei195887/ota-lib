
/*
 * Copyright (c) 2019 Semidrive Semiconductor.
 * All rights reserved.
 */
#ifndef __UPDATE_DEV_H__
#define __UPDATE_DEV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/stat.h>
#include "storage_device.h"
#include "partition_parser.h"
#include "syscall_interface.h"

#ifndef NUM_PARTITIONS
#define NUM_PARTITIONS             128
#endif

#ifndef MAX_GPT_NAME_SIZE
#define MAX_GPT_NAME_SIZE          72
#endif

#define FD_NODE_STRUCT_MAGIC 0x4e4f4445
#define SYSCALL_HEAD_STRUCT_MAGIC 0x48454144

#ifndef UPDATE_DEV_NAME_LEN
#define UPDATE_DEV_NAME_LEN MAX_GPT_NAME_SIZE
#endif

#define BASE_DEV_NAME_MMC                       "mmc1"
#define BASE_DEV_NAME_OSPI                      "ospi1"
#define BASE_DEV_NAME_MMC_REMOTE(x)             "mmc1_"#x""

#ifndef BOOT_FD_NODE_CNT
#define BOOT_FD_NODE_CNT 2
#endif

#define FD_NODE_TYPE_NORMAL             0
#define FD_NODE_TYPE_EMMC_BOOT          1
#define FD_NODE_TYPE_OSPI_BOOT          2
#define FD_NODE_TYPE_EMMC_PEERLOAD_BOOT 3
#define FD_NODE_TYPE_OSPI_PEERLOAD_BOOT 4

#define BOOT_UPDATE_CNT_V1 2
#define BOOT_NAME_CNT 4

/* Do not change the storage id sequence */
typedef enum storage_id {
    DEV_EMMC0,
    DEV_SPI_NOR0,
    DEV_EMMC1,
    DEV_EMMC2,
    DEV_EMMC3,
    DEV_EMMC4,
    DEV_EMMC5,
    DEV_EMMC6,
    //DEV_SPI_NOR1,
    DEV_MAX
} storage_id_e;

typedef enum update_monitor_mode {
    MODE_SKIP_UPDATE,
    MODE_NEED_UPDATE,
} update_monitor_mode_e;

typedef enum update_monitor_check {
    SAFETY_CHECK,
    SECURITY_CHECK,
    UM_CHECK_MAX,
} update_monitor_check_e;

typedef struct __attribute__((packed)) update_fd_node {
    uint32_t magic; //"N" "O" "D" "E"= 0x4e4f4445
    char partition_name[MAX_GPT_NAME_SIZE];
    uint32_t flags;
    uint64_t offset;
    uint64_t size;
    uint64_t current;
    uint32_t type;
    uint32_t bpt_v;
    uint32_t psn;
    uint32_t sec_ver;
    /*make sure crc32 is the last element, so we check crc32 more convenient,
         like this : crc32_val = crc32(0, (uint8_t *)fd_node, sizeof(update_fd_node_t) -4); */
    uint32_t crc32;
} update_fd_node_t;

typedef struct update_syscall_head {
    uint32_t magic; //"H" "E" "A" "D"= 0x48454144
    char partition_table_name[MAX_GPT_NAME_SIZE];
    void *ptdev;
    int fd_cnt;
    int mode;
    uint32_t crc32;
    update_fd_node_t fd_node_arry[NUM_PARTITIONS];
    update_fd_node_t boot_fd_node[BOOT_FD_NODE_CNT];
} update_syscall_head_t;

typedef struct update_device {
    storage_id_e id;
    bool active;
    char name[UPDATE_DEV_NAME_LEN];
    uint64_t gpt_offset;
    storage_device_t *storage;
    storage_device_t *mapped_storage;
    partition_device_t *ptdev;
    update_syscall_head_t *syscall_head;
    bool init;
    bool is_sub_ptdev;
} update_device_t;

typedef enum sub_chip {
    SUB_CHIP_ERROR = -1,
    SUB_CHIP_A = 0,
    SUB_CHIP_B = 1,
} sub_chip_e;

struct dcf_ioc_setproperty {
    uint32_t property_id;
    uint32_t property_value;
    uint32_t reserved1;
    uint32_t reserved2;
};

typedef enum ota_lib_property {
    PROPERTY_HANDSHAKE_BIT = 0,
    PROPERTY_OTA_LIB_MAX,
} ota_lib_property_e;

typedef enum ota_lib_cmd {
    OTA_LIB_CMD_NONE,
    OTA_LIB_CMD_ENABLE_HANDSHAKE,
    OTA_LIB_CMD_MAX,
} ota_lib_cmd_e;

extern const char* emmc_boot0_name[BOOT_NAME_CNT];
extern const char* emmc_boot1_name[BOOT_NAME_CNT];
extern const char* ospi_boot0_name;
extern const char* ospi_boot1_name;
extern const char* emmc_peerload_boot_name;
extern const char* ospi_peerload_boot_name;
extern const char* ospi_peerload_boot_name_a;
extern const char* ospi_peerload_boot_name_b;
extern const char* emmc_peerload_boot_name_a;
extern const char* emmc_peerload_boot_name_b;

extern void stop_safety_wdt(void);
extern void holdup_ap2(void);
extern bool get_update_device_is_sub_dev(storage_id_e dev);
extern bool get_update_device_is_init(storage_id_e dev);
extern bool get_update_device_is_active(storage_id_e dev);
extern char *get_update_device_name(storage_id_e dev);
extern storage_device_t *get_update_device_storage(storage_id_e dev);
extern storage_type_id_e get_update_device_storage_type(storage_id_e dev);
extern partition_device_t *get_update_device_ptdev(storage_id_e dev);
extern partition_device_t **get_update_device_ptdev_pointer(storage_id_e dev);
extern int set_update_device_ptdev(storage_id_e dev, partition_device_t *ptdev);
extern update_syscall_head_t *get_syscall_head(storage_id_e dev);
extern int set_syscall_head(storage_id_e dev,
                            update_syscall_head_t *syscall_head);
extern update_device_t *setup_update_dev(storage_id_e dev);
extern unsigned int destroy_update_dev(storage_id_e dev);
extern int handshake_with_other_chip(int timeout_s);
extern uint32_t get_update_device_num();
extern update_device_t *get_update_device(storage_id_e dev);
extern int check_mpc_status(void);
extern bool is_local_uniform_rollback_need_set(void);
extern bool is_uniform_rollback_need(void);
extern void set_local_uniform_rollback(char *property_value);
extern void set_global_uniform_rollback(char *property_value);
extern void set_ota_status_property(const char* property_value);
extern int wait_for_opposite_ota_status_property(const int para_cnt, ...);
extern int wait_for_property(const int para_cnt, ...);
extern void set_skip_uniform_rollback_value(int value);
extern bool is_skip_uniform_rollback_need(void);
extern int get_ota_target_emmc_dil(void);
extern int get_ota_target_ospi_dil(void);
extern int get_bpt_version(void);
extern int get_current_emmc_dil(void);
extern int get_current_ospi_dil(void);
extern const char* transform_ospi_boot_partition_name_bptv2(const char * name);
extern const char* transform_ospi_boot_partition_name_bptv1(const char * name);
extern const char* transform_emmc_boot_partition_name_bptv2(const char * name);
extern const char* transform_emmc_boot_partition_name_bptv1(const char * name);
extern bool is_ospi_boot1(const char * name);
extern bool is_ospi_boot0(const char * name);
extern bool is_emmc_boot0(const char * name);
extern bool is_emmc_boot1(const char * name);
extern bool is_run_in_ap2();
extern int get_rollback_index(void);
extern int get_partition_index_from_ptdev(partition_device_t *ptdev, const char *partition_name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
