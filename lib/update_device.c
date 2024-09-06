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
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <malloc.h>
#include <time.h>
#include "crc32.h"
#include "slots_parse.h"
#include <assert.h>
#include <sys/mman.h>
#if !RUN_IN_QNX
#include <linux/fs.h>
#else
#include <sd_prop.h>
#endif
#include <fcntl.h>
#if RUN_IN_ANDROID
#include <cutils/properties.h>
#endif
#include "communication.h"
#include <sys/ioctl.h>
#if !RUN_IN_ANDROID  && SUPPORT_PROPERTY_LIB
#include "libprop.h"
#endif
#include "bpt.h"

#define MAX_LEVEL2_UPDATE_DEV                   5
#define MAX_BASE_UPDATE_DEV                     3
#define BOOT_INFO_PREFIX                        "BOOT_MODE="
#define BOOT_INFO_PREFIX_SCAN                   "BOOT_MODE=%d"
#define LEVEL2_PTDEV_PREFIX                     "-SUB_PTDEV="
//bring up for Android14 start
//#define LEVEL2_PTDEV_PREFIX_SCAN                "-SUB_PTDEV=%72[^-]"
#define LEVEL2_PTDEV_PREFIX_SCAN                "-SUB_PTDEV=%71[^-]"
//bring up for Android14 end
#define SAFETY_UPDATE_MONITOR_CMDLINE_ANDROID   "ro.boot.safety_updatemonitor"
#define SECURE_UPDATE_MONITOR_CMDLINE_ANDROID   "ro.boot.secure_updatemonitor"
#define CHIPVERSION_CMDLINE_ANDROID             "ro.boot.chipversion"
#define SUBCHIP_CMDLINE_ANDROID                 "ro.boot.subchip"
#define SAFETY_UPDATE_MONITOR_CMDLINE_LINUX     "safety_updatemonitor="
#define SECURE_UPDATE_MONITOR_CMDLINE_LINUX     "secure_updatemonitor="
#define CHIPVERSION_CMDLINE_LINUX               "chipversion="
#define SUBCHIP_CMDLINE_LINUX                   "subchip="
#define OTA_CMD_LINUX                           "ota_cmd="
#define OTA_CMD_ANDROID                         "ro.boot.ota_cmd"
#define MAX_CMD_LEN                              200  //length of string :"slot_suffix=_a" is 14
#define MAX_CMD_FIND_LIMIT                       200
#define CMD_SCAN_FORMAT                         "%199s"
#define DCF_IOC_MAGIC                           'D'
#define DMP_ID_OTA_STATUS                        (20)
#define DCF_IOC_GET_PROPERTY                     _IOWR(DCF_IOC_MAGIC, 3, struct dcf_ioc_setproperty)
#define DCF_IOC_SET_PROPERTY                     _IOWR(DCF_IOC_MAGIC, 2, struct dcf_ioc_setproperty)
#define DOMAIN_INFO_CMDLINE_ANDROID              "ro.boot.domain"
#define DOMAIN_INFO_CMDLINE_LINUX                "domain="

#if MEM_TEST_MODE
int malloc_cnt = 0;
size_t malloc_size[MAX_MEM_NUMBER] = {0};
uint64_t malloc_addr[MAX_MEM_NUMBER] = {0};
#endif

static bool safety_um = true;
static bool secure_um = false;
static bool chipA_chipB_handshake = false;
static ota_lib_cmd_e ota_cmd = OTA_LIB_CMD_NONE;
static sub_chip_e sub_chip = SUB_CHIP_ERROR;
static int local_handshake_status = HANDSHAKE_ERROR;
static int skip_uniform_rollback = 0;

update_device_t update_device_list[] = {
    {.id = DEV_EMMC0,    .active = true,   .name = BASE_DEV_NAME_MMC,              .gpt_offset = 0,       .ptdev = NULL,  .storage = &mmc1,                .mapped_storage = NULL, .syscall_head = NULL, .init = false, .is_sub_ptdev = false,},
    {.id = DEV_SPI_NOR0, .active = true,   .name = BASE_DEV_NAME_OSPI,             .gpt_offset = 0x2000,  .ptdev = NULL,  .storage = &saf_update_monitor,  .mapped_storage = NULL, .syscall_head = NULL, .init = false, .is_sub_ptdev = false,},
    {.id = DEV_EMMC1,    .active = false,  .name = BASE_DEV_NAME_MMC_REMOTE(top),  .gpt_offset = 0,       .ptdev = NULL,  .storage = &sec_update_monitor,  .mapped_storage = NULL, .syscall_head = NULL, .init = false, .is_sub_ptdev = false,},
    {.id = DEV_EMMC2,    .active = false,  .name = {0},                            .gpt_offset = 0,       .ptdev = NULL,  .storage = &sec_update_monitor,  .mapped_storage = NULL, .syscall_head = NULL, .init = false, .is_sub_ptdev = true, },
    {.id = DEV_EMMC3,    .active = false,  .name = {0},                            .gpt_offset = 0,       .ptdev = NULL,  .storage = &sec_update_monitor,  .mapped_storage = NULL, .syscall_head = NULL, .init = false, .is_sub_ptdev = true, },
    {.id = DEV_EMMC4,    .active = false,  .name = {0},                            .gpt_offset = 0,       .ptdev = NULL,  .storage = &sec_update_monitor,  .mapped_storage = NULL, .syscall_head = NULL, .init = false, .is_sub_ptdev = true, },
    {.id = DEV_EMMC5,    .active = false,  .name = {0},                            .gpt_offset = 0,       .ptdev = NULL,  .storage = &sec_update_monitor,  .mapped_storage = NULL, .syscall_head = NULL, .init = false, .is_sub_ptdev = true, },
    {.id = DEV_EMMC6,    .active = false,  .name = {0},                            .gpt_offset = 0,       .ptdev = NULL,  .storage = &sec_update_monitor,  .mapped_storage = NULL, .syscall_head = NULL, .init = false, .is_sub_ptdev = true, },
    /*  {.id = DEV_SPI_NOR1, .active = false,  .name = "ospi1_handover",               .gpt_offset = 0x2000,  .ptdev = NULL,  .storage = &ospi1_handover,      .mapped_storage = NULL, .syscall_head = NULL, .init = false, .is_sub_ptdev = false,}, */
};

static uint32_t update_dev_max = sizeof(update_device_list) / sizeof(
                                     update_device_list[0]);


struct virtual_boot_name_map{
    int boot_slot;
    const char * name;
    char suffix[3];
};


const char* emmc_boot0_name[BOOT_NAME_CNT] =  {"mmcblk0boot0", "mmcblk1boot0", "emmcboot0", "spl0"};
const char* emmc_boot1_name[BOOT_NAME_CNT] =  {"mmcblk0boot1", "mmcblk1boot1", "emmcboot1", "spl1"};

const char* emmc_boot_name_v1[BOOT_UPDATE_CNT_V1]  =  {DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT0,  DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT1};
struct virtual_boot_name_map  emmc_boot_name_v2[2] = {
    {SELECT_BOOT0, DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V2, ""},
    {SELECT_BOOT1, DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V2, ""}
};

const char* ospi_boot0_name =  "dil";
const char* ospi_boot1_name =  "dil_bak";
const char* ospi_peerload_boot_name =    "dil_safety";
const char* ospi_peerload_boot_name_a =  "dil_safety_a";
const char* ospi_peerload_boot_name_b =  "dil_safety_b";
const char* emmc_peerload_boot_name =    "dil_sec";
const char* emmc_peerload_boot_name_a =  "dil_sec_a";
const char* emmc_peerload_boot_name_b =  "dil_sec_b";

const char* ospi_boot_name_v1[BOOT_UPDATE_CNT_V1]  =  {
    DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT0,  DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT1
};

struct virtual_boot_name_map  ospi_boot_name_v2[2] = {
    {SELECT_BOOT0, DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V2, ""},
    {SELECT_BOOT1, DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V2, ""}
};

uint32_t get_update_device_num()
{
    return update_dev_max;
}

update_device_t *get_update_device(storage_id_e dev)
{
    uint32_t i = 0;

    if ((dev < 0) || (dev >= DEV_MAX)) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        return NULL;
    }

    for (i = 0; i < get_update_device_num(); i++) {
        if (dev == (update_device_list[i].id)) {
#if DEBUGMODE
            assert(i == dev);
#endif
            return &update_device_list[i];
        }
    }

    return NULL;
}

update_device_t *get_empty_level2_update_device()
{
    int i = 0;

    for (i = 0; i < get_update_device_num(); i++) {
        /* find sub dev */
        if (get_update_device_is_sub_dev(i)) {
            /* do not active */
            if (get_update_device_is_active(i)) {
                continue;
            }

            return &update_device_list[i];
        }
    }

    return NULL;
}

bool get_update_device_is_sub_dev(storage_id_e dev)
{
    update_device_t *device = get_update_device(dev);

    if (device) {
        return device->is_sub_ptdev;
    }

    return false;
}

bool get_update_device_is_init(storage_id_e dev)
{
    update_device_t *device = get_update_device(dev);

    if (device) {
        return device->init;
    }

    return false;
}

bool get_update_device_is_active(storage_id_e dev)
{
    update_device_t *device = get_update_device(dev);

    if (device) {
        return device->active;
    }

    return true;
}

char *get_update_device_name(storage_id_e dev)
{
    update_device_t *device = get_update_device(dev);

    if (device) {
        return device->name;
    }

    return NULL;
}

storage_device_t *get_update_device_storage(storage_id_e dev)
{
    update_device_t *device = get_update_device(dev);

    if (device) {
        if (device->is_sub_ptdev)
            return device->mapped_storage;
        else
            return device->storage;
    }

    return NULL;
}

storage_type_id_e get_update_device_storage_type(storage_id_e dev)
{
    update_device_t *device = get_update_device(dev);

    if (device && device->storage) {
        return device->storage->type;
    }

    return STORAGE_ERROR;
}

partition_device_t *get_update_device_ptdev(storage_id_e dev)
{
    update_device_t *device = get_update_device(dev);

    if (device) {
        return device->ptdev;
    }

    return NULL;
}

partition_device_t **get_update_device_ptdev_pointer(storage_id_e dev)
{
    update_device_t *device = get_update_device(dev);

    if (device) {
        return &(device->ptdev);
    }

    return NULL;
}

int set_update_device_ptdev(storage_id_e dev, partition_device_t *ptdev)
{
    update_device_t *device = get_update_device(dev);

    if (device) {
        device->ptdev = ptdev;
        return 0;
    }

    return -1;
}

int set_syscall_head(storage_id_e dev, update_syscall_head_t *syscall_head)
{
    update_device_t *device = get_update_device(dev);

    if (device) {
        device->syscall_head = syscall_head;
        return 0;
    }

    return -1;
}

update_syscall_head_t *get_syscall_head(storage_id_e dev)
{
    update_device_t *device = get_update_device(dev);

    if (device) {
        return device->syscall_head;
    }

    return NULL;
}

static int get_ota_lib_property(int id)
{
    struct dcf_ioc_setproperty prop;
    int ret = -1;
    int fd = -1;

    fd = open("/dev/property", O_RDWR);

    if (fd < 0) {
        PRINTF_CRITICAL("Failed to open property device: %s", strerror(errno));
        return -1;
    }

    prop.property_id = id;
    ret = ioctl(fd, DCF_IOC_GET_PROPERTY, &prop);

    if (ret < 0) {
        PRINTF_CRITICAL("Failed to get ota-lib property: %s", strerror(errno));
        close(fd);
        return -1;
    }

    PRINTF_INFO("read ota lib property = 0x%x\n",  prop.property_value);
    close(fd);
    return (int)(prop.property_value);
}

static int set_ota_lib_property(int id,  int value)
{
    struct dcf_ioc_setproperty prop;
    int ret = -1;
    int fd = -1;

    fd = open("/dev/property", O_RDWR);

    if (fd < 0) {
        PRINTF_CRITICAL("Failed to open property device: %s", strerror(errno));
        return -1;
    }

    prop.property_id = id;
    prop.property_value = value;
    ret = ioctl(fd, DCF_IOC_SET_PROPERTY, &prop);

    if (ret < 0) {
        PRINTF_CRITICAL("Failed to set ota-lib property: %s", strerror(errno));
        close(fd);
        return -1;
    }

    PRINTF_INFO("set ota lib property = 0x%x\n",  prop.property_value);
    close(fd);
    return 0;
}

static void set_ota_lib_handshake_property(bool val)
{
    int ret = 0;
    ret = get_ota_lib_property(DMP_ID_OTA_STATUS);

    if (-1 == ret) {
        PRINTF_CRITICAL("Failed to get handshake property\n");
        return;
    }

    if (val) {
        ret |= (1 << PROPERTY_HANDSHAKE_BIT);
    }
    else {
        ret &= (~(1 << PROPERTY_HANDSHAKE_BIT));
    }

    PRINTF_INFO("handshake property set to 0x%x\n", ret);

    if (0 != set_ota_lib_property(DMP_ID_OTA_STATUS, ret)) {
        PRINTF_CRITICAL("Failed to set handshake property\n");
    }

    return;
}

static int get_ota_lib_handshake_property(bool *val)
{
    int ret = 0;
    ret = get_ota_lib_property(DMP_ID_OTA_STATUS);

    if (-1 == ret) {
        PRINTF_CRITICAL("Failed to get handshake property\n");
        return -1;
    }

    if (ret & ((1 << PROPERTY_HANDSHAKE_BIT) & 0xFFFFFFFF)) {
        *val = true;
    }
    else {
        *val = false;
    }

    PRINTF_INFO("get handshake property %d\n", *val);
    return 0;
}

static bool is_handshake_need()
{
    bool handshake_property = true;

    if (chipA_chipB_handshake && (ota_cmd == OTA_LIB_CMD_ENABLE_HANDSHAKE)) {
        if (local_handshake_status == HANDSHAKE_OK) {
            PRINTF_INFO("already handshake\n");
            return false;
        }
        else {
            if (0 == get_ota_lib_handshake_property(&handshake_property)) {
                PRINTF_INFO("handshake property is %d\n", handshake_property);
                return !handshake_property;
            }

            return true;
        }
    }

    return false;
}

static sub_chip_e get_sub_chip(void)
{
    return sub_chip;
}

int handshake_with_other_chip(int timeout_s)
{
    int ret = -1;
    sub_chip_e subchip = SUB_CHIP_ERROR;
    PRINTF_INFO("check handshake\n");

    if (is_handshake_need()) {
        PRINTF_INFO("need to handshake\n");
        subchip = get_sub_chip();

        switch (subchip) {
            case SUB_CHIP_A:
                PRINTF_INFO("subchip is side A\n");

                if (tcp_listen()) {
                    PRINTF_CRITICAL("tcp listen error\n");
                }
                else {
                    tcp_poll_enable();
                    local_handshake_status = get_handshake_status(timeout_s);

                    if (HANDSHAKE_OK == local_handshake_status) {
                        PRINTF_INFO("handshake ok\n");
                        set_ota_lib_handshake_property(true);
                        ret = 0;
                    }
                    else {
                        PRINTF_INFO("wait handshake error\n");
                    }

                    wait_ms(500);
                    close_listen();
                    tcp_poll_disable();
                }

                return ret;

            case SUB_CHIP_B:
                PRINTF_INFO("subchip is side B\n");

                if (tcp_client_init(timeout_s)) {
                    PRINTF_CRITICAL("tcp client init error\n");
                }
                else {
                    tcp_poll_enable();

                    if (0 == client_handshake_to_server()) {
                        PRINTF_INFO("handshake ok\n");
                        local_handshake_status = HANDSHAKE_OK;
                        set_ota_lib_handshake_property(true);
                        ret = 0;
                    }
                    else {
                        PRINTF_INFO("client handshake error\n");
                    }
                }

                close_client();
                tcp_poll_disable();
                return ret;

            default:
                PRINTF_INFO("subchip error\n");
                return 0;
        }
    }
    else {
        PRINTF_INFO("do not need handshake\n");
        return 0;
    }

}

#if CHECK_CMDLINE_MODE
#if RUN_IN_ANDROID && (RUN_IN_HOST == 0)
static int get_cmdline_in_android(const char *property, char *value)
{
    unsigned i = 0;

    if (!property || !value) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    property_get(property, value, "N/A");
#if DEBUGMODE > 1
    PRINTF_INFO("[%s]=[%s]\n", property, value);
#endif
    return 0;
}
#else

static int get_cmdline_in_linux(const char *target_cmd, char *value, int len)
{
    FILE *fp;
    int limit = MAX_CMD_FIND_LIMIT;

#ifndef RUN_IN_QNX
    const char *cmdline = "/proc/cmdline";
#else
    const char *cmdline = "/dev/scmdline";
#endif

    fp = fopen(cmdline, "r");

    if (!target_cmd || !value) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if (fp == NULL) {
        PRINTF_CRITICAL("open %s error %s\n", cmdline, strerror(errno));
        return -1;
    }

    fseek(fp, 0, SEEK_SET);

    do {
        memset(value, 0, len);

        if (fscanf(fp, CMD_SCAN_FORMAT, value) < 0) {
            PRINTF_INFO("scan cmdline over, can not find %s\n", target_cmd);
            fclose(fp);
            return -1;
        }

        //PRINTF_INFO("value = %s\n", value);
        if ((strlen(value) > strlen(target_cmd))
                && !strncmp(value, target_cmd, strlen(target_cmd))) {
#if DEBUGMODE > 1
            PRINTF_INFO("find value [%s]\n", value);
#endif
            fclose(fp);
            return 0;
        }

    }
    while (limit--);

    fclose(fp);
    PRINTF_INFO("can not find %s\n", target_cmd);
    return -1;
}
#endif

static void get_system_para_from_cmdline(bool *safety_um, bool *secure_um,
        bool *chipA_chipB_handshake,
        sub_chip_e *sub_chip, ota_lib_cmd_e *ota_cmd)
{
#if RUN_IN_ANDROID && (RUN_IN_HOST == 0)
    char value[PROPERTY_VALUE_MAX] = {'\0'};

    if (safety_um
            && !get_cmdline_in_android(SAFETY_UPDATE_MONITOR_CMDLINE_ANDROID, value) &&
            !strcmp(value, "0")) {
        *safety_um = false;
    }

    memset(value, 0, PROPERTY_VALUE_MAX);

    if (secure_um
            && !get_cmdline_in_android(SECURE_UPDATE_MONITOR_CMDLINE_ANDROID, value) &&
            !strcmp(value, "1")) {
        *secure_um = true;
    }

    memset(value, 0, PROPERTY_VALUE_MAX);

    if (chipA_chipB_handshake
            && !get_cmdline_in_android(CHIPVERSION_CMDLINE_ANDROID, value) &&
            (strstr(value, "x9_ultra") || strstr(value, "X9_ULTRA") || strstr(value, "X9CC"))) {
        *chipA_chipB_handshake = true;
    }

    if (sub_chip
            && !get_cmdline_in_android(SUBCHIP_CMDLINE_ANDROID, value)) {

        if (strstr(value, "SIDE_A") || strstr(value, "side_a")) {
            *sub_chip = SUB_CHIP_A;
        }
        else if (strstr(value, "SIDE_B") || strstr(value, "side_b")) {
            *sub_chip = SUB_CHIP_B;
        }
    }

    if (ota_cmd && !get_cmdline_in_android(OTA_CMD_ANDROID, value)
            && (strstr(value, "1"))) {
        *ota_cmd = OTA_LIB_CMD_ENABLE_HANDSHAKE;
    }

#else
    char value[MAX_CMD_LEN] = {'\0'};

    if (safety_um
            && !get_cmdline_in_linux(SAFETY_UPDATE_MONITOR_CMDLINE_LINUX, value,
                                     MAX_CMD_LEN) &&
            !strcmp(value, "safety_updatemonitor=0")) {
        *safety_um = false;
    }

    memset(value, 0, MAX_CMD_LEN);

    if (secure_um
            && !get_cmdline_in_linux(SECURE_UPDATE_MONITOR_CMDLINE_LINUX, value,
                                     MAX_CMD_LEN) &&
            !strcmp(value, "secure_updatemonitor=1")) {
        *secure_um = true;
    }

    memset(value, 0, MAX_CMD_LEN);

    if (chipA_chipB_handshake
            && !get_cmdline_in_linux(CHIPVERSION_CMDLINE_LINUX, value, MAX_CMD_LEN) &&
            (strstr(value, "x9_ultra") || strstr(value, "X9_ULTRA") || strstr(value, "X9CC"))) {
        *chipA_chipB_handshake = true;
    }

    if (sub_chip
            && !get_cmdline_in_linux(SUBCHIP_CMDLINE_LINUX, value, MAX_CMD_LEN)) {

        if (strstr(value, "SIDE_A") || strstr(value, "side_a")) {
            *sub_chip = SUB_CHIP_A;
        }
        else if (strstr(value, "SIDE_B") || strstr(value, "side_b")) {
            *sub_chip = SUB_CHIP_B;
        }
    }

    if (ota_cmd && !get_cmdline_in_linux(OTA_CMD_LINUX, value, MAX_CMD_LEN)
            && (strstr(value, "ota_cmd=1"))) {
        *ota_cmd = OTA_LIB_CMD_ENABLE_HANDSHAKE;
    }

#endif
}
#endif

static void check_system_para(bool *safety_um, bool *secure_um,
                              bool *chipA_chipB_handshake,
                              sub_chip_e *sub_chip, ota_lib_cmd_e *ota_cmd)
{
#ifdef FORCE_SAFETY_UM_CHECK
    *safety_um = FORCE_SAFETY_UM_CHECK;
    PRINTF_INFO("force set safety update moniotr is %d\n", (int)*safety_um);
#else
    PRINTF_INFO("safety update moniotr is %d\n", (int)*safety_um);
#endif

#ifdef FORCE_SECURE_UMCHECK
    *secure_um = FORCE_SECURE_UMCHECK;
    PRINTF_INFO("force set secure update moniotr is %d\n", (int)*secure_um);
#else
    PRINTF_INFO("secure update moniotr is %d\n", (int)*secure_um);
#endif

#ifdef FORCE_CHIPA_CHIPB_HANDSHAKE
    *chipA_chipB_handshake = FORCE_CHIPA_CHIPB_HANDSHAKE;
    PRINTF_INFO("force set chipA chipB handshake is %d\n",
                (int)*chipA_chipB_handshake);
#else
    PRINTF_INFO("chipA chipB handshake is %d\n", (int)*chipA_chipB_handshake);
#endif

#ifdef FORCE_SUB_CHIP
    *sub_chip = FORCE_SUB_CHIP;
    PRINTF_INFO("force set sub chip is %d\n", (int)*sub_chip);
#else
    PRINTF_INFO("sub chip is %d\n", (int)*sub_chip);
#endif

#ifdef FORCE_OTA_CMD
    *ota_cmd = FORCE_OTA_CMD;
    PRINTF_INFO("force ota cmd is %d\n", (int)*ota_cmd);
#else
    PRINTF_INFO("ota cmd is %d\n", (int)*ota_cmd);
#endif
}

/**
 * @brief Activate an update device with the specified sub-partition device name and storage device name
 *
 * This function activates an update device with the specified sub-partition device name and storage device name.
 * It first checks if the base update device and storage device are valid. If not, it returns -1.
 * Then it checks if the sub-partition device name and storage device name are valid. If not, it returns -1.
 * Next, it gets an empty level 2 update device and checks if it is available. If not, it returns -1.
 * If the storage device name contains "ap1" or "ap2", it skips the update and returns 0.
 * Otherwise, it clears the old mapped storage and sets up a new mapped storage.
 * Finally, it activates the mapped update device and returns 0.
 *
 * @param base_update_device A pointer to the base update device
 * @param level2_update_name The name of the sub-partition device
 * @param level2_storage_name The name of the storage device
 * @return int If the update device is successfully activated, return 0; otherwise, return -1
 */
static int active_update_device(update_device_t *base_update_device,
                                char *level2_update_name, \
                                char *level2_storage_name, bool run_in_ap2)
{
    update_device_t *new_update_device = NULL;
    storage_device_t *new_mapped_storage = NULL;
    storage_device_t *base_storage = base_update_device->storage;

    if (!base_update_device || !base_storage) {
        PRINTF_CRITICAL("base_update_device or base_storage error\n");
        return -1;
    }

    if (!level2_update_name || !level2_storage_name) {
        PRINTF_CRITICAL("para error update name: [%s], storage name: [%s]\n",
                        level2_update_name, level2_storage_name);
        return -1;
    }

    new_update_device = get_empty_level2_update_device();

    if (!new_update_device) {
        PRINTF_CRITICAL("no space left for update name: [%s], storage name: [%s]\n",
                        level2_update_name, level2_storage_name);
        return -1;
    }

    if (run_in_ap2) {
        /* skip ap2 */
        if (strstr(level2_storage_name, "ap2")) {
            PRINTF_INFO("skip update name: [%s], storage name: [%s]\n",
                        level2_update_name, level2_storage_name);
            return 0;
        }
    }
    else {
        /* skip ap1 */
        if (strstr(level2_storage_name, "ap1")) {
            PRINTF_INFO("skip update name: [%s], storage name: [%s]\n",
                        level2_update_name, level2_storage_name);
            return 0;
        }
    }

    /* clear old mapped storage */
    if (new_update_device->mapped_storage) {
        free(new_update_device->mapped_storage);
        new_update_device->mapped_storage = NULL;
    }

    new_mapped_storage = (storage_device_t *)CALLOC(1, sizeof(storage_device_t));

    if (!new_mapped_storage) {
        PRINTF_CRITICAL("fail to setup mapped storage, ptdev [%s] storage name [%s]\n",
                        level2_update_name, level2_storage_name);
        return -1;
    }

    /* new mapped device */
    memset(new_mapped_storage, 0, sizeof(storage_device_t));
    snprintf(new_mapped_storage->dev_name, STORAGE_NAME_LEN, "%s",
             level2_storage_name);
    new_mapped_storage->type = base_storage->type;
    new_mapped_storage->dev_fd = -1;
    new_mapped_storage->init = NULL;
    new_mapped_storage->cnt = 0;
    new_mapped_storage->mapped = true;
    new_mapped_storage->use_shared_memory = false;
    new_mapped_storage->memfd = -1;
    new_mapped_storage->shared_mem_ptr = MAP_FAILED;


    /* active a mapped update device */
    memset(new_update_device->name, 0, UPDATE_DEV_NAME_LEN);
    snprintf(new_update_device->name, UPDATE_DEV_NAME_LEN, "%s",
             level2_update_name);
    new_update_device->gpt_offset   = 0;
    new_update_device->ptdev        = NULL;
    new_update_device->storage      = base_storage;
    new_update_device->syscall_head = NULL;
    new_update_device->init = false;
    new_update_device->is_sub_ptdev = true;
    new_update_device->mapped_storage = new_mapped_storage;
    new_update_device->active = true;
    PRINTF_INFO("fine new ptdev [%s] storage name [%s]\n",
                level2_update_name, level2_storage_name);

    return 0;
}

/**
 * @brief The purpose of this function is to parse the boot info
 * string to extract the boot mode and sub-partition device name (if any).
 * The function accepts several input parameters, including the boot info string,
 * the base name of the storage device, a pointer to the update monitor mode variable,
 * a pointer to the integer variable used to store the number of sub-partition devices found,
 * and two two-dimensional character arrays.The function extracts the boot mode and
 * sub-partition device name by parsing the boot info string and stores them in the output
 * parameters.If the boot info string is successfully parsed and the output parameters are set,
 * the function returns 0; otherwise, it returns -1.
 *
 * @param boot_info The boot info string
 * @param base_name The base name of the storage device
 * @param mode A pointer to the update monitor mode variable
 * @param sub_ptdev_num A pointer to the integer variable used to store the number
 * of sub-partition devices found
 * @param level2_update_name A two-dimensional character array used to store the names
 * of the sub-partition devices found
 * @param level2_storage_name A two-dimensional character array used to store the storage
 * device names of the sub-partition devices found
 * @return int If the boot info string is successfully parsed and the output parameters are
 * set, return 0; otherwise, return -1
 */
static int parse_boot_info(char *boot_info, char *base_name, \
                           update_monitor_mode_e *mode, int *sub_ptdev_num, \
                           char (*level2_update_name)[UPDATE_DEV_NAME_LEN], \
                           char (*level2_storage_name)[UPDATE_DEV_NAME_LEN])
{
    char *temp = NULL;
    char sub_ptdev_name[UPDATE_DEV_NAME_LEN] = {0};
    char prefix_name[UPDATE_DEV_NAME_LEN] = {0};
    int limit = MAX_LEVEL2_UPDATE_DEV;
    int tmp_num = 0;
    int tmp_mode = MODE_NEED_UPDATE;

    if (!boot_info || !strlen(boot_info) || !base_name  || !strlen(base_name)) {
        PRINTF_CRITICAL("boot info %s or base_name %s is Null or empty\n", boot_info,
                        base_name);
        return -1;
    }

    snprintf(prefix_name, UPDATE_DEV_NAME_LEN, "%s%s", base_name, "_");

    /* scan for boot mode */
    temp = strstr(boot_info, BOOT_INFO_PREFIX);

    if (!temp) {
        PRINTF_CRITICAL("boot info %s format error, expect %s in it\n", boot_info,
                        BOOT_INFO_PREFIX);
        return -1;
    }

    if (1 != sscanf(temp, BOOT_INFO_PREFIX_SCAN, &tmp_mode)) {
        PRINTF_CRITICAL("scan for BOOT MODE error, boot info %s\n", boot_info);
        return -1;
    }

    if (strstr(base_name, BASE_DEV_NAME_MMC)) {
        /* scan for sub-ptdev */
        temp = strstr(temp, LEVEL2_PTDEV_PREFIX);

        if (temp) {
            do {
                if (1 != sscanf(temp, LEVEL2_PTDEV_PREFIX_SCAN, sub_ptdev_name)) {
                    break;
                }

                /* base name is mmc1_*/
                if (strlen(sub_ptdev_name) <= strlen(prefix_name) || \
                        strncmp(prefix_name, sub_ptdev_name, strlen(prefix_name))) {
                    PRINTF_CRITICAL("prefix_name %s , sub_ptdev_name %s error\n", prefix_name,
                                    sub_ptdev_name);
                    break;
                }
                else {
                    memset((char *)level2_update_name[tmp_num], 0, UPDATE_DEV_NAME_LEN);
                    memset((char *)level2_storage_name[tmp_num], 0, UPDATE_DEV_NAME_LEN);
                    strcpy((char *)level2_update_name[tmp_num], sub_ptdev_name);
                    strcpy((char *)level2_storage_name[tmp_num],
                           sub_ptdev_name + strlen(prefix_name));
                    PRINTF_INFO("upate_name [%s] \n", (char *)level2_update_name[tmp_num]);
                    PRINTF_INFO("storage_name [%s] \n", (char *)level2_storage_name[tmp_num]);
                    tmp_num++ ;
                }

                temp = strstr(temp + strlen(LEVEL2_PTDEV_PREFIX), LEVEL2_PTDEV_PREFIX);

                if (!temp || (tmp_num > MAX_LEVEL2_UPDATE_DEV)) {
                    break;
                }
            }
            while (limit--);

            /* get symble "-SUB_PTDEV=", but do not have any parament */
            if (0 == sub_ptdev_num) {
                PRINTF_CRITICAL("get symble '-SUB_PTDEV=', but do not have any parament\n");
                return -1;
            }
        }
    }

    *mode = tmp_mode;
    *sub_ptdev_num = tmp_num;
    return 0;
}

bool is_run_in_ap2()
{

#if RUN_IN_ANDROID
#if !RUN_IN_HOST
    char value[PROPERTY_VALUE_MAX] = {'\0'};

    if (!get_cmdline_in_android(DOMAIN_INFO_CMDLINE_ANDROID, value)
            && (!strcmp(value, "AP2") || !strcmp(value, "CLUSTER"))) {
        PRINTF_INFO("get cmdline domain=AP2\n");
        return true;
    }

    return false;
#else
    return false;
#endif
#else
    char value[MAX_CMD_LEN] = {'\0'};

    if (!get_cmdline_in_linux(DOMAIN_INFO_CMDLINE_LINUX, value, MAX_CMD_LEN) &&
            (!strcmp(value, "domain=AP2") || !strcmp(value, "domain=CLUSTER"))) {
        PRINTF_INFO("get cmdline domain=AP2\n");
        return true;
    }

    return false;
#endif
}


static int update_device_self_check(void)
{
    static bool safety_self_check = false;
    static bool secure_self_check = false;
    static bool init_job = false;
    bool run_in_ap2 = false;
    static int cnt = 0;
    int i = 0;
    storage_device_t *storage = NULL;
    char boot_info_safety[MAX_DATA_LENGTH]   = {0};
    char boot_info_security[MAX_DATA_LENGTH] = {0};
    update_monitor_mode_e um_mode[UM_CHECK_MAX] = {MODE_NEED_UPDATE};
    int sub_ptdev_num[UM_CHECK_MAX] = {0};
    char level2_update_name[MAX_LEVEL2_UPDATE_DEV][UPDATE_DEV_NAME_LEN];
    char level2_storage_name[MAX_LEVEL2_UPDATE_DEV][UPDATE_DEV_NAME_LEN];

    //assume that there is at least one update device
    assert(DEV_MAX >= 1);
    assert(DEV_MAX == update_dev_max);
    assert(DEV_MAX == MAX_LEVEL2_UPDATE_DEV + MAX_BASE_UPDATE_DEV);

    if ((true == safety_self_check) && (true == secure_self_check)
            && (true == init_job)) {
        return 0;
    }

    KEYNODE("update_device self check start, cnt=%d, saf=%d, sec=%d, init_job=%d\n",
            cnt++, safety_self_check, secure_self_check, init_job);

    if (!init_job) {
        init_job = true;
#if CHECK_CMDLINE_MODE
        get_system_para_from_cmdline(&safety_um, &secure_um, &chipA_chipB_handshake,
                                     &sub_chip, &ota_cmd);
#endif
        check_system_para(&safety_um, &secure_um, &chipA_chipB_handshake, &sub_chip,
                          &ota_cmd);
#if !RUN_IN_ANDROID && SUPPORT_PROPERTY_LIB
        sdrv_property_init();
#endif
    }

    /* 1. Check safety update mornitor, check [update skip mode] such
    as emmc only boot. If [update skip mode]  is used , then we do not
    need to update norflash through "update monitor service".
    In [update skip mode] " update monitor service" only carry out partial
    operations, such as turning off the watchdog or ospi handover. so we
    make safety inactive.
    */
    if (!safety_self_check) {
        for (i = 0; i < DEV_MAX; i++) {
            if (update_device_list[i].active != true) {
                continue;
            }

            storage = update_device_list[i].storage;
            assert(storage);

            if (!strcmp(storage->dev_name, MONITOR_CHANNEL_SAFETY)) {
                if (safety_um == false) {
                    update_device_list[i].active = false;
                    PRINTF_INFO("force set [safety %s] inactive\n", MONITOR_CHANNEL_SAFETY);
                    safety_self_check = true;
                    break;
                }

                update_device_list[i].active = true;

                if (init_storage(storage, NULL)) {
                    PRINTF_CRITICAL("init storage for [safety %s] error\n", MONITOR_CHANNEL_SAFETY);
                    break;
                }

                if (0 != remote_get_boot_info(storage, boot_info_safety)) {
                    PRINTF_CRITICAL("get boot info for [safety %s] error\n",
                                    MONITOR_CHANNEL_SAFETY);
                    break;
                }

                if (0 != parse_boot_info(boot_info_safety, BASE_DEV_NAME_OSPI,
                                         &um_mode[SAFETY_CHECK], \
                                         &sub_ptdev_num[SAFETY_CHECK], level2_update_name, level2_storage_name)) {
                    PRINTF_CRITICAL("parse for [safety %s] error\n", MONITOR_CHANNEL_SAFETY);
                    break;
                }

                if (MODE_SKIP_UPDATE == um_mode[SAFETY_CHECK]) {
                    update_device_list[i].active = false;
                    PRINTF_INFO("set for [safety %s] inactive by um msg\n", MONITOR_CHANNEL_SAFETY);
                }

                PRINTF_INFO("safety boot info [%s]\n", boot_info_safety);
                safety_self_check = true;
                break;
            }
        }
    }

    /* 2. Check ssystem update mornitor: first check whether there is an
    update monitor in security. If have, it proves that the current boot method is
    vmmc boot. Scan the secondary partition at this time and add these secondary
    partitions to the update device list. */
    if (!secure_self_check) {
        for (i = 0; i < DEV_MAX; i++) {
            storage = update_device_list[i].storage;
            assert(storage);

            if (storage && !strcmp(storage->dev_name, MONITOR_CHANNEL_SECURE)) {
                if (secure_um == false) {
                    update_device_list[i].active = false;
                    PRINTF_INFO("force set [secure %s] inactive\n", MONITOR_CHANNEL_SECURE);
                    secure_self_check = true;
                    break;
                }

                update_device_list[i].active = true;

                if (init_storage(storage, NULL)) {
                    PRINTF_CRITICAL("init storage for [security %s] error\n",
                                    MONITOR_CHANNEL_SECURE);
                    break;
                }

                if (0 != remote_get_boot_info(storage, boot_info_security)) {
                    PRINTF_CRITICAL("init storage for [security %s] error\n",
                                    MONITOR_CHANNEL_SECURE);
                    break;
                }

                if (0 != parse_boot_info(boot_info_security, BASE_DEV_NAME_MMC,
                                         &um_mode[SECURITY_CHECK], \
                                         &sub_ptdev_num[SECURITY_CHECK], level2_update_name, level2_storage_name)) {
                    PRINTF_CRITICAL("parse for [security %s] error\n", MONITOR_CHANNEL_SECURE);
                    break;
                }

#if RUN_IN_AP2
                run_in_ap2 = true;
#else
                run_in_ap2 = is_run_in_ap2();
#endif

                if (MODE_SKIP_UPDATE != um_mode[SECURITY_CHECK]) {
                    if ((sub_ptdev_num[SECURITY_CHECK] > 0 && \
                            (sub_ptdev_num[SECURITY_CHECK] < MAX_LEVEL2_UPDATE_DEV))) {
                        for (int j = 0; j < sub_ptdev_num[SECURITY_CHECK]; j++) {
                            active_update_device(&update_device_list[i], (char *)level2_update_name[j],
                                                 (char *)level2_storage_name[j], run_in_ap2);
                        }
                    }
                }
                else {
                    update_device_list[i].active = false;
                    PRINTF_INFO("set for [secure %s] inactive by um msg\n", MONITOR_CHANNEL_SECURE);
                }

                PRINTF_INFO("security boot info [%s]\n", boot_info_security);
                secure_self_check = true;
                break;
            }
        }
    }

    KEYNODE("update_device self check end\n");
    return 0;
}

void stop_safety_wdt(void)
{
#if !FORCE_SKIP_WDT_CHECK && !RUN_IN_AP2
    static bool stop = false;
    int i = 0;
    storage_device_t *storage = NULL;
    if(!is_run_in_ap2()) {
        if (true == stop)
            return;

        stop = true;

        for (i = 0; i < DEV_MAX; i++) {
            storage = get_update_device_storage(i);

            if (storage && !strcmp(storage->dev_name, MONITOR_CHANNEL_SAFETY)) {
                if (init_storage(storage, NULL)) {
                    PRINTF_CRITICAL("init storage failed when disable safety wdt\n");
                    break;
                }

                if (0 != remote_stop_wdt(storage)) {
                    PRINTF_CRITICAL("disable safety wdt failed\n");
                    uninit_storage(storage);
                    break;
                }

                PRINTF_INFO("stop safety wdt success\n")
                uninit_storage(storage);
                break;
            }
        }
    }
#endif
    return;
}

void holdup_ap2(void)
{
#if !RUN_IN_AP2
    static bool holdup = false;
    int i = 0;
    storage_device_t *storage = NULL;
    if(!is_run_in_ap2()) {
        if (true == holdup)
            return;

        holdup = true;

        for (i = 0; i < DEV_MAX; i++) {
            storage = get_update_device_storage(i);

            if (storage && !strcmp(storage->dev_name, MONITOR_CHANNEL_SECURE)) {
                if (init_storage(storage, NULL)) {
                    PRINTF_CRITICAL("init storage failed when holdup ap2\n");
                    break;
                }

                if (0 != remote_holdup_ap2(storage)) {
                    PRINTF_CRITICAL("holdup ap2 failed\n");
                    uninit_storage(storage);
                    break;
                }

                PRINTF_INFO("holdup ap2 success\n")
                uninit_storage(storage);
                break;
            }
        }
    }
#endif
    return;
}

int check_mpc_status(void)
{
    storage_device_t *storage = &mp_update_monitor;

    if (remote_init(storage)) {
        PRINTF_CRITICAL("init mp update monitor failed\n");
        return -1;
    }

    PRINTF_INFO("check mp status ok\n");

    return 0;
}

update_device_t *setup_update_dev(storage_id_e dev)
{
    storage_device_t *storage = NULL;
    storage_device_t *mapped_storage = NULL;
    update_device_self_check();
    update_device_t *device = get_update_device(dev);

    if (!device) {
        PRINTF_CRITICAL("can't find update device id = %d\n", dev);
        return NULL;
    }

    if (strlen(device->name)) {
        KEYNODE("setup_update_dev for %s\n", device->name);
    }

    if (dev >= DEV_MAX) {
        PRINTF_CRITICAL("bad storage index %d\n", dev);
        KEYNODE("setup_update_dev for %s failed\n", device->name);
        return NULL;
    }

    if (device->active != true) {
        if (strlen(device->name)) {
            PRINTF_INFO("%s is not active\n", device->name);
        }

        return NULL;
    }

    if (device->init == true) {
        goto end;
    }

    storage = device->storage;
    mapped_storage = device->mapped_storage;

    if (init_storage(storage, NULL)) {
        PRINTF_CRITICAL("init storage error\n");
        KEYNODE("setup_update_dev for %s failed\n", device->name);
        return NULL;
    }

    if (get_update_device_is_sub_dev(dev)) {
        if (init_storage(mapped_storage, storage)) {
            PRINTF_CRITICAL("init mapped_ torage error\n");
            KEYNODE("setup_update_dev for %s failed\n", device->name);
            return NULL;
        }
    }

    device->init = true;

end:
    KEYNODE("setup_update_dev for %s success\n", device->name);
    return device;
}

unsigned int destroy_update_dev(storage_id_e dev)
{

    update_device_t *device = get_update_device(dev);

    if (!device) {
        PRINTF_CRITICAL("can't find update device id = %d\n", dev);
        return -1;
    }

    device->init = false;

    if (uninit_storage(device->storage)) {
        PRINTF_CRITICAL("destroy storage error\n");
        return -1;
    }

    return 0;
}

static bool is_global_uniform_rollback_set(void)
{
    if (wait_for_property(3, GLOBAL_UNIFORM_ROLLBACK_PROPERTY, GLOBAL_UNIFORM_ROLLBACK_OFF, 3*SLEEP_TIME_INTERVAL) == 1) {
        PRINTF_INFO("ur: global uniform rollback is not set\n");
        return false;
    }
    else {
        PRINTF_INFO("ur: global uniform rollback is set\n");
        return true;
    }
}

bool is_local_uniform_rollback_need_set(void)
{
    if (chipA_chipB_handshake && is_global_uniform_rollback_set()) {
        PRINTF_INFO("ur: local uniform rollback need set\n");
        return true;
    }
    else {
        PRINTF_INFO("ur: local uniform rollback do not need set\n");
        return false;
    }
}

bool is_uniform_rollback_need(void)
{
    return (chipA_chipB_handshake && !is_run_in_ap2());
}

void set_local_uniform_rollback(char *property_value)
{
    property_set(LOCAL_UNIFORM_ROLLBACK_PROPERTY, property_value);
    PRINTF_INFO("ur: set local uniform rollback: %s\n", property_value);
}

void set_global_uniform_rollback(char *property_value)
{
    property_set(GLOBAL_UNIFORM_ROLLBACK_PROPERTY, property_value);
    PRINTF_INFO("ur: set global uniform rollback: %s\n", property_value);
}

void set_ota_status_property(const char* property_value)
{
    sub_chip_e subchip = SUB_CHIP_ERROR;
    subchip = get_sub_chip();

    switch (subchip) {
        case SUB_CHIP_A:
            property_set(PROPERTY_OTA_STATUS_SIDE_A, property_value);
            break;

        case SUB_CHIP_B:
            property_set(PROPERTY_OTA_STATUS_SIDE_B, property_value);
            break;

        default:
            break;
    }
    PRINTF_INFO("ur: set ota status property: %s\n", property_value);
}

void set_skip_uniform_rollback_value(int value)
{
    if(value == DO_NOT_SKIP_UNIFORM_ROLLBACK) {
        property_set(PROPERTY_SKIP_UNIFORM_ROLLBACK, "0");
    }
    else {
        property_set(PROPERTY_SKIP_UNIFORM_ROLLBACK, "1");
    }
    skip_uniform_rollback = value;
    PRINTF_INFO("ur: set skip uniform rollback property: %d\n", value);
}

bool is_skip_uniform_rollback_need(void)
{
    if(skip_uniform_rollback == SKIP_UNIFORM_ROLLBACK) {
        return SKIP_UNIFORM_ROLLBACK;
    }
    else{
        char property_value[OTA_LIB_PROPERTY_MAX_LEN] = {'\0'};
        property_get(PROPERTY_SKIP_UNIFORM_ROLLBACK, property_value, "N/A");
        if (!strcmp((char *)property_value, "1")) {
            return SKIP_UNIFORM_ROLLBACK;
        }
        else {
            return DO_NOT_SKIP_UNIFORM_ROLLBACK;
        }
    }
}

static int __wait_for_property(const int para_cnt, const char* property_name, const int wait_type, va_list args)
{
    int ret;
    int timeout_us;
    char **property_value_expect;
    char property_value[OTA_LIB_PROPERTY_MAX_LEN] = {'\0'};
    int expect_property_cnt = para_cnt - 1;

    property_value_expect = (char **)CALLOC(expect_property_cnt, sizeof(char*));
    if (!property_value_expect) {
        PRINTF_CRITICAL("fail to calloc memory\n");
        return -1;
    }

    for (int i = 0; i < expect_property_cnt; i++) {
        property_value_expect[i] = va_arg(args, char*);
    }
    timeout_us = va_arg(args, int);

    while(1)
    {
        memset(property_value, 0, OTA_LIB_PROPERTY_MAX_LEN);
        property_get(property_name, property_value, "N/A");
        PRINTF_INFO("property_name:%s, property_value:%s, timeout_us:%d\n", property_name, property_value, timeout_us);
        for(int i = 0; i < expect_property_cnt; i++)
        {
            PRINTF_INFO("property_value_expect[%d]:%s\n", i, property_value_expect[i]);
            if (!strcmp((char *)property_value, property_value_expect[i])) {
                ret = 1;
                goto end;
            }
        }

        if ((wait_type == WAIT_TYPE_NOT_NA) && strcmp((char *)property_value, "N/A")) {
            ret = 0;
            goto end;
        }

        if(timeout_us != WAIT_FOR_PROPERTY_ALWAYS) {
            if(timeout_us - SLEEP_TIME_INTERVAL >= 0) {
                usleep(SLEEP_TIME_INTERVAL);
                timeout_us -= SLEEP_TIME_INTERVAL;
            }
            else {
                if (!strcmp((char *)property_value, "N/A")) {
                    ret = -1;
                    PRINTF_CRITICAL("wait for property timeout\n");
                    goto end;
                }
                else {
                    ret = 0;
                    goto end;
                }
            }
        }else {
            usleep(SLEEP_TIME_INTERVAL);
        }
    }

end:
    free(property_value_expect);
    return ret;
}

/*
 * wait until opposite ota status property is the expect value
 * para_cnt = n*property_value_expect + 1*timeout_us
 * ret 1 ok; ret 0 not ok; return -1 error
 * return until opposite ota status property is the expected value or timeout
 **/
int wait_for_opposite_ota_status_property(const int para_cnt, ...)
{
    int ret;
    sub_chip_e subchip = SUB_CHIP_ERROR;

    if(para_cnt < 2)
    {
        return -1;
    }

    va_list args;
    va_start(args, para_cnt);

    subchip = get_sub_chip();
    switch (subchip) {
        case SUB_CHIP_A:
            ret = __wait_for_property(para_cnt, PROPERTY_OTA_STATUS_SIDE_B, WAIT_TYPE_SOMEVALUE, args);
            break;

        case SUB_CHIP_B:
            ret = __wait_for_property(para_cnt, PROPERTY_OTA_STATUS_SIDE_A, WAIT_TYPE_SOMEVALUE, args);
            break;

        default:
            ret = -1;
            break;
    }

    va_end(args);

    return ret;
}

/*
 * wait until opposite ota status property is the expect value
 * para_cnt = 1*property_name + n*property_value_expect + 1*timeout_us
 * ret 1 ok; ret 0 not ok; return -1 error
 * return when the value is not "N/A" or timeout
 **/
int wait_for_property(const int para_cnt, ...)
{
    int ret;
    char *property_name;

    if(para_cnt < 3)
    {
        return -1;
    }

    va_list args;
    va_start(args, para_cnt);
    property_name = va_arg(args, char*);

    ret = __wait_for_property(para_cnt - 1, property_name, WAIT_TYPE_NOT_NA, args);

    va_end(args);

    return ret;
}



#define BOOT_IMAGE_EMMC_ANDROID     "ro.boot.boot_image_emmc"
#define BOOT_IMAGE_EMMC_LINUX       "boot_image_emmc="
#define BOOT_IMAGE_OSPI_ANDROID     "ro.boot.boot_image_ospi"
#define BOOT_IMAGE_OSPI_LINUX       "boot_image_ospi="

#define BPT_VERSION_PROP            "ro.boot.bpt.version"
#define BPT_VERSION_LINUX           "bpt.version="
#define FUSE_ROLLBACK_INDEX_PROP    "ro.boot.rollback_index"
#define FUSE_ROLLBACK_INDEX_LINUX   "rollback_index="

//boot_image_emmc=normal boot_image_emmc=backup
static int get_current_dil(const char* name)
{
#if RUN_IN_ANDROID && (RUN_IN_HOST == 0)
    char value[PROPERTY_VALUE_MAX] = {'\0'};

    if (get_cmdline_in_android(name, value)) {
        PRINTF_CRITICAL("get %s in android propery error\n", name);
        return -1;
    }

    if(!strcmp(value, "normal")) {
#if DEBUGMODE
        PRINTF_INFO("current dil:%s is normal\n", name);
#endif
        return SELECT_BOOT0; // run in normal so ota-target is boot1
    }
    else if(!strcmp(value, "backup")) {
#if DEBUGMODE
        PRINTF_CRITICAL("current dil:%s is backup\n", name);
#endif
        return SELECT_BOOT1; // run in backup so ota-target is boot0
    }

#else
    char value[MAX_CMD_LEN] = {'\0'};
    char normal[MAX_CMD_LEN] = {'\0'};
    char backup[MAX_CMD_LEN] = {'\0'};
    snprintf(normal, MAX_CMD_LEN, "%s%s", name, "normal");
    snprintf(backup, MAX_CMD_LEN, "%s%s", name, "backup");

    if (get_cmdline_in_linux(name, value, MAX_CMD_LEN)) {
        PRINTF_CRITICAL("get %s in cmd in linux or qux error\n", name);
        return -1;
    }

    if(!strcmp(value, normal)) {
#if DEBUGMODE
        PRINTF_INFO("current dil:%s is normal\n", name);
#endif
        return SELECT_BOOT0; // run in normal so ota-target is boot1
    }
    else if(!strcmp(value, backup)) {
#if DEBUGMODE
        PRINTF_CRITICAL("current dil:%s is backup\n", name);
#endif
        return SELECT_BOOT1; // run in backup so ota-target is boot0
    }

    PRINTF_CRITICAL("Error: dil prop key: %s\n", value);

#endif
    return -1;
}

int get_bpt_version(void)
{
#if RUN_IN_ANDROID && (RUN_IN_HOST == 0)
    uint32_t bpt_v = 0;
    char value[PROPERTY_VALUE_MAX] = {'\0'};

    if (get_cmdline_in_android(BPT_VERSION_PROP, value)) {
        PRINTF_CRITICAL("get %s in android propery error\n", BPT_VERSION_PROP);
        return -1;
    }
    bpt_v = strtoul(value, NULL, 16);
    return bpt_v;
#else
    char value[MAX_CMD_LEN] = {'\0'};

    if (get_cmdline_in_linux(BPT_VERSION_LINUX, value, MAX_CMD_LEN)) {
        PRINTF_CRITICAL("get %s in cmd in linux or qux error\n", BPT_VERSION_LINUX);
        return -1;
    }

    if(!strcmp(value, "bpt.version=0x42505402")) {
        return BPT_V2;
    }

    else if(!strcmp(value, "bpt.version=0x42505401")) {
        return BPT_V1;
    }

    else {
        PRINTF_CRITICAL("value is %s, find't find bpt version\n", BPT_VERSION_LINUX);
        return -1;
    }
#endif

}

int get_rollback_index(void)
{
#if RUN_IN_ANDROID && (RUN_IN_HOST == 0)
    uint32_t rollback_index = 0;
    char value[PROPERTY_VALUE_MAX] = {'\0'};
    char *token;
    char *delimiter = "=";

    if (get_cmdline_in_android(FUSE_ROLLBACK_INDEX_PROP, value)) {
        PRINTF_CRITICAL("get %s in android propery error\n", FUSE_ROLLBACK_INDEX_PROP);
        return -1;
    }
    rollback_index = strtoul(value, NULL, 10);
    PRINTF_INFO("get rollback_index=%d\n", rollback_index);
    return rollback_index;
#else
    char value[MAX_CMD_LEN] = {'\0'};
    char *token;
    char *delimiter = "=";
    char *saveptr;
    uint32_t rollback_index = 0;

    if (get_cmdline_in_linux(FUSE_ROLLBACK_INDEX_LINUX, value, MAX_CMD_LEN)) {
        PRINTF_CRITICAL("get %s in cmd in linux or qux error\n", FUSE_ROLLBACK_INDEX_LINUX);
        return -1;
    }
    token = strtok_r(value, delimiter, &saveptr);
    token = strtok_r(NULL, delimiter, &saveptr);
    if (token != NULL) {
        rollback_index = strtoul(token, NULL, 10);
        PRINTF_INFO("get rollback_index=%d\n", rollback_index);
    } else {
        PRINTF_CRITICAL("get rollback_index error\n");
        return -1;
    }
    return rollback_index;
#endif

}

int get_current_emmc_dil(void)
{
#if RUN_IN_ANDROID && (RUN_IN_HOST == 0)
    return get_current_dil(BOOT_IMAGE_EMMC_ANDROID);
#else
    return get_current_dil(BOOT_IMAGE_EMMC_LINUX);
#endif
}


int get_current_ospi_dil(void)
{
#if RUN_IN_ANDROID && (RUN_IN_HOST == 0)
    return get_current_dil(BOOT_IMAGE_OSPI_ANDROID);
#else
    return get_current_dil(BOOT_IMAGE_OSPI_LINUX);
#endif
}


bool is_emmc_boot0(const char * name)
{
    if(name) {
        for(int i = 0; i < BOOT_NAME_CNT; i++) {
            if(strcmp(emmc_boot0_name[i], name) == 0) {
                return true;
            }
        }
    }

    return false;
}

bool is_emmc_boot1(const char * name)
{
    if(name) {
        for(int i = 0; i < BOOT_NAME_CNT; i++) {
            if(strcmp(emmc_boot1_name[i], name) == 0) {
                return true;
            }
        }
    }

    return false;
}

bool is_ospi_boot0(const char * name)
{
    if(name
      && (strcmp(ospi_boot0_name, name) == 0)) {
        return true;
    }
    return false;
}

bool is_ospi_boot1(const char * name)
{
    if(name
      && (strcmp(ospi_boot1_name, name) == 0)) {
        return true;
    }
    return false;
}

/* return name if not found */
const char* transform_emmc_boot_partition_name_bptv1(const char * name)
{
    for(int i = 0; i < BOOT_UPDATE_CNT_V1; i++) {
        if(strstr(name, emmc_boot_name_v1[i]) == name) {
            if (i == 0){
                return emmc_boot0_name[0];
            }else if(i == 1){
                return emmc_boot1_name[0];
            }
        }
    }
    return name;
}

/* return name if not found
 * if name is "mmcboot", return "mmcblk0boot0" or "mmcblk0boot1" based on current boot slot.
 * */
const char* transform_emmc_boot_partition_name_bptv2(const char * name)
{
    int current_boot;
    int suffix;
    char boot0_full_name[MAX_GPT_NAME_SIZE + 4] = {0};
    char boot1_full_name[MAX_GPT_NAME_SIZE + 4] = {0};

    current_boot = get_current_emmc_dil();
    suffix = get_slot_suffix_info();

    /* It means non-AB system */
    if (suffix != SLOT_A && suffix != SLOT_B) {
        if (strstr(name, emmc_boot_name_v2[0].name) == name){
            if (current_boot == SELECT_BOOT0){
                return emmc_boot1_name[0];
            }
            else if (current_boot == SELECT_BOOT1) {
                return emmc_boot0_name[0];
            }
        }
        PRINTF_INFO("name is %s, emmc_boot_name_v2[0].name is %s\n", name, emmc_boot_name_v2[0].name);
        return name;
    }

    if (current_boot != SELECT_BOOT0 && current_boot != SELECT_BOOT1){
        PRINTF_INFO("current boot error\n");
        return name;
    }

    /* map boot name */
    if ((current_boot == SELECT_BOOT0 && suffix == SLOT_A)
            ||(current_boot == SELECT_BOOT1 && suffix == SLOT_B))
    {
        strncpy(emmc_boot_name_v2[0].suffix, "_a", 2);
        strncpy(emmc_boot_name_v2[1].suffix, "_b", 2);
    }
    else if ((current_boot == SELECT_BOOT0 && suffix == SLOT_B)
            ||(current_boot == SELECT_BOOT1 && suffix == SLOT_A)) {
        strncpy(emmc_boot_name_v2[0].suffix, "_b", 2);
        strncpy(emmc_boot_name_v2[1].suffix, "_a", 2);
    }
    else {
        PRINTF_CRITICAL("current_boot:%d suffix:%d\n", current_boot, suffix);
        assert(0);
    }

    strcat(boot0_full_name, emmc_boot_name_v2[0].name);
    strcat(boot0_full_name, emmc_boot_name_v2[0].suffix);
    strcat(boot1_full_name, emmc_boot_name_v2[1].name);
    strcat(boot1_full_name, emmc_boot_name_v2[1].suffix);

    if(strcmp(name, boot0_full_name) == 0) {
        return emmc_boot0_name[0];
    }
    else if(strcmp(name, boot1_full_name) == 0) {
        return emmc_boot1_name[1];
    }
    else {
        PRINTF_INFO("name is %s, boot0_full_name is %s,  boot1_full_name is %s\n", name, boot0_full_name, boot1_full_name);
    }

    return name;
}

/* return name if not found */
const char* transform_ospi_boot_partition_name_bptv1(const char * name)
{
    for(int i = 0; i < BOOT_UPDATE_CNT_V1; i++) {
        if(strstr(name, ospi_boot_name_v1[i]) == name) {
            if (i == 0){
                return ospi_boot0_name;
            }else if(i == 1){
                return ospi_boot1_name;
            }
        }
    }
    return name;
}

/* return name if not found
 * if name is "ospiboot", return "dil" or "dil_bak" based on current boot slot.
 * */
const char* transform_ospi_boot_partition_name_bptv2(const char * name)
{
    int current_boot;
    int suffix;
    char boot0_full_name[MAX_GPT_NAME_SIZE + 4] = {0};
    char boot1_full_name[MAX_GPT_NAME_SIZE + 4] = {0};

    current_boot = get_current_ospi_dil();
    suffix = get_slot_suffix_info();

    /* It means non-AB */
    if (suffix != SLOT_A && suffix != SLOT_B){
        if (strstr(name, ospi_boot_name_v2[0].name) == name){
            if (current_boot == SELECT_BOOT0) {
                return ospi_boot1_name;
            }
            else if (current_boot == SELECT_BOOT1) {
                return ospi_boot0_name;
            }
        }
        PRINTF_INFO("name is %s, emmc_boot_name_v2[0].name is %s\n", name, ospi_boot_name_v2[0].name);
        return name;
    }

    if (current_boot != SELECT_BOOT0 && current_boot != SELECT_BOOT1) {
        PRINTF_INFO("current boot error\n");
        return name;
    }

    /* map boot name */
    if ((current_boot == SELECT_BOOT0 && suffix == SLOT_A) ||
            (current_boot == SELECT_BOOT1 && suffix == SLOT_B))
    {
        strncpy(ospi_boot_name_v2[0].suffix, "_a", 2);
        strncpy(ospi_boot_name_v2[1].suffix, "_b", 2);
    }
    else if ((current_boot == SELECT_BOOT0 && suffix == SLOT_B) ||
            (current_boot == SELECT_BOOT1 && suffix == SLOT_A)) {
        strncpy(ospi_boot_name_v2[0].suffix, "_b", 2);
        strncpy(ospi_boot_name_v2[1].suffix, "_a", 2);
    }
    else {
        PRINTF_CRITICAL("current_boot:%d suffix:%d\n", current_boot, suffix);
        assert(0);
    }

    strcat(boot0_full_name, ospi_boot_name_v2[0].name);
    strcat(boot0_full_name, ospi_boot_name_v2[0].suffix);
    strcat(boot1_full_name, ospi_boot_name_v2[1].name);
    strcat(boot1_full_name, ospi_boot_name_v2[1].suffix);

#if DEBUGMODE
    PRINTF_CRITICAL("boot0:%s boot1:%s name:%s\n", boot0_full_name, boot1_full_name, name);
#endif

    if(strcmp(name, boot0_full_name) == 0) {
        return ospi_boot0_name;
    }
    else if(strcmp(name, boot1_full_name) == 0) {
        return ospi_boot1_name;
    }
    else {
        PRINTF_INFO("name is %s, boot0_full_name is %s,  boot1_full_name is %s\n", name, boot0_full_name, boot1_full_name);
    }

    return name;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */
