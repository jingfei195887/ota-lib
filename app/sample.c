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

/*

OTA flow:
---------------|----------------------------------------------------------------------------------------------------
               |      SLOT       |       ATTR      |          DIL         |                linux
---------------|----------------------------------------------------------------------------------------------------
first bootup   |
---------------|----------------------------------------------------------------------------------------------------
     >>>       |      A          |        0        |           0          | +active +successful +retry(3) +bootable
               |      B (no data)|        0        |           0          |                    0
---------------|----------------------------------------------------------------------------------------------------
second bootup  |
---------------|----------------------------------------------------------------------------------------------------
     >>>       |      A          |   A + S + R + B |      A + S + R + B   |          A + S + R + B
               |      B (no data)|        0        |            0         |               0
---------------|----------------------------------------------------------------------------------------------------
update         |
---------------|----------------------------------------------------------------------------------------------------
     >>>       |      A          |   A + S + R + B |      A + S + R + B   |          A + S + R + B      - A
               |      B (NEW)    |         0       |            0         |               0             + A + B + R(3)
---------------|----------------------------------------------------------------------------------------------------
reboot         |
---------------|----------------------------------------------------------------------------------------------------
               |      A          |   S + R + B     |       S + R + B      |          S + R + B
     >>>       |      B (NEW)    |   A + B + R(3)  |       A + B + R(2)   |          A + B + R(2)       + S
---------------|----------------------------------------------------------------------------------------------------
normal boot    |
---------------|----------------------------------------------------------------------------------------------------
               |      A (data)   |   S + R + B     |       S + R + B      |          S + R + B
     >>>       |      B (data)   | A + S + B + R(2)|     A + S + B + R(2) |          A + S + B + R(2)
---------------|----------------------------------------------------------------------------------------------------


roll back:
---------------|----------------------------------------------------------------------------------------------------
               |      SLOT       |         ATTR        |          DIL         |                linux
---------------|----------------------------------------------------------------------------------------------------
first bootup   |
---------------|----------------------------------------------------------------------------------------------------
     >>>       |      A          |          0          |           0          | +active +successful +retry(3) +bootable
               |      B (no data)|          0          |           0          |                    0
---------------|----------------------------------------------------------------------------------------------------
second bootup  |
---------------|----------------------------------------------------------------------------------------------------
     >>>       |      A          |     A + S + R + B   |      A + S + R + B   |      A + S + R + B
               |      B (no data)|           0         |            0         |               0
---------------|----------------------------------------------------------------------------------------------------
update         |
---------------|----------------------------------------------------------------------------------------------------
     >>>       |      A          |     A + S + R + B   |      A + S + R + B   |      A + S + R + B       - A
               |      B (NEW)    |           0         |            0         |               0          + A + B + R(3)
---------------|----------------------------------------------------------------------------------------------------
reboot         |
---------------|----------------------------------------------------------------------------------------------------
               |      A          |      S + R + B      |       S + R + B      |      S + R + B
     >>>       |      B (NEW)    |      A + B + R(3)   |       A + B + R(2)   |      A + B + R(2)
---------------|----------------------------------------------------------------------------------------------------
reboot         |
---------------|----------------------------------------------------------------------------------------------------
               |      A (data)   |      S + R + B      |       S + R + B      |      S + R + B
     >>>       |      B (NEW)    |      A + B + R(2)   |       A + B + R(1)   |      A + B + R(1)
---------------|----------------------------------------------------------------------------------------------------
reboot         |
---------------|----------------------------------------------------------------------------------------------------
               |      A (data)   |      S + R + B      |       S + R + B      |      S + R + B
     >>>       |      B (NEW)    |      A + B + R(1)   |       A + B + R(0)   |      A + B + R(0)
---------------|----------------------------------------------------------------------------------------------------
reboot         |
---------------|----------------------------------------------------------------------------------------------------
     >>>       |      A (data)   |      S + R + B      |    S + R + B + A     |      A + S + R + B
               |      B (NEW)    |      A + B + R(0)   | A + B + R(0) - A - B |            0
---------------|----------------------------------------------------------------------------------------------------

*/
#define _LARGEFILE64_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "slots_parse.h"
#include "crc32.h"
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "bpt.h"

#define LBA_SIZE 512
#define MAX_CALLOC_SIZE (512*1024)
#define USE_RW
#define FILE_NAME_MAX (MAX_GPT_NAME_SIZE + 256)
#define MAX_PARTITION_NUM 64
#define CHOOSE_FUNCTION(func1, func2, choose_func1) ((choose_func1) ? (func1) : (func2))
#define MAX_PAC_FILE 2
#define DEFAULT_RW_SIZE 0x100000
#define OTA_WAKE_LOCK_NAME "ota_sample"

typedef struct __attribute__((packed)) PACKET_HEADER {
    uint32_t nMagic;           //(0x5041434B) which means "PACK"
    uint32_t nVersion;         //0
    uint8_t szPrdName[256];    // product name
    uint8_t szPrdVersion[256]; // product version
    uint32_t nPreLoadSize;     // spl or safety size
    uint32_t nPreLoadOffset;   //spl or safety offset from the packet header and the array of FILE_T struct buffer to preload file
    uint32_t nFileTCount;      // the number of PACKET_FILE_T
    uint32_t nFileTOffset;     // the offset from the packet file header to the array of FILE_T struct buffer
    uint8_t bReserved[484];    // reserved
    uint32_t nCRC32;           // CRC 32 for all data except  nCRC
} PACKET_HEADER_T;

typedef struct __attribute__((packed)) PACKET_FILE {
    uint8_t szPartitionName[72]; // partition name
    uint64_t llSize;             // file size
    uint64_t llOffset;           // data offset
    uint32_t nFileType;          //0:DA; 1:main gpt; 2:image; 3:secondary gpt; 4:pac;
    uint8_t bReserved[36];       // reserved
} PACKET_FILE_T;

typedef enum {
    E_PACK_FIRST_DA_FILE = 0, // FDA File
    E_PACK_MID_DA_FILE = 1, // OSPIDA File
    E_PACK_DLOADER_FILE = 2, // DLOADER File
    E_PACK_SPL_FILE = 3, // spl file
    E_PACK_SAFETY_FILE = 4, // sfs file
    E_PACK_MBR_GPT_FILE = 5, // gpt file
    E_PACK_IMG_FILE = 6, // image file
    E_PACK_PAC_FILE = 7, // pac file
    E_PACK_FBL_FILE = 8, // boot0 file
    E_PACK_SBL_FILE = 9, // boot1 file
    E_PACK_TBL_FILE = 10, // boot2 file
    E_PACK_NFS_FILE = 11, // nfs file
    E_PACK_RFD_FILE = 12 // rfd file
} E_PACK_FILE_TYPE;

typedef struct target_list {
    char *name;
    storage_id_e id;
} target_list_t;

extern bool ota_wake_lock(bool lock, const char * lock_name);

static bool storage_mode = false;
static bool write_with_check_mode = false;
static uint32_t rw_size = DEFAULT_RW_SIZE;
static int  flag;
static const char *short_opt = "pstA:B:a:b:wf:c:r:i:g:do";
static const struct option long_options[] = {
    { "print", no_argument, NULL, 'p' },
    { "success", no_argument, NULL, 's' },
    { "storage", no_argument, NULL, 't' },
    { "set-A", required_argument, &flag, 'A' },
    { "set-B", required_argument, &flag, 'B' },
    { "clr-A", required_argument, &flag, 'A' },
    { "clr-B", required_argument, &flag, 'B' },
    { "wcheck", no_argument, NULL, 'w' },
    { "file", required_argument, NULL, 'f' },
    { "pac", required_argument, NULL, 'c' },
    { "read", required_argument, NULL, 'r' },
    { "write", required_argument, NULL, 'i' },
    { "rwsize", required_argument, NULL, 'g' },
    { "dil", no_argument, NULL, 'd' },
    { "dil_only", no_argument, NULL, 'o' },
    { NULL, 0, NULL, 0 }
};
static uint8_t file_cnt = 0;
static uint8_t pac_file_cnt = 0;
static char *file_name[MAX_PARTITION_NUM] = {0};
static char *pac_file_name[MAX_PAC_FILE];
static bool dil_mode = false;
static bool only_dil_mode = false;
static int OTA_programming_use_storage(partition_device_t *ptdev);
static int OTA_programming_use_syscall(partition_device_t *ptdev);
static void slot_attr_test(partition_device_t *ptdev, char *op, int slotstr,
                           char *attrstr);
static int parse_pac(const char *pac_file_name, const char *target_name,
                     uint64_t *out_size, uint64_t *out_offset);
static int write_file_in_pac_to_partition(char *file, uint64_t img_size,
        uint64_t img_offset, int partition_fd, uint64_t partition_size);
static char test_partition_name[MAX_GPT_NAME_SIZE];
static int read_time_test(char* partition_name, char* test_file);
static int write_time_test(char* partition_name, char* test_file);
static int OTA_programming_dil_use_syscall(char* boot_partition_name);
static const char* emmc_boot_str[2] = {DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT0, DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT1};
static const char* ospi_boot_str[2] = {DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT0, DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT1};

void useage(char *prg_name)
{
    PRINTF("Usage: %s <option>\n", prg_name);
    PRINTF("%s [device]                       : do OTA for [device] by slot copy\n",
           prg_name);
    PRINTF("%s [device] -s                    : mark active slot as successful\n",
           prg_name);
    PRINTF("%s [device] -print                : print slot information\n",
           prg_name);
    PRINTF("%s [device] -t                    : do OTA for [device] using storage interface\n",
           prg_name);
    PRINTF("%s [device] -t -w                 : do OTA for [device] using storage interface with read back check\n",
           prg_name);
    PRINTF("%s [device] -f [file1] -f [file2] : do OTA for [device] by slot copy, some partitions will be upgraded using target file\n",
           prg_name);
    PRINTF("%s [device] -c [pac1] -c [pac2]   : do OTA for [device] from pac file\n",
           prg_name);
    PRINTF("%s [device] -d                    : the dil will be updated too\n",
           prg_name);
    PRINTF("%s [device] -o                    : only dil will be updated\n",
           prg_name);
    PRINTF("%s [device] -set-A A              : set slot A Active\n", prg_name);
    PRINTF("%s [device] -set-A B              : set slot A Bootable\n", prg_name);
    PRINTF("%s [device] -set-A S              : set slot A Successful\n", prg_name);
    PRINTF("%s [device] -set-A R              : set slot A Retry cnt = 3\n",
           prg_name);
    PRINTF("%s [device] -set-B A              : set slot B Active\n", prg_name);
    PRINTF("%s [device] -set-B B              : set slot B Bootable\n", prg_name);
    PRINTF("%s [device] -set-B S              : set slot B Successful\n", prg_name);
    PRINTF("%s [device] -set-B R              : set slot B Retry cnt = 3\n",
           prg_name);
    PRINTF("%s [device] -clr-A A              : clr slot A Active\n", prg_name);
    PRINTF("%s [device] -clr-A B              : clr slot A Bootable\n", prg_name);
    PRINTF("%s [device] -clr-A S              : clr slot A Successful\n", prg_name);
    PRINTF("%s [device] -clr-A R              : clr slot A Retry cnt = 3\n",
           prg_name);
    PRINTF("%s [device] -clr-B A              : clr slot B Active\n", prg_name);
    PRINTF("%s [device] -clr-B B              : clr slot B Bootable\n", prg_name);
    PRINTF("%s [device] -clr-B S              : clr slot B Successful\n", prg_name);
    PRINTF("%s [device] -clr-B R              : clr slot B Retry cnt = 3\n",
           prg_name);
    PRINTF("%s all --read [partition_name]    : aligned read a partition for ota read-speed test, example: %s all --read boot_a \n",
           prg_name, prg_name);

    PRINTF("%s all --read [partition_name] -f [file_name]    : aligned read a partition and write the data to a file\n",
           prg_name);

    PRINTF("%s all --read [partition_name] -g [each_read_size]    : read a file with with a given size, unaligned read test, example: %s all --read boot_a -g 0x100000\n",
           prg_name, prg_name);

    PRINTF("%s all --write [partition_name]    : aligned write a partition for ota write-speed test, example: %s all --write boot_b \n",
           prg_name, prg_name);

    PRINTF("%s all --write [partition_name] -f [file_name]    : aligned write a partition from a file\n",
           prg_name);

    PRINTF("%s all --write [partition_name] -g [each_write_size]   : write a file with a given size, for unaligned writing test. example: %s all --write boot_b -g 0x100000\n",
           prg_name, prg_name);

    PRINTF("\n[device] can be one of the following options in non-vmmc mode\n");
    PRINTF("\t all:   for all storage device\n");
    PRINTF("\t ospi:  for NorFlash in safety domain\n");
    PRINTF("\t emmc:  for all eMMC in AP domain\n");
    PRINTF("\t emmcboot:  only eMMC boot0 will be updated, ota_test emmcboot -f spl.bin\n");

    PRINTF("\n[device] can be one of the following options in vmmc mode\n");
    PRINTF("\t all:   for all storage device\n");
    PRINTF("\t ospi:  for NorFlash in safety domain\n");
    PRINTF("\t emmc:  for only AP1 viewed level2 partition\n");
    PRINTF("\t emmc1: for eMMC level1 partition\n");
    PRINTF("\t emmc2: for eMMC level2 partition1\n");
    PRINTF("\t emmc3: for eMMC level2 partition2\n");
    PRINTF("\t emmc4: for eMMC level2 partition3\n");
}

static target_list_t ota_target_list[] = {
    {"all", DEV_MAX},       /* 0. FOR ALL */
    {"emmc", DEV_EMMC0},    /* 1. FOR EMMC or V-EMMC LEVEL-2 Partition of AP1*/
    {"ospi", DEV_SPI_NOR0}, /* 2. FOR OSPI1 FLASH */
    {"emmc1", DEV_EMMC1},   /* 3. FOR V-EMMC LEVEL-1 Partition */
    {"emmc2", DEV_EMMC2},   /* 4. FOR V-EMMC LEVEL-2 Partition 1 */
    {"emmc3", DEV_EMMC3},   /* 5. FOR V-EMMC LEVEL-2 Partition 2 */
    {"emmc4", DEV_EMMC4},   /* 6. FOR V-EMMC LEVEL-2 Partition 3 */
    {"emmc5", DEV_EMMC5},   /* 7. FOR V-EMMC LEVEL-2 Partition 4 */
    {"emmc6", DEV_EMMC6},   /* 8. FOR V-EMMC LEVEL-2 Partition 5 */
};

static int do_set_attr_test(partition_device_t *ptdev, char *cmd,
                            char *attr_str)
{
    if (!ptdev || !cmd || !attr_str) {
        PRINTF_CRITICAL("set slot attr para error\n");
        return -1;
    }

    if (!strcmp(cmd, "set-A")) {
        slot_attr_test(ptdev, "set", flag, attr_str);
    }
    else if (!strcmp(cmd, "set-B")) {
        slot_attr_test(ptdev, "set", flag, attr_str);
    }
    else if (!strcmp(cmd, "clr-A")) {
        slot_attr_test(ptdev, "clr", flag, attr_str);
    }
    else if (!strcmp(cmd, "clr-B")) {
        slot_attr_test(ptdev, "clr", flag, attr_str);
    }

    return 0;
}
#if 0
static void hexdump8(const void *ptr, size_t len)
{
    unsigned long address = (unsigned long)ptr;
    size_t count;
    size_t i;

    for (count = 0 ; count < len; count += 16) {
        for (i = 0; i < MIN(len - count, 16); i++) {
            PRINTF("%02hhx ", *(const uint8_t *)(address + i));
        }

        PRINTF("\n");
        address += 16;
    }
}
#endif
static bool is_dil_sec_peer_load(void)
{
    int index;
    const char* dil_sec_peerload_name[3] = {emmc_peerload_boot_name, emmc_peerload_boot_name_a, emmc_peerload_boot_name_b};

    if(get_update_device_is_active(DEV_SPI_NOR0)) {
        for(int i = 0; i < 3; i++) {
            index = get_partition_index_from_ptdev(get_update_device_ptdev(DEV_SPI_NOR0), dil_sec_peerload_name[i]);

            if ((index >= 0) && (index < NUM_PARTITIONS)) {
                PRINTF_INFO("find dil peer load partition %s from %s\n", dil_sec_peerload_name[i], get_update_device_name(DEV_SPI_NOR0));
                return true;
            }
        }
    }

    return false;
}

static bool is_dil_saf_peer_load(void)
{
    int index;
    int i = 0;
    int j = 0;
    const char* dil_saf_peerload_name[3] = {ospi_peerload_boot_name, ospi_peerload_boot_name_a, ospi_peerload_boot_name_b};

    for (i = 0; i < DEV_MAX; i++) {
        if(get_update_device_is_active(i)
            && (!strcmp(BASE_DEV_NAME_MMC_REMOTE(top), get_update_device_name(i)) || !strcmp(BASE_DEV_NAME_MMC, get_update_device_name(i)))) {
            for(j = 0; j < 3; j++) {
                index = get_partition_index_from_ptdev(get_update_device_ptdev(i), dil_saf_peerload_name[j]);

                if ((index >= 0) && (index < NUM_PARTITIONS)) {
                    PRINTF_INFO("find dil peer load partition %s from %s\n", dil_saf_peerload_name[j], get_update_device_name(i));
                    return true;
                }
            }
        }
    }

    return false;
}

int main(int argc, char *argv[])
{
    int ret = -1;
    int slot, inactive_slot;
    partition_device_t *ptdev = NULL;
    const char *suffix;
    int option_index = 0;
    int c = -1;
    char *set_attr_cmd = NULL;
    char *attr_str = NULL;
    bool just_dump = false;
    bool just_mark_success = false;
    bool ota_for_all = false;
    int i = 0;
    int val = -1;
    int target_id = -1;
    bool do_read_test = false;
    bool do_write_test = false;
    int bpt_v;
    bool wake_locked = false;

    if(argc > 1) {
        /* prevent OS from autosleep */
        wake_locked = ota_wake_lock(true, OTA_WAKE_LOCK_NAME);
        if (!wake_locked)
        {
            PRINTF_CRITICAL("failed to get ota wake lock\n");
            goto end;
        }
        for (i = 0; i < get_update_device_num(); i++) {
            if (!strcmp(argv[1], ota_target_list[i].name)) {
                if (!strcmp(argv[1], "all")) {
                    val = boot_control_init_all();
                    ota_for_all = true;
                }
                else {
                    val = switch_storage_dev(&ptdev, ota_target_list[i].id);
                    target_id = ota_target_list[i].id;
                }

                break;
            }
        }
    }
    else {
        useage(argv[0]);
        goto end;
    }

    if (0 != val) {
        PRINTF_CRITICAL("failed to setup ptdev, target is %s\n", argv[1]);
        useage(argv[0]);
        goto end;
    }

    if (!ota_for_all && (target_id != -1)) {
        update_device_t *device = NULL;

        for (i = 0; i < get_update_device_num(); i++) {
            device = get_update_device(i);

            /* force disable norflash */
            if ((target_id != DEV_SPI_NOR0) && (device->id == DEV_SPI_NOR0)) {
                device->active = false;
            }
            /* force disable emmc */
            else if ((target_id == DEV_SPI_NOR0) && (device->id != DEV_SPI_NOR0)) {
                device->active = false;
            }
        }
    }

    file_cnt = 0;
    pac_file_cnt = 0;
    optind = 2;

    if ((argc > 2) && strncmp(argv[2], "-", 1)) {
        useage(argv[0]);
        goto end;
    }

    while (1) {
        c = getopt_long_only(argc, argv, short_opt, long_options, &option_index);

        if (-1 == c) {
            break;
        }

        switch (c) {
            case 0:
                set_attr_cmd = (char * )(long_options[option_index].name);
                attr_str = optarg;
                just_dump = true;
                break;

            case 'p':
                just_dump = true;
                break;

            case 't':
                storage_mode = true;
                break;

            case 's':
                just_mark_success = true;
                break;

            case 'c':
                if (access(optarg, F_OK)) {
                    PRINTF_CRITICAL("Not able to access %s\n", optarg);
                    goto end;
                }

                if (pac_file_cnt >= MAX_PAC_FILE) {
                    PRINTF_CRITICAL("too many pac file input\n");
                    goto end;
                }

                pac_file_name[pac_file_cnt] = optarg;
                PRINTF_INFO("get pac file %s\n", pac_file_name[pac_file_cnt]);
                pac_file_cnt++;
                break;

            case 'f':
                if (!do_read_test && access(optarg, F_OK)) {
                    PRINTF_CRITICAL("Not able to access %s\n", optarg);
                    goto end;
                }

                if (file_cnt >= MAX_PARTITION_NUM) {
                    PRINTF_CRITICAL("too many file input\n");
                    goto end;
                }

                file_name[file_cnt] = optarg;
                PRINTF_INFO("get file %s\n", file_name[file_cnt]);
                file_cnt++;
                break;

            case 'w':
                write_with_check_mode = true;
                PRINTF_INFO("wirte with check mode on\n");
                break;

            case 'r':
                do_read_test = true;
                strncpy((char *)test_partition_name, (char *)optarg, MIN(strlen((char *)optarg), MAX_GPT_NAME_SIZE-1));
                PRINTF_INFO("do read performance test\n");
                break;

            case 'i':
                do_write_test = true;
                strncpy((char *)test_partition_name, (char *)optarg, MIN(strlen((char *)optarg), MAX_GPT_NAME_SIZE-1));
                PRINTF_INFO("do write performance test\n");
                break;

            case 'g':
                rw_size = (uint32_t)strtoull(optarg, NULL, 16);
                PRINTF_INFO("give rw size = 0x%x\n", (uint32_t)rw_size);
                break;

            case 'd':
                dil_mode = true;
                PRINTF_INFO("dil mode on %d\n", dil_mode);
                break;

            case 'o':
                dil_mode = true;
                only_dil_mode = true;
                PRINTF_INFO("only dil mode on %d\n", only_dil_mode);
                break;

            case '?':
                PRINTF_CRITICAL("unknow input arg\n");

            default:
                useage(argv[0]);
                goto end;
                break;
        }
    }

    if (set_attr_cmd && attr_str) {
        if (ota_for_all) {
            for (i = 0; i < DEV_MAX; i++) {
                if (!get_update_device_is_active(i)) {
                    continue;
                }

                if (do_set_attr_test(get_update_device_ptdev(i), set_attr_cmd, attr_str)) {
                    PRINTF_CRITICAL("set attr for %s error\n", get_update_device_name(i));
                    goto end;
                }
            }
        }
        else {
            if (do_set_attr_test(ptdev, set_attr_cmd, attr_str)) {
                PRINTF_CRITICAL("set attr error\n");
                goto end;
            }
        }
    }

    if (just_dump) {
        ret = 0;
        goto dump;
    }

    if(do_read_test) {
        ret = read_time_test(test_partition_name, file_name[0]);
        goto end;
    }

    if(do_write_test) {
        ret = write_time_test(test_partition_name, file_name[0]);
        goto end;
    }

    /* 1st dump current partition table */
    PRINTF_INFO("first bootup dump ptdev.\n");
    CHOOSE_FUNCTION(ptdev_dump_all(), \
                    ptdev_attr_dump(ptdev), \
                    ota_for_all);


    /* get slot number */
    val = CHOOSE_FUNCTION(get_number_slots_all(), \
                          get_number_slots(ptdev), \
                          ota_for_all);

    PRINTF_INFO("slots count %d\n", val);

    if (val != 2) {
        PRINTF_CRITICAL("slots count %d is not 2\n", val);
        goto end;
    }

    /* get active slot */
    slot = CHOOSE_FUNCTION(get_current_slot_all(), \
                           get_current_slot(ptdev), \
                           ota_for_all);

    /* get active_slot suffix*/
    suffix = CHOOSE_FUNCTION(get_suffix_all(slot), \
                             get_suffix(ptdev, slot), \
                             ota_for_all);

    /* get inactive_slot. inactive_slot is ota target slot */
    inactive_slot = CHOOSE_FUNCTION(get_inverse_slot_all(slot), \
                                    get_inverse_slot(ptdev, slot), \
                                    ota_for_all);

    if (!suffix || ((slot != SLOT_A) && (slot != SLOT_B)) || \
            ((inactive_slot != SLOT_A) && (inactive_slot != SLOT_B))) {
        PRINTF_CRITICAL("bad slot %d, slot %d, suffix = %s\n", slot, inactive_slot,
                        suffix);
        goto end;
    }

    PRINTF_INFO("corrent slot %d, %s\n", slot, suffix);

    /* query if active slot marked successful */
    val = CHOOSE_FUNCTION(is_slot_marked_successful_all(slot), \
                          is_slot_marked_successful(ptdev, slot), \
                          ota_for_all);

    if (0 == val) {
        val = CHOOSE_FUNCTION(mark_boot_successful_all(), \
                              mark_boot_successful(ptdev), \
                              ota_for_all);

        if (0 != val) {
            PRINTF_CRITICAL("mark %s successful attr error\n", suffix);
            goto end;
        }
    }
    else if (1 != val) {
        PRINTF_CRITICAL("get slot %s successful attr error\n", suffix);
        goto end;
    }

    if (just_mark_success) {
        ret = 0;
        goto dump;
    }

    /* set ota target slot(inactive_slot) as unbootable */
    val = CHOOSE_FUNCTION(set_slot_as_unbootable_all(inactive_slot), \
                          set_slot_as_unbootable(ptdev, inactive_slot), \
                          ota_for_all);

    if (0 != val) {
        PRINTF_CRITICAL("set inactive slot unbootable error\n");
        goto end;
    }

    /* 2nd dump for debug */
    CHOOSE_FUNCTION(ptdev_dump_all(), \
                    ptdev_attr_dump(ptdev), \
                    ota_for_all);

    if(!only_dil_mode) {
        if (ota_for_all) {
            for (i = 0; i < DEV_MAX; i++) {
                if (!get_update_device_is_active(i)) {
                    continue;
                }

                /* do ota update */
                if (storage_mode) {
                    PRINTF_INFO("OTA updating by storage\n");
                    val = OTA_programming_use_storage(get_update_device_ptdev(i));
                }
                else {
                    PRINTF_INFO("OTA updating by syscall\n");
                    val = OTA_programming_use_syscall(get_update_device_ptdev(i));
                }

                if (val < 0) {
                    PRINTF_INFO("OTA_programming error\n");
                    goto end;
                }
            }
        }
        else {
            /* do ota update */
            if (storage_mode) {
                PRINTF_INFO("OTA updating by storage\n");
                val = OTA_programming_use_storage(ptdev);
            }
            else {
                PRINTF_INFO("OTA updating by syscall\n");
                val = OTA_programming_use_syscall(ptdev);
            }

            if (val < 0) {
                PRINTF_INFO("OTA_programming error\n");
                goto end;
            }
        }
    }

    /* update dil */
    if(dil_mode || only_dil_mode) {
        bpt_v = get_bpt_version();
        if (bpt_v != BPT_V1 && bpt_v != BPT_V2){
            PRINTF_CRITICAL("can't find bpt version bpt_v=0x%x\n", bpt_v);
            goto end;
        }

        if(bpt_v == BPT_V1) {
            if(false == is_dil_sec_peer_load()) {
                for(i = 0; i < 2; i++) {
                    if(OTA_programming_dil_use_syscall((char *)emmc_boot_str[i]) < 0) {
                        PRINTF_CRITICAL("failed to update emmc dil %d, bpt version is v1\n", i);
                        goto end;
                    }
                }
            }

            if(false == is_dil_saf_peer_load()) {
                for(i = 0; i < 2; i++) {
                    if(OTA_programming_dil_use_syscall((char *)ospi_boot_str[i]) < 0) {
                        PRINTF_CRITICAL("failed to update ospi dil %d, bpt version is v1\n", i);
                        goto end;
                    }
                }
            }
        }
        else {
            char dil_boot_name[FILE_NAME_MAX];
            snprintf(dil_boot_name ,FILE_NAME_MAX -1 , "mmcboot%s", suffix_slot[inactive_slot]);
            if(false == is_dil_sec_peer_load()) {
                if(OTA_programming_dil_use_syscall(dil_boot_name) < 0) {
                    PRINTF_CRITICAL("failed to update emmc dil, bpt version is v2\n");
                    goto end;
                }
            }
            snprintf(dil_boot_name ,FILE_NAME_MAX -1 , "ospiboot%s", suffix_slot[inactive_slot]);
            if(false == is_dil_saf_peer_load()) {
                if(OTA_programming_dil_use_syscall(dil_boot_name) < 0) {
                    PRINTF_CRITICAL("failed to update ospi dil, bpt version is v2\n");
                    goto end;
                }
            }
        }
    }

    /* set ota target slot as active and bootable */
    CHOOSE_FUNCTION(set_active_boot_slot_all(inactive_slot), \
                    set_active_boot_slot(ptdev, inactive_slot), \
                    ota_for_all);

dump:
    /* final dump for debug */
    CHOOSE_FUNCTION(ptdev_dump_all(), \
                    ptdev_attr_dump(ptdev), \
                    ota_for_all);

    if(ota_for_all) {
        PRINTF_INFO("active slot for all is %d\n", get_active_boot_slot_all());
        PRINTF_INFO("current slot for all is %d\n", get_current_slot_all());
    }
    else {
        PRINTF_INFO("active slot for this ptdev is %d\n", get_active_boot_slot(ptdev));
        PRINTF_INFO("current slot for this ptdev is %d\n", get_current_slot(ptdev));
    }

    sync();
    ret = 0;
    PRINTF_INFO("OTA finish, try reboot to take effect \n");

end:

    if (ptdev && (1 != argc)) {
        free_storage_dev(ptdev);
    }

    if (wake_locked)
        ota_wake_lock(false, OTA_WAKE_LOCK_NAME);
    return ret;
}


static int removeSuffix(char *str, const char *suffix)
{
    int len = strlen(str);
    int suffixLen = strlen(suffix);

    if (len >= suffixLen && strcmp(str + len - suffixLen, suffix) == 0) {
        str[len - suffixLen] = '\0';
        return 0;
    }
    return -1;
}

/*
    normal case:
    file_base_name = dil2.bin     partition_name = dil2_a ----> matched
    file_base_name = dil2.bin     partition_name = dil2   ----> matched
    file_base_name = dil2         partition_name = dil2   ----> matched

    take care of this case:
    file_base_name = dtbo.bin      partition_name = dtb_a   ----> not matched
    file_base_name = dtbo.bin      partition_name = dtb     ----> not matched
    file_base_name = dtbo          partition_name = dtb_a   ----> not matched
    file_base_name = dtbo          partition_name = dtb     ----> not matched
    file_base_name = dtb_a.bin     partition_name = dtb_a   ----> matched
    file_base_name = dtb.bin       partition_name = dtb_a   ----> matched
    file_base_name = dtb           partition_name = dtb     ----> matched
*/
static int match_update_files_for_one_partition(char *partition_name, bool ab_partition)
{
    int file_index = 0;
    char fname[FILE_NAME_MAX] = {0};
    char *file_base_name = NULL;
    int len = strlen(partition_name);
    int compare_len;

    if (!partition_name || !len || (len >= MAX_PARTITION_NUM)) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if(ab_partition) {
        if (strcmp((char *)(partition_name + len - 2), suffix_slot[0]) && strcmp((char *)(partition_name + len - 2), suffix_slot[1])) {
            PRINTF_CRITICAL("para error, %s not a ab partition\n", partition_name);
            return -1;
        }
    }

    for (file_index = 0; file_index < file_cnt; file_index++) {
        if (!strlen(file_name[file_index])
                || (strlen(file_name[file_index]) >= FILE_NAME_MAX)) {
            PRINTF_INFO("file_name[%d] = %s length error\n", file_index,
                        file_name[file_index]);
            continue;
        }

        memset(fname, 0, FILE_NAME_MAX);
        file_base_name = NULL;
        strncpy(fname, file_name[file_index], MIN(strlen(file_name[file_index]), FILE_NAME_MAX - 1));
        file_base_name = basename(fname);

        // partition and file name are exactly the same
        if (!strcmp(file_base_name, partition_name)) {
            PRINTF_INFO("basename = %s\n", file_base_name);
            return file_index;
        }

        /* remove .bin or .img */
        if(0 != removeSuffix(file_base_name, ".bin")) {
            removeSuffix(file_base_name, ".img");
        }

        /* partition and file name are exactly the same, after removing .bin or .img suffix */
        if (!strcmp(file_base_name, partition_name)) {
            PRINTF_INFO("basename = %s\n", file_base_name);
            return file_index;
        }

        if(ab_partition) {
            compare_len = len - 2;
        }
        else {
            compare_len = len;
        }

        if ((strlen(file_base_name) != compare_len)) {
            PRINTF_INFO("skip: file base name = %s\n", file_base_name);
            PRINTF_INFO("partition_name = %s\n", partition_name);
            PRINTF_INFO("strlen(file_base_name) = %zu \n", strlen(file_base_name));
            PRINTF_INFO("len = %d compare_len %d\n", len, compare_len);
            continue;
        }

        else if (!strncmp(file_base_name, partition_name, compare_len)) {
            PRINTF_INFO("basename = %s\n", file_base_name);
            return file_index;
        }

    }

    return -1;
}

int partition_grouped_by_A_and_B(partition_device_t *ptdev, int *slot_active,
                                 int *slot_inactive)
{
    int index = 0;
    int len = 0;
    char *pname = NULL;
    struct partition_entry *partition_entries = ptdev->partition_entries;
    const char *suffix = NULL;
    suffix = get_suffix(ptdev, get_current_slot(ptdev));

    if (!ptdev || !(ptdev->count) || !partition_entries || !suffix) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if (ptdev->count > 2 * MAX_PARTITION_NUM) {
        PRINTF_CRITICAL("too many partition\n");
        return -1;
    }

    for (int i = 0; i < ptdev->count; i++) {
        pname = (char *)partition_entries[i].name;
        len = strlen(pname);

        if (len < 4)
            continue; /* too few, ignore */

        if (strstr((char *)partition_entries[i].name, "$"))
            continue; /* ignore level2 partiton */

        if (strcmp((char *)(pname + len - 2), suffix_slot[0])
                && strcmp((char *)(pname + len - 2), suffix_slot[1])) {
            continue;
        }

        for (int j = i + 1; j < ptdev->count; j++) {
            if ((!strncmp(pname, (char *)partition_entries[j].name, len - 2)) &&
                    (len == strlen((char *)partition_entries[j].name))) {
                if (strstr(pname, suffix)) {
                    slot_active[index] = i;
                    slot_inactive[index] = j;
                }
                else {
                    slot_active[index] = j;
                    slot_inactive[index] = i;
                }

                index++;
            }
        }
    }

    return index;
}

static int OTA_programming_dil_use_syscall(char* boot_partition_name)
{
    int dil_fd;
    int ret = -1;
    uint64_t size = 0;
    bool update_from_pac = false;
    uint64_t img_size;
    uint64_t img_offset;
    int file_index = -1;
    bool find_dil_file = false;
    const char* emmc_dil_file_name = "spl";
    const char* ospi_dil_file_name = "dil";
    char* dil_file_name;
    char* dil_pac_file_name;

    if(strstr(boot_partition_name, "mmc")) {
        dil_file_name = (char*)emmc_dil_file_name;
        dil_pac_file_name = (char*)emmc_dil_file_name;
        PRINTF_CRITICAL("update emmc dil %s search for file: %s and file_in_pac: %s\n", boot_partition_name, dil_file_name, dil_pac_file_name);
    }
    else {
        dil_file_name = (char*)ospi_dil_file_name;
        dil_pac_file_name = (char*)ospi_dil_file_name;
        PRINTF_CRITICAL("update ospi dil %s search for file: %s and file_in_pac: %s\n", boot_partition_name, dil_file_name, dil_pac_file_name);
    }


    dil_fd = partition_dev_open(boot_partition_name, O_RDWR, SYSCALL_AUTO);

    if (dil_fd < 0) {
        PRINTF_CRITICAL("failed to open %s\n", boot_partition_name);
        goto end;
    }

    if (0 != partition_dev_seek(dil_fd, 0, SEEK_SET)) {
        PRINTF_CRITICAL("partition_dev_seek dil fd[0x%x] failed\n", dil_fd);
        partition_dev_dump(dil_fd);
        goto end;
    }

    /* get dil size */
    size = partition_dev_blockdevsize(dil_fd);
    PRINTF_INFO("%s size = 0x%llx\n", boot_partition_name, (unsigned long long)size);

    if (!size) {
        PRINTF_CRITICAL("failed to get partition size %lld\n", (unsigned long long)size);
        goto end;
    }

    if(partition_dev_set_readonly(dil_fd, false) != 0 ) {
        PRINTF_CRITICAL("reset boot fd 0x%x to read_write failed\n", dil_fd);
        partition_dev_dump(dil_fd);
        goto end;
    }

    /* update dil form pac file*/
    for (int pac_cnt = 0; pac_cnt < pac_file_cnt; pac_cnt++) {
        if (!parse_pac(pac_file_name[pac_cnt], dil_pac_file_name, &img_size, &img_offset)) {
            PRINTF_INFO("partition dev write file [%s] from pac, img_size = 0x%llx, img_offset = 0x%llx\n", (char *)dil_pac_file_name, (unsigned long long)img_size, (unsigned long long)img_offset);
            ret = write_file_in_pac_to_partition(pac_file_name[pac_cnt], img_size, img_offset, dil_fd, size);
            find_dil_file = true;
            if (ret < 0) {
                PRINTF_CRITICAL("partition dev write %s error file from pac\n", (char *)dil_pac_file_name);
                partition_dev_dump(dil_fd);
                goto end;
            }
            else {
                update_from_pac = true;
                break;
            }
        }
    }

    if (!update_from_pac) {
        /* update inactive partition from input file */
        file_index = match_update_files_for_one_partition((char *)dil_file_name, false);

        if ((file_index >= 0) && (file_index < file_cnt)) {
            PRINTF_INFO("update from file %s\n", file_name[file_index]);
            ret = partition_dev_write_file(dil_fd, file_name[file_index]);
            find_dil_file = true;
            if (ret < 0) {
                PRINTF_CRITICAL("partition dev write file\n");
                partition_dev_dump(dil_fd);
                goto end;
            }
        }
    }

    if(partition_dev_set_readonly(dil_fd, true) != 0 ) {
        PRINTF_CRITICAL("reset boot fd 0x%x to readonly failed\n", dil_fd);
        partition_dev_dump(dil_fd);
        goto end;
    }

end:
    if(dil_fd > 0) {
        partition_dev_close(dil_fd);
    }

    if(find_dil_file != true) {
        PRINTF_CRITICAL("update for dil failed, could not find any dil file\n");
    }

    return ret;
}

int OTA_programming_use_storage(partition_device_t *ptdev)
{
    int slot_active[MAX_PARTITION_NUM] = {0};
    int slot_inactive[MAX_PARTITION_NUM] = {0};
    int active_slot = 0;
    int inactive_slot = 0;
    int ret = -1;
    uint64_t in = 0;
    uint64_t out = 0;
    uint64_t size = 0;
    uint64_t left = 0;
    uint64_t cnt = 0;
    uint64_t read_size = 0;
    int ab_index = 0;
    int file_index = -1;
    uint8_t *data = NULL;
    struct partition_entry *partition_entries = ptdev->partition_entries;
    storage_device_t *storage = ptdev->storage;
    uint64_t gpt_offset = ptdev->gpt_offset;

    ab_index = partition_grouped_by_A_and_B(ptdev, slot_active, slot_inactive);

    if (ab_index <= 0) {
        PRINTF_CRITICAL("try to group partition by A/B failed\n");
        return -1;
    }

    for (int i = 0; i < ab_index; i++) {
        active_slot = slot_active[i];
        inactive_slot = slot_inactive[i];
        in = (partition_entries[active_slot].first_lba) * LBA_SIZE;
        out = (partition_entries[inactive_slot].first_lba) * LBA_SIZE;
        size = (partition_entries[active_slot].last_lba -
                partition_entries[active_slot].first_lba + 1) * LBA_SIZE;

        in += gpt_offset;
        out += gpt_offset;
        PRINTF_INFO("gpt_offset=0x%llx\n", (unsigned long long)gpt_offset);
        PRINTF_INFO("index=%d, size=0x%llx\n", i,  (unsigned long long)size);
        PRINTF_INFO("active_slot=%s, addr=%p, \n", partition_entries[active_slot].name,
                    (void *)in);
        PRINTF_INFO("inactive_slot=%s, addr=%p\n",
                    partition_entries[inactive_slot].name, (void *)out);

        /* update inactive partition from input file */
        file_index = match_update_files_for_one_partition((char *)(
                         partition_entries[inactive_slot].name), true);

        if ((file_index >= 0) && (file_index < file_cnt)) {
            PRINTF_INFO("update from file %s\n", file_name[file_index]);
            ret = storage->write_file(storage, out, size, file_name[file_index],
                                      write_with_check_mode);

            if (ret < 0) {
                PRINTF_INFO("OTA_programming write file failed\n");
                return -1;
            }
        }

        /* copy active to inactive partition */
        else {
#ifdef USE_RW
            cnt =  (size / MAX_CALLOC_SIZE);
            left = (size % MAX_CALLOC_SIZE);
            data = (unsigned char *)MEM_ALIGN(512, (cnt != 0 ? (MAX_CALLOC_SIZE) : size));

            if (!data) {
                PRINTF_INFO("OTA_programming calloc failed\n");
                return -1;
            }

            for (uint64_t n = 0; n <= cnt; n++) {
                read_size = (n != cnt) ? MAX_CALLOC_SIZE : left;

                if (read_size) {
                    PRINTF_INFO("copy src addr=%p\n", (void *)in);
                    PRINTF_INFO("copy dst addr=%p\n", (void *)out);
                    PRINTF_INFO("n = %lld, 0x%llx\n", (unsigned long long)n,
                                (unsigned long long)read_size);
                    ret = storage->read(storage, in, data, read_size);

                    if (ret < 0) {
                        PRINTF_CRITICAL("OTA_programming storage read failed\n");
                        FREE(data);
                        return -1;
                    }

                    if (write_with_check_mode)
                        ret = storage->write_with_check(storage, out, data, read_size);
                    else
                        ret = storage->write(storage, out, data, read_size);

                    if (ret < 0) {
                        PRINTF_CRITICAL("OTA_programming storage write failed\n");
                        FREE(data);
                        return -1;
                    }

                    in  += read_size;
                    out += read_size;
                }
            }

            FREE(data);
            data = NULL;

#else
            /* only copy data, not for download data
            in and out must align to 4k
            */
            ret = storage->copy(storage, in, out, size);

            if (ret < 0) {
                PRINTF_INFO("OTA_programming storage copy failed\n");
                return -1;
            }

#endif
        }

    }

    return 0;
}

int OTA_programming_use_syscall(partition_device_t *ptdev)
{
    int slot_active[MAX_PARTITION_NUM] = {0};
    int slot_inactive[MAX_PARTITION_NUM] = {0};
    int active_slot = 0;
    int inactive_slot = 0;
    int fd_active[MAX_PARTITION_NUM] = {-1};
    int fd_inactive[MAX_PARTITION_NUM] = {-1};
    int ret = -1;
    uint64_t size = 0;
    uint64_t left = 0;
    uint64_t cnt = 0;
    uint64_t read_size = 0;
    int ab_index = 0;
    int file_index = -1;
    uint8_t *data = NULL;
    struct partition_entry *partition_entries = ptdev->partition_entries;
    uint64_t img_size;
    uint64_t img_offset;
    bool update_from_pac = false;

    ab_index = partition_grouped_by_A_and_B(ptdev, slot_active, slot_inactive);

    if (ab_index <= 0) {
        PRINTF_CRITICAL("try to group partition by A/B failed\n");
        goto end;
    }

    for (int i = 0; i < ab_index; i++) {
        active_slot = slot_active[i];
        inactive_slot = slot_inactive[i];
        PRINTF_INFO("index=%d\n", i);
        PRINTF_INFO("active_slot=%s\n", partition_entries[active_slot].name);
        PRINTF_INFO("inactive_slot=%s\n", partition_entries[inactive_slot].name);
        update_from_pac = false;

        /* open active partition by partition name */
        fd_active[i] = partition_dev_open((const char *)
                                          partition_entries[active_slot].name, O_RDONLY, SYSCALL_AUTO);

        if (fd_active[i] < 0) {
            PRINTF_CRITICAL("failed to open %s\n", partition_entries[active_slot].name);
            goto end;
        }

        /* open inactive partition by partition name */
        fd_inactive[i] = partition_dev_open((const char *)
                                            partition_entries[inactive_slot].name, O_RDWR, SYSCALL_AUTO);

        if (fd_inactive[i] < 0) {
            PRINTF_CRITICAL("failed to open %s\n", partition_entries[inactive_slot].name);
            goto end;
        }

        /* active slot seek to 0 */
        if (0 != partition_dev_seek(fd_active[i], 0, SEEK_SET)) {
            PRINTF_CRITICAL("partition_dev_seek fd[%d] failed\n", active_slot);
            partition_dev_dump(fd_active[i]);
            goto end;
        }

        /* inactive slot seek to 0 */
        if (0 != partition_dev_seek(fd_inactive[i], 0, SEEK_SET)) {
            PRINTF_CRITICAL("partition_dev_seek fd[%d] failed\n", inactive_slot);
            partition_dev_dump(fd_inactive[i]);
            goto end;
        }

        /* get partition size */
        size = partition_dev_blockdevsize(fd_inactive[i]);
        PRINTF_INFO("partition size = %lld\n", (unsigned long long)size);

        if (!size || (size != (partition_entries[inactive_slot].last_lba -
                               partition_entries[inactive_slot].first_lba + 1) * LBA_SIZE)) {
            PRINTF_CRITICAL("failed to get partition size %lld\n",
                            (unsigned long long)size);
            goto end;
        }

        /* update inactive partition form pac file*/
        for (int pac_cnt = 0; pac_cnt < pac_file_cnt; pac_cnt++) {
            if (!parse_pac(pac_file_name[pac_cnt],
                           (char *)(partition_entries[inactive_slot].name),
                           &img_size, &img_offset)) {
                PRINTF_INFO("partition dev write file [%s] from pac, img_size = 0x%llx, img_offset = 0x%llx\n",
                            (char *)(partition_entries[inactive_slot].name), (unsigned long long)img_size,
                            (unsigned long long)img_offset);
                ret = write_file_in_pac_to_partition(pac_file_name[pac_cnt], img_size,
                                                     img_offset,
                                                     fd_inactive[i], size);

                if (ret < 0) {
                    PRINTF_CRITICAL("partition dev write %s error file from pac\n",
                                    (char *)(partition_entries[inactive_slot].name));
                    goto end;
                }
                else {
                    update_from_pac = true;
                    break;
                }
            }
        }

        if (update_from_pac) {
            continue;
        }

        /* update inactive partition from input file */
        file_index = match_update_files_for_one_partition((char *)(
                         partition_entries[inactive_slot].name), true);

        if ((file_index >= 0) && (file_index < file_cnt)) {
            PRINTF_INFO("update from file %s\n", file_name[file_index]);
            ret = partition_dev_write_file(fd_inactive[i], file_name[file_index]);

            if (ret < 0) {
                PRINTF_CRITICAL("partition dev write file\n");
                goto end;
            }
        }
        /* copy active to inactive partition */
        else {
            cnt =  (size / MAX_CALLOC_SIZE);
            left = (size % MAX_CALLOC_SIZE);
            data = (unsigned char *)MEM_ALIGN(512, (cnt != 0 ? (MAX_CALLOC_SIZE) : size));

            if (!data) {
                PRINTF_INFO("OTA_programming calloc failed\n");
                goto end;
            }

            /* do read and write copy */
            for (uint64_t n = 0; n <= cnt; n++) {
                read_size = (n != cnt) ? MAX_CALLOC_SIZE : left;

                if (read_size) {
                    if (read_size != partition_dev_read(fd_active[i], data, read_size)) {
                        PRINTF_CRITICAL("OTA_programming partition dev read failed\n");
                        partition_dev_dump(fd_active[i]);
                        goto end;
                    }

                    if (read_size != partition_dev_write(fd_inactive[i], data, read_size)) {
                        PRINTF_CRITICAL("OTA_programming partition dev write failed\n");
                        partition_dev_dump(fd_inactive[i]);
                        goto end;
                    }
                }
            }

            FREE(data);
            data = NULL;
        }
    }

    ret = 0;

end:

    for (int i = 0; i < ab_index; i++) {
        if (fd_active[i] >= 0) {
            partition_dev_close(fd_active[i]);
        }

        if (fd_inactive[i] >= 0) {
            partition_dev_close(fd_inactive[i]);
        }

    }

    if (data)
        free(data);

    return ret;
}

static void slot_attr_test(partition_device_t *ptdev, char *op, int slotstr,
                           char *attrstr)
{
    int slot = 0;
    int attr = 0;

    if ((char)slotstr == 'A') {
        slot = 0;
    }
    else if ((char)slotstr == 'B') {
        slot = 1;
    }
    else {
        PRINTF_INFO("error slot=%c\n", (char)slotstr);
        return;
    }

    if (!strcmp(attrstr, "B")) {
        attr = ATTR_UNBOOTABLE;
    }
    else if (!strcmp(attrstr, "A")) {
        attr = ATTR_ACTIVE;
    }
    else if (!strcmp(attrstr, "S")) {
        attr = ATTR_SUCCESSFUL;
    }
    else if (!strcmp(attrstr, "R")) {
        attr = ATTR_RETRY;
    }
    else {
        PRINTF_INFO("error attr=%s\n", attrstr);
        return;
    }

    if (!strcmp(op, "set")) {
        PRINTF_INFO("---------- set attr-----------\n");

        if (true == ptdev->local) {
            if (ptdev_mark_slot_attr(ptdev, slot, attr)) {
                PRINTF_INFO("error!\n");
                return;
            }
        }
        else {
            if (ptdev_mark_slot_attr_remote(ptdev, slot, attr)) {
                PRINTF_INFO("error!\n");
                return;
            }
        }
    }

    else if (!strcmp(op, "clr")) {
        PRINTF_INFO("----------clr attr-----------\n");

        if (true == ptdev->local) {
            if (ptdev_clean_slot_attr(ptdev, slot, attr)) {
                PRINTF_INFO("error!\n");
                return;
            }
        }
        else {
            if (ptdev_clean_slot_attr_remote(ptdev, slot, attr)) {
                PRINTF_INFO("error!\n");
                return;
            }
        }
    }

    else {
        PRINTF_INFO("error op=%s\n", op);
        return;
    }

    sync();
    ptdev_attr_dump(ptdev);
}

int read_img_file_from(const char *name, uint64_t offset, uint64_t len,
                       uint8_t *data)
{
    int ret;
    FILE *fp;
    char path[256];
    snprintf(path, 256, "%s", name);

    if ((fp = fopen(path, "rb+")) == NULL) {
        PRINTF_CRITICAL("Cannot open file %s, return!\n", path);
        return -1;
    }

    fseek(fp, offset, SEEK_SET);
    ret = fread(data, 1, len, fp);
    fclose(fp);

    if (ret == len) {
        return 0;
    }
    else {
        PRINTF_CRITICAL("failed to read %s ret %d len 0x%llx\n", name, ret,
                        (unsigned long long)len);
        return -1;
    }
}

static void wchar2char(char *src, char *des, int len)
{
    int index = 0;

    for (int i = 0; i < len; i++) {
        if (i % 2 == 0) {
            des[index] = src[i];
            index ++;
        }
    }
}

static void dump_pac_head(char *level, PACKET_HEADER_T *pack_head,
                          char *up_level_partition_name)
{
#if DEBUGMODE
    uint8_t prod_name[256] = {0};
    int8_t version[256] = {0};

    if (pack_head && level) {
        wchar2char((char *)(pack_head->szPrdName), (char *)prod_name, 256);
        wchar2char((char *)(pack_head->szPrdVersion), (char *)version, 256);

        if (!up_level_partition_name) {
            PRINTF("--------%s pack find--------\n", level);
        }
        else {
            PRINTF("--------%s pack find from %s--------\n", level,
                   up_level_partition_name);
        }

        PRINTF("%s pack head name %s\n", level, prod_name);
        PRINTF("%s pack head version %s\n", level, version);
        PRINTF("%s pack head preLoad Size 0x%x\n", level, pack_head->nPreLoadSize);
        PRINTF("%s pack head preLoad Offset 0x%x\n", level, pack_head->nPreLoadOffset);
        PRINTF("%s pack head file count %d\n", level, pack_head->nFileTCount);
        PRINTF("%s pack head file offset 0x%x\n", level, pack_head->nFileTOffset);
    }

#endif
}

static void dump_pac_img(char *level, PACKET_FILE_T *img_head, int index)
{
#if DEBUGMODE
    uint8_t img_name[MAX_GPT_NAME_SIZE] = {0};

    if (img_head && level) {
        wchar2char((char *)(img_head->szPartitionName), (char *)img_name,
                   MAX_GPT_NAME_SIZE);
        PRINTF("----------------------\n");
        PRINTF("%s img index = %d\n", level, index);
        PRINTF("%s PartitionName %s\n", level, img_name);
        PRINTF("%s Size 0x%llx\n",       level, (unsigned long long)(img_head->llSize));
        PRINTF("%s Offset 0x%llx\n",     level,
               (unsigned long long)(img_head->llOffset));
        PRINTF("%s FileType %d\n",       level, img_head->nFileType);
    }

#endif
}
#define MAX_FILE_CNT_IN_PAC 128

static bool ab_partition_name_match(const char * name1, const char * name2)
{
    int len;

    if(!name1 || !name2) {
        return false;
    }

    if(!strcmp(name1, name2)) {
        return true;
    }
    else {
        len = strlen(name1);

        if((len != strlen((char *)name2))) {
            return false;
        }

        if(len <= 2) {
            return false;
        }

        if(strncmp(name1, (char *)name2, len - 2)) {
            return false;
        }


        /* need partition_name_a or partition_name_b */
        if(strcmp((char *)(name1 + len - 2), suffix_slot[0]) && strcmp((char *)(name1 + len - 2), suffix_slot[1])) {
            return false;
        }

        /* need partition_name_a or partition_name_b */
        if(strcmp((char *)(name2 + len - 2), suffix_slot[0]) && strcmp((char *)(name2 + len - 2), suffix_slot[1])) {
            return false;
        }

        return true;
    }
}

static int parse_pac(const char *pac_file_name, const char *target_name,
                     uint64_t *out_size, uint64_t *out_offset)
{
    int ret = -1;
    char img_name[MAX_GPT_NAME_SIZE] = {0};
    char img_name_level_2[MAX_GPT_NAME_SIZE] = {0};
    PACKET_HEADER_T pack_head;
    PACKET_HEADER_T pack_head_level_2;
    PACKET_FILE_T img_head;
    PACKET_FILE_T img_head_level_2;
    uint64_t last_offset = 0;
    uint64_t last_offset_level_2 = 0;
    uint32_t i = 0;
    uint32_t j = 0;
    uint64_t offset = 0;

    PRINTF_CRITICAL("look for %s in read %s \n", target_name, pac_file_name);
    offset = 0;

    if (0 != read_img_file_from(pac_file_name, offset, sizeof(PACKET_HEADER_T),
                                (uint8_t *)&pack_head)) {
        PRINTF_CRITICAL("failed to read %s\n", pac_file_name);
        goto end;
    }

    if (pack_head.nMagic != 0x5041434B) {
        PRINTF_CRITICAL("head magic is 0x%08x, not 0x5041434B\n", pack_head.nMagic);
        goto end;
    }

    dump_pac_head("level 1", &pack_head, NULL);

    if (pack_head.nFileTCount > MAX_FILE_CNT_IN_PAC) {
        PRINTF_CRITICAL("pack_head.nFileTCount = %d, too many\n",
                        pack_head.nFileTCount);
        goto end;
    }

    last_offset = sizeof(PACKET_HEADER_T) + MAX_FILE_CNT_IN_PAC * sizeof(
                      PACKET_FILE_T);

    /* level 1 pac parse */
    for (i = 0; i < pack_head.nFileTCount; i++) {
        offset = sizeof(PACKET_HEADER_T) + i * sizeof(PACKET_FILE_T);
        memset((uint8_t *)&img_head, offset, sizeof(PACKET_FILE_T));

        if (0 != read_img_file_from(pac_file_name, offset, sizeof(PACKET_FILE_T),
                                    (uint8_t *)&img_head)) {
            PRINTF_CRITICAL("failed to read %s\n", pac_file_name);
            goto end;
        }

        memset((uint8_t *)&img_name, 0, MAX_GPT_NAME_SIZE);
        wchar2char((char *)(img_head.szPartitionName), (char *)img_name,
                   MAX_GPT_NAME_SIZE);
        dump_pac_img("level 1", &img_head, i);

        /* a valid image size and offset in head */
        if (img_head.llOffset == last_offset) {
            if (ab_partition_name_match(target_name, (const char *)img_name)) {
                    PRINTF_INFO("find %s in level 1 pac true Offset = 0x%llx Size = 0x%llx\n", \
                                (char *)img_name, (unsigned long long)(img_head.llOffset),
                                (unsigned long long)(img_head.llSize));

                    if (img_head.llSize) {
                        ret = 0;
                        *out_size = img_head.llSize;
                        *out_offset = img_head.llOffset;
                    }

                    goto end;
            }

            /* level 2 pac parse */
            if (img_head.nFileType == E_PACK_PAC_FILE) {
                last_offset_level_2 = sizeof(PACKET_HEADER_T) + MAX_FILE_CNT_IN_PAC * sizeof(
                                          PACKET_FILE_T);
                memset((uint8_t *)&pack_head_level_2, 0, sizeof(PACKET_HEADER_T));
                offset = img_head.llOffset;

                if (0 != read_img_file_from(pac_file_name, offset, sizeof(PACKET_HEADER_T),
                                            (uint8_t *)&pack_head_level_2)) {
                    PRINTF_CRITICAL("failed to read %s\n", pac_file_name);
                    goto end;
                }

                dump_pac_head("level 2", &pack_head_level_2, (char *)img_name);

                for (j = 0; j < pack_head_level_2.nFileTCount; j++) {
                    offset = img_head.llOffset + sizeof(PACKET_HEADER_T) + j * sizeof(
                                 PACKET_FILE_T);
                    memset((uint8_t *)&img_head_level_2, 0, sizeof(PACKET_FILE_T));

                    if (0 != read_img_file_from(pac_file_name, offset, sizeof(PACKET_FILE_T),
                                                (uint8_t *)&img_head_level_2)) {
                        PRINTF_CRITICAL("failed to read %s\n", pac_file_name);
                        goto end;
                    }

                    memset((uint8_t *)&img_name_level_2, 0, MAX_GPT_NAME_SIZE);
                    wchar2char((char *)(img_head_level_2.szPartitionName), (char *)img_name_level_2,
                               MAX_GPT_NAME_SIZE);
                    dump_pac_img("level 2", &img_head_level_2, j);

                    if (img_head_level_2.llOffset ==
                            last_offset_level_2) { //img_head_level_2.llSize &&
                        if (!strcmp(target_name, (char *)img_name_level_2)
                                || !strncmp(target_name, (char *)img_name_level_2, strlen(target_name) - 2)) {
                            if (strlen(target_name) == strlen((char *)img_name_level_2)) {
                                PRINTF_INFO("find %s in level 2 pac true Offset = 0x%llx Size = 0x%llx\n", \
                                            (char *)img_name_level_2,
                                            (unsigned long long)(img_head.llOffset + img_head_level_2.llOffset), \
                                            (unsigned long long)(img_head_level_2.llSize));

                                if (img_head_level_2.llSize) {
                                    ret = 0;
                                    *out_size = img_head_level_2.llSize;
                                    *out_offset = img_head.llOffset + img_head_level_2.llOffset;
                                }

                                goto end;
                            }
                        }

                        last_offset_level_2 += img_head_level_2.llSize;
                    }
                    else {
                        PRINTF_CRITICAL("level 2 parse img index = %d error, dump as:\n", j);
                        PRINTF_CRITICAL("level 2 Size = 0x%llx\n",
                                        (unsigned long long)(img_head_level_2.llSize));
                        PRINTF_CRITICAL("level 2 Offset = 0x%llx\n",
                                        (unsigned long long)(img_head_level_2.llOffset));
                        PRINTF_CRITICAL("level 2 last offset level2 = 0x%llx\n",
                                        (unsigned long long)last_offset_level_2);
                        goto end;
                    }
                }
            }

            last_offset += img_head.llSize;
        }
        else {
            PRINTF_CRITICAL("parse img index = %d error, dump as:\n", i);
            PRINTF_CRITICAL("size = 0x%llx\n", (unsigned long long)(img_head.llSize));
            PRINTF_CRITICAL("offset = 0x%llx\n", (unsigned long long)(img_head.llOffset));
            PRINTF_CRITICAL("last offset = 0x%llx\n", (unsigned long long)last_offset);
            goto end;
        }
    }

end:

    if (ret) {
        PRINTF_CRITICAL("info : %s not in read %s \n", target_name, pac_file_name);
        *out_size = 0;
        *out_offset = 0;
    }

    return ret;
}

static int write_sparse_file(int fd, uint64_t img_size, uint64_t img_offset,
                             int partition_fd, uint64_t partition_size)
{
    int ret = -1;
    uint64_t out_pos = 0;
    sparse_header_t sparse_header  = {0};
    chunk_header_t chunk_header    = {0};
    uint32_t chunk = 0;
    uint64_t chunk_data_sz_remain  = 0;
    uint64_t read_len = MAX_CALLOC_SIZE;
    uint32_t total_blocks   = 0;
    uint64_t chunk_data_sz  = 0;
    uint32_t fill_value = 0;
    uint64_t cnt = 0;
    uint8_t *buf = NULL;
    uint64_t file_storage_size = 0;

    if (fd < 0 || partition_fd < 0) {
        PRINTF_CRITICAL("write sparse file para error\n");
        goto end;
    }

#if RUN_IN_QNX

    if (lseek(fd, img_offset, SEEK_SET) != img_offset) {
#else

    if (lseek64(fd, img_offset, SEEK_SET) != img_offset) {
#endif
        PRINTF_CRITICAL("file lseek failed: err = %s\n", strerror(errno));
        goto end;
    }

    buf = (uint8_t *)MEM_ALIGN(512, MAX_CALLOC_SIZE);

    if (!buf) {
        PRINTF_CRITICAL("write sparse file calloc failed\n");
        goto end;
    }

    if (sizeof(sparse_header_t) != read(fd, buf, sizeof(sparse_header_t))) {
        PRINTF_CRITICAL("sparse file read sparse head error\n");
        goto end;
    }

    memcpy(&sparse_header, buf, sizeof(sparse_header_t));

    if (!sparse_header.blk_sz || (sparse_header.blk_sz % 4096)) {
        PRINTF_CRITICAL("sparse file block size error:%u\n", sparse_header.blk_sz);
        goto end;
    }

    file_storage_size = (uint64_t)(sparse_header.total_blks * sparse_header.blk_sz);

    if ( file_storage_size > partition_size) {
        PRINTF_CRITICAL("sparse file too large :%llu, limited %llu\n",
                        (unsigned long long)file_storage_size,
                        (unsigned long long)partition_size);
        goto end;
    }

    if (sparse_header.file_hdr_sz != sizeof(sparse_header_t)) {
        PRINTF_CRITICAL("sparse file image header error!\n");
        goto end;
    }

    PRINTF_INFO("=== Sparse Image Header ===\n");
    PRINTF_INFO("magic: 0x%x\n", sparse_header.magic);
    PRINTF_INFO("major_version: 0x%x\n", sparse_header.major_version);
    PRINTF_INFO("minor_version: 0x%x\n", sparse_header.minor_version);
    PRINTF_INFO("file_hdr_sz: %d\n", sparse_header.file_hdr_sz);
    PRINTF_INFO("chunk_hdr_sz: %d\n", sparse_header.chunk_hdr_sz);
    PRINTF_INFO("blk_sz: %d\n", sparse_header.blk_sz);
    PRINTF_INFO("total_blks: %d\n", sparse_header.total_blks);
    PRINTF_INFO("total_chunks: %d\n", sparse_header.total_chunks);

    cnt = file_storage_size / MAX_CALLOC_SIZE;
    read_len = MAX_CALLOC_SIZE;

    /* Start processing chunks */
    for (chunk = 0; chunk < sparse_header.total_chunks; chunk++) {
        /* Make sure the total image size does not exceed the partition size */
        if (((uint64_t)total_blocks * (uint64_t)sparse_header.blk_sz) >=
                partition_size) {
            PRINTF_CRITICAL("image 0x%llx too large, limited size 0x%llx \n",
                            (unsigned long long)(total_blocks * sparse_header.blk_sz),
                            (unsigned long long)partition_size);
            goto end;
        }

        if (sizeof(chunk_header_t) != read(fd, buf, sizeof(chunk_header_t))) {
            PRINTF_CRITICAL("sparse file read chunk head error, chunk = %d\n", chunk);
            goto end;
        }

        memcpy(&chunk_header, buf, sizeof(chunk_header_t));
#if DEBUGMODE
        PRINTF_INFO("=== Chunk Header ===\n");
        PRINTF_INFO("chunk %d\n", chunk);
        PRINTF_INFO("chunk_type: 0x%x\n", chunk_header.chunk_type);
        PRINTF_INFO("chunk_sz: 0x%x\n", chunk_header.chunk_sz);
        PRINTF_INFO("total_size: 0x%x\n", chunk_header.total_sz);
#endif

        if (sparse_header.chunk_hdr_sz != sizeof(chunk_header_t)) {
            PRINTF_CRITICAL("chunk header error:%u!\n", sparse_header.chunk_hdr_sz);
            goto end;
        }

        chunk_data_sz = (uint64_t)sparse_header.blk_sz * chunk_header.chunk_sz;

        /* Make sure that the chunk size calculated from sparse image does not
         * exceed partition size
         */
        out_pos = (uint64_t)total_blocks * (uint64_t)sparse_header.blk_sz;

        if ((out_pos + chunk_data_sz > partition_size) || (out_pos > partition_size)) {
            PRINTF_CRITICAL("calculate size: %lx\n",
                            (unsigned long)(out_pos + chunk_data_sz));
            PRINTF_CRITICAL("limited partition size: %lx\n", (unsigned long)partition_size);
            goto end;
        }

#if DEBUGMODE
        PRINTF_INFO("write offset: 0x%llx\n", (unsigned long long)out_pos);
        PRINTF_INFO("write block cnt: %d\n", total_blocks);
#endif

        switch (chunk_header.chunk_type) {
            case CHUNK_TYPE_RAW:
                if ((uint64_t)chunk_header.total_sz != ((uint64_t) sparse_header.chunk_hdr_sz +
                                                        chunk_data_sz)) {
                    PRINTF_CRITICAL("chunk size:%lu error!\n", (unsigned long)chunk_data_sz);
                    goto end;
                }

                if ((uint64_t)total_blocks + (uint64_t)(chunk_header.chunk_sz) > UINT32_MAX) {
                    PRINTF_CRITICAL("chunk = %d chunk size:%u error!\n", chunk,
                                    chunk_header.chunk_sz);
                    goto end;
                }

                PRINTF_INFO("chunk_data_sz: 0x%lx\n", (unsigned long)chunk_data_sz);
                cnt = chunk_data_sz / MAX_CALLOC_SIZE;
                chunk_data_sz_remain = chunk_data_sz % MAX_CALLOC_SIZE;
                read_len = MAX_CALLOC_SIZE;

                for (uint64_t i = 0; i < cnt + 1; i++) {
                    if (i == cnt) {
                        if (chunk_data_sz_remain)
                            read_len = chunk_data_sz_remain;
                        else
                            break;
                    }

                    if (read_len != read(fd, buf, read_len)) {
                        PRINTF_CRITICAL("sparse file read raw data chunk error, chunk = %d\n", chunk);
                        goto end;
                    }

                    if (read_len != partition_dev_write(partition_fd, buf, read_len)) {
                        PRINTF_CRITICAL("flash storage error\n");
                        goto end;
                    }

                    out_pos += read_len;
                }

                break;

            case CHUNK_TYPE_FILL:
                if ((uint64_t)total_blocks + (uint64_t)(chunk_header.chunk_sz) > UINT32_MAX) {
                    PRINTF_CRITICAL("chunk = %d chunk size:%u error!\n", chunk,
                                    chunk_header.chunk_sz);
                    goto end;
                }

                if (chunk_header.total_sz != (sparse_header.chunk_hdr_sz + sizeof(uint32_t))) {
                    PRINTF_CRITICAL("fill type error, size:%u!\n", chunk_header.total_sz);
                    goto end;
                }

                if (4 != read(fd, buf, 4)) {
                    PRINTF_CRITICAL("sparse file read fill data chunk error, chunk = %d\n", chunk);
                    goto end;
                }

                memcpy(&fill_value, buf, 4);
                cnt = chunk_data_sz / MAX_CALLOC_SIZE;
                chunk_data_sz_remain = chunk_data_sz % MAX_CALLOC_SIZE;
                read_len = MAX_CALLOC_SIZE;

                if ((0 != (MAX_CALLOC_SIZE % 4)) || (0 != (chunk_data_sz_remain % 4))) {
                    PRINTF_CRITICAL("data align error\n");
                    goto end;
                }

                PRINTF_INFO("chunk_data_sz: 0x%lx fill_value 0x%04x\n",
                            (unsigned long)chunk_data_sz,
                            fill_value);

                for (uint64_t i = 0; i < cnt + 1; i++) {
                    if (i == cnt) {
                        if (chunk_data_sz_remain)
                            read_len = chunk_data_sz_remain;
                        else
                            break;
                    }

                    for (uint64_t j = 0 ; j < read_len; j = j + 4) {
                        *(uint32_t *)(buf + j) = fill_value;
                    }

                    if (read_len != partition_dev_write(partition_fd, buf, read_len)) {
                        PRINTF_CRITICAL("flash storage error\n");
                        goto end;
                    }

                    out_pos += read_len;
                }

                break;

            case CHUNK_TYPE_DONT_CARE:
                if ((uint64_t)total_blocks + (uint64_t)(chunk_header.chunk_sz) > UINT32_MAX) {
                    PRINTF_CRITICAL("chunk = %d chunk size:%u error!\n", chunk,
                                    chunk_header.chunk_sz);
                    goto end;
                }

                cnt = chunk_data_sz / MAX_CALLOC_SIZE;
                chunk_data_sz_remain = chunk_data_sz % MAX_CALLOC_SIZE;
                read_len = MAX_CALLOC_SIZE;

                PRINTF_INFO("chunk_data_sz: 0x%lx\n", (unsigned long)chunk_data_sz);
                memset(buf, 0, MAX_CALLOC_SIZE);

                for (uint64_t i = 0; i < cnt + 1; i++) {
                    if (i == cnt) {
                        if (chunk_data_sz_remain)
                            read_len = chunk_data_sz_remain;
                        else
                            break;
                    }

                    if (read_len != partition_dev_write(partition_fd, buf, read_len)) {
                        PRINTF_CRITICAL("flash storage error\n");
                        goto end;
                    }

                    out_pos += read_len;
                }

                break;

            case CHUNK_TYPE_CRC:
                if (chunk_header.total_sz != sparse_header.chunk_hdr_sz) {
                    PRINTF_CRITICAL("crc type chunk total size:%u error!\n", chunk_header.total_sz);
                    goto end;
                }

                if ((uint64_t)total_blocks + (uint64_t)(chunk_header.chunk_sz) > UINT32_MAX) {
                    PRINTF_CRITICAL("chunk size:%u error!\n", chunk_header.chunk_sz);
                    goto end;
                }

                break;

            default:
                PRINTF_CRITICAL("Unkown chunk type: %x\n", chunk_header.chunk_type);
                goto end;
        }

        total_blocks += chunk_header.chunk_sz;

    }

    if (total_blocks != sparse_header.total_blks) {
        PRINTF_CRITICAL(" total block:%u error!\n", total_blocks);
        goto end;
    }

    ret = 0;
end:

    if (buf)
        FREE(buf);

    return ret;
}

static int write_file_in_pac_to_partition(char *file, uint64_t img_size,
        uint64_t img_offset, int partition_fd, uint64_t partition_size)
{
    uint64_t cnt = 0;
    uint64_t left = 0;
    uint8_t *read_buf = NULL;
    uint8_t  sparse_head[sizeof(sparse_header_t)] = {0};
    uint64_t read_len = MAX_CALLOC_SIZE;
    int ret = -1;
    uint64_t i = 0;
    int fd = 0;
    struct stat fstat;
    uint64_t file_size = img_size;

    if (stat(file, &fstat) < 0) {
        PRINTF_CRITICAL("stat %s error\n", file);
        goto end;
    }

    if (file_size > partition_size) {
        PRINTF_CRITICAL("image size = %lld too large, limited partition_size = %lld\n",
                        (unsigned long long)img_size, (unsigned long long)partition_size);
        goto end;
    }

    fd = open(file, O_RDONLY);

    if (fd < 0) {
        PRINTF_CRITICAL("open file %s error %s\n", file, strerror(errno));
        goto end;
    }

#if RUN_IN_QNX

    if (lseek(fd, img_offset, SEEK_SET) !=  img_offset) {
#else

    if (lseek64(fd, img_offset, SEEK_SET) !=  img_offset) {
#endif
        PRINTF_CRITICAL("file lseek failed: err = %s\n", strerror(errno));
        goto end;
    }

    if (sizeof(sparse_header_t) != read(fd, sparse_head, sizeof(sparse_header_t))) {
        PRINTF_INFO("file read head failed err = %s\n", strerror(errno));
        goto end;
    }

    if ((*(uint32_t *)sparse_head == SPARSE_HEADER_MAGIC) &&
            (*(uint16_t *)(sparse_head + 8)  == sizeof(sparse_header_t)) &&
            (*(uint16_t *)(sparse_head + 10) == sizeof(chunk_header_t))) {
        PRINTF_INFO("write pac in sparse mode\n");
        ret = write_sparse_file(fd, img_size, img_offset, partition_fd, partition_size);
    }
    else {
        PRINTF_INFO("write pac in normal mode\n");
        read_buf = (uint8_t *)MEM_ALIGN(512, MAX_CALLOC_SIZE);

        if (!read_buf) {
            PRINTF_CRITICAL("blk_write_with_check calloc failed\n");
            goto end;
        }

        cnt = file_size / MAX_CALLOC_SIZE;
        left = file_size % MAX_CALLOC_SIZE;
        read_len = MAX_CALLOC_SIZE;

#if RUN_IN_QNX

        if (lseek(fd, img_offset, SEEK_SET) != img_offset) {
#else

        if (lseek64(fd, img_offset, SEEK_SET) != img_offset) {
#endif
            PRINTF_CRITICAL("file lseek failed: err = %s\n", strerror(errno));
            goto end;
        }

        for (i = 0; i < cnt + 1; i++) {
            if (i == cnt) {
                if (left)
                    read_len = left;
                else
                    break;
            }

            if (read_len != read(fd, read_buf, read_len)) {
                PRINTF_INFO("file read failed err = %s\n", strerror(errno));
                goto end;
            }

#if DEBUGMODE
            PRINTF_CRITICAL("partition_dev_seek 0x%llx read_len = 0x%llx\n",
                            (unsigned long long)(partition_dev_seek(partition_fd, 0, SEEK_CUR)),
                            (unsigned long long)read_len);
            partition_dev_dump(partition_fd);
#endif

            if (read_len != partition_dev_write(partition_fd, read_buf, read_len)) {
                partition_dev_dump(partition_fd);
                PRINTF_CRITICAL("write failed\n");
                goto end;
            }
        }

        ret = 0;
    }

end:
    if (read_buf)
        FREE(read_buf);

    if (fd > 0)
        close(fd);

    return ret;
}

static long time_elapsed_us(struct timeval start, struct timeval end)
{
    return (end.tv_sec - start.tv_sec) * (1000000) + end.tv_usec - start.tv_usec;
}

static int read_time_test(char* partition_name, char* test_file)
{
    int ret = -1;
    uint64_t cnt = 0;
    uint64_t left = 0;
    uint64_t read_size = 0;
    char file[MAX_GPT_NAME_SIZE] = {0};
    uint64_t len =  0;
    uint8_t *buf = NULL;
    int fd = -1;
    int fd_file = -1;
    struct stat fstat;
    uint32_t each_read_size = rw_size;
    struct timeval start_time, end_time;
    int flags = (O_RDWR | O_NONBLOCK);

    if(!partition_name) {
        PRINTF_CRITICAL("partition_name for read is null\n");
        goto end;
    }

    fd = partition_dev_open(partition_name, flags,  0);

    if (fd <= 0) {
        PRINTF_CRITICAL("partition_dev_open failed");
        goto end;
    }

    len = partition_dev_blockdevsize(fd);

    if (!len) {
        PRINTF_CRITICAL("partition_dev_blockdevsize failed");
        goto end;
    }

    if(test_file) {
        snprintf(file, MAX_GPT_NAME_SIZE, "%s", test_file);
        PRINTF_INFO("test file name is %s\n", file);
        fd_file = open(file, O_RDWR | O_CREAT | O_TRUNC, 0777);

        if (fd_file <= 0) {
            PRINTF_CRITICAL("open file %s error %s\n", file, strerror(errno));
            goto end;
        }

        if (stat(file, &fstat) < 0) {
            PRINTF_CRITICAL("stat %s error\n", file);
            goto end;
        }

#if RUN_IN_QNX
        if (lseek(fd_file, 0, SEEK_SET) < 0)
#else
        if (lseek64(fd_file, 0, SEEK_SET) < 0)
#endif
        {
            PRINTF_CRITICAL("file lseek failed: err = %s\n", strerror(errno));
            goto end;
        }
    }
    else {
        PRINTF_INFO("no test file mode\n");
    }

    cnt = len / each_read_size;
    left = len % each_read_size;
    PRINTF_CRITICAL("each rw size = 0x%x, start to read...\n", (uint32_t)each_read_size);
    PRINTF_CRITICAL("read %s len = %lld cnt %lld\n", partition_name,
                     (unsigned long long)len, (unsigned long long)cnt);

    buf = (uint8_t *)MEM_ALIGN(512, each_read_size);

    if (!buf) {
        PRINTF_CRITICAL("memalign failed: %s\n",  strerror(errno));
        goto end;
    }

    pure_read_time = 0;
    read_ddr_copy_time = 0;
    read_hash_time = 0;
    seek_time = 0;
    finish_read_time = 0;
    gettimeofday(&start_time, NULL);

    /* seek to 0 */
    partition_dev_seek(fd, 0, SEEK_SET);

    for (uint64_t i = 0; i <= cnt; i++) {
        read_size = (i != cnt) ? each_read_size : left;

        if (read_size) {
            /* read */
            if (read_size != partition_dev_read(fd, buf, read_size)) {
                PRINTF_CRITICAL("read error");
                goto end;
            }

            /* write to target file */
            if ((fd_file > 0) && (read_size != write(fd_file, buf, read_size))) {
                PRINTF_CRITICAL("write file");
                goto end;
            }
        }
    }

    gettimeofday(&end_time, NULL);
    PRINTF_CRITICAL("len = %lld Byte, total time: %fs\n", (unsigned long long)len, time_elapsed_us(start_time, end_time)/1000000.0);
    PRINTF_CRITICAL("|----pure_read_time: %fs\n", pure_read_time/1000000.0);
    PRINTF_CRITICAL("|----finish_read_time: %fs\n", finish_read_time/1000000.0);
    PRINTF_CRITICAL("|----seek_time: %fs\n", seek_time/1000000.0);
    PRINTF_CRITICAL("|----read_ddr_copy_time: %fs\n", read_ddr_copy_time/1000000.0);
    PRINTF_CRITICAL("|----read_hash_time: %fs\n", read_hash_time/1000000.0);
    PRINTF_CRITICAL("total read speed = %fMB/s, pure read speed = %fMB/s \n",
            len*1000000.0/(time_elapsed_us(start_time, end_time)*1048576.0),
            len*1000000.0/(pure_read_time *1048576.0));
    ret = 0;
end:

    if (buf)
        free(buf);

    if (fd > 0)
        partition_dev_close(fd);

    if (fd_file > 0)
        close(fd_file);

    return ret;
}

static int write_time_test(char* partition_name, char* test_file)
{
    int ret = -1;
    uint64_t cnt = 0;
    uint64_t left = 0;
    uint64_t read_size = 0;
    char file[MAX_GPT_NAME_SIZE] = {0};
    uint64_t len =  0;
    uint8_t *buf = NULL;
    int fd = -1;
    int fd_file = -1;
    struct stat fstat;
    uint32_t each_write_size = rw_size;
    int flags = (O_RDWR | O_NONBLOCK);
    struct timeval start_time, end_time;

    if(!partition_name) {
        PRINTF_CRITICAL("partition_name for write is null\n");
        goto end;
    }

    fd = partition_dev_open(partition_name, flags,  0);

    if (fd <= 0) {
        PRINTF_CRITICAL("partition_dev_open failed\n");
        goto end;
    }

    len = partition_dev_blockdevsize(fd);

    if (!len) {
        PRINTF_CRITICAL("partition_dev_blockdevsize failed\n");
        goto end;
    }

    if(test_file) {
        snprintf(file, MAX_GPT_NAME_SIZE, "%s", test_file);
        PRINTF_INFO("test file name is %s\n", file);
        if (stat(file, &fstat) < 0) {
            PRINTF_CRITICAL("stat %s error\n", file);
            goto end;
        }

        fd_file = open(file, O_RDONLY);

        if (fd_file <= 0) {
            PRINTF_CRITICAL("open file %s error %s\n", file, strerror(errno));
            goto end;
        }

#if RUN_IN_QNX
        if (lseek(fd_file, 0, SEEK_SET) < 0)
#else
        if (lseek64(fd_file, 0, SEEK_SET) < 0)
#endif
        {
            PRINTF_CRITICAL("file lseek failed: err = %s\n", strerror(errno));
            goto end;
        }

        if (fstat.st_size > len) {
            PRINTF_CRITICAL("file too large\n");
            goto end;
        }

        len = fstat.st_size;

        PRINTF_CRITICAL("file size = %lld\n", (unsigned long long)fstat.st_size);
    }
    else {
        PRINTF_INFO("no test file mode\n");
    }

    cnt = len / each_write_size;
    left = len % each_write_size;
    PRINTF_CRITICAL("each rw size = 0x%x, start to write...\n", (uint32_t)each_write_size);
    PRINTF_CRITICAL("write %s len = %lld cnt %lld\n", partition_name,
                     (unsigned long long)len, (unsigned long long)cnt);

    buf = (uint8_t *)MEM_ALIGN(512, each_write_size);

    if (!buf) {
        PRINTF_CRITICAL("memalign failed: %s\n",  strerror(errno));
        goto end;
    }

    PRINTF_CRITICAL("start to write...\n");

    pure_write_time = 0;
    write_ddr_copy_time = 0;
    write_hash_time = 0;
    seek_time = 0;
    write_info_time = 0;
    gettimeofday(&start_time, NULL);

    /* seek to 0 */
    partition_dev_seek(fd, 0, SEEK_SET);

    for (uint64_t i = 0; i <= cnt; i++) {
        read_size = (i != cnt) ? each_write_size : left;

        if (read_size) {
            /* read file */
            if ((fd_file > 0) && (read_size != read(fd_file, buf, read_size))) {
                PRINTF_CRITICAL("write file");
                goto end;
            }

            /* write */
            if (read_size != partition_dev_write(fd, buf, read_size)) {
                PRINTF_CRITICAL("pread error");
                goto end;
            }
        }
    }

    gettimeofday(&end_time, NULL);
    PRINTF_CRITICAL("len = %lld Byte, total time: %fs\n", (unsigned long long)len, time_elapsed_us(start_time, end_time)/1000000.0);
    PRINTF_CRITICAL("|----pure_write_time: %fs\n", pure_write_time/1000000.0);
    PRINTF_CRITICAL("|----seek_time: %fs\n", seek_time/1000000.0);
    PRINTF_CRITICAL("|----write_info_time: %fs\n", write_info_time/1000000.0);
    PRINTF_CRITICAL("|----write_ddr_copy_time: %fs\n", write_ddr_copy_time/1000000.0);
    PRINTF_CRITICAL("|----write_hash_time: %fs\n", write_hash_time/1000000.0);
    PRINTF_CRITICAL("write speed = %fMB/s, pure write speed = %fMB/s \n",
            len*1000000.0/(time_elapsed_us(start_time, end_time)*1048576.0),
            len*1000000.0/(pure_write_time*1048576.0));

    ret = 0;
end:

    if (buf)
        free(buf);

    if (fd > 0)
        partition_dev_close(fd);

    if (fd_file > 0)
        close(fd_file);

    return ret;
}
