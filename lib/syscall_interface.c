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

#define DEBUGMODE 0
#define _LARGEFILE64_SOURCE
#include <string.h>
#include <stdint.h>
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
#include "bpt.h"
#include "crc32.h"
#include "slots_parse.h"
#include "syscall_interface.h"
#include <assert.h>
#include <libgen.h>
#ifndef SYSCALL_DEBUG
#define SYSCALL_DEBUG DEBUGMODE
#endif


#define EMMC_BOOT0_FD   0xB000   //   "/dev/block/mmcblk0boot0"
#define EMMC_BOOT1_FD   0xB001   //   "/dev/block/mmcblk0boot1"


#define ANDROID_DYNAMIC_PARTITION_DEV_PREFFIX  "/dev/block/dm-"
update_fd_node_t empty_fd_node = {0};

#if 1
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
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

static int storage_switch_part_by_fd(storage_device_t *storage, int fd);

/* return name if not found */
static const char* transform_boot_partition_name(const char * name)
{
    const char *temp;
    uint32_t bpt_v = 0;

    bpt_v = get_bpt_version();
    if (bpt_v != BPT_V1 && bpt_v != BPT_V2) {
        return name;
    }

    if (bpt_v == BPT_V1) {
        temp = transform_emmc_boot_partition_name_bptv1(name);

        if (temp != name) {
            PRINTF_INFO("bpt v1 emmc dil partition name is changed to %s\n", temp);
            return temp;
        }

        temp = transform_ospi_boot_partition_name_bptv1(name);
        if (temp != name) {
            PRINTF_INFO("bpt v1 ospi dil partition name is changed to %s\n", temp);
            return temp;
        }

    }else if(bpt_v == BPT_V2) {
        temp = transform_emmc_boot_partition_name_bptv2(name);
        if (temp != name) {
            PRINTF_INFO("bpt v2 emmc dil partition name is changed to %s\n", temp);
            return temp;
        }

        temp = transform_ospi_boot_partition_name_bptv2(name);
        if (temp != name) {
            PRINTF_INFO("bpt v2 ospi dil partition name is changed to %s\n", temp);
            return temp;
        }
    }
    else {
        PRINTF_INFO("no bpt version find\n");
    }

    return name;
}

int get_partition_index_from_ptdev(partition_device_t *ptdev,
                                   const char *partition_name)
{
    int32_t index = INVALID_PTN;

    if (!ptdev || !(ptdev->storage)) {
        PRINTF_CRITICAL("ptdev or storage is NULL\n");
        goto end;
    }

    if (!partition_name) {
        PRINTF_CRITICAL("partition_name is NULL\n");
        goto end;
    }

    if ((STORAGE_REMOTE == ptdev->storage->type ) && (false == ptdev->local)) {
#if SYSCALL_DEBUG
        PRINTF_INFO("try to find partition [%s] in remote ptdev\n", partition_name);
#endif
        index = ptdev_get_index_remote(ptdev, partition_name);

        if (index == INVALID_PTN) {
#if SYSCALL_DEBUG
            PRINTF_INFO("can't find partition [%s] in remote ptdev\n", partition_name);
#endif
        }
    }
    else {
#if SYSCALL_DEBUG
        PRINTF_INFO("try to find partition [%s] in local ptdev\n", partition_name);
#endif
        index = ptdev_get_index(ptdev, partition_name);

        if (index == INVALID_PTN) {
#if SYSCALL_DEBUG
            PRINTF_INFO("can't find partition [%s] in local ptdev\n", partition_name);
#endif
        }
    }

    if ((INVALID_PTN == index) || (index >= NUM_PARTITIONS)) {
        return INVALID_PTN;
    }

#if SYSCALL_DEBUG
    PRINTF_INFO("find index = %d\n", index);
#endif

end:
    return (int)index;
}

uint64_t get_partition_size_from_ptdev(partition_device_t *ptdev,
                                       const char *partition_name)
{
    uint64_t size = 0;

    if (!ptdev || !(ptdev->storage)) {
        PRINTF_CRITICAL("ptdev or storage is NULL\n");
        goto end;
    }

    if (!partition_name) {
        PRINTF_CRITICAL("partition_name is NULL\n");
        goto end;
    }

    if ((STORAGE_REMOTE == ptdev->storage->type ) && (false == ptdev->local)) {
#if SYSCALL_DEBUG
        PRINTF_INFO("try to find partition [%s]'s size in remote ptdev\n",
                    partition_name);
#endif
        size = ptdev_get_size_remote(ptdev, partition_name);
    }
    else {
#if SYSCALL_DEBUG
        PRINTF_INFO("try to find partition [%s]'s size in local ptdev\n",
                    partition_name);
#endif
        size = ptdev_get_size(ptdev, partition_name);
    }

end:
    return size;
}

uint64_t get_partition_offset_from_ptdev(partition_device_t *ptdev,
        const char *partition_name)
{
    uint64_t offset = 0;

    if (!ptdev || !(ptdev->storage)) {
        PRINTF_CRITICAL("ptdev or storage is NULL\n");
        goto end;
    }

    if (!partition_name) {
        PRINTF_CRITICAL("partition_name is NULL\n");
        goto end;
    }

    if ((STORAGE_REMOTE == ptdev->storage->type ) && (false == ptdev->local)) {
#if SYSCALL_DEBUG
        PRINTF_CRITICAL("try to find partition [%s]'s offset in remote ptdev\n",
                        partition_name);
#endif
        offset = ptdev_get_offset_remote(ptdev, partition_name);
    }
    else {
#if SYSCALL_DEBUG
        PRINTF_CRITICAL("try to find partition [%s]'s offset in local ptdev\n",
                        partition_name);
#endif
        offset = ptdev_get_offset(ptdev, partition_name);
    }

end:
    return offset;
}

int get_storage_type_by_partition_name(char const *partition_name, int mode,
                                       int *out_val, int *out_cnt)
{
    int i = 0;
    int index = -1;
    bool dev[DEV_MAX] = {false};
    int index_count = 0;

    for (i = 0; i < DEV_MAX; i++) {
        dev[i] = false;
#if SYSCALL_DEBUG
        PRINTF_INFO("dev = %d, find step 1\n", i);
#endif

        if (!get_update_device_is_active(i)) {
            continue;
        }

#if SYSCALL_DEBUG
        PRINTF_INFO("dev = %d, find step 2\n", i);
#endif

        if (!get_update_device_storage(i)) {
            continue;
        }

#if SYSCALL_DEBUG
        PRINTF_INFO("dev = %d, find step 3\n", i);
#endif

        /* emmc boot0 partition */
        if ((i == DEV_EMMC0) && is_emmc_boot0(partition_name)) {
            PRINTF_INFO("boot0\n");
            dev[DEV_EMMC0] = true;
            index_count++;
            continue;
        }
        /* emmc boot1 partition */
        else if ((i == DEV_EMMC0) && is_emmc_boot1(partition_name)) {
            PRINTF_INFO("boot1\n");
            dev[DEV_EMMC0] = true;
            index_count++;
            continue;
        }

        if ((SYSCALL_FORCE_REMOTE == mode)
                && (STORAGE_LOCAL == get_update_device_storage_type(i))) {
            continue;
        }

#if SYSCALL_DEBUG
        PRINTF_INFO("dev = %d, find step 4\n", i);
#endif

        if ((SYSCALL_FORCE_LOCAL == mode)
                && (STORAGE_REMOTE == get_update_device_storage_type(i))) {
            continue;
        }

#if SYSCALL_DEBUG
        PRINTF_INFO("dev = %d, find step 5\n", i);
#endif

        if (check_ptdev_exist(i)) {
            PRINTF_CRITICAL("failed to init ptdev in %s\n", get_update_device_name(i));
            continue;
        }

        index = get_partition_index_from_ptdev(get_update_device_ptdev(i), partition_name);

        if ((index < 0) || (index >= NUM_PARTITIONS)) {
#if SYSCALL_DEBUG
            PRINTF_INFO("can't find fd from %s\n", get_update_device_name(i));
#endif
            continue;
        }

#if SYSCALL_DEBUG
        PRINTF_INFO("dev = %d, find step 6\n", i);
        PRINTF_INFO("find %s from %s, partition index = %d\n", partition_name,
                    get_update_device_name(i), index);
#endif
        dev[i] = true;
        index_count++;
    }

    if (index_count >= 1) {
        for (i = 0; i < DEV_MAX; i++) {
            if (true == dev[i]) {
                *out_val = i;
                *out_cnt = index_count;
                return 0;
            }
        }
    }

    *out_val = -1;
    *out_cnt = 0;
    return -1;
}

int check_partition_local_or_remote(char const *partition_name, int mode)
{
    int i = 0;
    int cnt[2] = {0};
    const char *name_raw = basename((char *)partition_name);
    int index = -1;

#if SYSCALL_DEBUG
    PRINTF_INFO("check_partition_local_or_remote\n");
#endif
    assert(STORAGE_LOCAL == 0);
    assert(STORAGE_REMOTE == 1);

    if (strlen(partition_name) > strlen(ANDROID_DYNAMIC_PARTITION_DEV_PREFFIX)) {
        if (!strncmp(partition_name, ANDROID_DYNAMIC_PARTITION_DEV_PREFFIX,
                     strlen(ANDROID_DYNAMIC_PARTITION_DEV_PREFFIX))) {
            PRINTF_INFO("%s is a device mapper(dm) device name, return local\n", partition_name);
            return STORAGE_LOCAL;
        }
    }

    /*
       for android14, update engine will try find partition name without "_a" or "_b" first, and we can't use
       transform_boot_partition_name() transform the partition string "mmcboot" or "ospiboot" to new partition name.
       So we force return a "remote result"
       (For android12 or androi10 update engine try open partition name with "_a" or "_b", "mmcboot_a/_b" or "ospiboot_a/_b" )
    */
    if (!strcmp(partition_name, DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V2)
        || !strcmp(partition_name, DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT0)
        || !strcmp(partition_name, DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT1)) {
        PRINTF_INFO("this an emmc dil partiton name, force return remote to use ota-lib only\n");
        return STORAGE_REMOTE;
    }

    if (!strcmp(partition_name, DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V2)
        || !strcmp(partition_name, DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT0)
        || !strcmp(partition_name, DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT0)) {
        PRINTF_INFO("this an ospi dil partiton name, force return remote to use ota-lib only\n");
        return STORAGE_REMOTE;
    }


    const char *name = transform_boot_partition_name(name_raw);

    PRINTF_INFO("raw name:[%s] transform to name = [%s], \n",name_raw, name);


    /* for partition name use mmcblk0boot0 mmcblk1boot0 mmcblk1boot0 mmcblk1boot1
       return STORAGE_LOCAL
       */
    if (is_emmc_boot0(name) || is_emmc_boot1(name)) {
        PRINTF_INFO("%s(raw name:%s) is an emmc boot name, force return remote to use ota-lib only\n", name, name_raw);
        return STORAGE_REMOTE;
    }

    for (i = 0; i < DEV_MAX; i++) {
#if DEBUGMODE
        PRINTF_INFO("i = %d\n", i);
#endif

        if (!get_update_device_is_active(i)) {
            continue;
        }

        if (!get_update_device_storage(i)) {
            continue;
        }

        if (STORAGE_LOCAL == get_update_device_storage_type(i)) {
            if (SYSCALL_FORCE_REMOTE == mode) {
                continue;
            }

            if (check_ptdev_exist(i)) {
                PRINTF_CRITICAL("failed to init ptdev in %s\n", get_update_device_name(i));
                continue;
            }

            index = get_partition_index_from_ptdev(get_update_device_ptdev(i), name);

            if ((index < 0) || (index >= NUM_PARTITIONS)) {
#if DEBUGMODE
                PRINTF_INFO("can't find fd from %s\n", get_update_device_name(i));
#endif
                continue;
            }

            cnt[STORAGE_LOCAL]++;
            PRINTF_INFO("find %s from %s cnt %d, partition index = %d\n", name,
                        get_update_device_name(i), cnt[STORAGE_LOCAL], index);
        }

        else if (STORAGE_REMOTE == get_update_device_storage_type(i)) {
            if (SYSCALL_FORCE_LOCAL == mode) {
                continue;
            }

            if (check_ptdev_exist(i)) {
                PRINTF_CRITICAL("failed to init ptdev in %s\n", get_update_device_name(i));
                continue;
            }

            index = get_partition_index_from_ptdev(get_update_device_ptdev(i), name);

            if ((index < 0) || (index >= NUM_PARTITIONS)) {
#if DEBUGMODE
                PRINTF_INFO("can't find fd from %s\n", get_update_device_name(i));
#endif
                continue;
            }

            cnt[STORAGE_REMOTE]++;
            PRINTF_INFO("find %s from %s cnt %d, partition index = %d\n", name,
                        get_update_device_name(i), cnt[STORAGE_REMOTE], index);
        }
    }

    if ((1 == cnt[STORAGE_LOCAL]) && (1 == cnt[STORAGE_REMOTE])) {
        PRINTF_INFO("%s(raw name:%s) is remote-or-local\n", name, name_raw);
        return STORAGE_REMOTE_LOCAL;
    }

    else if ((1 == cnt[STORAGE_LOCAL]) && (0 == cnt[STORAGE_REMOTE])) {
        PRINTF_INFO("%s(raw name:%s) is local\n", name, name_raw);
        return STORAGE_LOCAL;
    }
    else if ((0 == cnt[STORAGE_LOCAL]) && (1 == cnt[STORAGE_REMOTE])) {
        PRINTF_INFO("%s(raw name:%s) is remote\n", name, name_raw);
        return STORAGE_REMOTE;
    }
    else {
        PRINTF_CRITICAL("find %s error: remote is %d, local is %d\n", name, cnt[STORAGE_REMOTE],
                    cnt[STORAGE_LOCAL]);
        return STORAGE_ERROR;
    }

}

storage_device_t *get_storage_inst_by_id(int dev)
{
    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        return NULL;
    }

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage %d is not active\n", dev);
        return NULL;
    }

    return get_update_device_storage(dev);
}

char *get_storage_name_by_id(int dev)
{
    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        return NULL;
    }

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage %d is not active\n", dev);
        return NULL;
    }

    return get_update_device_name(dev);
}

static void fd_node_update_crc(update_fd_node_t *fd_node)
{

    uint32_t crc32_val = 0xFFFFFFFF;

    if (!fd_node) {
        PRINTF_CRITICAL("fd node is null\n");
        return;
    }

    crc32_val = crc32(0, (uint8_t *)fd_node, sizeof(update_fd_node_t) -4);
    fd_node->crc32 = crc32_val;

    return;
}

static void fd_node_destroy(update_fd_node_t *fd_node)
{
    memset((uint8_t *)fd_node, 0, sizeof(update_fd_node_t));
}

static int fd_node_check(update_fd_node_t *fd_node)
{
    int ret = -1;

    uint32_t crc32_val = 0xFFFFFFFF;

#if DEBUGMODE
    PRINTF_INFO("check for %s\n", fd_node->partition_name);
    PRINTF_INFO("fd_node->magic   = 0x%08x\n", fd_node->magic);
#endif

    if (!fd_node) {
        PRINTF_CRITICAL("fd node is null\n");
        goto end;
    }

    if (!memcmp((void *)&empty_fd_node, (void *)fd_node,
                sizeof(update_fd_node_t))) {
#if DEBUGMODE
        PRINTF_INFO("fd node is empty\n");
#endif
        goto end;
    }

    if (FD_NODE_STRUCT_MAGIC != fd_node->magic) {
        PRINTF_CRITICAL("fd node magic check error, fd_node->magic = 0x%08x , should be 0x4e4f4445\n",
                        fd_node->magic);
        goto dump;
    }


    if ((0 == fd_node->offset) && (FD_NODE_TYPE_EMMC_BOOT != fd_node->type)) {
        PRINTF_CRITICAL("fd node check error, fd_node->offset = 0x%llx\n",
                        (unsigned long long)fd_node->offset);
        goto dump;
    }

    if (0 == fd_node->size) {
        PRINTF_CRITICAL("fd node check error, fd_node->size = 0x%llx\n",
                        (unsigned long long)fd_node->size);
        goto dump;
    }

    crc32_val = crc32(0, (uint8_t *)fd_node, sizeof(update_fd_node_t) -4);

    if (fd_node->crc32 != crc32_val) {
        PRINTF_CRITICAL("fd node check error, fd_node->crc32 = 0x%x, calc crc32 = 0x%x\n\n",
                        fd_node->crc32, crc32_val);
        goto dump;
    }

    ret = 0;

dump:
#if DEBUGMODE

    if (ret) {
        PRINTF_INFO("------fd_node------\n");
        PRINTF_INFO("fd_node->magic   = 0x%08x\n", fd_node->magic);
        PRINTF_INFO("fd_node->name    = %s\n", fd_node->partition_name);
        PRINTF_INFO("fd_node->offset  = 0x%llx\n", (unsigned long long)fd_node->offset);
        PRINTF_INFO("fd_node->size    = 0x%llx\n", (unsigned long long)fd_node->size);
        PRINTF_INFO("fd_node->current = 0x%llx\n",
                    (unsigned long long)fd_node->current);
        PRINTF_INFO("fd_node->flags   = 0x%08x\n", fd_node->flags);
        PRINTF_INFO("fd_node->type    = 0x%08x\n", fd_node->type);
        PRINTF_INFO("fd_node->bpt_v   = 0x%08x\n", fd_node->bpt_v);
        PRINTF_INFO("fd_node->psn     = 0x%08x\n", fd_node->psn);
        PRINTF_INFO("fd_node->sec_ver     = 0x%08x\n", fd_node->sec_ver);
        PRINTF_INFO("fd_node->crc32   = 0x%08x\n", fd_node->crc32);
        PRINTF_INFO("fd_node dump as:\n");
        hexdump8((uint8_t *)fd_node, sizeof(update_fd_node_t));
    }

#endif

end:
    return ret;
}

static void fd_node_dump(update_fd_node_t *fd_node)
{
    if (!fd_node) {
        PRINTF_CRITICAL("fd node is null\n");
        return;
    }

    PRINTF_INFO("------fd_node------\n");
    PRINTF_INFO("fd_node->magic   = 0x%08x\n", fd_node->magic);
    PRINTF_INFO("fd_node->name    = %s\n", fd_node->partition_name);
    PRINTF_INFO("fd_node->offset  = 0x%llx\n", (unsigned long long)fd_node->offset);
    PRINTF_INFO("fd_node->size    = 0x%llx\n", (unsigned long long)fd_node->size);
    PRINTF_INFO("fd_node->current = 0x%llx\n",
                (unsigned long long)fd_node->current);
    PRINTF_INFO("fd_node->flags   = 0x%08x\n", fd_node->flags);
    PRINTF_INFO("fd_node->type    = 0x%08x\n", fd_node->type);
    PRINTF_INFO("fd_node->bpt_v   = 0x%08x\n", fd_node->bpt_v);
    PRINTF_INFO("fd_node->psn     = 0x%08x\n", fd_node->psn);
    PRINTF_INFO("fd_node->sec_ver     = 0x%08x\n", fd_node->sec_ver);
    PRINTF_INFO("fd_node->crc32   = 0x%08x\n", fd_node->crc32);

    if (fd_node_check(fd_node)) {
        PRINTF_CRITICAL("fd_node check failed\n");
    }
    else {
        PRINTF_INFO("fd_node check success\n");
    }
}

static void syscall_head_update(update_syscall_head_t *syscall_head)
{
    uint32_t crc32_val = 0;
    update_fd_node_t *fd_node = NULL;
    update_fd_node_t *fd_node_special = NULL;
    int limit = 0;
    int cnt = 0;

    if (!syscall_head) {
        PRINTF_CRITICAL("fd node is null\n");
        return;
    }

    if (syscall_head->magic != SYSCALL_HEAD_STRUCT_MAGIC) {
        syscall_head->magic = SYSCALL_HEAD_STRUCT_MAGIC;
    }

    fd_node = syscall_head->fd_node_arry;
    fd_node_special = syscall_head->boot_fd_node;
    for (limit = 0; limit < NUM_PARTITIONS; limit ++) {
        if ((fd_node[limit].magic != FD_NODE_STRUCT_MAGIC)
                || (fd_node_check(&fd_node[limit]))) {
#if 0
            PRINTF_CRITICAL("fd node %d magic 0x%08x error or crc error\n", limit,
                            fd_node[limit].magic);
#endif
            memset(&fd_node[limit], 0, sizeof(update_fd_node_t));
            continue;
        }

        //crc32_val = crc32(crc32_val, (uint8_t*)&(fd_node[limit].crc32), sizeof(fd_node[limit].crc32));
        cnt++;
    }
    for (limit = 0; limit < BOOT_FD_NODE_CNT; limit++) {
        if ((fd_node_special[limit].magic != FD_NODE_STRUCT_MAGIC)
                || (fd_node_check(&fd_node_special[limit]))) {
#if 0
            PRINTF_CRITICAL("fd node %d magic 0x%08x error or crc error\n", limit,
                            fd_node[limit].magic);
#endif
            memset(&fd_node_special[limit], 0, sizeof(update_fd_node_t));
            continue;
        }

        //crc32_val = crc32(crc32_val, (uint8_t*)&(fd_node[limit].crc32), sizeof(fd_node[limit].crc32));
        cnt++;
    }


#if DEBUGMODE

    if (0 == cnt) {
        PRINTF_CRITICAL("no fd node in syscall head\n");
    }

#endif

    if (cnt != syscall_head->fd_cnt) {
        syscall_head->fd_cnt = cnt;
    }

    crc32_val = crc32(crc32_val, (uint8_t *) & (syscall_head->magic),
                      sizeof(syscall_head->magic));
    //crc32_val = crc32(crc32_val, (uint8_t*)(syscall_head->partition_table_name), MAX_GPT_NAME_SIZE);
    crc32_val = crc32(crc32_val, (uint8_t *)(syscall_head->ptdev),
                      sizeof(syscall_head->ptdev));
    crc32_val = crc32(crc32_val, (uint8_t *) & (syscall_head->fd_cnt),
                      sizeof(syscall_head->fd_cnt));
    crc32_val = crc32(crc32_val, (uint8_t *) & (syscall_head->mode),
                      sizeof(syscall_head->fd_cnt));
    syscall_head->crc32 = crc32_val;
    return;
}

static int syscall_head_check(update_syscall_head_t *syscall_head)
{
    uint32_t crc32_val = 0;
    update_fd_node_t *fd_node = NULL;
    update_fd_node_t *fd_node_special = NULL;
    int limit = 0;
    int cnt = 0;

    if (!syscall_head) {
        PRINTF_CRITICAL("syscall head is null\n");
        goto end;
    }

    if (syscall_head->magic != SYSCALL_HEAD_STRUCT_MAGIC) {
        PRINTF_CRITICAL("syscall head magic 0x%08x error\n", syscall_head->magic);
        goto end;
    }

    fd_node = syscall_head->fd_node_arry;
    fd_node_special = syscall_head->boot_fd_node;
    for (limit = 0; limit < NUM_PARTITIONS; limit ++) {
        if ((fd_node[limit].magic != FD_NODE_STRUCT_MAGIC)
                || (fd_node_check(&fd_node[limit]))) {
#if 0
            PRINTF_CRITICAL("fd node %d magic 0x%08x error or crc error\n", limit,
                            fd_node[limit].magic);
#endif
            continue;
        }

#if 0
        crc32_val = crc32(crc32_val, (uint8_t *) & (fd_node[limit].crc32),
                          sizeof(fd_node[limit].crc32));
#endif
        cnt++;
    }
    for (limit = 0; limit < BOOT_FD_NODE_CNT; limit ++) {
        if ((fd_node_special[limit].magic != FD_NODE_STRUCT_MAGIC)
                || (fd_node_check(&fd_node_special[limit]))) {
#if 0
            PRINTF_CRITICAL("fd node %d magic 0x%08x error or crc error\n", limit,
                            fd_node[limit].magic);
#endif
            continue;
        }

#if 0
        crc32_val = crc32(crc32_val, (uint8_t *) & (fd_node[limit].crc32),
                          sizeof(fd_node[limit].crc32));
#endif
        cnt++;
    }

#if DEBUGMODE

    if (0 == cnt) {
        PRINTF_CRITICAL("no fd node in syscall head\n");
    }

#endif

    if (cnt != syscall_head->fd_cnt) {
        PRINTF_CRITICAL("syscall fd cnt is %d, but calc cnt is %d, error\n", cnt,
                        syscall_head->fd_cnt);
        goto end;
    }

    if (!syscall_head->ptdev) {
        PRINTF_CRITICAL("syscall ptdev error\n");
        goto end;
    }

#if 0

    if (!syscall_head->partition_table_name) {
        PRINTF_CRITICAL("syscall partition name error\n");
        goto end;
    }

    crc32_val = crc32(crc32_val, (uint8_t *)(syscall_head->partition_table_name),
                      MAX_GPT_NAME_SIZE);
#endif

    crc32_val = crc32(crc32_val, (uint8_t *) & (syscall_head->magic),
                      sizeof(syscall_head->magic));
    crc32_val = crc32(crc32_val, (uint8_t *)(syscall_head->ptdev),
                      sizeof(syscall_head->ptdev));
    crc32_val = crc32(crc32_val, (uint8_t *) & (syscall_head->fd_cnt),
                      sizeof(syscall_head->fd_cnt));
    crc32_val = crc32(crc32_val, (uint8_t *) & (syscall_head->mode),
                      sizeof(syscall_head->fd_cnt));

    if (syscall_head->crc32 != crc32_val) {
        PRINTF_CRITICAL("syscall crc error, syscall_head->crc32 = 0x%08x, but calc crc is 0x%08x\n",
                        syscall_head->crc32, crc32_val);
        goto end;
    }

    return 0;

end:
    return -1;
}

static void syscall_head_destroy(update_syscall_head_t *syscall_head)
{
    int i = 0;

    if (syscall_head) {
        for (i = 0; i < DEV_MAX; i++) {
            if (!get_update_device_is_active(i)) {
                continue;
            }

            if (syscall_head == get_syscall_head(i)) {
                set_syscall_head(i, NULL);
                break;
            }
        }

        FREE(syscall_head);
    }

    return;
}

static update_syscall_head_t *syscall_head_init(int dev,
        const char *partition_table_name, partition_device_t *ptdev, int mode)
{
    update_syscall_head_t *syscall_head = NULL;

    if ((dev < 0) || (dev >= DEV_MAX)) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        goto fail;
    }

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage id %d is not active\n", dev);
        goto fail;
    }

    if (!partition_table_name || !ptdev
            || (strlen(partition_table_name) >= MAX_GPT_NAME_SIZE)) {
        PRINTF_CRITICAL("init para error while init syscall head\n");
        goto fail;
    }

    syscall_head = (update_syscall_head_t *)MEM_ALIGN(512,
                   sizeof(update_syscall_head_t));

    if (!syscall_head) {
        PRINTF_CRITICAL("Error MEM_ALIGN memory while init syscall head\n");
        goto fail;
    }

    memset(syscall_head, 0, sizeof(update_syscall_head_t));
    syscall_head->magic = SYSCALL_HEAD_STRUCT_MAGIC;
    syscall_head->ptdev = ptdev;
    syscall_head->fd_cnt = 0;
    syscall_head->mode = mode;
    snprintf(syscall_head->partition_table_name, MAX_GPT_NAME_SIZE, "%s",
             partition_table_name);
    syscall_head_update(syscall_head);
    set_syscall_head(dev, syscall_head);
    return syscall_head;

fail:
    syscall_head_destroy(syscall_head);
    return NULL;
}

static void syscall_head_dump(update_syscall_head_t *syscall_head)
{
    update_fd_node_t *fd_node = NULL;
    update_fd_node_t *fd_node_special = NULL;
    int limit = 0;

    if (!syscall_head) {
        PRINTF_CRITICAL("syscall head is null\n");
        return;
    }

    PRINTF_INFO("------syscall head------\n");
    PRINTF_INFO("syscall_head->magic    = 0x%08x\n", syscall_head->magic);
    PRINTF_INFO("syscall_head->gpt_name = %s\n",
                syscall_head->partition_table_name);
    PRINTF_INFO("syscall_head->fd_cnt   = %d\n", syscall_head->fd_cnt);
    PRINTF_INFO("syscall_head->mode     = %d\n", syscall_head->mode);
    PRINTF_INFO("syscall_head->crc32    = 0x%08x\n", syscall_head->crc32);
    fd_node = syscall_head->fd_node_arry;
    fd_node_special = syscall_head->boot_fd_node;
    if (syscall_head_check(syscall_head)) {
        PRINTF_CRITICAL("syscall check failed\n");
    }
    else {
        PRINTF_INFO("syscall check success\n\n");
    }

    for (limit = 0; limit < NUM_PARTITIONS; limit ++) {
        if ((fd_node[limit].magic != FD_NODE_STRUCT_MAGIC)
                || (fd_node_check(&fd_node[limit]))) {
            continue;
        }

        fd_node_dump(&fd_node[limit]);
    }
    for (limit = 0; limit < BOOT_FD_NODE_CNT; limit ++) {
        if ((fd_node_special[limit].magic != FD_NODE_STRUCT_MAGIC)
                || (fd_node_check(&fd_node_special[limit]))) {
            continue;
        }

        fd_node_dump(&fd_node_special[limit]);
    }
}

static int remove_fd_node(int dev_fd)
{
    int dev;
    int fd;
    update_syscall_head_t *syscall_head = NULL;
    update_fd_node_t *fd_node = NULL;

    dev = (dev_fd >> 16) & 0xFFFF;

    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        goto end;
    }

    fd = dev_fd & 0xFFFF;

    syscall_head = get_syscall_head(dev);

    if (!syscall_head) {
        PRINTF_CRITICAL("syscall_head is NULL\n");
        goto end;
    }

    if (syscall_head_check(syscall_head)) {
        PRINTF_CRITICAL("syscall_head check error\n");
        goto free_syscall_buffer;
    }

    switch (fd)
    {
        case EMMC_BOOT0_FD:
            fd_node = &(syscall_head->boot_fd_node[0]);
            break;

        case EMMC_BOOT1_FD:
            fd_node = &(syscall_head->boot_fd_node[1]);
            break;

        default:
            if (fd < 0 || fd >= NUM_PARTITIONS) {
                PRINTF_CRITICAL("fd number too big %d\n", fd);
                goto end;
            }
            fd_node = &(syscall_head->fd_node_arry[fd]);
            break;
    }

    if (fd_node_check(fd_node)) {
        PRINTF_CRITICAL("fd node check error\n");
        goto end;
    }

    fd_node_destroy(fd_node);
    syscall_head->fd_cnt--;
    syscall_head_update(syscall_head);
    return 0;

free_syscall_buffer:
    syscall_head_destroy(syscall_head);

end:
    return -1;
}

static int put_fd_node(int dev_fd, update_fd_node_t *fd_node)
{
    int dev;
    int fd;
    update_syscall_head_t *syscall_head = NULL;

    dev = (dev_fd >> 16) & 0xFFFF;

    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        goto end;
    }

    fd = dev_fd & 0xFFFF;

    syscall_head = get_syscall_head(dev);

    if (!syscall_head || !fd_node) {
        PRINTF_CRITICAL("syscall_head or fd_node is NULL\n");
        goto end;
    }

    if (fd_node_check(fd_node)) {
        PRINTF_CRITICAL("fd node check error dev_fd = 0x%x\n", dev_fd);
        goto end;
    }

    if (syscall_head_check(syscall_head)) {
        PRINTF_CRITICAL("syscall_head check error\n");
        goto free_syscall_buffer;
    }

    switch (fd)
    {
        case EMMC_BOOT0_FD:
            memcpy(&(syscall_head->boot_fd_node[0]), fd_node, sizeof(update_fd_node_t));
            break;

        case EMMC_BOOT1_FD:
            memcpy(&(syscall_head->boot_fd_node[1]), fd_node, sizeof(update_fd_node_t));

            break;

        default:
            if (fd < 0 || fd >= NUM_PARTITIONS) {
                PRINTF_CRITICAL("fd number too big %d\n", fd);
                goto end;
            }

            memcpy(&(syscall_head->fd_node_arry[fd]), fd_node, sizeof(update_fd_node_t));
            break;
    }


    syscall_head->fd_cnt++;
    syscall_head_update(syscall_head);

    return 0;

free_syscall_buffer:
    syscall_head_destroy(syscall_head);

end:
    return -1;
}

static update_fd_node_t *get_fd_node(int dev_fd)
{
    int dev;
    int fd;
    update_syscall_head_t *syscall_head = NULL;
    update_fd_node_t *fd_node = NULL;

    dev = (dev_fd >> 16) & 0xFFFF;

    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        goto end;
    }

    fd = dev_fd & 0xFFFF;

    syscall_head = get_syscall_head(dev);

    if (!syscall_head) {
        PRINTF_CRITICAL("syscall_head %d is null\n", dev);
        goto end;
    }

    if (syscall_head_check(syscall_head)) {
        PRINTF_CRITICAL("syscall_head check error\n");
        goto free_syscall_buffer;
    }

#if DEBUGMODE
    PRINTF_CRITICAL("fd is %d\n", fd);
#endif

    switch (fd)
    {
        case EMMC_BOOT0_FD:
            fd_node = &(syscall_head->boot_fd_node[0]);
            break;

        case EMMC_BOOT1_FD:
            fd_node = &(syscall_head->boot_fd_node[1]);
            break;

        default:
            if (fd < 0 || fd >= NUM_PARTITIONS) {
                PRINTF_CRITICAL("fd number too big %d\n", fd);
                goto end;
            }
            fd_node = &(syscall_head->fd_node_arry[fd]);
            break;
    }

    if (fd_node_check(fd_node)) {
        if (fd_node->magic != 0x00000000) {
            PRINTF_CRITICAL("fd_node check error\n");
        }

        goto end;
    }

    return fd_node;

free_syscall_buffer:
    syscall_head_destroy(syscall_head);

end:
    return NULL;
}
static bool check_bpt_crc32(const uint8_t *bpt_buf, uint32_t crc32_off)
{
    uint32_t crc32_orig = 0, crc32_calc = 0;
    crc32_orig = *((uint32_t *)(bpt_buf + crc32_off));
    crc32_calc = sd_crc32(0, bpt_buf, crc32_off);
        PRINTF_CRITICAL("crc32_orig:0x%x crc32_calc:0x%x\n", crc32_orig, crc32_calc);
    return ((crc32_orig != 0 ) && (crc32_orig == crc32_calc));
}
static uint32_t get_bpt_info(partition_device_t *ptdev, const char* partition_name,
                             uint32_t *out_psn, int fd, int boot_part_type)
{
    uint8_t *bpt_buf = NULL;
    uint32_t bpt_v = 0, bpt_sz, crc32_off = 0;
    storage_device_t * storage;
    uint64_t off = 0;

    storage = ptdev->storage;
    *out_psn = 0;
    bpt_sz = MAX(BPT_V1_SZ, BPT_V2_SZ);
    bpt_buf = calloc(1, bpt_sz);
    if (!bpt_buf)
    {
        PRINTF_CRITICAL("Fail to allocate memory for BPT\n");
        goto end;
    }

    if(boot_part_type == FD_NODE_TYPE_EMMC_BOOT
        && storage_switch_part_by_fd(storage, fd) != 0) {
        PRINTF_CRITICAL("failed to switch part for boot fd:%d\n", fd);
        goto end;

    }else if ((boot_part_type == FD_NODE_TYPE_OSPI_BOOT) ||
        (boot_part_type == FD_NODE_TYPE_EMMC_PEERLOAD_BOOT) ||
        (boot_part_type == FD_NODE_TYPE_OSPI_PEERLOAD_BOOT)) {
        off = get_partition_offset_from_ptdev(ptdev, partition_name);
        if (0 == off) {
            PRINTF_CRITICAL("offset of partition %s errno\n", partition_name);
            goto end;
        }
    }
    else {
        PRINTF_CRITICAL("boot part_type %d unkown\n", boot_part_type);
        goto end;
    }

    if (storage->read(storage, off, bpt_buf, bpt_sz) != 0) {
        PRINTF_CRITICAL("block dev read failed for boot fd: %d\n", fd);
        goto end;
    }

    bpt_v = *((uint32_t *)bpt_buf);

    if (bpt_v == BPT_V2) {
        bpt_sz = BPT_V2_SZ;
        crc32_off = BPT_V2_CRC_OFF;
    }
    else if(bpt_v == BPT_V1) {
        bpt_sz = BPT_V1_SZ;
        crc32_off = BPT_V1_CRC_OFF;
    }
    else{
        PRINTF_CRITICAL("Invalid BPT magic for partition_name %s, boot_part_type %d\n", partition_name, boot_part_type);
        bpt_v = 0;
        hexdump8(bpt_buf, bpt_sz);
        goto end;
    }
    if (!check_bpt_crc32(bpt_buf, crc32_off)){
        PRINTF_CRITICAL("BPT crc32 error partition_name %s, boot_part_type %d\n", partition_name, boot_part_type);
        bpt_v = 0;
        hexdump8(bpt_buf, bpt_sz);
        goto end;
    }

    if (bpt_v == BPT_V2){
        *out_psn = *((uint32_t*)(bpt_buf + BPT_PSN_OFF));
    }

end:
    if (bpt_buf)
        free(bpt_buf);

    return bpt_v;
}

//partition_name may with "_a" or "_b" suffix or maybe not
//peerload_dil_partition_name without "_a" or "_b" suffix or maybe not
static bool is_peerload_dil_partition_name(const char *partition_name, const char * peerload_dil_partition_name)
{
    int len;
    int len_peerload_dil_partition_name;

    if(!partition_name || !peerload_dil_partition_name) {
        return false;
    }

    if(!strcmp(partition_name, peerload_dil_partition_name)) {
        return true;
    }
    else {
        len = strlen(partition_name);
        len_peerload_dil_partition_name = strlen(peerload_dil_partition_name);

        if (len <= 2) {
            return false;
        }

        /* case 1: length of partition_name("dil_safety_a") is length of peerload_dil_partition_name ("dil_safety"） + 2 */
        /* case 2: length of partition_name("dil_safety"）eqaul to length of peerload_dil_partition_name ("dil_safety"）*/
        if(len != len_peerload_dil_partition_name + 2) {
            return false;
        }

        if(strncmp(partition_name, peerload_dil_partition_name, len - 2)) {
            return false;
        }

        /* need "_a: or "_b" suffix */
        if(strcmp((char *)(partition_name + len - 2), suffix_slot[0]) && strcmp((char *)(partition_name + len - 2), suffix_slot[1])) {
            return false;
        }

        return true;
    }
}

int init_fd_node(update_fd_node_t *fd_node, const char *partition_name,
                 partition_device_t *ptdev, int flags)
{
    const char* cur_boot_name;
    int ret = -1, part_type, current_boot_slot;
    uint64_t offset = 0;
    uint64_t size = 0;
    uint32_t psn = 0;
    uint32_t bpt_v;
    uint32_t rollback_index_from_bootloader = 0;
    uint32_t bpt_version_from_bootloader = 0;

    if (!partition_name || !ptdev) {
        PRINTF_CRITICAL("partition name error or ptdev is null\n");
        goto end;
    }

    size = get_partition_size_from_ptdev(ptdev, partition_name);

    if (0 == size) {
        PRINTF_CRITICAL("size of partition %s errno\n", partition_name);
        goto end;
    }

    offset = get_partition_offset_from_ptdev(ptdev, partition_name);

    if (0 == offset) {
        PRINTF_CRITICAL("offset of partition %s errno\n", partition_name);
        goto end;
    }

    part_type = FD_NODE_TYPE_NORMAL;

    /* ospi boot partitions are
       1. "dil"
       2. "dil_bak"
    */
    if (!strcmp(partition_name, ospi_boot0_name) || !strcmp(partition_name, ospi_boot1_name)) {
        part_type = FD_NODE_TYPE_OSPI_BOOT;
    }

    /* ospi peerload boot partitions are
       1. "dil_safety_a"
       2. "dil_safety_b"
       3. "dil_safety" (non-ab system)
    */
    else if(is_peerload_dil_partition_name(partition_name, ospi_peerload_boot_name)) {
        part_type = FD_NODE_TYPE_OSPI_PEERLOAD_BOOT;
    }

    /* emmc peerload boot partitions are
       1. dil_sec_a
       2. dil_sec_b
       3. dil_sec (non-ab system)
    */
    else if(is_peerload_dil_partition_name(partition_name, emmc_peerload_boot_name)) {
        part_type = FD_NODE_TYPE_EMMC_PEERLOAD_BOOT;
    }

    /* get cmdline para */
    bpt_version_from_bootloader = get_bpt_version();
    if((bpt_version_from_bootloader != BPT_V2) && (bpt_version_from_bootloader != BPT_V1)) {
        PRINTF_CRITICAL("Invalid bpt version from bootloader:0x%0x\n", bpt_version_from_bootloader);
        goto end;
    }

    /* check these partition: dil/dil_bak/dil_sec_a/dil_sec_b/dil_safety_a/dil_safety_b */
    if(part_type != FD_NODE_TYPE_NORMAL) {

        switch (part_type)
        {
            /* For boot partition name is  "dil" or "dil_bak" :
                roll 1: the psn of new dil_safemust be larger than current dil_safe */
            case FD_NODE_TYPE_OSPI_BOOT:
                current_boot_slot = get_current_ospi_dil();
                if(current_boot_slot == SELECT_BOOT0) {
                    cur_boot_name = ospi_boot0_name;
                }
                else if(current_boot_slot == SELECT_BOOT1) {
                    cur_boot_name = ospi_boot1_name;
                }
                else {
                    PRINTF_CRITICAL("current boot slot is %d, but when dil or dil_bak partition exist, boot slot is %d or %d\n",
                        current_boot_slot, SELECT_BOOT0, SELECT_BOOT1);
                    goto end;
                }

                if(fd_node->bpt_v == BPT_V2) {
                    bpt_v = get_bpt_info(ptdev, cur_boot_name, &psn, 0, part_type);
                    if (bpt_v != bpt_version_from_bootloader) {
                        PRINTF_CRITICAL("Invalid bpt version from storage:0x%0x\n", bpt_v);
                        goto end;
                    }
                }

            /* notice: no break here. so "dil" or "dil_bak" run forward */

            /* For boot partition  "dil" or "dil_bak"  and peerload partiton "dil_safety_a/b" or "dil_sec_a/b":
                roll 2:  The new updated dil's secure version is not allowed to be less than the current rollback index */

            case FD_NODE_TYPE_OSPI_PEERLOAD_BOOT:
            case FD_NODE_TYPE_EMMC_PEERLOAD_BOOT:
                rollback_index_from_bootloader = get_rollback_index();
                if(rollback_index_from_bootloader < 0) {
                    PRINTF_CRITICAL("Invalid rollback_index from bootloader:%d\n", rollback_index_from_bootloader);
                    goto end;
                }

                break;
            default:
                    PRINTF_CRITICAL("invalid part_type:%d\n", part_type);
                    goto end;
                break;
        }
    }

    memset(fd_node, 0, sizeof(update_fd_node_t));
    fd_node->magic = FD_NODE_STRUCT_MAGIC;
    fd_node->offset = offset;
    fd_node->size = size;
    fd_node->current = 0;
    fd_node->flags = flags;
    fd_node->type = part_type;
    fd_node->bpt_v = bpt_version_from_bootloader;
    fd_node->psn = psn;
    fd_node->sec_ver = rollback_index_from_bootloader;
    snprintf(fd_node->partition_name, MAX_GPT_NAME_SIZE, "%s", partition_name);
    fd_node_update_crc(fd_node);
    ret = 0;

end:
    return ret;
}

static int init_boot_fd_node(update_fd_node_t *fd_node, const char *partition_name,
                 partition_device_t *ptdev, int flags)
{
    int ret = -1, current_boot_slot, cur_fd;
    uint32_t bpt_v = 0;
    uint32_t psn = 0;
    uint64_t size = 0;
    uint32_t bpt_version_from_bootloader = 0;
    uint32_t rollback_index_from_bootloader = 0;

    if (!partition_name || !ptdev) {
        PRINTF_CRITICAL("partition name error or ptdev is null\n");
        goto end;
    }

    /* emmc boot0 partition */
    if (is_emmc_boot0(partition_name)) {
        size = ptdev->storage->boot0_capacity;
    }
    /* emmc boot1 partition */
    else if (is_emmc_boot1(partition_name)) {
        size = ptdev->storage->boot1_capacity;
    }
    else {
        PRINTF_CRITICAL("boot name error\n");
        goto end;
    }

    if (0 == size) {
        PRINTF_CRITICAL("size of emmc boot %s errno\n", partition_name);
        goto end;
    }

    bpt_version_from_bootloader = get_bpt_version();
    if((bpt_version_from_bootloader != BPT_V2) && (bpt_version_from_bootloader != BPT_V1)) {
        PRINTF_CRITICAL("Invalid bpt version from bootloader:0x%0x\n", bpt_version_from_bootloader);
        goto end;
    }

    /* For BPT v2 and BPT v1
     * secure version should large than current rollback index
     */
    rollback_index_from_bootloader = get_rollback_index();
    if(rollback_index_from_bootloader < 0) {
        PRINTF_CRITICAL("Invalid rollback_index from bootloader:%d\n", rollback_index_from_bootloader);
        goto end;
    }

    current_boot_slot = get_current_emmc_dil();


    if(current_boot_slot == SELECT_BOOT0) {
        cur_fd =EMMC_BOOT0_FD;
    }
    else if(current_boot_slot == SELECT_BOOT1)  {
        cur_fd =EMMC_BOOT1_FD;
    }
    else {
        PRINTF_CRITICAL("Fail to get current emmc boot info\n");
        goto end;
    }

    /* For BPT v2,
     * the psn of new dil_sec must be larger than current dil_dec
     */
    if(fd_node->bpt_v == BPT_V2) {
        bpt_v = get_bpt_info(ptdev, partition_name, &psn, cur_fd, FD_NODE_TYPE_EMMC_BOOT);
        if (bpt_v != bpt_version_from_bootloader)
        {
            PRINTF_CRITICAL("Invalid bpt version:0x%0x\n", bpt_v);
            goto end;
        }
    }

    memset(fd_node, 0, sizeof(update_fd_node_t));
    fd_node->magic = FD_NODE_STRUCT_MAGIC;
    fd_node->offset = 0;
    fd_node->size = size;
    fd_node->current = 0;
    fd_node->flags = flags;
    fd_node->type = FD_NODE_TYPE_EMMC_BOOT;
    fd_node->bpt_v = bpt_version_from_bootloader;
    fd_node->psn = psn;
    fd_node->sec_ver = rollback_index_from_bootloader;
    snprintf(fd_node->partition_name, MAX_GPT_NAME_SIZE, "%s", partition_name);
    fd_node_update_crc(fd_node);
    ret = 0;

end:
    return ret;
}

static int storage_switch_part_by_fd(storage_device_t *storage, int fd)
{
    int part;

    if (!storage) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if((storage->support_switch_part == true) && (storage->switch_part)) {
        switch (fd)
        {
            case EMMC_BOOT0_FD:
                part = SELECT_BOOT0;
                break;

            case EMMC_BOOT1_FD:
                part = SELECT_BOOT1;
                break;

            default:
                part = SELECT_USERDATA;
                break;
        }

        if (storage->switch_part(storage, part) != 0) {
            PRINTF_CRITICAL("storage %s switch part to %d error\n", storage->dev_name, part);
            return -1;
        }
        return 0;
    }
    return 0;
}

int partition_dev_open(const char *path, int flags, mode_t mode)
{
    partition_device_t *ptdev = NULL;
    update_syscall_head_t *syscall_head = NULL;
    update_fd_node_t *fd_node = NULL;
    update_fd_node_t  fd_node_temp = {0};
    int dev = -1;
    int fd = -1;
    char *raw_partition_name = basename((char *)path);
    int dev_cnt = 0;
    bool boot_fd = false;

    const char *partition_name = transform_boot_partition_name(raw_partition_name);

    PRINTF_INFO("try to open partition name = [%s], raw name:[%s]\n", partition_name, raw_partition_name);

    if (strlen(partition_name) >= MAX_GPT_NAME_SIZE) {
        PRINTF_CRITICAL("partition_name string %s too long\n", partition_name);
        goto fail;
    }

    /* get the storage type from a partition name string */
    if (0 != get_storage_type_by_partition_name(partition_name, (int)mode, &dev,
            &dev_cnt)) {
        PRINTF_CRITICAL("can not find %s in any storage device\n", partition_name);
        goto fail;
    }

    if (dev < 0 || dev >= DEV_MAX || dev_cnt != 1) {
        PRINTF_CRITICAL("dev id %d or more than one dev find, cnt = %d\n", dev,
                        dev_cnt);
        goto fail;
    }

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage id %d is not active\n", dev);
        goto fail;
    }

    fd_node = &fd_node_temp;
    /* if syscall_head is empty, get init a syscall_head and init a fd_node */
    syscall_head = get_syscall_head(dev);
    ptdev = get_update_device_ptdev(dev);
    assert(ptdev);

    if (syscall_head_check(syscall_head)) {
#if DEBUGMODE
        PRINTF_INFO("try to init a syscall_head[%d]\n", dev);
#endif
        /* if syscall_head has error, so destroy it first */
        syscall_head_destroy(syscall_head);
        /* init a syscall_head */
        syscall_head = syscall_head_init(dev, get_storage_name_by_id(dev), ptdev,
                                         (int)mode);

        if (!syscall_head) {
            PRINTF_CRITICAL("failed to init syscall head\n");
            goto fail;
        }
    }

    assert(syscall_head);

    /* emmc boot0 partition */
    if (is_emmc_boot0(partition_name)) {
        dev = DEV_EMMC0;
        fd = EMMC_BOOT0_FD;
        boot_fd = true;
    }

    /* emmc boot1 partition */
    else if (is_emmc_boot1(partition_name)) {
        dev = DEV_EMMC0;
        fd = EMMC_BOOT1_FD;
        boot_fd = true;
    }

    if(boot_fd == false) {
        /* get fd from ptdev */
        fd = get_partition_index_from_ptdev(ptdev, partition_name);

        if ((fd < 0) || (fd >= NUM_PARTITIONS)) {
            PRINTF_CRITICAL("failed to get fd from ptdev\n");
            goto fail;
        }

        /* init a fd node */
        if (init_fd_node(fd_node, partition_name, ptdev, flags)) {
            PRINTF_CRITICAL("failed init fd node for %s\n", partition_name);
            goto fail;
        }
    }
    else {
        /* init a fd node */
        if (init_boot_fd_node(fd_node, partition_name, ptdev, flags)) {
            PRINTF_CRITICAL("failed init boot fd node for %s\n", partition_name);
            goto fail;
        }
    }

    /* put this fd node into syscall head */
    if (put_fd_node(((dev << 16) | fd), fd_node)) {
        PRINTF_CRITICAL("put fd: 0x%x error\n", ((dev << 16) | fd));
        goto fail;
    }

#if DEBUGMODE
    PRINTF_INFO("final fd = %d\n", (dev << 16) + fd);
#endif
    return ((dev << 16) + fd);

#if 0
free_ptdev:
    free_storage_dev(ptdev);
#endif

fail:
    return -1;
}

ssize_t partition_dev_read(int dev_fd, void *buf, size_t count)
{
    update_fd_node_t *fd_node = get_fd_node(dev_fd);

    if (!fd_node) {
        PRINTF_CRITICAL("fd_node error\n");
        return -1;
    }

    if (count != partition_dev_pread(dev_fd, buf, count, fd_node->current)) {
        PRINTF_CRITICAL("block dev read failed for fd node: %s\n",
                        fd_node->partition_name);
        return -1;
    }
#if DEBUGMODE
    PRINTF_INFO("read address 0x%llx size 0x%llx for fd_dev = %d \n",
                (unsigned long long)(fd_node->current + fd_node->offset),
                (unsigned long long)count, dev_fd);
#endif
    fd_node->current += count;
    fd_node_update_crc(fd_node);

    return count;
}

ssize_t partition_dev_pread(int dev_fd, void *buf, size_t count, int64_t offset)
{
    int dev;
    int fd;
    ssize_t ret = -1;
    storage_device_t *storage = NULL;
    update_fd_node_t *fd_node = NULL;

    if (!buf) {
        PRINTF_CRITICAL("read buffer is null\n");
        goto end;
    }

    dev = (dev_fd >> 16) & 0xFFFF;
    fd = dev_fd & 0xFFFF;

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage id %d is not active\n", dev);
        goto end;
    }

    fd_node = get_fd_node(dev_fd);

    if (!fd_node) {
        PRINTF_CRITICAL("fd_node error %d\n", fd);
        goto end;
    }

    if (O_WRONLY == (fd_node->flags & 0x3)) {
        PRINTF_CRITICAL("%s flags = 0x%08x, write only\n", fd_node->partition_name,
                        fd_node->flags);
        goto end;
    }

    storage = get_storage_inst_by_id(dev);

    if (!storage) {
        PRINTF_CRITICAL("failed to get storage inst for fd node: %s\n",
                        fd_node->partition_name);
        goto end;
    }

    if ((offset + count) > fd_node->size) {
        PRINTF_CRITICAL("read size error for fd node: %s, offset(0x%llx) + count(0x%llx) = 0x%llx > fd_node->size(0x%llx)\n",
                        \
                        fd_node->partition_name, \
                        (unsigned long long)(offset), \
                        (unsigned long long)count, \
                        (unsigned long long)(offset + count), \
                        (unsigned long long)(fd_node->size));
        goto end;
    }

    if(storage_switch_part_by_fd(storage, fd) != 0) {
        PRINTF_CRITICAL("failed to switch part for fd node: %s fd: %d\n", fd_node->partition_name, fd);
        goto end;
    }

    ret = storage->read(storage, offset + fd_node->offset, buf, count);

    if (ret != 0) {
        PRINTF_CRITICAL("block dev read failed for fd node: %s\n",
                        fd_node->partition_name);
        goto end;
    }
#if DEBUGMODE
    PRINTF_INFO("pread address 0x%llx size 0x%llx for fd_dev = %d \n",
                (unsigned long long)(offset + fd_node->offset),
                (unsigned long long)count, dev_fd);
#endif
    return count;

end:
    return -1;
}

ssize_t partition_dev_write(int dev_fd, const void *buf, size_t count)
{
    uint32_t crc32_off;
    uint32_t sec_ver;
    uint32_t bpt_v;
    uint32_t psn;
    uint32_t bpt_size;
    update_fd_node_t *fd_node = get_fd_node(dev_fd);

    if (!fd_node) {
        PRINTF_CRITICAL("fd_node error\n");
        return -1;
    }

    /* The first pack of boot partition data, it must contain the whole BPT data */
    if (fd_node->type != FD_NODE_TYPE_NORMAL && fd_node->current == 0)
    {
        /* For BPT , the size of buffer must be larger than BPT_SZ */
        bpt_size = (fd_node->bpt_v == BPT_V2) ? BPT_V2_SZ : BPT_V1_SZ;
        if (count < bpt_size)
        {
            PRINTF_CRITICAL("Fait to write boot partition, invalid size\n");
            return -1;
        }

        bpt_v = *((uint32_t *)buf);
        if (bpt_v != fd_node->bpt_v)
        {
            PRINTF_CRITICAL("Fail to write boot partition, invalid bpt version:0x%0x, name:%s\n", bpt_v, fd_node->partition_name);
            return -1;
        }

        crc32_off = (fd_node->bpt_v == BPT_V2) ? BPT_V2_CRC_OFF : BPT_V1_CRC_OFF;
        if (!check_bpt_crc32(buf, crc32_off)){
            PRINTF_CRITICAL("BPT crc32 error\n");
            return -1;
        }

        if((fd_node->bpt_v == BPT_V2) && ((fd_node->type == FD_NODE_TYPE_OSPI_BOOT) || (fd_node->type == FD_NODE_TYPE_EMMC_BOOT))) {
            psn = *((uint32_t*)((uint8_t *)buf + BPT_PSN_OFF));
            PRINTF_INFO("new psn:0x%x old psn:0x%x\n", psn, fd_node->psn);
            if (psn <= fd_node->psn) {
                PRINTF_CRITICAL("new psn:0x%x isn't larger than old psn:0x%x\n", psn, fd_node->psn);
                return -1;
            }
        }

        sec_ver = *((uint32_t*)((uint8_t *)buf + BPT_SEC_VER_OFF));
        PRINTF_INFO("new sec_ver:0x%x, system sec_ver(rollback index) 0x%x\n", sec_ver, fd_node->sec_ver);
        if (sec_ver < fd_node->sec_ver) {
            PRINTF_CRITICAL("The value of new sec_ver:0x%x is not allowed to be less than system sec_ver(rollback index):0x%x\n", sec_ver, fd_node->sec_ver);
            return -1;
        }

    }

    if (count != partition_dev_pwrite(dev_fd, buf, count, fd_node->current)) {
        PRINTF_CRITICAL("block dev write failed for fd_node %s\n",
                        fd_node->partition_name);
        return -1;
    }
#if DEBUGMODE
    PRINTF_INFO("write address 0x%llx size 0x%llx for fd_dev = %d \n",
                (unsigned long long)(fd_node->current + fd_node->offset),
                (unsigned long long)count, dev_fd);
#endif
    fd_node->current += count;
    fd_node_update_crc(fd_node);
    return count;
}

ssize_t partition_dev_pwrite(int dev_fd, const void *buf, size_t count,
                             int64_t offset)
{
    int dev;
    int fd;
    ssize_t ret = -1;
    storage_device_t *storage = NULL;
    update_fd_node_t *fd_node = NULL;

    if (!buf) {
        PRINTF_CRITICAL("write buffer is null\n");
        goto end;
    }

    dev = (dev_fd >> 16) & 0xFFFF;
    fd = dev_fd & 0xFFFF;

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage id %d is not active\n", dev);
        goto end;
    }

    fd_node = get_fd_node(dev_fd);

    if (!fd_node) {
        PRINTF_CRITICAL("fd_node error %d\n", fd);
        goto end;
    }

    if (O_RDONLY == (fd_node->flags & 0x3)) {
        PRINTF_CRITICAL("%s flags = 0x%08x, read only\n", fd_node->partition_name,
                        fd_node->flags);
        goto end;
    }

    storage = get_storage_inst_by_id(dev);

    if (!storage) {
        PRINTF_CRITICAL("failed to get storage inst for fd_node %s\n",
                        fd_node->partition_name);
        goto end;
    }

    if ((offset + count) > fd_node->size) {
        PRINTF_CRITICAL("write size error for fd_node %s, offset(0x%llx) + count(0x%llx) = 0x%llx > fd_node->size(0x%llx)\n",
                        \
                        fd_node->partition_name, \
                        (unsigned long long)(offset), \
                        (unsigned long long)count, \
                        (unsigned long long)(offset + count), \
                        (unsigned long long)(fd_node->size));
        goto end;
    }

    if(storage_switch_part_by_fd(storage, fd) != 0) {
        PRINTF_CRITICAL("failed to switch part for fd node: %s fd: %d\n", fd_node->partition_name, fd);
        goto end;
    }

    if (fd_node->type == FD_NODE_TYPE_NORMAL){
        ret = storage->write(storage, offset + fd_node->offset, buf, count);
    }else{
        ret = storage->write_with_check(storage, offset + fd_node->offset, buf, count);
    }

    if (ret != 0) {
        PRINTF_CRITICAL("block dev write failed for fd_node %s\n",
                        fd_node->partition_name);
        goto end;
    }
#if DEBUGMODE
    PRINTF_INFO("pwrite address 0x%llx size 0x%llx for fd_dev = %d \n",
                (unsigned long long)(offset + fd_node->offset),
                (unsigned long long)count, dev_fd);
#endif
    return count;

end:
    return -1;
}

static int get_file_length(char *file, uint64_t *write_size)
{
    int ret = -1;
    uint8_t sparse_head[sizeof(sparse_header_t)] = {0};
    struct stat fstat;
    int file_fd = -1;

    if (!write_size || !file) {
        PRINTF_CRITICAL("para error\n");
        goto end;
    }

    if (stat(file, &fstat) < 0) {
        PRINTF_CRITICAL("stat %s error\n", file);
        goto end;
    }

    file_fd = open(file, O_RDONLY);

    if (file_fd < 0) {
        PRINTF_CRITICAL("open file %s error %s\n", file, strerror(errno));
        goto end;
    }

#if RUN_IN_QNX

    if (lseek(file_fd, 0, SEEK_SET) < 0) {
#else

    if (lseek64(file_fd, 0, SEEK_SET) < 0) {
#endif
        PRINTF_CRITICAL("file lseek failed: err = %s\n", strerror(errno));
        goto end;
    }

    if (sizeof(sparse_header_t) != read(file_fd, (uint8_t *)sparse_head,
                                        sizeof(sparse_header_t))) {
        PRINTF_CRITICAL("file read head failed err = %s\n", strerror(errno));
        goto end;
    }

    if ((*(uint32_t *)sparse_head == SPARSE_HEADER_MAGIC) &&
            (*(uint16_t *)(sparse_head + 8)  == sizeof(sparse_header_t)) &&
            (*(uint16_t *)(sparse_head + 10) == sizeof(chunk_header_t))) {
        *write_size = (uint64_t)(((sparse_header_t *)sparse_head)->total_blks * ((
                                     sparse_header_t *)sparse_head)->blk_sz);
    }
    else {
        *write_size = fstat.st_size;
    }

    ret = 0;

end:

    if (file_fd)
        close(file_fd);

    return ret;
}

ssize_t partition_dev_write_file(int dev_fd, char *file)
{
    int dev;
    int fd;
    ssize_t ret = -1;
    storage_device_t *storage = NULL;
    update_fd_node_t *fd_node = NULL;
    uint64_t write_size = 0;

    dev = (dev_fd >> 16) & 0xFFFF;

    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        goto end;
    }

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage id %d is not active\n", dev);
        goto end;
    }

    fd = dev_fd & 0xFFFF;

    fd_node = get_fd_node(dev_fd);

    if (!fd_node) {
        PRINTF_CRITICAL("fd_node error %d\n", fd);
        goto end;
    }

    if ((FD_NODE_TYPE_EMMC_BOOT != fd_node->type) && (fd < 0 || fd >= NUM_PARTITIONS)) {
        PRINTF_CRITICAL("fd number too big %d\n", fd);
        goto end;
    }

    if (O_RDONLY == (fd_node->flags & 0x3)) {
        PRINTF_CRITICAL("%s flags = 0x%08x, read only\n", fd_node->partition_name,
                        fd_node->flags);
        goto end;
    }

    storage = get_storage_inst_by_id(dev);

    if (!storage) {
        PRINTF_CRITICAL("failed to get storage inst for fd_node %s\n",
                        fd_node->partition_name);
        goto end;
    }

    if (get_file_length(file, &write_size)) {
        PRINTF_CRITICAL("fail to get file %s length\n", file);
        goto end;
    }

    if ((fd_node->current + write_size) > fd_node->size) {
        PRINTF_CRITICAL("write size error for fd_node %s, fd_node->current(0x%llx) + file_size(0x%llx) = 0x%llx > fd_node->size(0x%llx)\n",
                        \
                        fd_node->partition_name, \
                        (unsigned long long)(fd_node->current), \
                        (unsigned long long)write_size, \
                        (unsigned long long)(fd_node->current + write_size), \
                        (unsigned long long)(fd_node->size));
        goto end;
    }

    if(storage_switch_part_by_fd(storage, fd) != 0) {
        PRINTF_CRITICAL("failed to switch part for fd node: %s fd: %d\n", fd_node->partition_name, fd);
        goto end;
    }

    ret = storage->write_file(storage, fd_node->current + fd_node->offset,
                              (fd_node->size - fd_node->current), file, 0);

    if (ret != 0) {
        PRINTF_CRITICAL("block dev read failed for fd_node %s",
                        fd_node->partition_name);
        goto end;
    }

#if DEBUGMODE
    PRINTF_INFO("write address 0x%llx size 0x%llx for fd_dev = %d \n",
                (unsigned long long)(fd_node->current + fd_node->offset),
                (unsigned long long)write_size, dev_fd);
#endif

    fd_node->current += write_size;
    fd_node_update_crc(fd_node);
    return (ssize_t)write_size;
end:
    return -1;
}

#if 0
int partition_dev_write_file(int dev_fd, char *file)
{
    uint64_t cnt = 0;
    uint64_t left = 0;
    uint8_t *read_buf = NULL;
    uint64_t read_len = FILE_READ_LENGTH;
    int ret = -1;
    uint64_t i = 0;
    int fd = 0;
    struct stat fstat;
    uint64_t file_size = 0;
    uint64_t partition_size = 0;

    if ((stat(file, &fstat) < 0) || !fstat.st_size) {
        PRINTF_CRITICAL("stat %s error\n", file);
        goto end;
    }

    partition_size = partition_dev_blockdevsize(dev_fd);

    if (fstat.st_size > partition_size) {
        PRINTF_CRITICAL("file = %lld too large, limited file size = %lld\n",
                        (unsigned long long)fstat.st_size, (unsigned long long)partition_size);
        goto end;
    }

    file_size = fstat.st_size;
    fd = open(file, O_RDONLY);

    if (fd <= 0) {
        PRINTF_CRITICAL("open file %s error %s\n", file, strerror(errno));
        goto end;
    }

    PRINTF_CRITICAL("write file to partition write size = %lld\n",
                    (unsigned long long)read_len);
    read_buf = (uint8_t *)MEM_ALIGN(512, read_len);

    if (!read_buf) {
        PRINTF_CRITICAL("memalign failed\n");
        goto end;
    }

    cnt = file_size / read_len;
    left = file_size % read_len;

#if RUN_IN_QNX

    if (lseek(fd, 0, SEEK_SET) < 0) {
#else

    if (lseek64(fd, 0, SEEK_SET) < 0) {
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
            PRINTF_CRITICAL("file read failed err = %s\n", strerror(errno));
            goto end;
        }

        if (read_len != partition_dev_write(dev_fd, read_buf, read_len)) {
            PRINTF_CRITICAL("write failed\n");
            goto end;
        }
    }

    ret = 0;
end:

    if (read_buf)
        FREE(read_buf);

    if (fd > 0)
        close(fd);

    return ret;
}

#endif

int64_t partition_dev_seek(int dev_fd, int64_t offset, int whence)
{
    int dev;
    int fd;
    ssize_t ret = -1;
    storage_device_t *storage = NULL;
    update_fd_node_t *fd_node = NULL;

    dev = (dev_fd >> 16) & 0xFFFF;


    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        goto end;
    }

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage id %d is not active\n", dev);
        goto end;
    }

    fd = dev_fd & 0xFFFF;

    fd_node = get_fd_node(dev_fd);

    if (!fd_node) {
        PRINTF_CRITICAL("fd_node error %d\n", fd);
        goto end;
    }

    if ((FD_NODE_TYPE_EMMC_BOOT != fd_node->type) && (fd < 0 || fd >= NUM_PARTITIONS)){
        PRINTF_CRITICAL("fd number too big %d\n", fd);
        goto end;
    }

    storage = get_storage_inst_by_id(dev);

    if (!storage) {
        PRINTF_CRITICAL("failed to get storage inst\n");
        goto end;
    }

    if(storage_switch_part_by_fd(storage, fd) != 0) {
        PRINTF_CRITICAL("failed to switch part for fd node: %s fd: %d\n", fd_node->partition_name, fd);
        goto end;
    }

    switch (whence) {
        case SEEK_SET:
            if ((offset < 0) || (offset >= fd_node->size)) {
                PRINTF_CRITICAL("offset = %lld is too large, limit size = 0~%llu\n",
                                (long long)offset, (unsigned long long)fd_node->size);
                goto end;
            }

            ret = storage->seek(storage, fd_node->offset + offset, SEEK_SET);

            if (ret < 0) {
                PRINTF_CRITICAL("block dev seek failed, whence is SEEK_SET\n");
                goto end;
            }

            fd_node->current = offset;
            break;

        case SEEK_CUR:
            if (((offset + fd_node->current) >= fd_node->size) ||
                    ((offset + (int64_t)fd_node->current) < 0)) {
                PRINTF_CRITICAL("offset(%lld) + fd_node->current(%llu) is out of range, limit size = 0~%llu\n",
                                (long long)offset, (unsigned long long)fd_node->current,
                                (unsigned long long)fd_node->size);
                goto end;
            }

            ret = storage->seek(storage, fd_node->offset + fd_node->current + offset,
                                SEEK_SET);

            if (ret < 0) {
                PRINTF_CRITICAL("block dev seek failed, whence is SEEK_CUR\n");
                goto end;
            }

            fd_node->current = fd_node->current + offset;
            break;

        case SEEK_END:
            if ((offset > 0) || ((offset + (int64_t)(fd_node->size)) < 0)) {
                PRINTF_CRITICAL("offset + fd_node->size = (%lld) is out of range, limit size = 0~%lld\n",
                                (long long)(offset + fd_node->current), (unsigned long long)fd_node->size);
                goto end;
            }

            ret = storage->seek(storage,
                                (int64_t)(fd_node->offset) + (int64_t)(fd_node->size) + offset, SEEK_SET);

            if (ret < 0) {
                PRINTF_CRITICAL("block dev seek failed, whence is SEEK_END\n");
                goto end;
            }

            fd_node->current = (int64_t)(fd_node->size) + offset;
            break;

        default:
            PRINTF_CRITICAL("whence = %d not supported\n", whence);
            goto end;
    }

    fd_node_update_crc(fd_node);
#if DEBUGMODE
    PRINTF_INFO("seek for dev_fd: 0x%x offset = %lld, whence = %d\n", dev_fd, (long long)offset, whence);
#endif
    return (int64_t)(fd_node->current);

end:
    return -1;
}

uint64_t partition_dev_blockdevsize(int dev_fd)
{
    int dev;
    int fd;
    uint64_t ret = 0;
    update_fd_node_t *fd_node = NULL;

    dev = (dev_fd >> 16) & 0xFFFF;

    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        goto end;
    }

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage id %d is not active\n", dev);
        goto end;
    }

    fd = dev_fd & 0xFFFF;

    fd_node = get_fd_node(dev_fd);

    if (!fd_node) {
        PRINTF_CRITICAL("fd_node error %d\n", fd);
        goto end;
    }

    if ((FD_NODE_TYPE_EMMC_BOOT != fd_node->type) && (fd < 0 || fd >= NUM_PARTITIONS)) {
        PRINTF_CRITICAL("fd number too big %d\n", fd);
        goto end;
    }

    ret = fd_node->size;

    if (ret == 0) {
        PRINTF_CRITICAL("block dev read blocksize failed: %s", strerror(errno));
    }
#if DEBUGMODE
    else {
        PRINTF_INFO("block dev read blocksize: 0X%llx for 0x%x\n", (unsigned long long)ret,  dev_fd);
    }
#endif

    return ret;

end:
    return 0;
}

uint64_t partition_dev_blockdevoffset(int dev_fd)
{
    int dev;
    int fd;
    uint64_t ret = 0;
    update_fd_node_t *fd_node = NULL;

    dev = (dev_fd >> 16) & 0xFFFF;

    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        goto end;
    }

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage id %d is not active\n", dev);
        goto end;
    }

    fd = dev_fd & 0xFFFF;

    fd_node = get_fd_node(dev_fd);

    if (!fd_node) {
        PRINTF_CRITICAL("fd_node error %d\n", fd);
        goto end;
    }

    if ((FD_NODE_TYPE_EMMC_BOOT != fd_node->type) && (fd < 0 || fd >= NUM_PARTITIONS)) {
        PRINTF_CRITICAL("fd number too big %d\n", fd);
        goto end;
    }

    ret = fd_node->offset;

    if (ret == 0) {
        PRINTF_CRITICAL("block dev read blockoffset failed: %s", strerror(errno));
    }
#if DEBUGMODE
    else{
        PRINTF_INFO("block dev read blockoffset: 0X%llx for 0x%x\n", (unsigned long long)ret,  dev_fd);
    }
#endif
    return ret;

end:
    return 0;
}

#if RUN_IN_QNX
#include <sys/dcmd_cam.h>
#include <hw/dcmd_sim_sdmmc.h>
#endif

int partition_dev_blkioctl(int dev_fd, int request, uint64_t start,
                           uint64_t length, int *result)
{
    int dev;
    int fd;
    uint64_t ret = -1;
    int act = request;
    uint64_t range[2] = {0};
    storage_device_t *storage = NULL;
    update_fd_node_t *fd_node = NULL;
    uint64_t left = 0;
    uint64_t cnt = 0;
    uint64_t size = 0;
    uint8_t *data = NULL;

    dev = (dev_fd >> 16) & 0xFFFF;

    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        goto end;
    }

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage id %d is not active\n", dev);
        goto end;
    }

    fd = dev_fd & 0xFFFF;

    fd_node = get_fd_node(dev_fd);

    if (!fd_node) {
        PRINTF_CRITICAL("fd_node error %d\n", fd);
        goto end;
    }

    if ((FD_NODE_TYPE_EMMC_BOOT != fd_node->type) && (fd < 0 || fd >= NUM_PARTITIONS)) {
        PRINTF_CRITICAL("fd number too big %d\n", fd);
        goto end;
    }

    if (O_RDONLY == (fd_node->flags & 0x3)) {
        PRINTF_CRITICAL("%s flags = 0x%08x, read only\n", fd_node->partition_name,
                        fd_node->flags);
        goto end;
    }

    storage = get_update_device_storage(dev);

    if(storage_switch_part_by_fd(storage, fd) != 0) {
        PRINTF_CRITICAL("failed to switch part for fd node: %s fd: %d\n", fd_node->partition_name, fd);
        goto end;
    }

    range[0] = fd_node->offset + start;
    range[1] = length;

    if ((start + length) > fd_node->size) {
        PRINTF_CRITICAL("discard para error, start = 0x%llx, size = 0x%llx, partition size = 0x%llx\n",
                        \
                        (unsigned long long)start,  (unsigned long long)length,
                        (unsigned long long)(fd_node->size));
        goto end;
    }

    if (0 == length) {
        ret = 0;
        goto end;
    }

    switch (act) {
#if !RUN_IN_QNX

        case BLKDISCARD :
        case BLKSECDISCARD  :
        case BLKZEROOUT :
#else
        case SDMMC_ERASE_ACTION_NORMAL :
        case SDMMC_ERASE_ACTION_SECURE :
        case SDMMC_ERASE_ACTION_TRIM :
        case SDMMC_ERASE_ACTION_SECURE_TRIM :
        case SDMMC_ERASE_ACTION_SECURE_PURGE :
        case SDMMC_ERASE_ACTION_DISCARD :
#endif

            if ((range[0] % 512) || (range[1] % 512)) {
                PRINTF_CRITICAL("alignment error\n");
                goto end;
            }

#if !RUN_IN_QNX

            if (!strcmp(storage->dev_name, MMC_PATH(mmcblk0))) {
                if (ioctl(storage->dev_fd, act, &range)) {
                    PRINTF_CRITICAL("ioctl fd= %d error %s for %s, range[0]=0x%llx, range[1]=0x%llx\n", storage->dev_fd, strerror(errno), fd_node->partition_name, (unsigned long long)range[0], (unsigned long long)range[1]);
                    goto end;
                }

                PRINTF_INFO("ioctl start 0x%llx, size 0x%llx\n", (unsigned long long)range[0], (unsigned long long)range[1]);
            }

#else

            if (!strcmp(storage->dev_name, MMC_PATH(emmc0))) {
                SDMMC_ERASE sdmmc_erase_info = {0};
                sdmmc_erase_info.action = act;
                sdmmc_erase_info.lba = range[0] / 512;
                sdmmc_erase_info.nlba = range[1] / 512;

                if (EOK != devctl (dev_fd, DCMD_SDMMC_ERASE, &sdmmc_erase_info,
                                   sizeof(SDMMC_ERASE), NULL)) {
                    PRINTF_CRITICAL("devctl filed to get capacity info\n");
                    return 0;
                }
            }

#endif
            else {
#define BLKIOCTRL_MAX_CALLOC_SIZE (256*1024)
                cnt =  (range[1] / BLKIOCTRL_MAX_CALLOC_SIZE);
                left = (range[1] % BLKIOCTRL_MAX_CALLOC_SIZE);
                size = (cnt != 0) ? (BLKIOCTRL_MAX_CALLOC_SIZE) : left;
                data = (unsigned char *)MEM_ALIGN(512, size);

                if (!data) {
                    PRINTF_CRITICAL("data memalign failed\n");
                    goto end;
                }

#if !RUN_IN_QNX

                if (!strcmp(storage->dev_name, MONITOR_CHANNEL_SAFETY)
                        || !strcmp(storage->dev_name, MTD_PATH(mtdblock0))) {
                    if (BLKZEROOUT == act) {
                        memset(data, 0, size);
                    }
                    else {
                        memset(data, 0xFF, size);
                    }
                }
                else {
                    memset(data, 0, size);
                }

#else
                memset(data, 0, size);
#endif

                for (int i = 0; i <= cnt; i++) {
                    size = (i != cnt) ? BLKIOCTRL_MAX_CALLOC_SIZE : left;

                    if (size > 0) {
                        ret = storage->write(storage, range[0] + i * BLKIOCTRL_MAX_CALLOC_SIZE, data,
                                             size);

                        if (ret != 0) {
                            PRINTF_CRITICAL("erase addr = 0x%llx size = 0x%llx\n",
                                            (unsigned long long)(range[0] + i * BLKIOCTRL_MAX_CALLOC_SIZE), \
                                            (unsigned long long)size);
                            PRINTF_CRITICAL("ioctl error for %s\n", fd_node->partition_name);
                            FREE(data);
                            goto end;
                        }
                    }
                }

                FREE(data);
                ret = 0;
            }

            break;

        default:
            PRINTF_CRITICAL("request not suupported\n");
            goto end;
    }

    ret = 0;

    PRINTF_INFO("ioctl type: %d, dev_fd:0x%x, storage_fd:0x%x para: start = 0x%llx, size = 0x%llx, partition size = 0x%llx, partition offset = 0x%llx\n", act, dev_fd, storage->dev_fd,
                    (unsigned long long)start,  (unsigned long long)length,
                    (unsigned long long)(fd_node->size), (unsigned long long)(fd_node->offset));

end:
    *result = ret;
    return ret;
}

int partition_dev_flush(int dev_fd)
{
    sync();
    return 0;
}

int partition_dev_close(int dev_fd)
{
    int dev;
    uint64_t ret = -1;
    update_syscall_head_t *syscall_head = NULL;

    dev = (dev_fd >> 16) & 0xFFFF;

    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        goto end;
    }

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage id %d is not active\n", dev);
        goto end;
    }

    if (!remove_fd_node(dev_fd)) {
        syscall_head = get_syscall_head(dev);

        if (!syscall_head) {
            PRINTF_CRITICAL("syscall_head %d is null\n", dev);
            goto end;
        }

        if (syscall_head->fd_cnt <= 0) {
            PRINTF_CRITICAL("syscall head destroy %d\n", dev);
            syscall_head_destroy(syscall_head);
        }

        ret = 0;
    }
#if DEBUGMODE
    PRINTF_INFO("close 0x%x\n", dev_fd);
#endif
end:
    return ret;
}

int partition_dev_issettingerrno(int dev_fd)
{
    return 0;
}

int partition_dev_isopen(int dev_fd)
{
    return 0;
}

void partition_dev_dump_all(int dev_fd)
{
    int dev;

    dev = (dev_fd >> 16) & 0xFFFF;

    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        return;
    }

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage id %d is not active\n", dev);
        return;
    }

    syscall_head_dump(get_syscall_head(dev));
}

void partition_dev_dump(int dev_fd)
{
    int dev;
    int fd;
    update_fd_node_t *fd_node = NULL;

    dev = (dev_fd >> 16) & 0xFFFF;

    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        return;
    }

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage id %d is not active\n", dev);
        return;
    }

    fd = dev_fd & 0xFFFF;

    PRINTF_CRITICAL("dump for dev = %d, fd = %d\n", dev, fd);

    fd_node = get_fd_node(dev_fd);

    if (!fd_node) {
        PRINTF_CRITICAL("can't find fd node\n");
        return;
    }

    if ((FD_NODE_TYPE_EMMC_BOOT != fd_node->type) && (fd < 0 || fd >= NUM_PARTITIONS)) {
        PRINTF_CRITICAL("fd number too big %d\n", fd);
        return;
    }

    fd_node_dump(fd_node);
}

int partition_dev_set_readonly(int dev_fd, bool read_only)
{
    int dev;
    int fd;
    int ret = -1;
    update_fd_node_t *fd_node = NULL;
    storage_device_t *storage = NULL;

    dev = (dev_fd >> 16) & 0xFFFF;

    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        goto end;
    }

    if (!get_update_device_is_active(dev)) {
        PRINTF_CRITICAL("storage id %d is not active\n", dev);
        goto end;
    }


    fd = dev_fd & 0xFFFF;

    fd_node = get_fd_node(dev_fd);

    if (!fd_node) {
        PRINTF_CRITICAL("fd_node error %d\n", fd);
        goto end;
    }

    if ((FD_NODE_TYPE_EMMC_BOOT != fd_node->type) && (fd < 0 || fd >= NUM_PARTITIONS)) {
        PRINTF_CRITICAL("fd number too big %d\n", fd);
        goto end;
    }

    storage = get_storage_inst_by_id(dev);

    if (!storage) {
        PRINTF_CRITICAL("failed to get storage inst for fd node: %s\n",
                        fd_node->partition_name);
        goto end;
    }


    if (read_only) {
        fd_node->flags = O_RDONLY;
    }
    else {
        fd_node->flags = O_RDWR;
    }

    if(storage_switch_part_by_fd(storage, fd) != 0) {
        PRINTF_CRITICAL("failed to switch part for fd node: %s fd: %d\n", fd_node->partition_name, fd);
        goto end;
    }

    if((fd == EMMC_BOOT0_FD) || (fd == EMMC_BOOT1_FD)) {
        if(0 != storage->set_readonly(storage, read_only)) {
            PRINTF_CRITICAL("failed to set readonly=%d for fd node: %s\n", read_only, fd_node->partition_name);
            goto end;
        }
    }

    fd_node_update_crc(fd_node);
    ret = 0;
    PRINTF_INFO("set readonly=%d for fd node: %s\n", read_only, fd_node->partition_name);

end:
    return ret;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */


