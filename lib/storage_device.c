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

#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <malloc.h>
#include "system_cfg.h"
#ifdef RUN_IN_QNX
#include <sys/dcmd_cam.h>
#include <hw/dcmd_sim_sdmmc.h>
#include <sys/dcmd_blk.h>
#else
#include <linux/fs.h>
#endif
#include <string.h>
#include "crc32.h"
#include <assert.h>
#include <dirent.h>
#include <stdint.h>
#include <termios.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include "storage_device.h"
#include "storage_dev_ospi.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <libgen.h>

#define CALLOC_SIZE (256*1024)
#define BY_NAME_STR  "/dev/block/by-name"

int blk_init(storage_device_t *storage_dev);
static const int sparse_header_t_size = sizeof(
        sparse_header_t);    // Length = 128
static const int chunk_header_t_size = sizeof(chunk_header_t);    // Length = 12

#define RPMSG_HANDLE_FOR_SAFETY 0
#define RPMSG_HANDLE_FOR_SECURE 1
#define RPMSG_HANDLE_FOR_MP     2

static const char* emmc_part_str[3] = {"boot0", "boot1", "userdata"};

extern bool get_number_slots_all();
extern bool is_in_android_recovery();

#if RUN_IN_QNX
static rpmsg_handle_t rpmsg_handle[3] = {
    {.ctl_fd = -1, .ept_fd = -1, .count = 0, .rp_op = {0}},
    {.ctl_fd = -1, .ept_fd = -1, .count = 0, .rp_op = {0}},
    {.ctl_fd = -1, .ept_fd = -1, .count = 0, .rp_op = {0}},
};
#endif

storage_device_t mmc1 = {
#ifndef RUN_IN_QNX
    .dev_name = MMC_PATH(mmcblk0),
#else
    .dev_name = MMC_PATH(emmc0),
#endif
    .type = STORAGE_LOCAL,
    .dev_fd = -1,
    .init = &blk_init,
    .cnt = 0,
    .mapped = false,
    .use_shared_memory = false,
    .shared_memory_name = "null",
    .memfd = -1,
    .shared_mem_ptr = MAP_FAILED,
    .support_switch_part = true,
    .part = SELECT_USERDATA,
#if (RUN_IN_ANDROID && !RUN_IN_HOST) || RUN_IN_QNX
    .rpmsg_handler = NULL,
#endif
};

storage_device_t saf_update_monitor = {
    .dev_name = MONITOR_CHANNEL_SAFETY,
    .type = STORAGE_REMOTE,
    .dev_fd = -1,
    .init = &remote_init,
    .cnt = 0,
    .mapped = false,
    .use_shared_memory = false,
    .shared_memory_name = "up_mon_saf",
    .memfd = -1,
    .shared_mem_ptr = MAP_FAILED,
    .shared_mem_mode = {
        .digest_mode = DIGEST_MODE_CRC32_WITH_RAMDOM,
        .reserved = {0},
    },
    .support_switch_part = false,
#if RUN_IN_ANDROID && !RUN_IN_HOST
    .rpmsg_handler = NULL,
#elif RUN_IN_QNX
    .rpmsg_handler = &rpmsg_handle[RPMSG_HANDLE_FOR_SAFETY],
#endif
};

storage_device_t sec_update_monitor = {
    .dev_name = MONITOR_CHANNEL_SECURE,
    .type = STORAGE_REMOTE,
    .dev_fd = -1,
    .init = &remote_init,
    .cnt = 0,
    .mapped = false,
    .use_shared_memory = true,
    .shared_memory_name = "up_mon_sec",
    .memfd = -1,
    .shared_mem_ptr = MAP_FAILED,
    .shared_mem_mode = {
        .digest_mode = DIGEST_MODE_SHA256,
        .reserved = {0},
    },
    .support_switch_part = false,
#if RUN_IN_ANDROID && !RUN_IN_HOST
    .rpmsg_handler = NULL,
#elif RUN_IN_QNX
    .rpmsg_handler = &rpmsg_handle[RPMSG_HANDLE_FOR_SECURE],
#endif
};

storage_device_t mp_update_monitor = {
    .dev_name = MONITOR_CHANNEL_MP,
    .type = STORAGE_REMOTE,
    .dev_fd = -1,
    .init = &remote_init,
    .cnt = 0,
    .mapped = false,
    .use_shared_memory = false,
    .shared_memory_name = "up_mon_mp",
    .memfd = -1,
    .shared_mem_ptr = MAP_FAILED,
    .shared_mem_mode = {
        .digest_mode = DIGEST_MODE_CRC32_WITH_RAMDOM,
        .reserved = {0},
    },

    .support_switch_part = false,
#if RUN_IN_ANDROID && !RUN_IN_HOST
    .rpmsg_handler = NULL,
#elif RUN_IN_QNX
    .rpmsg_handler = &rpmsg_handle[RPMSG_HANDLE_FOR_MP],
#endif
};

int find_true_blkmmc_name(char *name, char *expect_name)
{
    char fpath[FILE_PATH_LEN] = {0};
    char link_name[2 * FILE_PATH_LEN] = {0};
    DIR *dir;
    int ret = -1;
    struct dirent *ent;
    char *prefix[] = { "mmcblk", "boot", "kernel", "bootloader", "ssystem", "ap1"};
    int i = 0;

    if (!strlen(expect_name)) {
        PRINTF_CRITICAL("expect_name length error\n");
        goto end;
    }

    snprintf(fpath, FILE_PATH_LEN, "%s", BY_NAME_STR);

    if (access(fpath, F_OK)) {
        PRINTF_INFO("%s not exits\n", fpath);
        goto end;
    }

    dir = opendir(fpath);

    if (dir == NULL) {
        PRINTF_INFO("Failed to open dir %s, %s\n", fpath, strerror(errno));
        goto end;
    }

    while ((ent = readdir(dir)) != NULL) {
        for (i = 0; i < (sizeof(prefix) / sizeof(prefix[0])); i++) {
            if (!strncmp(ent->d_name, prefix[i], strlen(prefix[i]))) {
                snprintf(link_name, 2 * FILE_PATH_LEN, "%s/%s", BY_NAME_STR, ent->d_name);

                if ((-1 == readlink(link_name, name, strlen(expect_name)) || !strlen(name))) {
                    goto end;
                }

                PRINTF_INFO("find new blk name : %s from %s)\n", name, link_name);
                ret = 0;
                goto end;
            }
        }
    }

end:
    return ret;
}

static uint64_t get_capacity(int fd)
{
    uint64_t size;
    if(fd < 0) {
        PRINTF_CRITICAL("boot%d fd error", fd);
        return 0;
    }

#ifdef RUN_IN_QNX

    SDMMC_DEVICE_INFO emmc_dev_info = {0};

    if (EOK != devctl(fd, DCMD_SDMMC_DEVICE_INFO, &emmc_dev_info,
                       sizeof(SDMMC_DEVICE_INFO), NULL)) {
        PRINTF_CRITICAL("devctl failed to get capacity info\n");
        return 0;
    }

    size = (uint64_t)emmc_dev_info.sectors * (uint64_t)emmc_dev_info.sector_size;

#else

    if (ioctl(fd, BLKGETSIZE64, &size) < 0) {
        PRINTF_CRITICAL("failed to get dev size:%s\n", strerror(errno));
        return 0;
    }

#endif

    return size;
}

#if !RUN_IN_QNX
static int set_boot_force_ro(const char* dev, const char *part, bool read_only) {
    char force_ro_path[FILE_PATH_LEN] = {0};
    FILE *file = NULL;
    int result = 0;

    if (!dev || !part) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    snprintf(force_ro_path, FILE_PATH_LEN, "/sys/block/%s%s/force_ro", dev, part);

    file = fopen(force_ro_path, "w");
    if (file) {
        if (read_only) {
            result = fprintf(file, "1");
            PRINTF_INFO("write 1 to %s\n", force_ro_path);
        } else {
            result = fprintf(file, "0");
            PRINTF_INFO("write 0 to %s\n", force_ro_path);
        }
        fclose(file);
        if (result < 0) {
            PRINTF_INFO("write to force ro failed\n");
        }
    } else {
        PRINTF_CRITICAL("error opening file: %s: %s\n", force_ro_path, strerror(errno));
        return -1;
    }

    return 0;
}
#else
static int set_boot_force_ro(const char* dev, const char *part, bool read_only) {
    return 0;
}
#endif

static int open_boot_partition(char* dev_path, const char *part)
{
    int fd;
    char boot_dev_name[FILE_PATH_LEN] = {0};

#if !RUN_IN_QNX
    snprintf(boot_dev_name, FILE_PATH_LEN, "%s%s", dev_path, part);
#else
    snprintf(boot_dev_name, FILE_PATH_LEN, "%s.%s", dev_path, part);
#endif

    fd = open(boot_dev_name, O_RDWR | O_SYNC);
    if (fd < 0) {
        PRINTF_CRITICAL("failed to open %s: %s\n", boot_dev_name, strerror(errno));
        return fd;
    }

#if !RUN_IN_QNX
    if (is_in_android_recovery() && (get_number_slots_all() == 1)) {
        int ro = 0;

        if(set_boot_force_ro(basename(dev_path), part, false)) {
            PRINTF_CRITICAL("recovery mode: set force_ro failed\n");
            close(fd);
            return -1;
        }

        if (ioctl(fd, BLKROSET, &ro) != 0) {
            PRINTF_CRITICAL("recovery mode: set %s read-write failed: %s\n", boot_dev_name, strerror(errno));
            close(fd);
            return -1;
        }
    }
#endif

    return fd;
}

int blk_init(storage_device_t *storage_dev)
{
    int fd;
    struct stat buf;
    char dev_name[FILE_PATH_LEN] = {0};
    char boot0_dev_name[FILE_PATH_LEN] = {0};
    char boot1_dev_name[FILE_PATH_LEN] = {0};
    static bool do_once = true;

    if ((!storage_dev) || (!strlen(storage_dev->dev_name))) {
        PRINTF_CRITICAL("blk init para error");
        return -1;
    }

    if (do_once && (find_true_blkmmc_name(dev_name, storage_dev->dev_name) == 0)) {
        snprintf(storage_dev->dev_name, MIN(FILE_PATH_LEN, STORAGE_NAME_LEN), "%s", dev_name);
        do_once = false;
    }

    if (stat(storage_dev->dev_name, &buf)) {
        PRINTF_CRITICAL("no such dev file: %s\n", storage_dev->dev_name);
        return -1;
    }

    fd = open(storage_dev->dev_name, O_RDWR);

    if (fd < 0) {
        PRINTF_CRITICAL("failed to open %s %s\n", storage_dev->dev_name, strerror(errno));
        return -1;
    }

    storage_dev->dev_fd = fd;
    storage_dev->user_data_dev_fd = fd;
    storage_dev->part = SELECT_USERDATA;

    if(storage_dev->support_switch_part) {
        /* boot0 */
        storage_dev->boot0_dev_fd = open_boot_partition(storage_dev->dev_name, "boot0");
        if(storage_dev->boot0_dev_fd < 0) {
            PRINTF_CRITICAL("failed to open boot0 partiton of emmc\n");
        }
        else {
            storage_dev->boot0_capacity = get_capacity(storage_dev->boot0_dev_fd);
            PRINTF_INFO("emmc %s capacity is %lld, storage_dev->boot0_dev_fd is %d\n",\
                boot0_dev_name, (unsigned long long)storage_dev->boot0_capacity, storage_dev->boot0_dev_fd);
        }

        /* boot1 */
        storage_dev->boot1_dev_fd = open_boot_partition(storage_dev->dev_name, "boot1");
        if(storage_dev->boot1_dev_fd < 0) {
            PRINTF_CRITICAL("failed to open boot1 partiton of emmc\n");
        }
        else {
            storage_dev->boot1_capacity = get_capacity(storage_dev->boot1_dev_fd);
            PRINTF_INFO("emmc %s capacity is %lld, storage_dev->boot1_dev_fd is %d\n",\
                boot1_dev_name, (unsigned long long)storage_dev->boot1_capacity, storage_dev->boot1_dev_fd);
        }
    }

    return 0;
}

int blk_release(storage_device_t *storage_dev)
{
    if (!storage_dev) {
        PRINTF_CRITICAL("blk_release para error");
        return -1;
    }

    if (storage_dev->dev_fd >= 0) {
        close(storage_dev->dev_fd);
    }

    if (storage_dev->boot0_dev_fd >= 0) {
        close(storage_dev->boot0_dev_fd);
    }

    if (storage_dev->boot1_dev_fd >= 0) {
        close(storage_dev->boot1_dev_fd);
    }

    return 0;
}

static int blk_switch_part(storage_device_t *storage_dev, uint32_t part)
{
    if (!storage_dev || (part > SELECT_USERDATA)) {
        PRINTF_CRITICAL("para error, part is %d\n", part);
        return -1;
    }

    if(storage_dev->part != part) {
        PRINTF_INFO("part:%s(0x%x)  boot0:0x%x boot1:0x%x user:0x%x\n", emmc_part_str[part], part,
            storage_dev->boot0_dev_fd, storage_dev->boot1_dev_fd, storage_dev->user_data_dev_fd);
    }

    switch (part)
    {
        case SELECT_USERDATA:
            /* user data */
            if(storage_dev->user_data_dev_fd < 0) {
                PRINTF_CRITICAL("user data dev fd error, could not switch to userdata mode\n");
                return -1;
            }
            storage_dev->dev_fd = storage_dev->user_data_dev_fd;
            storage_dev->part = SELECT_USERDATA;
            break;

        case SELECT_BOOT0:
            /* boot0 mode */
            if(storage_dev->boot0_dev_fd < 0) {
                PRINTF_CRITICAL("user data dev fd error, could not switch to boot0 mode\n");
                return -1;
            }
            storage_dev->dev_fd = storage_dev->boot0_dev_fd;
            storage_dev->part = SELECT_BOOT0;
            break;

        case SELECT_BOOT1:
            /* boot1 mode */
            if(storage_dev->boot1_dev_fd < 0) {
                PRINTF_CRITICAL("user data dev fd error, could not switch to boot1 mode\n");
                return -1;
            }
            storage_dev->dev_fd = storage_dev->boot1_dev_fd;
            storage_dev->part = SELECT_BOOT1;
            break;

        default:
            PRINTF_CRITICAL("unknown part id");
            return -1;
    }

    return 0;
}

static int void_switch_part(storage_device_t *storage_dev, uint32_t part)
{
    return 0;
}

uint32_t blk_get_block_size(storage_device_t *storage_dev)
{
    uint32_t block_size = LBA_SIZE;

    if (!storage_dev) {
        PRINTF_CRITICAL("para error");
        return 0;
    }

#if !RUN_IN_QNX

    if (ioctl(storage_dev->dev_fd, BLKSSZGET, &block_size) != 0) {
        PRINTF_CRITICAL("failed to get dev block size\n");
        return 0;
    }

#endif

    return block_size;
}

int64_t blk_read_direct(storage_device_t *storage_dev, uint8_t *dst,
                        uint64_t size)
{
    int64_t r;

    if ((!storage_dev) || (!dst) || (int64_t)size <= 0) {
        PRINTF_CRITICAL("blk_read para error");
        return -1;
    }

    r = read(storage_dev->dev_fd, dst, size);

    if (r < 0) {
        PRINTF_CRITICAL("block dev read direct failed: %s", strerror(errno));
    }

    return r;
}

int blk_read(storage_device_t *storage_dev, uint64_t src, uint8_t *dst,
             uint64_t size)
{
    if ((!storage_dev) || (!dst)) {
        PRINTF_CRITICAL("blk_read para error");
        return -1;
    }

#if RUN_IN_QNX

    if (lseek(storage_dev->dev_fd, src, SEEK_SET) < 0) {
#else

    if (lseek64(storage_dev->dev_fd, src, SEEK_SET) < 0) {
#endif
        PRINTF_CRITICAL("block dev lseek %lu failed: %s\n", (unsigned long)src,
                        strerror(errno));
        return -1;
    }

    if (blk_read_direct(storage_dev, dst, size) < 0) {
        PRINTF_CRITICAL("block dev read failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int64_t blk_seek(storage_device_t *storage_dev, off_t offset, int whence)
{
    int64_t ret = -1;

    if (!storage_dev) {
        PRINTF_CRITICAL("blk_read para error");
        return -1;
    }

#if RUN_IN_QNX
    ret = lseek(storage_dev->dev_fd, offset, whence);
#else
    ret = lseek64(storage_dev->dev_fd, offset, whence);
#endif

    if (ret < 0) {
        PRINTF_CRITICAL("block dev lseek %lu failed: %s\n", (unsigned long)offset,
                        strerror(errno));
        return -1;
    }

    return ret;
}

int blk_set_readonly(storage_device_t *storage_dev, bool read_only)
{
#if !RUN_IN_QNX
    int ro = (int)read_only;
    char* part = NULL;

    PRINTF_INFO("blk fd:%d set r/w:%d\n", storage_dev->dev_fd, read_only);
    if (!storage_dev) {
        PRINTF_CRITICAL("para error");
        return -1;
    }
    /*
        kernel 6.1 : To set/unset read only flag of boot0/1 of emmc partition we need to handle
            1. /sys/block/mmcblk0xxx/force_ro
            2. ioctl BLKROGET result
            (see bdev_read_only in kernel/include/linux/blkdev.h)
        kenel below 6.1:
            we already knew "ioctl BLKROGET" is enough to set readonly flag.
    */
    if(storage_dev->dev_fd ==  storage_dev->boot0_dev_fd ||
        storage_dev->dev_fd ==  storage_dev->boot1_dev_fd) {
        part = (storage_dev->dev_fd ==  storage_dev->boot0_dev_fd) ? "boot0" : "boot1";
        if(set_boot_force_ro(basename(storage_dev->dev_name), part, read_only)) {
            PRINTF_CRITICAL("set force_ro failed\n");
            return -1;
        }
    }

    if(ioctl(storage_dev->dev_fd, BLKROSET, &ro) != 0) {
        if(read_only) {
            PRINTF_CRITICAL("set blk readonly failed: %s\n", strerror(errno));
        }
        else {
            PRINTF_CRITICAL("set blk read-write failed: %s\n", strerror(errno));
        }
        return -1;
    }
#endif
    return 0;
}

int blk_get_readonly(storage_device_t *storage_dev)
{
#if !RUN_IN_QNX
    int ro;

    if (!storage_dev) {
        PRINTF_CRITICAL("para error");
        return -1;
    }

    /*
        Do not need to read both /sys/block/mmcblk0xxx/force_ro and ioctl BLKROGET result,
        and "ioctl BLKROGET" is enough to get readonly result.
        because for kernel 6.1 :
            ioctl BLKROGET will obtain readonly result by "the OR of two read-only flags".
            see bdev_read_only in kernel/include/linux/blkdev.h
        for kenel below 6.1:
            we already knew "ioctl BLKROGET" is enough to get readonly result.
    */
    if(ioctl(storage_dev->dev_fd, BLKROGET, &ro) == -1) {
        PRINTF_CRITICAL("get emmc boot readonly failed: %s\n", strerror(errno));
        return -1;
    }

    return ro;
#endif
   return 0;
}

int void_set_readonly(storage_device_t *storage_dev, bool read_only)
{
    return 0;
}

int void_get_readonly(storage_device_t *storage_dev)
{
    return 0;
}


int64_t blk_write_direct(storage_device_t *storage_dev, const uint8_t *buf,
                         uint64_t data_len)
{
    int64_t r;

    if ((!storage_dev) || (!buf)) {
        PRINTF_CRITICAL("blk_write para error");
        return -1;
    }

    r = write(storage_dev->dev_fd, buf, data_len);

    if (r < 0) {
        PRINTF_CRITICAL("block dev write direct failed: %s\n", strerror(errno));
    }

    return r;
}

int blk_write(storage_device_t *storage_dev, uint64_t dst,
              const uint8_t *buf, uint64_t data_len)
{
    if ((!storage_dev) || (!buf)) {
        PRINTF_CRITICAL("blk_write para error");
        return -1;
    }

#if RUN_IN_QNX

    if (lseek(storage_dev->dev_fd, dst, SEEK_SET) < 0)
#else
    if (lseek64(storage_dev->dev_fd, dst, SEEK_SET) < 0)
#endif
    {
        PRINTF_CRITICAL("block dev lseek %lu failed: %s\n", (unsigned long)dst,
                        strerror(errno));
        return -1;
    }

    if (blk_write_direct(storage_dev, buf, data_len) < 0) {
        PRINTF_CRITICAL("block dev write failed: %s\n", strerror(errno));
        return -1;
    }

#if WRITE_WITH_SYNC
#if RUN_IN_QNX

    if (fsync(storage_dev->dev_fd) < 0) {
        PRINTF_CRITICAL("Error flushing data to device: %s", strerror(errno));
    }

#else
    sync();
#endif
#endif

    return 0;
}

static int write_sparse_file(storage_device_t *storage_dev, uint64_t dst,
                             uint64_t size, int fd, uint8_t write_check)
{
    int ret = -1;
    uint64_t out_pos = dst;
    sparse_header_t sparse_header  = {0};
    chunk_header_t chunk_header    = {0};
    uint32_t chunk = 0;
    uint64_t chunk_data_sz_remain  = 0;
    uint64_t read_len = FILE_READ_LENGTH;
    uint32_t total_blocks   = 0;
    uint64_t chunk_data_sz  = 0;
    uint32_t fill_value = 0;
    uint64_t cnt = 0;
    uint8_t *buf = NULL;
    uint64_t file_storage_size = 0;

    if (!storage_dev || fd < 0) {
        PRINTF_CRITICAL("write sparse file para error\n");
        goto end;
    }

#if RUN_IN_QNX

    if (lseek(fd, 0, SEEK_SET) < 0) {
#else

    if (lseek64(fd, 0, SEEK_SET) < 0) {
#endif
        PRINTF_CRITICAL("file lseek failed: err = %s\n", strerror(errno));
        goto end;
    }

    buf = (uint8_t *)MEM_ALIGN(512, FILE_READ_LENGTH);

    if (!buf) {
        PRINTF_CRITICAL("write sparse file calloc failed\n");
        goto end;
    }

    if (sparse_header_t_size != read(fd, buf, sparse_header_t_size)) {
        PRINTF_CRITICAL("sparse file read sparse head error\n");
        goto end;
    }

    memcpy(&sparse_header, buf, sparse_header_t_size);

    if (!sparse_header.blk_sz || (sparse_header.blk_sz % 4096)) {
        PRINTF_CRITICAL("sparse file block size error:%u\n", sparse_header.blk_sz);
        goto end;
    }

    file_storage_size = (uint64_t)sparse_header.total_blks *
                        (uint64_t)sparse_header.blk_sz;

    if ( file_storage_size > size) {
        PRINTF_CRITICAL("sparse file too large :%lu, limited %lu\n",
                        (unsigned long)file_storage_size,
                        (unsigned long)size);
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

    cnt = file_storage_size / FILE_READ_LENGTH;
    read_len = FILE_READ_LENGTH;

    /* Start processing chunks */
    for (chunk = 0; chunk < sparse_header.total_chunks; chunk++) {
        /* Make sure the total image size does not exceed the partition size */
        if (((uint64_t)total_blocks * (uint64_t)sparse_header.blk_sz) >= size) {
            PRINTF_CRITICAL("image too large:%lu!\n", (unsigned long)size);
            goto end;
        }

        if (chunk_header_t_size != read(fd, buf, chunk_header_t_size)) {
            PRINTF_CRITICAL("sparse file read chunk head error, chunk = %d\n", chunk);
            goto end;
        }

        memcpy(&chunk_header, buf, chunk_header_t_size);
#if DEBUGMODE
        PRINTF_INFO("=== Chunk Header ===\n");
        PRINTF_INFO("chunk %d\n", chunk);
        PRINTF_INFO("chunk_type: 0x%x\n", chunk_header.chunk_type);
        PRINTF_INFO("chunk_sz: 0x%x\n", chunk_header.chunk_sz);
        PRINTF_INFO("total_size: 0x%x\n", chunk_header.total_sz);
#endif

        if (sparse_header.chunk_hdr_sz != chunk_header_t_size) {
            PRINTF_CRITICAL("chunk header error:%u!\n", sparse_header.chunk_hdr_sz);
            goto end;
        }

        chunk_data_sz = (uint64_t)sparse_header.blk_sz * chunk_header.chunk_sz;

        /* Make sure that the chunk size calculated from sparse image does not
         * exceed partition size
         */

        out_pos = (uint64_t)total_blocks * (uint64_t)sparse_header.blk_sz;

        if ((out_pos + chunk_data_sz > size) || (out_pos > size)) {
            PRINTF_CRITICAL("calculate size: %lx\n",
                            (unsigned long)(out_pos + chunk_data_sz));
            PRINTF_CRITICAL("limited size: %lx\n", (unsigned long)size);
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
                cnt = chunk_data_sz / FILE_READ_LENGTH;
                chunk_data_sz_remain = chunk_data_sz % FILE_READ_LENGTH;
                read_len = FILE_READ_LENGTH;

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

                    if (write_check) {
                        if (storage_dev->write_with_check(storage_dev, dst + out_pos, buf, read_len)) {
                            PRINTF_CRITICAL("flash storage error\n");
                            goto end;
                        }
                    }
                    else {
                        if (storage_dev->write(storage_dev, dst + out_pos, buf, read_len)) {
                            PRINTF_CRITICAL("flash storage error\n");
                            goto end;
                        }
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
                cnt = chunk_data_sz / FILE_READ_LENGTH;
                chunk_data_sz_remain = chunk_data_sz % FILE_READ_LENGTH;
                read_len = FILE_READ_LENGTH;
                assert(FILE_READ_LENGTH % 4 == 0);
                assert(chunk_data_sz_remain % 4 == 0);

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

                    if (write_check) {
                        if (storage_dev->write_with_check(storage_dev, dst + out_pos, buf, read_len)) {
                            PRINTF_CRITICAL("flash storage error\n");
                            goto end;
                        }
                    }
                    else {
                        if (storage_dev->write(storage_dev, dst + out_pos, buf, read_len)) {
                            PRINTF_CRITICAL("flash storage error\n");
                            goto end;
                        }
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

                cnt = chunk_data_sz / FILE_READ_LENGTH;
                chunk_data_sz_remain = chunk_data_sz % FILE_READ_LENGTH;
                read_len = FILE_READ_LENGTH;

                PRINTF_INFO("chunk_data_sz: 0x%lx\n", (unsigned long)chunk_data_sz);
                memset(buf, 0, FILE_READ_LENGTH);

                for (uint64_t i = 0; i < cnt + 1; i++) {
                    if (i == cnt) {
                        if (chunk_data_sz_remain)
                            read_len = chunk_data_sz_remain;
                        else
                            break;
                    }

                    if (write_check) {
                        if (storage_dev->write_with_check(storage_dev, dst + out_pos, buf, read_len)) {
                            PRINTF_CRITICAL("flash storage error\n");
                            goto end;
                        }
                    }
                    else {
                        if (storage_dev->write(storage_dev, dst + out_pos, buf, read_len)) {
                            PRINTF_CRITICAL("flash storage error\n");
                            goto end;
                        }
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
                    PRINTF_CRITICAL(" chunk size:%u error!\n", chunk_header.chunk_sz);
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

int storage_write_file(storage_device_t *storage_dev, uint64_t dst,
                       uint64_t size, char *file, uint8_t write_check)
{
    uint64_t cnt = 0;
    uint64_t left = 0;
    uint8_t *read_buf = NULL;
    uint8_t  sparse_head[sizeof(sparse_header_t)] = {0};
    uint64_t read_len = FILE_READ_LENGTH;
    int ret = -1;
    uint64_t i = 0;
    int fd = 0;
    struct stat fstat;
    uint64_t file_size = 0;

    if (!storage_dev) {
        PRINTF_CRITICAL("blk write sparse file para error");
        goto end;
    }

    if (stat(file, &fstat) < 0) {
        PRINTF_CRITICAL("stat %s error\n", file);
        goto end;
    }

    if (fstat.st_size > size) {
        PRINTF_CRITICAL("file original size = %ld too large, limited size = %ld\n",
                        (unsigned long)fstat.st_size, (unsigned long)size);
        goto end;
    }

    file_size = fstat.st_size;
    fd = open(file, O_RDONLY);

    if (fd < 0) {
        PRINTF_CRITICAL("open file %s error %s %s\n", file, strerror(errno),
                        strerror(errno));
        goto end;
    }

#if RUN_IN_QNX

    if (lseek(fd, 0, SEEK_SET) < 0) {
#else

    if (lseek64(fd, 0, SEEK_SET) < 0) {
#endif
        PRINTF_CRITICAL("file lseek failed: err = %s\n", strerror(errno));
        goto end;
    }

    if (sparse_header_t_size != read(fd, sparse_head, sparse_header_t_size)) {
        PRINTF_INFO("file read head failed err = %s\n", strerror(errno));
        goto end;
    }

    PRINTF_INFO("write check mode = %d\n", write_check);
    PRINTF_INFO("storage->dev_name = %s\n", storage_dev->dev_name);

    if ((*(uint32_t *)sparse_head == SPARSE_HEADER_MAGIC) &&
            (*(uint16_t *)(sparse_head + 8)  == sparse_header_t_size) &&
            (*(uint16_t *)(sparse_head + 10) == chunk_header_t_size)) {
        PRINTF_INFO("sparse mode\n");
        ret = write_sparse_file(storage_dev, dst, size, fd, write_check);
    }
    else {
        PRINTF_INFO("normal mode\n");
        read_buf = (uint8_t *)MEM_ALIGN(512, FILE_READ_LENGTH);

        if (!read_buf) {
            PRINTF_CRITICAL("blk_write_with_check calloc failed\n");
            goto end;
        }

        cnt = file_size / FILE_READ_LENGTH;
        left = file_size % FILE_READ_LENGTH;
        read_len = FILE_READ_LENGTH;

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
                PRINTF_INFO("file read failed err = %s\n", strerror(errno));
                goto end;
            }

            if (write_check) {
                if (0 != storage_dev->write_with_check(storage_dev, dst, read_buf, read_len)) {
                    PRINTF_CRITICAL("write failed\n");
                    goto end;
                }
            }
            else {
                if (0 != storage_dev->write(storage_dev, dst, read_buf, read_len)) {
                    PRINTF_CRITICAL("write failed\n");
                    goto end;
                }
            }

            dst += read_len;
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

int blk_write_with_check(storage_device_t *storage_dev, uint64_t dst,
                         const uint8_t *buf, uint64_t data_len)
{
    uint32_t crc_w = 0xFFFFFFFF;
    uint32_t crc_r = 0;
    uint64_t cnt = 0;
    uint64_t  left = 0;
    uint8_t *read_buf = NULL;
    uint64_t read_len = WRITE_CHECK_LENGTH;
    int ret = -1;
    uint64_t i = 0;

    read_buf = (uint8_t *)MEM_ALIGN(512, WRITE_CHECK_LENGTH);

    if (!read_buf) {
        PRINTF_INFO("blk_write_with_check calloc failed\n");
        goto end;
    }

    crc_w = crc32(0, buf, data_len);

    if (0 != blk_write(storage_dev, dst, buf, data_len)) {
        PRINTF_CRITICAL("block dev write with check write failed\n");
        goto end;
    }

    cnt = data_len / WRITE_CHECK_LENGTH;
    left = data_len % WRITE_CHECK_LENGTH;

    for (i = 0; i < cnt + 1; i++) {
        if (i == cnt) {
            if (left)
                read_len = left;
            else
                break;
        }

        if (0 != blk_read(storage_dev, dst, read_buf, read_len)) {
            PRINTF_CRITICAL("block dev write with check write failed\n");
            goto end;
        }

        crc_r = crc32(crc_r, read_buf, read_len);
        dst += read_len;
    }

    if (crc_r != crc_w) {
        PRINTF_CRITICAL("block dev write crc check error, crc read = 0x%08x, crc write = 0x%08x\n",
                        crc_r, crc_w);
        goto end;
    }

    ret = 0;

end:

    if (read_buf)
        FREE(read_buf);

    return ret;
}

uint64_t blk_get_capacity(storage_device_t *storage_dev)
{
    if (!storage_dev) {
        PRINTF_CRITICAL("blk_get_capacity para error");
        return 0;
    }

    return get_capacity(storage_dev->dev_fd);
}

uint32_t blk_get_erase_group_size(storage_device_t *storage_dev)
{
    uint32_t sector_size;

    if (!storage_dev) {
        PRINTF_CRITICAL("blk_get_erase_group_size para error");
        return 0;
    }

#ifdef RUN_IN_QNX

    SDMMC_DEVICE_INFO emmc_dev_info = {0};

    if (EOK != devctl (storage_dev->dev_fd, DCMD_SDMMC_DEVICE_INFO, &emmc_dev_info,
                       sizeof(SDMMC_DEVICE_INFO), NULL)) {
        PRINTF_CRITICAL("devctl failed to get emmc erase_group_size info\n");
        return 0;
    }

    sector_size = emmc_dev_info.erase_size;

#else

    if (ioctl(storage_dev->dev_fd, BLKIOMIN, &sector_size) < 0) {
        fprintf(stderr, "failed to get dev size:%s\n", strerror(errno));
        return 0;
    }

#endif

    return sector_size;
}

int blk_copy(storage_device_t *storage_dev, uint64_t src, uint64_t dst,
             uint64_t size)
{
    uint64_t cnt = (size / CALLOC_SIZE);
    uint64_t left = (size % CALLOC_SIZE);
    uint8_t *data;
    int ret = -1;

    if (!storage_dev) {
        PRINTF_CRITICAL("blk_copy para error");
        return -1;
    }

    data = (uint8_t *)CALLOC(1, (cnt != 0 ? (CALLOC_SIZE) : size));

    if (!data) {
        PRINTF_INFO("blk_copy calloc failed\n");
        return -1;
    }

    for (unsigned long long n = 0; n < cnt; n++) {
        ret = storage_dev->read(storage_dev, src, data, CALLOC_SIZE);

        if (ret < 0) {
            PRINTF_INFO("blk_copy read failed\n");
            FREE(data);
            return -1;
        }

        storage_dev->write(storage_dev, dst, data, CALLOC_SIZE);

        if (ret < 0) {
            PRINTF_INFO("blk_copy write failed\n");
            FREE(data);
            return -1;
        }

        src  += CALLOC_SIZE;
        dst  += CALLOC_SIZE;
    }

    if (0 != left) {
        ret = storage_dev->read(storage_dev, src, data, left);

        if (ret < 0) {
            PRINTF_INFO("OTA_programming storage->read failed\n");
            FREE(data);
            return -1;
        }

        ret = storage_dev->write(storage_dev, dst, data, left);

        if (ret < 0) {
            PRINTF_INFO("OTA_programming storage->write failed\n");
            FREE(data);
            return -1;
        }
    }

    return 0;
}

int blk_setup_ptdev(storage_device_t *storage_dev, const char *ptdev_name)
{
    PRINTF_CRITICAL("do not support %s\n", __FUNCTION__);
    return -1;
}

int blk_destroy_ptdev(storage_device_t *storage_dev, const char *ptdev_name)
{
    PRINTF_CRITICAL("do not support %s\n", __FUNCTION__);
    return -1;
}

int blk_get_partition_index(storage_device_t *storage_dev,
                            const char *ptdev_name, const char *partition_name)
{
    PRINTF_CRITICAL("do not support %s\n", __FUNCTION__);
    return -1;
}

uint64_t blk_get_partition_offset(storage_device_t *storage_dev,
                                  const char *ptdev_name, const char *partition_name)
{
    PRINTF_CRITICAL("do not support %s\n", __FUNCTION__);
    return -1;
}

uint64_t blk_get_partition_size(storage_device_t *storage_dev,
                                const char *ptdev_name, const char *partition_name)
{
    PRINTF_CRITICAL("do not support %s\n", __FUNCTION__);
    return -1;
}

int blk_get_slot_number(storage_device_t *storage_dev, const char *ptdev_name)
{
    PRINTF_CRITICAL("do not support %s\n", __FUNCTION__);
    return -1;
}

int blk_update_slot_attr(storage_device_t *storage_dev, const char *ptdev_name)
{
    PRINTF_CRITICAL("do not support %s\n", __FUNCTION__);
    return -1;
}

int blk_set_slot_attr(storage_device_t *storage_dev, const char *ptdev_name,
                      uint8_t slot, uint8_t attr, uint8_t set_value)
{
    PRINTF_CRITICAL("do not support %s\n", __FUNCTION__);
    return -1;
}

int blk_get_slot_attr(storage_device_t *storage_dev, const char *ptdev_name,
                      uint8_t slot, uint8_t attr)
{
    PRINTF_CRITICAL("do not support %s\n", __FUNCTION__);
    return -1;
}

int blk_get_current_slot(storage_device_t *storage_dev, const char *ptdev_name)
{
    PRINTF_CRITICAL("do not support %s\n", __FUNCTION__);
    return -1;
}

int blk_get_partition_info(storage_device_t *storage_dev,
                           const char *ptdev_name, uint8_t partition_index, void *entry)
{
    PRINTF_CRITICAL("do not support %s\n", __FUNCTION__);
    return -1;
}

int blk_get_partition_number(storage_device_t *storage_dev,
                             const char *ptdev_name)
{
    PRINTF_CRITICAL("do not support %s\n", __FUNCTION__);
    return -1;
}

/*
    storage : storage to be init
*/
int init_storage(storage_device_t *storage, storage_device_t *base_storage)
{
    int ret = -1;

    KEYNODE("try to init storage %s\n", storage->dev_name);
    KEYNODE("mapped storage is %d\n", storage->mapped);

    if (!storage) {
        PRINTF_CRITICAL("storage dev is null\n");
        goto end;
    }

    if (storage->dev_fd >= 0) {
        PRINTF_INFO("already opened %s\n", storage->dev_name);
        ret = 0;
        goto end;
    }

    switch (storage->type) {
        case STORAGE_LOCAL:
            /* emmc init function assigned before */
            //storage->init =                 &blk_init;
            storage->read_direct =          &blk_read_direct;
            storage->write_direct =         &blk_write_direct;
            storage->seek =                 &blk_seek;
            storage->read =                 &blk_read;
            storage->write =                &blk_write;
            storage->write_with_check =     &blk_write_with_check;
            storage->get_capacity =         &blk_get_capacity;
            storage->get_erase_group_size = &blk_get_erase_group_size;
            storage->get_block_size =       &blk_get_block_size;
            storage->release =              &blk_release;
            storage->copy =                 &blk_copy;
            storage->setup_ptdev =          &blk_setup_ptdev;
            storage->destroy_ptdev =        &blk_destroy_ptdev;
            storage->get_partition_index =  &blk_get_partition_index;
            storage->get_partition_offset = &blk_get_partition_offset;
            storage->get_partition_size =   &blk_get_partition_size;
            storage->get_slot_number      = &blk_get_slot_number;
            storage->update_slot_attr     = &blk_update_slot_attr;
            storage->set_slot_attr        = &blk_set_slot_attr;
            storage->get_slot_attr        = &blk_get_slot_attr;
            storage->get_current_slot     = &blk_get_current_slot;
            storage->get_partition_number = &blk_get_partition_number;
            storage->get_partition_info   = &blk_get_partition_info;
            storage->switch_part          = &blk_switch_part;
            storage->set_readonly         = &blk_set_readonly;
            storage->get_readonly         = &blk_get_readonly;
            break;

        case STORAGE_REMOTE:
            if (false == storage->mapped) {
                storage->init =                 &remote_init;
                storage->read_direct =          &remote_read_direct;
                storage->write_direct =         &remote_write_direct;
                storage->seek =                 &remote_seek;
                storage->read =                 &remote_read;
                storage->write =                &remote_write;
                storage->write_with_check =     &remote_write_with_check;
                storage->get_capacity =         &remote_get_capacity;
                storage->get_erase_group_size = &remote_get_erase_group_size;
                storage->get_block_size       = &remote_get_block_size;
                storage->release              = &remote_release;
                storage->copy =                 &remote_copy;
                storage->setup_ptdev =          &remote_setup_ptdev;
                storage->destroy_ptdev =        &remote_destroy_ptdev;
                storage->get_partition_index  = &remote_get_partition_index;
                storage->get_partition_offset = &remote_get_partition_offset;
                storage->get_partition_size   = &remote_get_partition_size;
                storage->get_slot_number      = &remote_get_slot_number;
                storage->update_slot_attr     = &remote_update_slot_attr;
                storage->set_slot_attr        = &remote_set_slot_attr;
                storage->get_slot_attr        = &remote_get_slot_attr;
                storage->get_current_slot     = &remote_get_current_slot;
                storage->get_partition_number = &remote_get_partition_number;
                storage->get_partition_info   = &remote_get_partition_info;
                storage->switch_part          = &void_switch_part;
                storage->set_readonly         = &void_set_readonly;
                storage->get_readonly         = &void_get_readonly;
                break;
            }
            else {
                if (!base_storage || !(base_storage->cnt || (base_storage->dev_fd < 0))) {
                    PRINTF_CRITICAL("base storage not init\n");
                }

                storage->init                                 = remote_init_mapped;
                storage->seek                                 = &remote_seek_mapped;
                storage->read                                 = &remote_read_mapped;
                storage->write                                = &remote_write_mapped;
                storage->write_with_check                     = &remote_write_with_check_mapped;
                storage->get_capacity                         = &remote_get_capacity_mapped;
                storage->release                              = &remote_release_mapped;
                storage->copy                                 = &remote_copy_mapped;
                storage->dev_fd                               = base_storage->dev_fd;
                storage->use_shared_memory                    = base_storage->use_shared_memory;
                storage->memfd                                = base_storage->memfd;
                storage->shared_mem_ptr                       = base_storage->shared_mem_ptr;
                storage->max_shared_memory_read_data_length   =
                    base_storage->max_shared_memory_read_data_length;
                storage->max_shared_memory_write_data_length  =
                    base_storage->max_shared_memory_write_data_length;
                storage->max_shared_memory_length             =
                    base_storage->max_shared_memory_length;
                storage->shared_memory_read_data_offset       =
                    base_storage->shared_memory_read_data_offset;
                storage->shared_memory_write_data_offset      =
                    base_storage->shared_memory_write_data_offset;
                storage->shared_memory_read_crc_offset        =
                    base_storage->shared_memory_read_crc_offset;
                storage->shared_memory_write_crc_offset       =
                    base_storage->shared_memory_write_crc_offset;
                storage->max_shared_memory_crc_length       =
                    base_storage->max_shared_memory_crc_length;
                storage->thread_read_size                     = base_storage->thread_read_size;
                storage->thread_read_crc_size                 = base_storage->thread_read_crc_size;
                storage->read_direct                          = base_storage->read_direct;
                storage->write_direct                         = base_storage->write_direct;
                storage->get_erase_group_size                 =
                    base_storage->get_erase_group_size;
                storage->get_block_size                       = base_storage->get_block_size;
                storage->setup_ptdev                          = base_storage->setup_ptdev;
                storage->destroy_ptdev                        = base_storage->destroy_ptdev;
                storage->get_partition_index                  =
                    base_storage->get_partition_index;
                storage->get_partition_offset                 =
                    base_storage->get_partition_offset;
                storage->get_partition_size                   =
                    base_storage->get_partition_size;
                storage->get_slot_number                      = base_storage->get_slot_number;
                storage->update_slot_attr                     = base_storage->update_slot_attr;
                storage->set_slot_attr                        = base_storage->set_slot_attr;
                storage->get_slot_attr                        = base_storage->get_slot_attr;
                storage->get_current_slot                     = base_storage->get_current_slot;
                storage->get_partition_number                 =
                    base_storage->get_partition_number;
                storage->get_partition_info                   =
                    base_storage->get_partition_info;
                storage->switch_part                          = &void_switch_part;
                storage->set_readonly                         = &void_set_readonly;
                storage->get_readonly                         = &void_get_readonly;

                memcpy(&storage->shared_mem_mode, &base_storage->shared_mem_mode,
                       sizeof(shared_memory_mode_t));

                break;
            }

        default:
            PRINTF_CRITICAL("storage type error\n");
            goto end;
    }

    storage->write_file = &storage_write_file;

    if (!(storage->init) || (storage->init(storage) != 0)) {
        PRINTF_CRITICAL("storage dev for %s init failed\n", storage->dev_name);
        goto end;
    }

    if (storage->dev_fd < 0) {
        PRINTF_CRITICAL("storage fd %d error\n", storage->dev_fd);
        goto end;
    }

    storage->capacity = storage->get_capacity(storage);

    if (!storage->capacity) {
        PRINTF_CRITICAL("get storage capacity error\n");
        goto end;
    }

    storage->erase_size = storage->get_erase_group_size(storage);

    if (!storage->erase_size) {
        PRINTF_CRITICAL("get storage erase size error\n");
        goto end;
    }

    storage->block_size = storage->get_block_size(storage);

    if (!storage->block_size) {
        PRINTF_CRITICAL("get storage block size error\n");
        goto end;
    }

    ret = 0;

end:

    if (ret) {
        storage->dev_fd = -1;
        storage->capacity = 0;
        storage->erase_size = 0;
        storage->block_size = 0;
        KEYNODE("%s init failed\n", storage->dev_name);
    }
    else {
        storage->cnt++;
    }

    if (0 == ret) {
        KEYNODE("%s init success, inst cnt = %d\n", storage->dev_name, storage->cnt);
    }

    return ret;
}

int uninit_storage(storage_device_t *storage)
{
    int ret = -1;

    if (!storage) {
        PRINTF_CRITICAL("storage dev is null\n");
        goto end;
    }

    if (storage->dev_fd < 0) {
        PRINTF_CRITICAL("storage already uninit\n");
        goto end;
    }

    if (storage->cnt > 1) {
        storage->cnt--;
        ret = 0;
        goto end;
    }

    if (storage->cnt <= 1) {
        storage->cnt = 0;

        if (storage->release(storage) != 0) {
            PRINTF_CRITICAL("storage dev release failed\n");
            goto end;
        }

        storage->capacity = 0;
        storage->erase_size = 0;
        storage->block_size = 0;
        storage->dev_fd = -1;
        ret = 0;
    }

end:

    if (!storage->cnt) {
        storage->dev_fd = -1;
    }

    if (!ret)
        PRINTF_INFO("destroy %s cnt = %d\n", storage->dev_name, storage->cnt);

    return ret;
}

#ifdef __cplusplus
}

#endif /* __cplusplus */
