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

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <malloc.h>
#include <sys/utsname.h>
#include "system_cfg.h"
#include "storage_device.h"
#include "storage_dev_ospi.h"
#include "crc32.h"
#include "partition_parser.h"
#include "ab_partition_parser.h"
#include "crypto_software.h"
#include "crypto_platform.h"
#include <sys/mman.h>
#include <pthread.h>
#include "list.h"

#if !RUN_IN_QNX
#include <linux/types.h>
#define RPMSG_CREATE_EPT_IOCTL _IOW(0xb5, 0x1, struct rpmsg_endpoint_info)
#define RPMSG_DESTROY_EPT_IOCTL _IO(0xb5, 0x2)
#define RPMSG_BUS_SYS "/sys/bus/rpmsg"
#endif

#if RUN_IN_ANDROID && !RUN_IN_HOST
#include <sdrv_rpmsg_channel.h>
#endif

#include <share_memory.h>
#define SHM_DEVNAME		"/dev/sdrv-shm"

#define RECV_BUF_LEN 256
#define CMD_LEN 256
#define ALIGNED_LEN 32
//#define SET_REMOTE_HIGH_PRIO 1

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define SHARED_MEMORY_ALIGN                   (0x1000)
#define MAX_SHARED_MEMORY_RW_LENGTH           (0x200000)
#define MAX_SHARED_MEMORY_CRC_LENGTH          (0x1000)
#define MAX_SHARED_MEMORY_READ_DATA_LENGTH    MAX_SHARED_MEMORY_RW_LENGTH
#define MAX_SHARED_MEMORY_WRITE_DATA_LENGTH   MAX_SHARED_MEMORY_RW_LENGTH
#define MAX_SHARED_MEMORY_SIZE                (MAX_SHARED_MEMORY_RW_LENGTH + \
                                               MAX_SHARED_MEMORY_CRC_LENGTH + \
                                               MAX_SHARED_MEMORY_CRC_LENGTH)

extern bool is_run_in_ap2();

bool ospi_use_handover = USE_HAND_OVER;
/* Read Write time */
static struct timeval read_start, read_end;
static struct timeval write_start, write_end, write_info_start, write_info_end;
uint64_t pure_read_time = 0;
uint64_t pure_write_time = 0;
uint64_t write_info_time = 0;

/* Copy time */
static struct timeval read_copy_start, read_copy_end;
static struct timeval write_copy_start, write_copy_end;
uint64_t read_ddr_copy_time = 0;
uint64_t write_ddr_copy_time = 0;

/* Hash time */
static struct timeval read_hash_start, read_hash_end;
static struct timeval write_hash_start, write_hash_end;
uint64_t read_hash_time = 0;
uint64_t write_hash_time = 0;

/* Seek time */
static struct timeval seek_start, seek_end;
uint64_t seek_time = 0;

/* shared memory base */
static uint32_t shared_memory_base_AP_core_view = 0;

static struct timeval finish_start, finish_end;
uint64_t finish_read_time = 0;

/* The following data structure is for thread read and will only be used within this file. */
typedef struct ddr_copy_arg {
    struct list_node node;
    uint8_t* src;
    uint8_t* dst;
    uint8_t* crc_base;
    size_t len;
    shared_memory_digest_mode_e digest_mode;
    uint32_t rand_data;
    uint32_t data_offset;
    uint32_t crc_offset;
}shm_copy_arg_t;

typedef enum queue_status_enum {
    QUEUE_STATUS_OK = 0,
    QUEUE_LENGTH_ERR,
    SHM_MEMORY_COPY_ERR,
    SHM_MEMORY_HASH_ERR,
    QUEUE_WAIT_TIMEOUT,
    QUEUE_QUIT,
    QUEUE_TOTAL_TASK_ERR,
    QUEUE_UNKNOWN,
}queue_status_e;

typedef struct task_queue_struct {
    struct list_node        list;
    pthread_mutex_t         mutex;
    queue_status_e          status;
    int                     total;
} task_queue_t;

static const char *ota_cmd_str[OTA_CMD_MAX] = {
    [OTA_CMD_START                      ] =  "OTA_CMD_START",
    [OTA_CMD_START_OK                   ] =  "OTA_CMD_START_OK",
    [OTA_CMD_START_FAIL                 ] =  "OTA_CMD_START_FAIL ",
    [OTA_CMD_SEEK                       ] =  "OTA_CMD_SEEK",
    [OTA_CMD_SEEK_OK                    ] =  "OTA_CMD_SEEK_OK",
    [OTA_CMD_SEEK_FAIL                  ] =  "OTA_CMD_SEEK_FAIL",
    [OTA_CMD_READ                       ] =  "OTA_CMD_READ",
    [OTA_CMD_READ_OK                    ] =  "OTA_CMD_READ_OK",
    [OTA_CMD_READ_FAIL                  ] =  "OTA_CMD_READ_FAIL",
    [OTA_CMD_WRITE                      ] =  "OTA_CMD_WRITE",
    [OTA_CMD_WRITE_OK                   ] =  "OTA_CMD_WRITE_OK",
    [OTA_CMD_WRITE_FAIL                 ] =  "OTA_CMD_WRITE_FAIL",
    [OTA_CMD_WRITE_INFO                 ] =  "OTA_CMD_WRITE_INFO",
    [OTA_CMD_WRITE_INFO_OK              ] =  "OTA_CMD_WRITE_INFO_OK",
    [OTA_CMD_WRITE_INFO_FAIL            ] =  "OTA_CMD_WRITE_INFO_FAIL",
    [OTA_CMD_GET_CAPACITY               ] =  "OTA_CMD_GET_CAPACITY",
    [OTA_CMD_GET_CAPACITY_OK            ] =  "OTA_CMD_GET_CAPACITY_OK",
    [OTA_CMD_GET_CAPACITY_FAIL          ] =  "OTA_CMD_GET_CAPACITY_FAIL ",
    [OTA_CMD_GET_BLOCK                  ] =  "OTA_CMD_GET_BLOCK",
    [OTA_CMD_GET_BLOCK_OK               ] =  "OTA_CMD_GET_BLOCK_OK",
    [OTA_CMD_GET_BLOCK_FAIL             ] =  "OTA_CMD_GET_BLOCK_FAIL",
    [OTA_CMD_GET_ERASESIZE              ] =  "OTA_CMD_GET_ERASESIZE",
    [OTA_CMD_GET_ERASESIZE_OK           ] =  "OTA_CMD_GET_ERASESIZE_OK",
    [OTA_CMD_GET_ERASESIZE_FAIL         ] =  "OTA_CMD_GET_ERASESIZE_FAIL",
    [OTA_CMD_COPY                       ] =  "OTA_CMD_COPY",
    [OTA_CMD_COPY_OK                    ] =  "OTA_CMD_COPY_OK",
    [OTA_CMD_COPY_FAIL                  ] =  "OTA_CMD_COPY_FAIL",
    [OTA_CMD_HANDOVER                   ] =  "OTA_CMD_HANDOVER",
    [OTA_CMD_HANDOVER_OK                ] =  "OTA_CMD_HANDOVER_OK",
    [OTA_CMD_HANDOVER_FAIL              ] =  "OTA_CMD_HANDOVER_FAIL",
    [OTA_CMD_CLOSE                      ] =  "OTA_CMD_CLOSE",
    [OTA_CMD_CLOSE_OK                   ] =  "OTA_CMD_CLOSE_OK",
    [OTA_CMD_CLOSE_FAIL                 ] =  "OTA_CMD_CLOSE_FAIL",
    [OTA_CMD_PRIORITY                   ] =  "OTA_CMD_PRIORITY",
    [OTA_CMD_PRIORITY_OK                ] =  "OTA_CMD_PRIORITY_OK",
    [OTA_CMD_PRIORITY_FAIL              ] =  "OTA_CMD_PRIORITY_FAIL",
    [OTA_CMD_STOP_WDT                   ] =  "OTA_CMD_STOP_WDT",
    [OTA_CMD_STOP_WDT_OK                ] =  "OTA_CMD_STOP_WDT_OK",
    [OTA_CMD_STOP_WDT_FAIL              ] =  "OTA_CMD_STOP_WDT_FAIL",
    [OTA_CMD_SETUP_PTDEV                ] =  "OTA_CMD_SETUP_PTDEV",
    [OTA_CMD_SETUP_PTDEV_OK             ] =  "OTA_CMD_SETUP_PTDEV_OK",
    [OTA_CMD_SETUP_PTDEV_FAIL           ] =  "OTA_CMD_SETUP_PTDEV_FAIL",
    [OTA_CMD_DESTROY_PTDEV              ] =  "OTA_CMD_DESTROY_PTDEV",
    [OTA_CMD_DESTROY_PTDEV_OK           ] =  "OTA_CMD_DESTROY_PTDEV_OK",
    [OTA_CMD_DESTROY_PTDEV_FAIL         ] =  "OTA_CMD_DESTROY_PTDEV_FAIL",
    [OTA_CMD_GET_PARTITION_INDEX        ] =  "OTA_CMD_GET_PARTITION_INDEX",
    [OTA_CMD_GET_PARTITION_INDEX_OK     ] =  "OTA_CMD_GET_PARTITION_INDEX_OK",
    [OTA_CMD_GET_PARTITION_INDEX_FAIL   ] =  "OTA_CMD_GET_PARTITION_INDEX_FAIL",
    [OTA_CMD_GET_PARTITION_SIZE         ] =  "OTA_CMD_GET_PARTITION_SIZE",
    [OTA_CMD_GET_PARTITION_SIZE_OK      ] =  "OTA_CMD_GET_PARTITION_SIZE_OK",
    [OTA_CMD_GET_PARTITION_SIZE_FAIL    ] =  "OTA_CMD_GET_PARTITION_SIZE_FAIL",
    [OTA_CMD_GET_PARTITION_OFFSET       ] =  "OTA_CMD_GET_PARTITION_OFFSET",
    [OTA_CMD_GET_PARTITION_OFFSET_OK    ] =  "OTA_CMD_GET_PARTITION_OFFSET_OK",
    [OTA_CMD_GET_PARTITION_OFFSET_FAIL  ] =  "OTA_CMD_GET_PARTITION_OFFSET_FAIL",
    [OTA_CMD_GET_NUMBER_SLOTS           ] =  "OTA_CMD_GET_NUMBER_SLOTS",
    [OTA_CMD_GET_NUMBER_SLOTS_OK        ] =  "OTA_CMD_GET_NUMBER_SLOTS_OK",
    [OTA_CMD_GET_NUMBER_SLOTS_FAIL      ] =  "OTA_CMD_GET_NUMBER_SLOTS_FAIL",
    [OTA_CMD_GET_CURRENT_SLOTS          ] =  "OTA_CMD_GET_CURRENT_SLOTS",
    [OTA_CMD_GET_CURRENT_SLOTS_OK       ] =  "OTA_CMD_GET_CURRENT_SLOTS_OK",
    [OTA_CMD_GET_CURRENT_SLOTS_FAIL     ] =  "OTA_CMD_GET_CURRENT_SLOTS_FAIL",
    [OTA_CMD_GET_SLOT_ATTR              ] =  "OTA_CMD_GET_SLOT_ATTR",
    [OTA_CMD_GET_SLOT_ATTR_OK           ] =  "OTA_CMD_GET_SLOT_ATTR_OK",
    [OTA_CMD_GET_SLOT_ATTR_FAIL         ] =  "OTA_CMD_GET_SLOT_ATTR_FAIL",
    [OTA_CMD_SET_SLOT_ATTR              ] =  "OTA_CMD_SET_SLOT_ATTR",
    [OTA_CMD_SET_SLOT_ATTR_OK           ] =  "OTA_CMD_SET_SLOT_ATTR_OK",
    [OTA_CMD_SET_SLOT_ATTR_FAIL         ] =  "OTA_CMD_SET_SLOT_ATTR_FAIL",
    [OTA_CMD_UPDATE_SLOT_ATTR           ] =  "OTA_CMD_UPDATE_SLOT_ATTR",
    [OTA_CMD_UPDATE_SLOT_ATTR_OK        ] =  "OTA_CMD_UPDATE_SLOT_ATTR_OK",
    [OTA_CMD_UPDATE_SLOT_ATTR_FAIL      ] =  "OTA_CMD_UPDATE_SLOT_ATTR_FAIL",
    [OTA_CMD_GET_NUMBER_PARTITION       ] =  "OTA_CMD_GET_NUMBER_PARTITION",
    [OTA_CMD_GET_NUMBER_PARTITION_OK    ] =  "OTA_CMD_GET_NUMBER_PARTITION_OK",
    [OTA_CMD_GET_NUMBER_PARTITION_FAIL  ] =  "OTA_CMD_GET_NUMBER_PARTITION_FAIL",
    [OTA_CMD_GET_PARTITION_INFO         ] =  "OTA_CMD_GET_PARTITION_INFO",
    [OTA_CMD_GET_PARTITION_INFO_OK      ] =  "OTA_CMD_GET_PARTITION_INFO_OK",
    [OTA_CMD_GET_PARTITION_INFO_FAIL    ] =  "OTA_CMD_GET_PARTITION_INFO_FAIL",
    [OTA_CMD_GET_BOOT_INFO              ] =  "OTA_CMD_GET_BOOT_INFO",
    [OTA_CMD_GET_BOOT_INFO_OK           ] =  "OTA_CMD_GET_BOOT_INFO_OK",
    [OTA_CMD_GET_BOOT_INFO_FAIL         ] =  "OTA_CMD_GET_BOOT_INFO_FAIL",
    [OTA_CMD_SEEK_MAPPED                ] = "OTA_CMD_SEEK_MAPPED",
    [OTA_CMD_SEEK_MAPPED_OK             ] = "OTA_CMD_SEEK_MAPPED_OK",
    [OTA_CMD_SEEK_MAPPED_FAIL           ] = "OTA_CMD_SEEK_MAPPED_FAIL",
    [OTA_CMD_GET_CAPACITY_MAPPED        ] = "OTA_CMD_GET_CAPACITY_MAPPED",
    [OTA_CMD_GET_CAPACITY_MAPPED_OK     ] = "OTA_CMD_GET_CAPACITY_MAPPED_OK",
    [OTA_CMD_GET_CAPACITY_MAPPED_FAIL   ] = "OTA_CMD_GET_CAPACITY_MAPPED_FAIL",
    [OTA_CMD_COPY_MAPPED                ] = "OTA_CMD_COPY_MAPPED",
    [OTA_CMD_COPY_MAPPED_OK             ] = "OTA_CMD_COPY_MAPPED_OK",
    [OTA_CMD_COPY_MAPPED_FAIL           ] = "OTA_CMD_COPY_MAPPED_FAIL",
    [OTA_CMD_SETUP_MAPPED_STORAGE       ] = "OTA_CMD_SETUP_MAPPED_STORAGE",
    [OTA_CMD_SETUP_MAPPED_STORAGE_OK    ] = "OTA_CMD_SETUP_MAPPED_STORAGE_OK ",
    [OTA_CMD_SETUP_MAPPED_STORAGE_FAIL  ] = "OTA_CMD_SETUP_MAPPED_STORAGE_FAIL",
    [OTA_CMD_CHECK_AP                   ] = "OTA_CMD_CHECK_AP",
    [OTA_CMD_CHECK_AP_OK                ] = "OTA_CMD_CHECK_AP_OK ",
    [OTA_CMD_CHECK_AP_FAIL              ] = "OTA_CMD_CHECK_AP_FAIL",
};

uint64_t time_elapsed_us(struct timeval start, struct timeval end)
{
    return (end.tv_sec - start.tv_sec) * (1000000) + end.tv_usec - start.tv_usec;
}

#ifdef RUN_IN_QNX
static void release_rpmsg_handle(storage_device_t *storage_dev);
#endif

const char  *get_ota_cmd_str(ota_cmd_enum num)
{
    return ota_cmd_str[num];
}

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

static int put_data(uint8_t *target, int offset, const uint8_t *value,
                    size_t size)
{
    for (size_t i = 0; i < size; i++, offset++) {
        *(target + offset) = value[i];
    }

    return offset;
}

static int put_char(uint8_t *target, int offset, uint8_t value)
{
    return put_data(target, offset, &value, sizeof(value));
}


static int send_rpmsg(ota_op_t *op, uint8_t *data, uint16_t data_len)
{
    uint8_t buf[MAX_SEND_LENGTH] = {0};
    uint16_t i = 0;
    int ret = -1;
    ota_msg_head_struct_t *head;
    uint16_t total_len = data_len + MSG_HEAD_SIZE;
    int offset = MSG_HEAD_SIZE;

    if ((NULL == op)) {
        PRINTF_CRITICAL("sendMsg para error\n");
        return ret;
    }

    if ((op->cmd >= OTA_CMD_MAX) || (op->fd < 0)) {
        PRINTF_CRITICAL("sendMsg op error, cmd = %s, fd = %d\n",
                        get_ota_cmd_str(op->cmd),
                        op->fd);
        return ret;
    }

    if (total_len > MAX_SEND_LENGTH) {
        PRINTF_CRITICAL("sendMsg send length error,cmd = %s length = %d\n",
                        get_ota_cmd_str(op->cmd), data_len);
        return ret;
    }

    /* head */
    head = (ota_msg_head_struct_t *)buf;
    head->flag1 = OTA_START_MAGIC;
    head->len = data_len;
    head->cmd = op->cmd;
    head->crc = 0;
    head->flag2 = OTA_END_MAGIC;

    /* data */
    if ((0 != data_len) && (NULL != data)) {
        for (i = 0; i < data_len; i++) {
            offset = put_char(buf, offset, data[i]);
        }
    }

    /* crc */
    head->crc = crc32(0, buf, total_len);

#if DEBUGMODE > 1
    PRINTF("send msg:\n");
    hexdump8((void *)buf, total_len);
    PRINTF_CRITICAL("write %d\n", op->fd);
#endif

    ret = write(op->fd, buf, total_len);


    if (ret < 0) {
        PRINTF_CRITICAL("sendMsg write msg error ...%s\n", strerror(errno));
    }

    return ret;
}

static int recv_rpmsg(ota_op_t *op, uint8_t *recv_msg)
{
    struct timeval tv;
    fd_set rfds;
    int fd = op->fd;
    int ret = -1;

    if ((NULL == op) || (NULL == recv_msg)) {
        PRINTF_CRITICAL("recvMsg para error\n");
        return ret;
    }

    if ((op->cmd >= OTA_CMD_MAX) || (op->fd < 0)) {
        PRINTF_CRITICAL("recvMsg op error, cmd = %s, fd = %d", get_ota_cmd_str(op->cmd),
                        op->fd);
        return ret;
    }

    tv.tv_sec =   (op->timeout_ms) / 1000;
    tv.tv_usec = ((op->timeout_ms) % 1000) * 1000;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

#if DEBUGMODE > 1
    PRINTF_CRITICAL("wait %d\n", op->fd);
#endif

    ret = select(fd + 1, &rfds, NULL, NULL, &tv);


    if (ret <= 0) {
        PRINTF_CRITICAL("recvMsg select error\n");
        return -1;
    }
    else {
        ret = read(fd, recv_msg, MAX_SEND_LENGTH);

        if (ret < 0) {
            PRINTF_CRITICAL("recvMsg read error ...\n");
            return ret;
        }

#if DEBUGMODE > 1
        PRINTF("recv msg:\n");
        hexdump8((void *)recv_msg, ret);
#endif
    }

    return ret;
}

static int check_rpmsg(ota_op_t *op, uint8_t *recv_msg)
{
    ota_msg_head_struct_t *head;
    uint16_t total_len;
    uint32_t crc_val;

    if (!recv_msg) {
        PRINTF_CRITICAL("recv_msg para is NULL\n");
        return -1;
    }

    head = (ota_msg_head_struct_t *)recv_msg;
    total_len = head->len + MSG_HEAD_SIZE;

    if ((total_len > MAX_RECV_LENGTH) || (total_len < MSG_HEAD_SIZE)) {
        PRINTF_CRITICAL("msg len error, total_len:%d\n", total_len);
        return -1;
    }

    if (head->flag1 != OTA_START_MAGIC) {
        PRINTF_CRITICAL("flag1 is 0x%04x, expect 0x%04x \n", head->flag1,
                        OTA_START_MAGIC);
        return -1;
    }

    if (head->flag2 != OTA_END_MAGIC) {
        PRINTF_CRITICAL("flag2 is 0x%04x, expect 0x%04x \n", head->flag2,
                        OTA_END_MAGIC);
        return -1;
    }

    crc_val = head->crc;
    head->crc = 0;
    head->crc = crc32(0, recv_msg, total_len);

    if (crc_val != head->crc) {
        PRINTF_CRITICAL("crc = 0x%08x error, expect 0x%08x \n", crc_val, head->crc);
        return -1;
    }

    if (head->cmd != (op->expect_recv_cmd)) {
        PRINTF_CRITICAL("cmd = %s  error, expect %s \n", get_ota_cmd_str(head->cmd),
                        get_ota_cmd_str(op->expect_recv_cmd));
        return -1;
    }

    return 0;
}


static int remote_ops(ota_op_t *op, uint8_t *send_data, uint16_t send_len,
                      uint8_t *recv_data)
{
    int ret = -1;

    /* send msg */
    ret = send_rpmsg(op, send_data, send_len);

    if (ret < 0) {
        PRINTF_CRITICAL("remote ops:send msg error, cmd=%s\n",
                        get_ota_cmd_str(op->cmd));
        return -1;
    }

    /* recv msg */
    ret = recv_rpmsg(op, recv_data);

    if (ret < (signed)MSG_HEAD_SIZE) {
        PRINTF_CRITICAL("remote ops:recv msg error, len=%d , cmd=%s\n", ret,
                        get_ota_cmd_str(op->cmd));
        return -1;
    }

    /* check msg */
    ret = check_rpmsg(op, recv_data);

    if (ret < 0) {
        PRINTF_CRITICAL("remote ops:recv msg check error, cmd=%s\n",
                        get_ota_cmd_str(op->cmd));
        return -1;
    }

    return ret;
}

#if SET_REMOTE_HIGH_PRIO
static int remote_set_priority(int fd, uint32_t priority)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_SEND_LENGTH] = {0};
    uint32_t priority_set = priority;

    op.fd = fd;
    op.cmd = OTA_CMD_PRIORITY;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_PRIORITY_OK;
    ret = remote_ops(&op, (uint8_t *)&priority_set, sizeof(priority_set),
                     recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_set_priority error \n");
        return -1;
    }

    return 0;
}
#endif

static int  ota_shm_alloc(uint32_t align_size, uint32_t size, uint32_t flags, uint16_t mode, const char *name, uint32_t *pysical_addr)
{
#if !RUN_IN_HOST
    uint64_t addr = 0;

    if(!name || !size) {
        PRINTF_CRITICAL("para error\n");
        *pysical_addr = 0;
        return -1;
    }

    if (0 == shm_find(name, &addr)) {
        PRINTF_INFO("find '%s' already exist at 0x%llx\n", name, (unsigned long long)addr);

    } else {
        PRINTF_INFO("creat a new share memory :%s\n", name);

        if (0 == shm_alloc(align_size, size, flags, mode, name, &addr)) {
            PRINTF_INFO("allocate 0x%x bytes, pysical_addr 0x%llx\n", size, (unsigned long long)addr);

        } else {
            PRINTF_CRITICAL("Error: fail to allocate 0x%x bytes\n", size);
            *pysical_addr = 0;
            return -1;
        }
    }

    if((addr == 0) || ((addr + size)> UINT_MAX)) {
        PRINTF_CRITICAL("shm ddr error 0x%llx \n", (unsigned long long)addr);
        *pysical_addr = 0;
        return -1;
    }

    *pysical_addr = (uint32_t)addr;
    PRINTF_INFO("shm pysical addr is 0x%x\n", *pysical_addr);
    return 0;
#else
    return -1;
#endif
}

static int remote_start(storage_device_t *storage_dev, int fd)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_SEND_LENGTH] = {0};
    uint32_t *p;
    uint32_t bram_pbase_local = 0;   // always use ap view base
    uint32_t bram_pbase_remote = 0;  // always use R5 view base
    uint32_t read_data_size = 0;
    uint32_t write_data_size = 0;
    uint32_t crc_size = 0;
    ota_msg_head_struct_t *head;
    uint32_t thread_read_size;
    uint32_t thread_read_crc_size;
    uint32_t shm_size = 0;
    uint8_t shm_info[sizeof(bram_pbase_remote) + sizeof(shm_size)] = {0};

    op.fd = fd;
    op.cmd = OTA_CMD_START;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_START_OK;

    char name_with_domain[16] = {0};


    if(RUN_IN_AP2 || is_run_in_ap2()) {
        snprintf(name_with_domain, 16, "%s_ap2", storage_dev->shared_memory_name);
    }
    else {
        snprintf(name_with_domain, 16, "%s_ap1", storage_dev->shared_memory_name);
    }

    /* calloc shared memory fisrt */
    if(storage_dev->use_shared_memory) {
        if((ota_shm_alloc(SHARED_MEMORY_ALIGN, MAX_SHARED_MEMORY_SIZE, SHM_F_PHYS_ADDR_BELOW_4G, 0, name_with_domain, &bram_pbase_local)
            || (bram_pbase_local <= SHARED_MEMORY_BASE_AP_OFFSET))) {
                    PRINTF_CRITICAL("shared memory calloc failed\n");
                    bram_pbase_local = 0;
                    shm_size = 0;
        }
        bram_pbase_remote = bram_pbase_local;
        shm_size = MAX_SHARED_MEMORY_SIZE;
    }
    else {
        bram_pbase_local = 0;
        shm_size = 0;
    }

    if((bram_pbase_remote != 0) && (shm_size != 0)) {
        memcpy(&shm_info[0], (uint8_t *)&bram_pbase_remote, sizeof(bram_pbase_remote));
        memcpy(&shm_info[sizeof(bram_pbase_remote)], (uint8_t *)&shm_size, sizeof(shm_size));
        ret = remote_ops(&op, (uint8_t *)shm_info, sizeof(bram_pbase_remote) + sizeof(shm_size), recv_msg);
    }
    else {
        ret = remote_ops(&op, NULL, 0, recv_msg);
    }

    if (ret < 0) {
        PRINTF_CRITICAL("remote start error \n");
        return -1;
    }

    /* len check */
    head = (ota_msg_head_struct_t *)recv_msg;

    if (head->len == 0) {
        PRINTF_INFO("run in RPMSG mode\n");
        storage_dev->use_shared_memory = false;
        return 0;
    }

    if (head->len >= (sizeof(bram_pbase_remote) + sizeof(read_data_size) +
                      sizeof(write_data_size) + sizeof(crc_size))) {
        crypto_uninit();

        if (crypto_init()) {
            PRINTF_CRITICAL("crypto init error\n");
            return -1;
        }

        p = (uint32_t *)(recv_msg + MSG_HEAD_SIZE);
        /* copy the capacity */
        memcpy(&bram_pbase_remote, p++, sizeof(bram_pbase_remote));
        memcpy(&read_data_size, p++, sizeof(read_data_size));
        memcpy(&write_data_size, p++, sizeof(write_data_size));
        memcpy(&crc_size, p++, sizeof(crc_size));

        if(bram_pbase_local) {
            if(bram_pbase_local != bram_pbase_remote) {
                PRINTF_CRITICAL("shared memory base error, shm base ap(ap view) = 0x%08x, shm base r5(ap view) = 0x%08x\n", bram_pbase_local, bram_pbase_remote);
                return -1;
            }
        }

        if (head->len == (sizeof(bram_pbase_remote) + sizeof(read_data_size) +
                          sizeof(write_data_size) + sizeof(crc_size) + sizeof(shared_memory_mode_t))) {

            memcpy(&(storage_dev->shared_mem_mode), (shared_memory_mode_t *)p,
                   sizeof(shared_memory_mode_t));
        }

        PRINTF_INFO("shared memory digest mode = %d\n",
                    storage_dev->shared_mem_mode.digest_mode);

        storage_dev->max_shared_memory_read_data_length = read_data_size;
        storage_dev->max_shared_memory_write_data_length = write_data_size;
        storage_dev->max_shared_memory_length = MAX(read_data_size, write_data_size) + 2 *
                                                crc_size;
        storage_dev->shared_memory_read_data_offset  = 0x0;
        storage_dev->shared_memory_write_data_offset = 0x0;
        storage_dev->shared_memory_read_crc_offset =
            storage_dev->shared_memory_write_data_offset + MAX(read_data_size, write_data_size);
        storage_dev->shared_memory_write_crc_offset =
            storage_dev->shared_memory_read_crc_offset + crc_size;

        storage_dev->max_shared_memory_crc_length = crc_size;

        PRINTF_INFO("%s run in shared memory mode, shared ram_pbase(AP view) = 0x%08x\n",
                    storage_dev->dev_name, bram_pbase_remote);
        PRINTF_INFO("%s read data offset = 0x%08x, write data offset = 0x%08x\n",
                    storage_dev->dev_name, storage_dev->shared_memory_read_data_offset,
                    storage_dev->shared_memory_write_data_offset);
        PRINTF_INFO("%s read crc offset = 0x%08x, write crc coffset = 0x%08x\n",
                    storage_dev->dev_name, storage_dev->shared_memory_read_crc_offset,
                    storage_dev->shared_memory_write_crc_offset);
        PRINTF_INFO("max_shared_memory_crc_length = 0x%08x\n",
                    storage_dev->max_shared_memory_crc_length);
        shared_memory_base_AP_core_view = bram_pbase_remote;

        thread_read_size = (storage_dev->max_shared_memory_read_data_length)/THREAD_READ_PIECE_NUM;
        thread_read_crc_size =  (storage_dev->max_shared_memory_crc_length)/THREAD_READ_PIECE_NUM;

        if(!thread_read_size || !thread_read_crc_size
            || (0 != storage_dev->max_shared_memory_read_data_length % THREAD_READ_PIECE_NUM)
            || (0 != storage_dev->max_shared_memory_crc_length % THREAD_READ_PIECE_NUM)) {
            PRINTF_CRITICAL("thread read size 0x%x or thread read crc size 0x%x error\n", thread_read_size, thread_read_crc_size);
            PRINTF_CRITICAL("shared memory read data length = 0x%x \n", storage_dev->max_shared_memory_read_data_length);
            PRINTF_CRITICAL("shared memory crc length = 0x%x \n", storage_dev->max_shared_memory_crc_length);
            PRINTF_CRITICAL("THREAD_READ_PIECE_NUM = %d \n", THREAD_READ_PIECE_NUM);
            return -1;
        }

        storage_dev->thread_read_size = thread_read_size;
        storage_dev->thread_read_crc_size = thread_read_crc_size;
        PRINTF_INFO("thread_read_size = 0x%08x\n", storage_dev->thread_read_size);
        PRINTF_INFO("thread_read_crc_size = 0x%08x\n", storage_dev->thread_read_crc_size);

        if ((MAP_FAILED != storage_dev->shared_mem_ptr) || (storage_dev->memfd > 0)) {
            PRINTF_INFO("unmap first\n");
            munmap(storage_dev->shared_mem_ptr, storage_dev->max_shared_memory_length);

            if (storage_dev->memfd > 0) {
                PRINTF_INFO("close /dev/mem first\n");
                close(storage_dev->memfd);
                storage_dev->memfd = -1;
            }

            storage_dev->shared_mem_ptr = MAP_FAILED;
        }

        // Map the BRAM physical address into user space getting a virtual address for it
#if RUN_IN_QNX
        const char* mem_dev_str = "/dev/mem";
        storage_dev->memfd = open(mem_dev_str, O_RDWR | O_SYNC);
        if (storage_dev->memfd > 0) {
            storage_dev->shared_mem_ptr = (uint8_t *)mmap(NULL,
                                          storage_dev->max_shared_memory_length,
                                          PROT_READ | PROT_WRITE | PROT_NOCACHE, MAP_SHARED, storage_dev->memfd,
                                          bram_pbase_local);
#else
        const char* mem_dev_str = SHM_DEVNAME;
        storage_dev->memfd = open(mem_dev_str, O_RDWR | O_SYNC);
        if (storage_dev->memfd > 0) {
            storage_dev->shared_mem_ptr = (uint8_t *)mmap(NULL,
                                          storage_dev->max_shared_memory_length,
                                          PROT_READ | PROT_WRITE, MAP_SHARED, storage_dev->memfd, bram_pbase_local);
#endif

            if (MAP_FAILED == storage_dev->shared_mem_ptr) {
                PRINTF_INFO("mmap shared memory dev %s for %s failed, fd = %d, error %s\n", mem_dev_str,
                        storage_dev->dev_name, storage_dev->memfd, strerror(errno));
                close(storage_dev->memfd);
                storage_dev->memfd = -1;
                return -1;
            }

            PRINTF_INFO("open shared memory dev %s for %s success, fd = %d, shared_mem_ptr = %p\n", mem_dev_str,
                        storage_dev->dev_name, storage_dev->memfd, storage_dev->shared_mem_ptr);
        }
        else {
            PRINTF_CRITICAL("open shared memory device %s for %s failed, %s\n", mem_dev_str, storage_dev->dev_name,
                            strerror(errno));
            return -1;
        }

        storage_dev->use_shared_memory = true;
    }

    return 0;
}

static int remote_close(int fd)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_SEND_LENGTH] = {0};

    op.fd = fd;
    op.cmd = OTA_CMD_CLOSE;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_CLOSE_OK;
    ret = remote_ops(&op, NULL, 0, recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote close error \n");
        return -1;
    }

    return 0;
}

int remote_init_mapped(storage_device_t *storage_dev)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[MAX_GPT_NAME_SIZE] = {0};
    assert(MAX_DATA_LENGTH > MAX_GPT_NAME_SIZE);

    if (!storage_dev || !strlen(storage_dev->dev_name)) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if (!storage_dev->mapped) {
        PRINTF_CRITICAL("partition name %s is not mapped\n", storage_dev->dev_name);
        return -1;
    }

    if (strlen(storage_dev->dev_name) >= MAX_GPT_NAME_SIZE) {
        PRINTF_CRITICAL("partition name too long\n");
        return -1;
    }

    if (snprintf((char *)name, MAX_GPT_NAME_SIZE, "%s",
                 storage_dev->dev_name) < 0) {
        PRINTF_CRITICAL("string proccess error\n");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_SETUP_MAPPED_STORAGE;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_SETUP_MAPPED_STORAGE_OK;

    ret = remote_ops(&op, (uint8_t *)name, (strlen(storage_dev->dev_name) + 1),
                     recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote init mapped storage for %s error\n", name);
        return -1;
    }

    return 0;
}

#if 0
// int remote_init(storage_device_t *storage_dev, char const *dev_name,
//                      )
// {
//     int fd;
//     int fd_rpmsg;
//     struct stat buf;
//     int ret = -1;
//     char const *rpmsg_name = storage_dev->dev_name;

//     if ((!storage_dev) || (!rpmsg_name)) {
//         PRINTF_CRITICAL("remote init para error");
//         return -1;
//     }

//     /* rpmsg init */
//     fd_rpmsg = rpmsg_init(rpmsg_name);

//     if (fd_rpmsg < 0) {
//         PRINTF_CRITICAL("init %s device failed\n", rpmsg_name);
//         goto unbind;
//     }

//     if (1 == ospi_use_handover) {
//         /* try handover */
//         ret = remote_handover(fd_rpmsg);
//     }

//     if (0 == ret) {
//         PRINTF_INFO("update monitor handover ospi done\n");
//         /* install mtdblock device driver */
//         ret = install_ospi_driver(NULL);

//         if (ret < 0) {
//             PRINTF_CRITICAL("failed to install modules\n");
//             goto unbind;
//         }

//         /* waiting for uevent raised */
//         usleep(100000);
//         ret = stat(dev_name, &buf);

//         if (0 != ret) {
//             PRINTF_CRITICAL("no such dev file: %s\n", dev_name);
//             ret = -1;
//             goto unbind;
//         }

//         fd = open(dev_name, O_RDWR);

//         if (fd < 0) {
//             PRINTF_CRITICAL("filed to open %s\n", dev_name);
//             ret = -1;
//             goto unbind;
//         }

//         storage_dev->dev_fd = fd;
//         storage_dev->dev_name = dev_name;
//         ret = OSPI_HANDOVER_MODE;

//     }
//     else {
//         ret = remote_start(fd_rpmsg);

//         if (ret < 0) {
//             PRINTF_CRITICAL("failed to start communicate with update monitor\n");
//             goto unbind;
//         }

// #if SET_REMOTE_HIGH_PRIO
//         /* set remote safet update thread's priority, 0: default 1: highest */
//         ret = remote_set_priority(fd_rpmsg, 1);

//         if (ret < 0) {
//             PRINTF_CRITICAL("failed to set the priority of update monitor in safety\n");
//             goto unbind;
//         }

// #endif
//         PRINTF_INFO("ospi start \n");
//         storage_dev->dev_fd = fd_rpmsg;
//         storage_dev->dev_name = rpmsg_name;
//         ret = OSPI_REMOTE_MODE;
//         goto end;
//     }

// unbind:

//     /* unbind rgmsg */
//     if (rpmsg_unbind_chrdev(rpmsg_name) < 0) {
//         PRINTF_CRITICAL("Failed to unbind rpmsg device %s\n", rpmsg_name);
//     }

//     if (fd_rpmsg >= 0)
//         close(fd_rpmsg);

// end:
//     return ret;
// }
#endif

int64_t remote_seek(storage_device_t *storage_dev, off_t offset, int whence)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_SEND_LENGTH] = {0};

    if (!storage_dev) {
        PRINTF_CRITICAL("remote_seek para error");
        return -1;
    }
    gettimeofday(&seek_start, NULL);
    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_SEEK;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_SEEK_OK;
    ret = remote_ops(&op, (uint8_t *)&offset, sizeof(offset), recv_msg);
    gettimeofday(&seek_end, NULL);
    if (ret < 0) {
        PRINTF_CRITICAL("remote_seek error \n");
        return -1;
    }
    seek_time += time_elapsed_us(seek_start, seek_end);
    return 0;
}

int64_t remote_seek_mapped(storage_device_t *storage_dev, off_t offset,
                           int whence)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[MAX_GPT_NAME_SIZE + sizeof(uint64_t)] = {0};
    assert(MAX_DATA_LENGTH > (MAX_GPT_NAME_SIZE + sizeof(uint64_t)));
    gettimeofday(&seek_start, NULL);
    if (!storage_dev || !strlen(storage_dev->dev_name)) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if (strlen(storage_dev->dev_name) >= MAX_GPT_NAME_SIZE) {
        PRINTF_CRITICAL("partition name too long\n");
        return -1;
    }

    if ((uint64_t)offset > storage_dev->capacity) {
        PRINTF_CRITICAL("remote read too long, offset = 0x%llx, capacity = 0x%llx\n",
                        (unsigned long long)offset, (unsigned long long)(storage_dev->capacity));
        return -1;
    }

    *(uint64_t *)(&name[0]) = (uint64_t)offset;

    if (snprintf((char *)(name + sizeof(uint64_t)), MAX_GPT_NAME_SIZE, "%s",
                 storage_dev->dev_name) < 0) {
        PRINTF_CRITICAL("string proccess error\n");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_SEEK_MAPPED;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_SEEK_MAPPED_OK;

    ret = remote_ops(&op, (uint8_t *)name,
                     (strlen(storage_dev->dev_name) + 1 + sizeof(uint64_t)), recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_ops error \n");
        return -1;
    }
    gettimeofday(&seek_end, NULL);
    seek_time += time_elapsed_us(seek_start, seek_end);
    return 0;
}


static int check_read_data_digest(shared_memory_digest_mode_e digest_mode, uint8_t *data,
                                  uint32_t data_size, uint8_t *digest_addr, uint32_t rand_data)
{
    uint32_t data_crc = 0;
    uint32_t crc_val  = 0xFFFFFFFF;
    uint8_t digest_val[128] = {0};
    uint8_t *digest_recv = digest_addr;
    const char *method_sha256 = "sha256";
    const char *method_md5 = "md5";
    char *method = NULL;
    int digest_len = 0;

    switch (digest_mode) {
        case DIGEST_MODE_NONE:
#if DEBUGMODE
            PRINTF_CRITICAL("no digest mode\n");
#endif
            return 0;

        case DIGEST_MODE_CRC32:
            rand_data = 0;

        case DIGEST_MODE_CRC32_WITH_RAMDOM:
            /* calc crc */
            crc_val = crc32(rand_data, data, data_size);
            /* read crc */
            data_crc = *(uint32_t *)digest_addr;

            /* check crc */
            if (data_crc != crc_val) {
                PRINTF_CRITICAL("rand_data = 0x%08x, read_size = 0x%08x\n", rand_data,
                                data_size);
                PRINTF_CRITICAL("shared memory read data crc error, crc calc = 0x%08x, crc read = 0x%08x\n",
                                crc_val, data_crc);
                return -1;
            }

            return 0;

        case DIGEST_MODE_MD5:
        case DIGEST_MODE_SHA256:
            if (DIGEST_MODE_MD5 == digest_mode) {
                method = (char *)method_md5;
                digest_len = MD5_DIGEST_SIZE;
            }
            else {
                method = (char *)method_sha256;
                digest_len = SHA256_DIGEST_SIZE;
            }

            /* calc digest */
            if (crypto_digest_buffer((const char *)method, data, data_size, digest_val,
                                     digest_len)) {
                PRINTF_CRITICAL("crypto_digest_buffer failed\n");
                return -1;
            }

            /* check digest */
            if (memcmp(digest_val, digest_recv, digest_len) != 0) {
                PRINTF_CRITICAL("shared memory read data calc error, %s calc is:\n", method);
                hexdump8(digest_val, digest_len);
                PRINTF_CRITICAL("%s recv is:\n", method);
                hexdump8(digest_recv, digest_len);
                return -1;
            }

            return 0;

        default:
            PRINTF_CRITICAL("digest mode error\n");
            return -1;
    }

    return -1;
}

int64_t remote_read_direct(storage_device_t *storage_dev, uint8_t *dst,
                           uint64_t size)
{
    ota_op_t op;
    int ret = -1;
    uint64_t cnt = 0;
    uint64_t i = 0;
    uint32_t  left = 0;
    ota_msg_head_struct_t *head;
    uint8_t  recv_msg[MAX_RECV_LENGTH] = {0};
    uint32_t read_size = MAX_DATA_LENGTH;
    uint32_t rand_data = 0;
    uint8_t *out = dst;
    uint8_t send_data[MAX_SEND_LENGTH] = {0};
    int offset = 0;
    static uint32_t last_rand_data = 0;
    uint32_t unaligned = 0;
    uint32_t aligned = 0;
    uint8_t temp_buf[ALIGNED_LEN] = {0};
    uint32_t data_offset = 0;
    uint32_t crc_offset = 0;

    if (!storage_dev || !dst || (int64_t)size <= 0) {
        PRINTF_CRITICAL("remote_read para error");
        return -1;
    }

    if (storage_dev->use_shared_memory) {
        read_size = storage_dev->max_shared_memory_read_data_length;
        rand_data = rand() % UINT_MAX;

        if (last_rand_data == rand_data) {
            rand_data++;
        }

        last_rand_data = rand_data;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_READ;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_READ_OK;
    cnt = size / read_size;
    left = size % read_size;

    for (i = 0; i < cnt + 1; i++) {
#if DEBUGMODE
        PRINTF_CRITICAL("remote read direct: cnt=%llu\n", (unsigned long long)cnt);
#endif

        if (i == cnt) {
            if (left) {
                read_size = left;
                unaligned = left % ALIGNED_LEN;
                aligned = left - unaligned;
            }
            else
                break;
        }

        head = (ota_msg_head_struct_t *)recv_msg;

        if (storage_dev->use_shared_memory) {
            offset = 0;
            offset = put_data(send_data, offset, (uint8_t *)&read_size, sizeof(read_size));
            offset = put_data(send_data, offset, (uint8_t *)&rand_data, sizeof(rand_data));
            offset = put_data(send_data, offset, (uint8_t *)&shared_memory_base_AP_core_view, sizeof(shared_memory_base_AP_core_view));
            offset = put_data(send_data, offset, (uint8_t *)&data_offset, sizeof(data_offset));
            offset = put_data(send_data, offset, (uint8_t *)&crc_offset, sizeof(crc_offset));
            gettimeofday(&read_start, NULL);
            ret = remote_ops(&op, send_data, offset, recv_msg);
            gettimeofday(&read_end, NULL);
            pure_read_time += time_elapsed_us(read_start, read_end);
            if (ret < 0) {
                PRINTF_CRITICAL("remote read by shared memory error \n");
                return -1;
            }
            gettimeofday(&read_hash_start, NULL);
            if (check_read_data_digest(storage_dev->shared_mem_mode.digest_mode,
                                       ((uint8_t *)(storage_dev->shared_mem_ptr) +
                                        storage_dev->shared_memory_read_data_offset), read_size,
                                       ((uint8_t *)(storage_dev->shared_mem_ptr) +
                                        storage_dev->shared_memory_read_crc_offset), rand_data)) {
                PRINTF_CRITICAL("check read data digest failed\n");
                return -1;
            }
            gettimeofday(&read_hash_end, NULL);
            read_hash_time += time_elapsed_us(read_hash_start, read_hash_end);

            gettimeofday(&read_copy_start, NULL);
            /* copy the read data */
            if (!unaligned) {
                memcpy(out, (uint8_t *)(storage_dev->shared_mem_ptr) +
                       storage_dev->shared_memory_read_data_offset,
                       read_size);
            }
            else {
                memcpy(out, (uint8_t *)(storage_dev->shared_mem_ptr) +
                       storage_dev->shared_memory_read_data_offset,
                       aligned);
                memcpy(temp_buf, (uint8_t *)(storage_dev->shared_mem_ptr) +
                       storage_dev->shared_memory_read_data_offset + aligned,
                       ALIGNED_LEN);
                memcpy(out + aligned, temp_buf, unaligned);
            }
            gettimeofday(&read_copy_end, NULL);
            read_ddr_copy_time += time_elapsed_us(read_copy_start, read_copy_end);

            rand_data++;

#if DEBUGMODE > 1
            hexdump8((uint8_t *)(storage_dev->shared_mem_ptr) +
                     storage_dev->shared_memory_read_data_offset, read_size);
#endif
        }
        else {
            gettimeofday(&read_start, NULL);
            ret = remote_ops(&op, (uint8_t *)&read_size, sizeof(read_size), recv_msg);
            gettimeofday(&read_end, NULL);
            pure_read_time += time_elapsed_us(read_start, read_end);
            if (ret < 0) {
                PRINTF_CRITICAL("remote_read error \n");
                return -1;
            }

            /* len check */
            if (head->len != read_size) {
                PRINTF_CRITICAL("remote_read:recv len is %d, not %d  \n", head->len,
                                read_size);
                return -1;
            }

            /* copy the read data */
            memcpy(out, recv_msg + MSG_HEAD_SIZE, read_size);
        }

        out = out + read_size;
    }

    return (int64_t)size;
}

static queue_status_e task_queue_get_status(task_queue_t *queue) {
    if(queue) {
        queue_status_e status;
        pthread_mutex_lock(&queue->mutex);
        status = queue->status;
        pthread_mutex_unlock(&queue->mutex);
        return status;
    }
    else {
        return QUEUE_UNKNOWN;
    }
}

static void task_queue_set_status(task_queue_t *queue, queue_status_e status) {
    if(queue) {
        pthread_mutex_lock(&queue->mutex);
        queue->status = status;
        pthread_mutex_unlock(&queue->mutex);
    }
}

static bool is_task_already_enqueued(task_queue_t *queue, shm_copy_arg_t *ddr_copy)
{
    shm_copy_arg_t *ddr_copy_task = NULL;
    shm_copy_arg_t *ddr_copy_task_temp = NULL;
    if(queue && ddr_copy && !list_is_empty(&queue->list)) {
        list_for_every_entry_safe(&queue->list, ddr_copy_task, ddr_copy_task_temp, shm_copy_arg_t, node)
        {
            if(ddr_copy_task && (ddr_copy->data_offset == ddr_copy_task->data_offset)) {
                return true;
            }
        }
    }
    return false;
}

static int task_queue_wait_task_finish(task_queue_t *queue, shm_copy_arg_t *ddr_copy)
{
    time_t startTime, endTime;
    int timeout_us = 5000000;

    if(!queue || !ddr_copy) {
        PRINTF_CRITICAL("wait queue para errir\n");
        return -1;
    }

    if(task_queue_get_status(queue) != QUEUE_STATUS_OK) {
        PRINTF_CRITICAL("queue status error, status = %d\n", queue->status);
        return -1;
    }

    startTime = time(NULL);
    pthread_mutex_lock(&queue->mutex);
    while(is_task_already_enqueued(queue, ddr_copy)) {
        pthread_mutex_unlock(&queue->mutex);
        endTime = time(NULL);
        if((timeout_us-- > 0) && (difftime(endTime, startTime) < 5.0)) {
            usleep(1);
        }
        else {
            PRINTF_CRITICAL("wait queue timeout: %fs\n", difftime(endTime, startTime));
            task_queue_set_status(queue, QUEUE_WAIT_TIMEOUT);
            return -1;
        }
        pthread_mutex_lock(&queue->mutex);
    }
    pthread_mutex_unlock(&queue->mutex);
    return 0;
}

static int task_queue_wait_all_task_finish(task_queue_t *queue, pthread_t *tid)
{
    if(!queue || !tid) {
        PRINTF_CRITICAL("wait queue para error\n");
        return -1;
    }

    if(task_queue_get_status(queue) != QUEUE_STATUS_OK) {
        PRINTF_CRITICAL("queue status error\n");
    }

#if RUN_IN_QNX
    struct timespec timeout;
    timeout.tv_sec = time(NULL) + 5;
    int result = pthread_timedjoin(*tid, NULL, &timeout);
    if (result == 0) {
        task_queue_set_status(queue, QUEUE_QUIT);
        pthread_join(*tid, NULL);
        return 0;
    } else if (result == ETIMEDOUT) {
        PRINTF_CRITICAL("wait queue timeout\n");
        task_queue_set_status(queue, QUEUE_WAIT_TIMEOUT);
        pthread_join(*tid, NULL);
        return -1;
    } else {
        PRINTF_CRITICAL("Error joining thread\n");
        task_queue_set_status(queue, QUEUE_WAIT_TIMEOUT);
        pthread_join(*tid, NULL);
        return -1;
    }
#else
    time_t startTime, endTime;
    int timeout_us = 5000000;

    startTime = time(NULL);
    pthread_mutex_lock(&queue->mutex);
    while(!list_is_empty(&queue->list)) {
        pthread_mutex_unlock(&queue->mutex);
        endTime = time(NULL);
        if((timeout_us-- > 0) && (difftime(endTime, startTime) < 5.0)) {
            usleep(1);
        }
        else {
            PRINTF_CRITICAL("wait queue timeout: %fs\n", difftime(endTime, startTime));
            task_queue_set_status(queue, QUEUE_WAIT_TIMEOUT);
            pthread_join(*tid, NULL);
            return -1;
        }
        pthread_mutex_lock(&queue->mutex);
    }
    pthread_mutex_unlock(&queue->mutex);
    task_queue_set_status(queue, QUEUE_QUIT);
    pthread_join(*tid, NULL);
    return 0;
#endif
}

static int task_queue_enqueue(task_queue_t *queue, shm_copy_arg_t *ddr_copy)
{
    /* Acquire the mutex to ensure exclusive access to the queue */
    pthread_mutex_lock(&queue->mutex);

    /* check list length */
    if((list_length(&queue->list) >= THREAD_READ_PIECE_NUM) || (list_length(&(queue->list)) < 0)) {
        PRINTF_CRITICAL("queue length error 1\n");
        queue->status = QUEUE_LENGTH_ERR;
        return -1;
    }

    /* Add an ddr_copy to the queue */
    list_add_tail(&queue->list, &ddr_copy->node);

    /* check list length */
    if((list_length(&(queue->list)) > THREAD_READ_PIECE_NUM) || (list_length(&(queue->list)) <= 0)){
        PRINTF_CRITICAL("queue length error 2\n");
        queue->status = QUEUE_LENGTH_ERR;
        return -1;
    }

    pthread_mutex_unlock(&queue->mutex);
    return 0;
}

static shm_copy_arg_t* task_queue_get_task(task_queue_t *queue)
{
    shm_copy_arg_t *ddr_copy = NULL;
    if(queue) {
        pthread_mutex_lock(&queue->mutex);
        ddr_copy = list_peek_head_type(&queue->list, shm_copy_arg_t, node);
        pthread_mutex_unlock(&queue->mutex);
    }
    return ddr_copy;
}

static void task_queue_dequeue(task_queue_t *queue, shm_copy_arg_t *ddr_copy)
{
    if(queue) {
        pthread_mutex_lock(&queue->mutex);
        if(is_task_already_enqueued(queue, ddr_copy)) {
            list_delete(&ddr_copy->node);
        }
        pthread_mutex_unlock(&queue->mutex);
    }
    return;
}

static void* shm_copy_thread(void *arg)
{
    task_queue_t *queue = (task_queue_t *)arg;
    shm_copy_arg_t *task;
    uint8_t temp_buf[ALIGNED_LEN] = {0};
    size_t unaligned = 0;
    size_t aligned = 0;
    uint32_t data_offset_back = 0xFFFFFFFF;
    int total = 0;

    while(queue && (QUEUE_STATUS_OK == task_queue_get_status(queue))) {
#if DEBUGMODE
        PRINTF_CRITICAL("shm copy thread running\n");
#endif
        if(queue->total <= total) {
            if(queue->total <=0) {
                task_queue_set_status(queue, QUEUE_TOTAL_TASK_ERR);
            }
            pthread_exit(NULL);
        }
        task = task_queue_get_task(queue);
        if(NULL != task) {
            gettimeofday(&read_copy_start, NULL);
#if DEBUGMODE
            PRINTF_CRITICAL("handle task = %p, task->data_offset = 0x%x \n", task, task->data_offset);
#endif
            unaligned = task->len % ALIGNED_LEN;
            aligned = task->len - unaligned;

            if(data_offset_back != task->data_offset) {
                /* copy the read data from shm to output buffer*/
                if (!unaligned) {
                    memcpy((void *)(task->dst), (void *)(task->src + task->data_offset), task->len);
                }
                else {
                    memcpy((void *)(task->dst), (void *)(task->src + task->data_offset), aligned);
                    memcpy(temp_buf, (void *)(task->src + aligned), ALIGNED_LEN);
                    memcpy((void *)(task->dst + aligned), temp_buf, unaligned);
                }
            }
            else {
                PRINTF_CRITICAL("check data offset failed\n");
                task_queue_set_status(queue, SHM_MEMORY_COPY_ERR);
                pthread_exit(NULL);
            }

            gettimeofday(&read_copy_end, NULL);
            read_ddr_copy_time += time_elapsed_us(read_copy_start, read_copy_end);

            gettimeofday(&read_hash_start, NULL);
            /* hash check direct use output buffer */
            if (check_read_data_digest(task->digest_mode, task->dst, task->len, task->crc_base + task->crc_offset, task->rand_data)) {
                PRINTF_CRITICAL("check read data digest failed, task->data_offset = 0x%x, task->crc_offset = 0x%x\n", task->data_offset, task->crc_offset);
                task_queue_set_status(queue, SHM_MEMORY_HASH_ERR);
                pthread_exit(NULL);
            }
            gettimeofday(&read_hash_end, NULL);
            read_hash_time += time_elapsed_us(read_hash_start, read_hash_end);

            data_offset_back = task->data_offset;
            task_queue_dequeue(queue, task);
            total++;
#if DEBUGMODE
            PRINTF_CRITICAL("task number = %zu\n", list_length(&queue->list));
#endif
        }
        else {
            usleep(1);
        }
    }

    pthread_exit(NULL);
}

static int64_t remote_read_direct_thread(storage_device_t *storage_dev, uint8_t *dst,
                           uint64_t size)
{
    int ret = -1;
    uint32_t data_offset = 0;
    uint32_t crc_offset = 0;
    uint64_t cnt = 0;
    uint64_t i = 0;
    uint32_t  left = 0;
    uint32_t read_size = 0;
    uint8_t *out = dst;
    uint32_t rand_data = 0;
    static uint32_t last_rand_data = 0;
    ota_op_t op;
    uint8_t send_data[MAX_SEND_LENGTH];
    int send_len;
    uint8_t recv_data[MAX_RECV_LENGTH];
    static pthread_t tid;
    task_queue_t task_queue = {.mutex = PTHREAD_MUTEX_INITIALIZER, .status = QUEUE_STATUS_OK};
    shm_copy_arg_t task_list[THREAD_READ_PIECE_NUM];
    shm_copy_arg_t task;

    if (!storage_dev || !dst || (int64_t)size <= 0) {
        PRINTF_CRITICAL("remote_read para error");
        return -1;
    }

    read_size = storage_dev->thread_read_size;

    rand_data = rand() % UINT_MAX;
    if (last_rand_data == rand_data) {
        rand_data++;
    }
    last_rand_data = rand_data;
    cnt = size / read_size;
    left = size % read_size;
    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_READ;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_READ_OK;

    task_queue.total = cnt;
    if(left) {
        task_queue.total++;
    }

    if(task_queue.total <= 0) {
        PRINTF_CRITICAL("task_queue total task error %d", task_queue.total);
        return -1;
    }

    /* creat a data copy thread */
    list_initialize(&task_queue.list);
    pthread_mutex_init(&task_queue.mutex, NULL);
    if(pthread_create(&tid, NULL, shm_copy_thread, (void *)&task_queue) != 0) {
        PRINTF_CRITICAL("creat pthread error %s", strerror(errno));
        return -1;
    }

#if DEBUGMODE
    PRINTF_CRITICAL("remoten read direct multi thread: cnt=%llu\n", (unsigned long long)cnt);
#endif

    for (i = 0; i < cnt + 1; i++) {
        if (i == cnt) {
            if (left) {
                read_size = left;
            }
            else {
                break;
            }
        }

#if DEBUGMODE
        PRINTF_CRITICAL("prepare para\n");
#endif
        memset((void *)send_data, 0, MAX_SEND_LENGTH);
        memset((void *)recv_data, 0, MAX_RECV_LENGTH);
        data_offset = (i % THREAD_READ_PIECE_NUM) * storage_dev->thread_read_size;
        crc_offset = (i % THREAD_READ_PIECE_NUM) * storage_dev->thread_read_crc_size;
        send_len = 0;
        send_len = put_data(send_data, send_len, (uint8_t *)&read_size, sizeof(read_size));
        send_len = put_data(send_data, send_len, (uint8_t *)&rand_data, sizeof(rand_data));
        send_len = put_data(send_data, send_len, (uint8_t *)&shared_memory_base_AP_core_view, sizeof(shared_memory_base_AP_core_view));
        send_len = put_data(send_data, send_len, (uint8_t *)&data_offset, sizeof(data_offset));
        send_len = put_data(send_data, send_len, (uint8_t *)&crc_offset, sizeof(crc_offset));

        /* We use a task to temporarily store the "copy work" that needs to be pushed into the queue, instead of directly
        modifying the value in the task_list, because the task_list may be processing by another thread. */
        task.data_offset = data_offset;
        task.crc_offset = crc_offset;
        task.src =      (uint8_t *)(storage_dev->shared_mem_ptr) + storage_dev->shared_memory_read_data_offset;
        task.crc_base = (uint8_t *)(storage_dev->shared_mem_ptr) + storage_dev->shared_memory_read_crc_offset;
        task.dst = out;
        task.len = read_size;
        task.digest_mode = storage_dev->shared_mem_mode.digest_mode;
        task.rand_data = rand_data;

#if DEBUGMODE
        PRINTF_CRITICAL("wait to op data_offset = 0x%x crc_offset = 0x%x\n", data_offset, crc_offset);
#endif
        if(task_queue_wait_task_finish(&task_queue, &task)) {
            PRINTF_CRITICAL("wait task error\n");
            ret = -1;
            goto end;
        }
#if DEBUGMODE
        PRINTF_CRITICAL("op start\n");
#endif
        gettimeofday(&read_start, NULL);
        ret = remote_ops(&op, send_data, send_len, recv_data);
        if(ret) {
            PRINTF_CRITICAL("remote_ops error\n");
            ret = -1;
            goto end;
        }
        gettimeofday(&read_end, NULL);
        pure_read_time += time_elapsed_us(read_start, read_end);

#if DEBUGMODE
        PRINTF_CRITICAL("op end\n");
#endif

        memcpy(&task_list[i%THREAD_READ_PIECE_NUM], &task, sizeof(shm_copy_arg_t));
        if(task_queue_enqueue(&task_queue, &task_list[i%THREAD_READ_PIECE_NUM])) {
            PRINTF_CRITICAL("enqueue error\n");
            ret = -1;
            goto end;
        }

        out = out + read_size;
        rand_data++;

#if DEBUGMODE
        PRINTF_CRITICAL("enqueue finish\n");
#endif
    }
    ret = 0;
end:
    gettimeofday(&finish_start, NULL);
    if(task_queue_wait_all_task_finish(&task_queue, &tid)) {
        PRINTF_CRITICAL("wait all task finish error\n");
        ret = -1;
    }
    gettimeofday(&finish_end, NULL);
    finish_read_time += time_elapsed_us(finish_start, finish_end);

    if(0 == ret) {
        task_queue_set_status(&task_queue, QUEUE_QUIT);
        return (int64_t)size;
    }
    else {
        return -1;
    }
}

int remote_read(storage_device_t *storage_dev, uint64_t src, uint8_t *dst,
                uint64_t size)
{
    if (!storage_dev || !dst) {
        PRINTF_CRITICAL("remote read para error");
        return -1;
    }

    if (remote_seek(storage_dev, src, SEEK_SET) < 0) {
        PRINTF_CRITICAL("remote read seek error\n");
        return -1;
    }

    if(storage_dev->use_shared_memory && (size >= 2*storage_dev->thread_read_size)) {
        if (remote_read_direct_thread(storage_dev, dst, size) < 0) {
            PRINTF_CRITICAL("remote read with multi thread read error\n");
            return -1;
        }
    }
    else if (remote_read_direct(storage_dev, dst, size) < 0) {
            PRINTF_CRITICAL("remote read read error\n");
            return -1;
    }
    return 0;
}

int remote_read_mapped(storage_device_t *storage_dev, uint64_t src,
                       uint8_t *dst,
                       uint64_t size)
{
    if (!storage_dev || !dst) {
        PRINTF_CRITICAL("remote read para error");
        return -1;
    }

    if (remote_seek_mapped(storage_dev, src, SEEK_SET) < 0) {
        PRINTF_CRITICAL("remote read seek error\n");
        return -1;
    }

    if ((src + size) > storage_dev->capacity) {
        PRINTF_CRITICAL("remote read too long, src = 0x%llx, size = 0x%llx, capacity = 0x%llx\n",
                        (unsigned long long)src, (unsigned long long)size,
                        (unsigned long long)storage_dev->capacity);
        return -1;
    }

    if(storage_dev->use_shared_memory && (size >= 2*storage_dev->thread_read_size)) {
        if (remote_read_direct_thread(storage_dev, dst, size) < 0) {
            PRINTF_CRITICAL("remote read with multi thread read error\n");
            return -1;
        }
    }
    else if (remote_read_direct(storage_dev, dst, size) < 0) {
            PRINTF_CRITICAL("remote read read error\n");
            return -1;
    }

    return 0;
}

static int remote_write_info(int fd, uint64_t data_len)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_SEND_LENGTH] = {0};

    op.fd = fd;
    op.cmd = OTA_CMD_WRITE_INFO;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_WRITE_INFO_OK;
    ret = remote_ops(&op, (uint8_t *)&data_len, sizeof(data_len), recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote write info error \n");
        return -1;
    }

    return 0;
}

static int set_write_data_digest(shared_memory_digest_mode_e digest_mode, uint8_t *data,
                                 uint32_t data_size, uint8_t *diagest_addr, uint32_t rand_data)
{
    uint8_t digest_val[128] = {0};
    uint32_t data_crc = 0;
    int digest_len = 0;
    const char *method_sha256 = "sha256";
    const char *method_md5 = "md5";
    char *method = NULL;

#if DEBUGMODE
    PRINTF_CRITICAL("digest_mode = %d\n", digest_mode);
#endif

    switch (digest_mode) {
        case DIGEST_MODE_NONE:
#if DEBUGMODE
            PRINTF_CRITICAL("no digest mode\n");
#endif
            return 0;

        case DIGEST_MODE_CRC32:
            rand_data = 0;

        case DIGEST_MODE_CRC32_WITH_RAMDOM:
            data_crc = crc32(rand_data, data, data_size);
            memcpy(diagest_addr, (uint8_t *)&data_crc, sizeof(data_crc));

#if DEBUGMODE
            PRINTF_CRITICAL("rand data = %x, data crc  = %x\n", rand_data, data_crc);
#endif
            return 0;

        case DIGEST_MODE_MD5:
        case DIGEST_MODE_SHA256:
            if (DIGEST_MODE_MD5 == digest_mode) {
                method = (char *)method_md5;
                digest_len = MD5_DIGEST_SIZE;
            }
            else {
                method = (char *)method_sha256;
                digest_len = SHA256_DIGEST_SIZE;
            }

            /* calc digest */
            if (crypto_digest_buffer((const char *)method, data, data_size, digest_val,
                                     digest_len)) {
                PRINTF_CRITICAL("crypto digest buffer failed\n");
                return -1;
            }

            memcpy(diagest_addr, digest_val, digest_len);

#if DEBUGMODE
            PRINTF_CRITICAL("write digest is\n");
            hexdump8(diagest_addr, digest_len);
#endif
            return 0;

        default:
            PRINTF_CRITICAL("digest mode error\n");
            return -1;
    }

    return -1;
}

/*
   success : return write size
   failed : return -1
*/
int64_t remote_write_direct(storage_device_t *storage_dev, const uint8_t *buf,
                            uint64_t data_len)
{
    ota_op_t op;
    int ret = -1;
    uint64_t cnt = 0;
    uint64_t i = 0;
    uint32_t write_size = MAX_DATA_LENGTH;
    uint32_t  left = 0;
    uint8_t  recv_msg[MAX_SEND_LENGTH] = {0};
    uint8_t *in = (uint8_t *)buf;
    uint32_t rand_data = 0;
    static uint32_t last_rand_data = 0;
    int offset = 0;
    uint8_t send_data[sizeof(rand_data) + sizeof(write_size) + sizeof(shared_memory_base_AP_core_view)] = {0};
    uint32_t unaligned = 0;
    uint32_t aligned = 0;
    uint8_t temp_buf[ALIGNED_LEN] = {0};

    if (!storage_dev || !buf || (int64_t)data_len <= 0) {
        PRINTF_CRITICAL("remote_write para error\n");
        return -1;
    }

    /* write info */
    gettimeofday(&write_info_start, NULL);
    if (remote_write_info(storage_dev->dev_fd, data_len) < 0) {
        PRINTF_CRITICAL("remote_write: set info error\n");
        return -1;
    }
    gettimeofday(&write_info_end, NULL);
    write_info_time += time_elapsed_us(write_info_start, write_info_end);

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_WRITE;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_WRITE_OK;

    if (storage_dev->use_shared_memory) {
        write_size = storage_dev->max_shared_memory_write_data_length;
    }

    cnt = data_len / write_size;
    left = data_len % write_size;

    if (storage_dev->use_shared_memory) {
        rand_data = rand() % UINT_MAX;

        if (last_rand_data == rand_data) {
            rand_data++;
        }

        last_rand_data = rand_data;
    }

    for (i = 0; i < cnt + 1; i++) {
        if (i == cnt) {
            if (left) {
                write_size = left;
                unaligned = left % ALIGNED_LEN;
                aligned = left - unaligned;
            }
            else
                break;
        }

#if DEBUGMODE
        PRINTF_CRITICAL("remote_write: i=%llu, cnt=%llu\n", (unsigned long long)i,
                        (unsigned long long)cnt);
        PRINTF_CRITICAL("data_len = 0x%llx\n", (unsigned long long)data_len);
        PRINTF_CRITICAL("write_size = 0x%llx\n", (unsigned long long)write_size);
        PRINTF_CRITICAL("left = 0x%x\n", left);
#endif

        if (storage_dev->use_shared_memory) {
#if DEBUGMODE
            PRINTF_CRITICAL("write in shared_memory, write base = 0x%p\n",
                            (uint8_t *)(storage_dev->shared_mem_ptr) +
                            storage_dev->shared_memory_write_data_offset);
            PRINTF_CRITICAL("crc base = 0x%p\n",
                            (uint8_t *)(storage_dev->shared_mem_ptr) +
                            storage_dev->shared_memory_write_crc_offset);
#endif

            gettimeofday(&write_copy_start, NULL);
            /* copy the write data */
            if (!unaligned) {
                memcpy(((uint8_t *)(storage_dev->shared_mem_ptr) +
                        storage_dev->shared_memory_write_data_offset), in, write_size);
            }
            else {
                memcpy(((uint8_t *)(storage_dev->shared_mem_ptr) +
                        storage_dev->shared_memory_write_data_offset), in, aligned);
                memcpy(temp_buf, in + aligned, unaligned);
                memcpy(((uint8_t *)(storage_dev->shared_mem_ptr) +
                        storage_dev->shared_memory_write_data_offset) + aligned,
                       temp_buf, ALIGNED_LEN);
            }
            gettimeofday(&write_copy_end, NULL);
            write_ddr_copy_time += time_elapsed_us(write_copy_start, write_copy_end);

            gettimeofday(&write_hash_start, NULL);
            /* clac the digest for shared memory buffer */
            if (set_write_data_digest(storage_dev->shared_mem_mode.digest_mode,
                                      ((uint8_t *)(storage_dev->shared_mem_ptr) +
                                       storage_dev->shared_memory_write_data_offset), write_size,
                                      ((uint8_t *)(storage_dev->shared_mem_ptr) +
                                       storage_dev->shared_memory_write_crc_offset), rand_data)) {
                PRINTF_CRITICAL("set write data digest error\n");
                return -1;
            }
            gettimeofday(&write_hash_end, NULL);
            write_hash_time += time_elapsed_us(write_hash_start, write_hash_end);

            offset = 0;
            offset = put_data(send_data, offset, (uint8_t *)&write_size,
                              sizeof(write_size));
            offset = put_data(send_data, offset, (uint8_t *)&rand_data, sizeof(rand_data));
            offset = put_data(send_data, offset, (uint8_t *)&shared_memory_base_AP_core_view, sizeof(shared_memory_base_AP_core_view));
            gettimeofday(&write_start, NULL);
            ret = remote_ops(&op, send_data, offset, recv_msg);
            gettimeofday(&write_end, NULL);
            pure_write_time += time_elapsed_us(write_start, write_end);
            rand_data++;

        }
        else {
            gettimeofday(&write_start, NULL);
            ret = remote_ops(&op, in, write_size, recv_msg);
            gettimeofday(&write_end, NULL);
            pure_write_time += time_elapsed_us(write_start, write_end);
        }

        if (ret < 0) {
            PRINTF_CRITICAL("remote_write error \n");
            return -1;
        }

        /* increase the data source */
        in = in + write_size;
    }

    return (int64_t)data_len;
}

int remote_write(storage_device_t *storage_dev, uint64_t dst,
                 const uint8_t *buf, uint64_t data_len)
{
    if (!storage_dev) {
        PRINTF_CRITICAL("remote_write para error");
        return -1;
    }

    /* seek */
    if (remote_seek(storage_dev, dst, SEEK_SET) < 0) {
        PRINTF_CRITICAL("remote_write:seek error\n");
        return -1;
    }

    if (remote_write_direct(storage_dev, buf, data_len) < 0) {
        PRINTF_CRITICAL("remote_write:write error\n");
        return -1;
    }

    return 0;
}

int remote_write_mapped(storage_device_t *storage_dev, uint64_t dst,
                        const uint8_t *buf, uint64_t data_len)
{
    if (!storage_dev || !dst) {
        PRINTF_CRITICAL("remote_write para error");
        return -1;
    }

    /* seek */
    if (remote_seek_mapped(storage_dev, dst, SEEK_SET) < 0) {
        PRINTF_CRITICAL("remote_write:seek error\n");
        return -1;
    }

    if ((dst + data_len) > storage_dev->capacity) {
        PRINTF_CRITICAL("remote write too long, dst = 0x%llx, data_len = 0x%llx, capacity = 0x%llx\n",
                        (unsigned long long)dst, (unsigned long long)data_len,
                        (unsigned long long)storage_dev->capacity);
        return -1;
    }

    if (remote_write_direct(storage_dev, buf, data_len) < 0) {
        PRINTF_CRITICAL("remote_write:write error\n");
        return -1;
    }

    return 0;
}

uint64_t remote_get_capacity(storage_device_t *storage_dev)
{
    uint64_t capacity;
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_SEND_LENGTH] = {0};
    ota_msg_head_struct_t *head;

    if (!storage_dev) {
        PRINTF_CRITICAL("remote_get_capacity para error");
        return 0;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_GET_CAPACITY;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_GET_CAPACITY_OK;

    ret = remote_ops(&op, NULL, 0, recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_get_capacity error \n");
        return 0;
    }

    /* len check */
    head = (ota_msg_head_struct_t *)recv_msg;

    if (head->len != sizeof(capacity)) {
        PRINTF_CRITICAL("remote_get_capacity:recv len is %d, not %u  \n",
                        head->len, (uint32_t)sizeof(capacity));
        return 0;
    }

    /* copy the capacity */
    memcpy(&capacity, recv_msg + MSG_HEAD_SIZE, sizeof(capacity));
#if DEBUGMODE
    PRINTF_CRITICAL("capacity = %lld \n", (unsigned long long)capacity);
#endif
    return capacity;
}

uint64_t remote_get_capacity_mapped(storage_device_t *storage_dev)
{
    uint64_t capacity;
    ota_msg_head_struct_t *head;
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[MAX_GPT_NAME_SIZE] = {0};
    assert(MAX_DATA_LENGTH > MAX_GPT_NAME_SIZE);

    if (!storage_dev || !strlen(storage_dev->dev_name)) {
        PRINTF_CRITICAL("para error\n");
        return 0;
    }

    if (!storage_dev->mapped) {
        PRINTF_CRITICAL("partition name %s is not mapped\n", storage_dev->dev_name);
        return 0;
    }

    if (strlen(storage_dev->dev_name) >= MAX_GPT_NAME_SIZE) {
        PRINTF_CRITICAL("partition name too long\n");
        return 0;
    }

    if (snprintf((char *)name, MAX_GPT_NAME_SIZE, "%s",
                 storage_dev->dev_name) < 0) {
        PRINTF_CRITICAL("string proccess error\n");
        return 0;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_GET_CAPACITY_MAPPED;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_GET_CAPACITY_MAPPED_OK;

    ret = remote_ops(&op, (uint8_t *)name, (strlen(storage_dev->dev_name) + 1),
                     recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote get capacity for %s error\n", name);
        return 0;
    }

    /* len check */
    head = (ota_msg_head_struct_t *)recv_msg;

    if (head->len != sizeof(capacity)) {
        PRINTF_CRITICAL("remote get capacity mapped:recv len is %d, not %u\n",
                        head->len, (uint32_t)sizeof(capacity));
        return 0;
    }

    /* copy the capacity */
    memcpy(&capacity, recv_msg + MSG_HEAD_SIZE, sizeof(capacity));
#if DEBUGMODE
    PRINTF_CRITICAL("get mapped capacity = %lld \n", (unsigned long long)capacity);
#endif
    return capacity;
}

uint32_t remote_get_erase_group_size(storage_device_t *storage_dev)
{
    uint32_t erase_size;
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_SEND_LENGTH] = {0};
    ota_msg_head_struct_t *head;

    if (!storage_dev) {
        PRINTF_CRITICAL("remote_get_erase_size para error");
        return 0;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_GET_ERASESIZE;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_GET_ERASESIZE_OK;

    ret = remote_ops(&op, NULL, 0, recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_get_erase_size error \n");
        return 0;
    }

    /* len check */
    head = (ota_msg_head_struct_t *)recv_msg;

    if (head->len != sizeof(erase_size)) {
        PRINTF_CRITICAL("remote_get_erase_size:recv len is %d, not %u \n", head->len,
                        (uint32_t)sizeof(erase_size));
        return 0;
    }

    /* copy the erase_size */
    memcpy(&erase_size, recv_msg + MSG_HEAD_SIZE, sizeof(erase_size));
#if DEBUGMODE
    PRINTF_CRITICAL("erase_size = %d \n", erase_size);
#endif
    return erase_size;
}

uint32_t remote_get_block_size(storage_device_t *storage_dev)
{
    uint32_t block_size;
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_SEND_LENGTH] = {0};
    ota_msg_head_struct_t *head;

    if (!storage_dev) {
        PRINTF_CRITICAL("para error");
        return 0;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_GET_BLOCK;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_GET_BLOCK_OK;

    ret = remote_ops(&op, NULL, 0, recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote get block size error \n");
        return 0;
    }

    /* len check */
    head = (ota_msg_head_struct_t *)recv_msg;

    if (head->len != sizeof(block_size)) {
        PRINTF_CRITICAL("remote get block size :recv len is %d, not %u  \n", head->len,
                        (uint32_t)sizeof(block_size));
        return 0;
    }

    /* copy the block_size */
    memcpy(&block_size, recv_msg + MSG_HEAD_SIZE, sizeof(block_size));
#if DEBUGMODE
    PRINTF_CRITICAL("block_size = %d \n", block_size);
#endif
    return block_size;
}

int remote_release(storage_device_t *storage_dev)
{
    if (!storage_dev) {
        PRINTF_CRITICAL("remote release para error");
        return -1;
    }

    if (storage_dev->dev_fd >= 0) {
        remote_close(storage_dev->dev_fd);
#ifdef RUN_IN_QNX
        release_rpmsg_handle(storage_dev);
#else
        close(storage_dev->dev_fd);
#endif
    }

    if (storage_dev->use_shared_memory) {
        if (MAP_FAILED != storage_dev->shared_mem_ptr) {
            munmap(storage_dev->shared_mem_ptr, storage_dev->max_shared_memory_length);

            if (storage_dev->memfd > 0) {
                close(storage_dev->memfd);
                storage_dev->memfd = -1;
            }
        }

        storage_dev->shared_mem_ptr = MAP_FAILED;
    }

    return 0;
}

int remote_release_mapped(storage_device_t *storage_dev)
{
    if (!storage_dev) {
        PRINTF_CRITICAL("remote release mapped para error");
        return -1;
    }

    return 0;
}

int remote_copy(storage_device_t *storage_dev, uint64_t src, uint64_t dst,
                uint64_t size)
{
    ota_op_t op;
    int ret = -1;
    uint8_t  send_data[sizeof(src) + sizeof(dst) + sizeof(size)];
    uint8_t  recv_msg[MAX_RECV_LENGTH] = {0};
    int offset = 0;

    if (!storage_dev) {
        PRINTF_CRITICAL("remote_copy para error");
        return -1;
    }

    if ((src % storage_dev->block_size) || (dst % storage_dev->block_size)
            || (size % storage_dev->block_size)) {
        PRINTF_CRITICAL("para error not aligned, block_size = %x",
                        storage_dev->block_size);
        return -1;
    }

    if (!strcmp(storage_dev->dev_name, MONITOR_CHANNEL_SAFETY)) {
        if ((src % storage_dev->erase_size) || (dst % storage_dev->erase_size)
                || (size % storage_dev->erase_size)) {
            PRINTF_CRITICAL("para error not aligned, erase_size = %x",
                            storage_dev->erase_size);
            return -1;
        }
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_COPY;
    op.timeout_ms = 500000;
    op.expect_recv_cmd = OTA_CMD_COPY_OK;
    offset = put_data(send_data, offset, (uint8_t *)&src, sizeof(src));
    offset = put_data(send_data, offset, (uint8_t *)&dst, sizeof(dst));
    offset = put_data(send_data, offset, (uint8_t *)&size, sizeof(size));

    ret = remote_ops(&op, send_data, offset, recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote copy error \n");
        return -1;
    }

    return 0;
}

int remote_copy_mapped(storage_device_t *storage_dev, uint64_t src,
                       uint64_t dst,
                       uint64_t size)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[MAX_GPT_NAME_SIZE + sizeof(src) + sizeof(dst) + sizeof(size)] = {0};
    assert(MAX_DATA_LENGTH > (MAX_GPT_NAME_SIZE + sizeof(src) + sizeof(
                                  dst) + sizeof(size)));
    int offset = 0;

    if (!storage_dev || !strlen(storage_dev->dev_name)) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if (strlen(storage_dev->dev_name) >= MAX_GPT_NAME_SIZE) {
        PRINTF_CRITICAL("partition name too long\n");
        return -1;
    }

    offset = put_data(name, offset, (uint8_t *)&src, sizeof(src));
    offset = put_data(name, offset, (uint8_t *)&dst, sizeof(dst));
    offset = put_data(name, offset, (uint8_t *)&size, sizeof(size));

    if (snprintf((char *)(name + sizeof(src) + sizeof(dst) + sizeof(size)),
                 MAX_GPT_NAME_SIZE, "%s", storage_dev->dev_name) < 0) {
        PRINTF_CRITICAL("string proccess error\n");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_COPY_MAPPED;
    op.timeout_ms = 500000;
    op.expect_recv_cmd = OTA_CMD_COPY_MAPPED_OK;

    ret = remote_ops(&op, (uint8_t *)name,
                     (strlen(storage_dev->dev_name) + 1 + sizeof(src) + sizeof(dst) + sizeof(size)),
                     recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote copy error \n");
        return -1;
    }

    return 0;
}

int remote_stop_wdt(storage_device_t *storage_dev)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};

    if (!storage_dev) {
        PRINTF_CRITICAL("remote_stop_wdt para error\n");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_STOP_WDT;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_STOP_WDT_OK;

    ret = remote_ops(&op, NULL, 0, recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_stop_wdt error \n");
        return -1;
    }

    return 0;
}

int remote_holdup_ap2(storage_device_t *storage_dev)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};

    if (!storage_dev) {
        PRINTF_CRITICAL("remote_holdup_ap2 para error\n");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_HOLDUP_AP2;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_HOLDUP_AP2_OK;

    ret = remote_ops(&op, NULL, 0, recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_holdup_ap2 error \n");
        return -1;
    }

    return 0;
}

int remote_write_with_check(storage_device_t *storage_dev, uint64_t dst,
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

    if (0 != remote_write(storage_dev, dst, buf, data_len)) {
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

        if (0 != remote_read(storage_dev, dst, read_buf, read_len)) {
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

int remote_write_with_check_mapped(storage_device_t *storage_dev, uint64_t dst,
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

    if (0 != remote_write_mapped(storage_dev, dst, buf, data_len)) {
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

        if (0 != remote_read_mapped(storage_dev, dst, read_buf, read_len)) {
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

int remote_setup_ptdev(storage_device_t *storage_dev, const char *ptdev_name)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[MAX_GPT_NAME_SIZE] = {0};
    assert(MAX_DATA_LENGTH > MAX_GPT_NAME_SIZE);

    if (!storage_dev || !ptdev_name) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if ((0 == strlen(ptdev_name)) || (strlen(ptdev_name) >= MAX_GPT_NAME_SIZE)) {
        PRINTF_CRITICAL("partition name too long\n");
        return -1;
    }

    if (snprintf((char *)name, MAX_GPT_NAME_SIZE, "%s", ptdev_name) < 0) {
        PRINTF_CRITICAL("string proccess error\n");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_SETUP_PTDEV;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_SETUP_PTDEV_OK;

    ret = remote_ops(&op, (uint8_t *)name, (strlen(ptdev_name) + 1), recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_ops error \n");
        return -1;
    }

    return 0;
}

int remote_destroy_ptdev(storage_device_t *storage_dev, const char *ptdev_name)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[MAX_GPT_NAME_SIZE] = {0};
    assert(MAX_DATA_LENGTH > MAX_GPT_NAME_SIZE);

    if (!storage_dev || !ptdev_name) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if ((0 == strlen(ptdev_name)) || (strlen(ptdev_name) >= MAX_GPT_NAME_SIZE)) {
        PRINTF_CRITICAL("partition name too long\n");
        return -1;
    }

    if (snprintf((char *)name, MAX_GPT_NAME_SIZE, "%s", ptdev_name) < 0) {
        PRINTF_CRITICAL("string proccess error\n");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_DESTROY_PTDEV;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_DESTROY_PTDEV_OK;

    ret = remote_ops(&op, (uint8_t *)name, (strlen(ptdev_name) + 1), recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_ops error \n");
        return -1;
    }

    return 0;
}

int remote_get_partition_index(storage_device_t *storage_dev,
                               const char *ptdev_name, const char *partition_name)
{
    ota_op_t op;
    int ret = -1;
    int32_t index = INVALID_PTN;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[3 * MAX_GPT_NAME_SIZE] = {0};
    int token_num = 0;
    assert(MAX_DATA_LENGTH > (3 * MAX_GPT_NAME_SIZE));

    if (!storage_dev || !ptdev_name || !partition_name) {
        PRINTF_CRITICAL("para error\n");
        return INVALID_PTN;
    }

    for (uint32_t i = 0; i < strlen(partition_name); i++) {
        if (partition_name[i] == '$') {
            token_num++;
        }
    }

    if (token_num > 1) {
        PRINTF_CRITICAL("partition_name have too many $\n");
        return INVALID_PTN;
    }

    if ((0 == strlen(ptdev_name)) || (strlen(ptdev_name) >= MAX_GPT_NAME_SIZE) ||
            (0 == strlen(partition_name))
            || (strlen(partition_name) >= MAX_GPT_NAME_SIZE)) {
        PRINTF_CRITICAL("ptdev name or partition name error, strlen(ptdev_name) = %zu, strlen(partition_name) = %zu\n",
                        strlen(ptdev_name), strlen(partition_name));
        return INVALID_PTN;
    }

    if (1 == token_num) {
        if (snprintf((char *)name, 3 * MAX_GPT_NAME_SIZE, "%s$%s", ptdev_name,
                     partition_name) < 0) {
            PRINTF_CRITICAL("string proccess error\n");
            return INVALID_PTN;
        }
    }
    else {
        if (snprintf((char *)name, 3 * MAX_GPT_NAME_SIZE, "%s$$%s", ptdev_name,
                     partition_name) < 0) {
            PRINTF_CRITICAL("string proccess error\n");
            return INVALID_PTN;
        }
    }

#if DEBUGMODE
    PRINTF_CRITICAL("partition name is %s\n", name);
#endif

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_GET_PARTITION_INDEX;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_GET_PARTITION_INDEX_OK;

    ret = remote_ops(&op, (uint8_t *)name, (strlen((char *)name) + 1), recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote ops error, name is [%s]\n", name);
        return INVALID_PTN;
    }

    /* copy the index */
    memcpy(&index, recv_msg + MSG_HEAD_SIZE, sizeof(index));

    if (index < 0 || index >= NUM_PARTITIONS) {
        return INVALID_PTN;
    }

    return index;
}

uint64_t remote_get_partition_size(storage_device_t *storage_dev,
                                   const char *ptdev_name, const char *partition_name)
{
    ota_op_t op;
    int ret = -1;
    uint64_t size = 0;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[3 * MAX_GPT_NAME_SIZE] = {0};
    int token_num = 0;
    assert(MAX_DATA_LENGTH > (3 * MAX_GPT_NAME_SIZE));

    if (!storage_dev || !ptdev_name || !partition_name) {
        PRINTF_CRITICAL("para error\n");
        return 0;
    }

    for (uint32_t i = 0; i < strlen(partition_name); i++) {
        if (partition_name[i] == '$') {
            token_num++;
        }
    }

    if (token_num > 1) {
        PRINTF_CRITICAL("partition_name have too many $\n");
        return 0;
    }

    if ((0 == strlen(ptdev_name)) || (strlen(ptdev_name) >= MAX_GPT_NAME_SIZE) ||
            (0 == strlen(partition_name))
            || (strlen(partition_name) >= MAX_GPT_NAME_SIZE)) {
        PRINTF_CRITICAL("ptdev name or partition name error, strlen(ptdev_name) = %zu, strlen(partition_name) = %zu\n",
                        strlen(ptdev_name), strlen(partition_name));
        return 0;
    }

    if (1 == token_num) {
        if (snprintf((char *)name, 3 * MAX_GPT_NAME_SIZE, "%s$%s", ptdev_name,
                     partition_name) < 0) {
            PRINTF_CRITICAL("string proccess error\n");
            return 0;
        }
    }
    else {
        if (snprintf((char *)name, 3 * MAX_GPT_NAME_SIZE, "%s$$%s", ptdev_name,
                     partition_name) < 0) {
            PRINTF_CRITICAL("string proccess error\n");
            return 0;
        }
    }

#if DEBUGMODE
    PRINTF_CRITICAL("partition name is %s\n", name);
#endif
    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_GET_PARTITION_SIZE;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_GET_PARTITION_SIZE_OK;

    ret = remote_ops(&op, (uint8_t *)name, (strlen((char *)name) + 1), recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote ops error, name is [%s]\n", name);
        return 0;
    }

    /* copy the size */
    memcpy(&size, recv_msg + MSG_HEAD_SIZE, sizeof(size));
    return size;
}

uint64_t remote_get_partition_offset(storage_device_t *storage_dev,
                                     const char  *ptdev_name, const char *partition_name)
{
    ota_op_t op;
    int ret = -1;
    uint64_t offset = 0;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[3 * MAX_GPT_NAME_SIZE + 2] = {0};
    int token_num = 0;
    assert(MAX_DATA_LENGTH > (3 * MAX_GPT_NAME_SIZE + 2));

    if (!storage_dev || !ptdev_name || !partition_name) {
        PRINTF_CRITICAL("para error\n");
        return 0;
    }

    for (uint32_t i = 0; i < strlen(partition_name); i++) {
        if (partition_name[i] == '$') {
            token_num++;
        }
    }

    if ((0 == strlen(ptdev_name)) || (strlen(ptdev_name) >= MAX_GPT_NAME_SIZE) ||
            (0 == strlen(partition_name))
            || (strlen(partition_name) >= MAX_GPT_NAME_SIZE)) {
        PRINTF_CRITICAL("ptdev name or partition name error, strlen(ptdev_name) = %zu, strlen(partition_name) = %zu\n",
                        strlen(ptdev_name), strlen(partition_name));
        return 0;
    }

    if (1 == token_num) {
        if (snprintf((char *)name, 3 * MAX_GPT_NAME_SIZE, "%s$%s", ptdev_name,
                     partition_name) < 0) {
            PRINTF_CRITICAL("string proccess error\n");
            return 0;
        }
    }
    else {
        if (snprintf((char *)name, 3 * MAX_GPT_NAME_SIZE, "%s$$%s", ptdev_name,
                     partition_name) < 0) {
            PRINTF_CRITICAL("string proccess error\n");
            return 0;
        }
    }

#if DEBUGMODE
    PRINTF_CRITICAL("partition name is %s\n", name);
#endif
    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_GET_PARTITION_OFFSET;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_GET_PARTITION_OFFSET_OK;

    ret = remote_ops(&op, (uint8_t *)name, (strlen((char *)name) + 1), recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote ops error, name is [%s]\n", name);
        return 0;
    }

    /* copy the offset */
    memcpy(&offset, recv_msg + MSG_HEAD_SIZE, sizeof(offset));
    return offset;
}

int remote_get_slot_number(storage_device_t *storage_dev,
                           const char *ptdev_name)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[MAX_GPT_NAME_SIZE] = {0};
    int8_t value = 0;
    assert(MAX_DATA_LENGTH > MAX_GPT_NAME_SIZE);

    if (!storage_dev || !ptdev_name) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if ((0 == strlen(ptdev_name)) || (strlen(ptdev_name) >= MAX_GPT_NAME_SIZE)) {
        PRINTF_CRITICAL("partition name too long\n");
        return -1;
    }

    if (snprintf((char *)name, MAX_GPT_NAME_SIZE, "%s", ptdev_name) < 0) {
        PRINTF_CRITICAL("string proccess error\n");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_GET_NUMBER_SLOTS;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_GET_NUMBER_SLOTS_OK;

    ret = remote_ops(&op, (uint8_t *)name, (strlen(ptdev_name) + 1), recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_ops error \n");
        return -1;
    }

    /* copy the return vaue */
    memcpy(&value, recv_msg + MSG_HEAD_SIZE, sizeof(value));

    if ((1 != value) && (2 != value)) {
        PRINTF_CRITICAL("return value error\n");
        return -1;
    }

    return value;
}

int remote_get_current_slot(storage_device_t *storage_dev,
                            const char *ptdev_name)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[MAX_GPT_NAME_SIZE] = {0};
    int8_t value = 0;
    assert(MAX_DATA_LENGTH > MAX_GPT_NAME_SIZE);

    if (!storage_dev || !ptdev_name) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if ((0 == strlen(ptdev_name)) || (strlen(ptdev_name) >= MAX_GPT_NAME_SIZE)) {
        PRINTF_CRITICAL("partition name too long\n");
        return -1;
    }

    if (snprintf((char *)name, MAX_GPT_NAME_SIZE, "%s", ptdev_name) < 0) {
        PRINTF_CRITICAL("string proccess error\n");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_GET_CURRENT_SLOTS;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_GET_CURRENT_SLOTS_OK;

    ret = remote_ops(&op, (uint8_t *)name, (strlen(ptdev_name) + 1), recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_ops error \n");
        return -1;
    }

    /* copy the return vaue */
    memcpy(&value, recv_msg + MSG_HEAD_SIZE, sizeof(value));

    if ((0 != value) && (1 != value)) {
        PRINTF_CRITICAL("return value = %d error\n", value);
        return -1;
    }

    return value;
}

#if DEBUGMODE
const char *attr_str[] = {
    "ATTR_UNBOOTABLE",
    "ATTR_ACTIVE",
    "ATTR_SUCCESSFUL",
    "ATTR_RETRY",
};
#endif

int remote_get_slot_attr(storage_device_t *storage_dev, const char *ptdev_name,
                         uint8_t slot, uint8_t attr)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[MAX_GPT_NAME_SIZE + sizeof(attr) + sizeof(slot)] = {0};
    int8_t value = 0;
    assert(MAX_DATA_LENGTH > (MAX_GPT_NAME_SIZE + 2));

    if (!storage_dev || !ptdev_name) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if ((0 != slot) && (1 != slot)) {
        PRINTF_CRITICAL("slot error\n");
        return -1;
    }

    if (attr >= ATTR_NUM) {
        PRINTF_CRITICAL("attr error\n");
        return -1;
    }

    if ((0 == strlen(ptdev_name)) || (strlen(ptdev_name) >= MAX_GPT_NAME_SIZE)) {
        PRINTF_CRITICAL("partition name too long\n");
        return -1;
    }

    name[0] = slot;
    name[1] = attr;

    if (snprintf((char *)&name[2], MAX_GPT_NAME_SIZE, "%s", ptdev_name) < 0) {
        PRINTF_CRITICAL("string proccess error\n");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_GET_SLOT_ATTR;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_GET_SLOT_ATTR_OK;

    ret = remote_ops(&op, (uint8_t *)name,
                     (strlen(ptdev_name) + 1  + sizeof(attr) + sizeof(slot)), recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_ops error \n");
        return -1;
    }

    /* copy the return vaue */
    memcpy(&value, recv_msg + MSG_HEAD_SIZE, sizeof(value));

    if (((0 != value) && (1 != value) && (attr != ATTR_RETRY)) ||
            ((attr == ATTR_RETRY) && ((value >= MAX_RETRY_COUNT) || (value < 0)))) {
        PRINTF_CRITICAL("return value error, attr = %d, value = %d\n", attr, value);
        return -1;
    }

#if DEBUGMODE
    PRINTF_CRITICAL("get slot = %d attr = %s, value = %d\n", slot, attr_str[attr],
                    value);
#endif
    return value;
}

int remote_set_slot_attr(storage_device_t *storage_dev, const char *ptdev_name,
                         uint8_t slot, uint8_t attr, uint8_t set_value)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[MAX_GPT_NAME_SIZE +  + sizeof(attr) + sizeof(slot) + sizeof(
                                       set_value)] = {0};
    assert(MAX_DATA_LENGTH > (MAX_GPT_NAME_SIZE + 3));

    if (!storage_dev || !ptdev_name) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if ((0 != slot) && (1 != slot)) {
        PRINTF_CRITICAL("slot error\n");
        return -1;
    }

    if (attr >= ATTR_NUM) {
        PRINTF_CRITICAL("attr error\n");
        return -1;
    }

    if (((0 != set_value) && (1 != set_value) && (attr != ATTR_RETRY)) ||
            ((attr == ATTR_RETRY) && (set_value >= MAX_RETRY_COUNT) )) {
        PRINTF_CRITICAL("set value error, attr = %d, value = %d\n", attr, set_value);
        return -1;
    }

    if ((0 == strlen(ptdev_name)) || (strlen(ptdev_name) >= MAX_GPT_NAME_SIZE)) {
        PRINTF_CRITICAL("partition name too long\n");
        return -1;
    }

    name[0] = slot;
    name[1] = attr;
    name[2] = set_value;

    if (snprintf((char *)&name[3], MAX_GPT_NAME_SIZE, "%s", ptdev_name) < 0) {
        PRINTF_CRITICAL("string proccess error\n");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_SET_SLOT_ATTR;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_SET_SLOT_ATTR_OK;

#if DEBUGMODE
    PRINTF_CRITICAL("set slot = %d attr = %s, set_value = %d\n", slot,
                    attr_str[attr], set_value);
#endif

    ret = remote_ops(&op, (uint8_t *)name,
                     (strlen(ptdev_name) + 1 + sizeof(attr) + sizeof(slot) + sizeof(set_value)),
                     recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_ops error \n");
        return -1;
    }

    return 0;
}

int remote_update_slot_attr(storage_device_t *storage_dev,
                            const char *ptdev_name)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[MAX_GPT_NAME_SIZE] = {0};
    assert(MAX_DATA_LENGTH > MAX_GPT_NAME_SIZE);

    if (!storage_dev || !ptdev_name) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if ((0 == strlen(ptdev_name)) || (strlen(ptdev_name) >= MAX_GPT_NAME_SIZE)) {
        PRINTF_CRITICAL("partition name too long\n");
        return -1;
    }

    if (snprintf((char *)name, MAX_GPT_NAME_SIZE, "%s", ptdev_name) < 0) {
        PRINTF_CRITICAL("string proccess error\n");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_UPDATE_SLOT_ATTR;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_UPDATE_SLOT_ATTR_OK;

    ret = remote_ops(&op, (uint8_t *)name, (strlen(ptdev_name) + 1), recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_ops error \n");
        return -1;
    }

    return 0;
}

int remote_get_partition_number(storage_device_t *storage_dev,
                                const char *ptdev_name)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[MAX_GPT_NAME_SIZE] = {0};
    uint8_t value = 0;
    assert(MAX_DATA_LENGTH > MAX_GPT_NAME_SIZE);

    if (!storage_dev || !ptdev_name) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    if ((0 == strlen(ptdev_name)) || (strlen(ptdev_name) >= MAX_GPT_NAME_SIZE)) {
        PRINTF_CRITICAL("partition name too long\n");
        return -1;
    }

    if (snprintf((char *)name, MAX_GPT_NAME_SIZE, "%s", ptdev_name) < 0) {
        PRINTF_CRITICAL("string proccess error\n");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_GET_NUMBER_PARTITION;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_GET_NUMBER_PARTITION_OK;

    ret = remote_ops(&op, (uint8_t *)name, (strlen(ptdev_name) + 1), recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_ops error \n");
        return -1;
    }

    /* copy the return vaue */
    memcpy(&value, recv_msg + MSG_HEAD_SIZE, sizeof(value));

    if (value >= NUM_PARTITIONS) {
        PRINTF_CRITICAL("return value error\n");
        return -1;
    }

    return (int)value;
}

int remote_get_partition_info(storage_device_t *storage_dev,
                              const char *ptdev_name, uint8_t partition_index, void *entry_in)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_RECV_LENGTH] = {0};
    uint8_t name[MAX_GPT_NAME_SIZE + sizeof(uint8_t)] = {0};
    um_partition_info_t info = {{0}, {0}, 0, 0, 0, {0}};
    assert(MAX_DATA_LENGTH > (MAX_GPT_NAME_SIZE + 1));
    struct partition_entry *entry = (struct partition_entry *)entry_in;

    if (!storage_dev || !ptdev_name || !entry) {
        PRINTF_CRITICAL("para error\n");
        goto end;
    }

    if (partition_index >= NUM_PARTITIONS) {
        PRINTF_CRITICAL("partition index %d error\n", partition_index);
        goto end;
    }

    if ((0 == strlen(ptdev_name)) || (strlen(ptdev_name) >= MAX_GPT_NAME_SIZE)) {
        PRINTF_CRITICAL("partition name too long\n");
        goto end;
    }

    name[0] = partition_index;

    if (snprintf((char *)&name[1], MAX_GPT_NAME_SIZE, "%s", ptdev_name) < 0) {
        PRINTF_CRITICAL("string proccess error\n");
        goto end;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_GET_PARTITION_INFO;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_GET_PARTITION_INFO_OK;

    ret = remote_ops(&op, (uint8_t *)name,
                     (strlen(ptdev_name) + 1  + sizeof(partition_index)), recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_ops error\n");
        PRINTF_CRITICAL("(uint8_t *)name + 1 = %s, len = %zu\n", (char *)&name[1],
                        strlen((char *)&name[1]));
        goto end;
    }

    /* copy the return vaue */
    memcpy(&info, recv_msg + MSG_HEAD_SIZE, sizeof(um_partition_info_t));
    memcpy((uint8_t *)(entry->type_guid), (uint8_t *)(info.type_guid),
           PARTITION_TYPE_GUID_SIZE);
    memcpy((uint8_t *)(entry->unique_partition_guid),
           (uint8_t *)(info.unique_partition_guid), UNIQUE_PARTITION_GUID_SIZE);
    memset((uint8_t *)(entry->name), 0, MAX_GPT_NAME_SIZE);
    snprintf((char *)(entry->name), MAX_GPT_NAME_SIZE, "%s", (char *)(info.name));
    //memcpy((uint8_t *)(entry->name), (uint8_t *)(info.name), strlen((char *)info.name));
    entry->first_lba = info.first_lba;
    entry->last_lba = info.last_lba;
    entry->attribute_flag = info.attribute_flag;
    ret = 0;

end:
    return ret;
}

int remote_get_boot_info(storage_device_t *storage_dev, char *boot_info)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_SEND_LENGTH] = {0};
    ota_msg_head_struct_t *head;

    if (!storage_dev || !boot_info) {
        PRINTF_CRITICAL("para error");
        return -1;
    }

    op.fd = storage_dev->dev_fd;
    op.cmd = OTA_CMD_GET_BOOT_INFO;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_GET_BOOT_INFO_OK;

    ret = remote_ops(&op, NULL, 0, recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("get boot info error \n");
        return -1;
    }

    /* len check */
    head = (ota_msg_head_struct_t *)recv_msg;

    if (head->len != MAX_DATA_LENGTH) {
        PRINTF_CRITICAL("get boot pin  recv len is %d, not %d\n",
                        head->len, MAX_DATA_LENGTH);
        return -1;
    }

    /* copy the capacity */
    memcpy(boot_info, recv_msg + MSG_HEAD_SIZE, MAX_DATA_LENGTH);
#if DEBUGMODE
    PRINTF_CRITICAL("boot info = %s \n", boot_info);
#endif
    return 0;
}


#if 0
static int remote_handover(int fd)
{
    ota_op_t op;
    int ret = -1;
    uint8_t recv_msg[MAX_SEND_LENGTH] = {0};

    op.fd = fd;
    op.cmd = OTA_CMD_HANDOVER;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_HANDOVER_OK;
    ret = remote_ops(&op, NULL, 0, recv_msg);

    if (ret < 0) {
        PRINTF_CRITICAL("remote_handover error \n");
        return -1;
    }

    return 0;
}
#endif

#if RUN_IN_ANDROID && !RUN_IN_HOST
int rpmsg_init(storage_device_t *storage_dev)
{
    int try_cnt = 30;
    int ret;
    int fd = -1;
    char fpath[FILE_PATH_LEN + 64] = {0};
    const char *monitor_channel = storage_dev->dev_name;
    sprintf(fpath, "%s/devices/%s", RPMSG_BUS_SYS, monitor_channel);

retry:
    PRINTF_INFO("try %d access rpmsg device %s\n", try_cnt, fpath);

    if (access(fpath, F_OK)) {
        PRINTF_INFO("try %d Not able to access rpmsg device %s, %s\n", try_cnt, fpath,
                    strerror(errno));
        goto end;
    }

    /* close rpmsg first */
    if(storage_dev->rpmsg_handler) {
        rpmsg_close_channel(storage_dev->rpmsg_handler);
        storage_dev->rpmsg_handler = NULL;
    }

    ret = rpmsg_open_channel(monitor_channel, "update-monitor", O_RDWR | O_NONBLOCK,
        &(storage_dev->rpmsg_handler));
    if (ret) {
        PRINTF_CRITICAL("Failed to open rpmsg device %s", monitor_channel);
        goto end;
    }

    fd =  storage_dev->rpmsg_handler->fd;

end:
    if (fd < 0) {
        if (try_cnt-- > 0) {
            usleep(100000);
            goto retry;
        }

        if(storage_dev->rpmsg_handler) {
            rpmsg_close_channel(storage_dev->rpmsg_handler);
            storage_dev->rpmsg_handler = NULL;
        }
    }

    return fd;
}

#elif RUN_IN_QNX //qnx

static int open_rpmsg_ctl_fd(char *rpmsg_node, rpmsg_op_t *rp_op)
{
    int ctl_fd = -1;
    char rpmsg_ctl_pathname[FILE_PATH_LEN + 4];
    snprintf(rpmsg_ctl_pathname, FILE_PATH_LEN, "%s/ctl", rpmsg_node);

    if ((rp_op->chid = ChannelCreate(_NTO_CHF_PRIVATE)) < 0) {
        PRINTF_CRITICAL("ChannelCreate failed: errno=%d(%s)\n\n", errno,
                        strerror(errno));
        return -1;
    }

    if ((rp_op->coid = ConnectAttach(0, 0, rp_op->chid, _NTO_SIDE_CHANNEL,
                                     0)) < 0) {
        PRINTF_CRITICAL("ConnectAttach failed: errno=%d(%s)", errno, strerror(errno));
        return -1;
    }

    ctl_fd = open(rpmsg_ctl_pathname, O_RDWR);

    if (ctl_fd < 0) {
        PRINTF_CRITICAL("Failed to open %s! errno=%d(%s)\n\n", rpmsg_ctl_pathname,
                        errno, strerror(errno));
        return -1;
    }

    PRINTF_CRITICAL("Open rpmsg device %s!\n", rpmsg_node);

    return ctl_fd;
}

static int open_rpmsg_ept_fd(char *rpmsg_node, int ctl_fd, rpmsg_op_t *rp_op)
{
    int ept_num = RP_ENDPOINT;
    int ret = -1;
    char rpmsg_ept_pathname[FILE_PATH_LEN];
    struct sigevent sigev;
    rpmsg_endpoint_prop_t prop;
    int ept_fd;

    rpmsg_endpoint_attr_t eattr;
    eattr.local_name     = "ospi_ota_service";
    eattr.remote_name    = NULL;
    eattr.ept_class_name = "char";
    eattr.local_addr     = ept_num;
    eattr.remote_addr    = RP_ENDPOINT;
    eattr.flags          = 0;

    rp_op->ept_id = rpmsg_create_endpoint(ctl_fd, &eattr);

    if (rp_op->ept_id == RPMSG_INVALID_ID) {
        PRINTF_CRITICAL("Failed to create endpoint! ept_id=%d\n\n", rp_op->ept_id);
        return -1;
    }

    snprintf(rpmsg_ept_pathname, FILE_PATH_LEN, "%s/ept%d", rpmsg_node,
             rp_op->ept_id);

    SIGEV_PULSE_INIT(&sigev, rp_op->coid, RP_EVENT_PRIORITY, RP_EVENT_CODE,
                     ((ept_num & RPMSG_EVENT_DATA_USER_MASK) << RPMSG_EVENT_DATA_USER_SHIFT));

    rp_op->ept_hdl = rpmsg_open_endpoint(rpmsg_ept_pathname, O_RDWR, &sigev);

    if (rp_op->ept_hdl == NULL) {
        PRINTF_CRITICAL("Failed to open endpoint! %s\n\n", rpmsg_ept_pathname);
        return -1;
    }

    ret = rpmsg_endpoint_get_properties(rp_op->ept_hdl, &prop);

    if (ret != EOK) {
        PRINTF_CRITICAL("Failed to get endpoint properties! %s\n\n",
                        rpmsg_ept_pathname);
        return -1;
    }

    ept_fd = rpmsg_endpoint_get_fd(rp_op->ept_hdl);

    if (ept_fd < 0) {
        PRINTF_CRITICAL("Failed to get endpoint fd! %s\n\n", rpmsg_ept_pathname);
        return -1;
    }

    return ept_fd;
}

static int close_rpmsg_test_ept_fd(int ctl_fd, int ept_fd, rpmsg_op_t *rp_op)
{
    int ret = -1;

    if (rp_op->ept_hdl != NULL) {
        ret = rpmsg_close_endpoint(rp_op->ept_hdl);

        if (ret != EOK) {
            PRINTF_CRITICAL("Failed to close endpoint! ept=%d, ept_hdl=0x%p, ret2=%d(%s)\n\n",
                            rp_op->ept_id, rp_op->ept_hdl, ret, strerror(ret));
        }
    }

    if (rp_op->ept_id != RPMSG_INVALID_ID) {
        ret = rpmsg_destroy_endpoint(ctl_fd, rp_op->ept_id);

        if (ret != EOK) {
            PRINTF_CRITICAL("Failed to destroy endpoint! ept=%d, ret2=%d(%s)\n\n",
                            rp_op->ept_id, ret, strerror(ret));
        }
    }

    return 0;
}

static void release_rpmsg_handle(storage_device_t *storage_dev)
{
    const char *monitor_channel = storage_dev->dev_name;
    rpmsg_handle_t *rpmsg_handle_local = storage_dev->rpmsg_handler;

    if (!rpmsg_handle_local) {
        PRINTF_CRITICAL("Failed to get rpmsg handler for %s\n\n", monitor_channel);
        return;
    }

    if (rpmsg_handle_local->ctl_fd >= 0 &&
            rpmsg_handle_local->ept_fd >= 0 &&
            rpmsg_handle_local->count > 1) {
        rpmsg_handle_local->count--;
        return;
    }

    close_rpmsg_test_ept_fd(rpmsg_handle_local->ctl_fd, rpmsg_handle_local->ept_fd,
                            &rpmsg_handle_local->rp_op);
    rpmsg_handle_local->ctl_fd = -1;
    rpmsg_handle_local->ept_fd = -1;
    memset(&(rpmsg_handle_local->rp_op), 0, sizeof(rpmsg_op_t));
    rpmsg_handle_local->count = 0;

    return;
}

int rpmsg_init(storage_device_t *storage_dev)
{
    const char *monitor_channel = storage_dev->dev_name;
    rpmsg_handle_t *rpmsg_handle_local = storage_dev->rpmsg_handler;
    int retry_cnt = 30;

    if (!rpmsg_handle_local) {
        PRINTF_CRITICAL("Failed to get rpmsg handler for %s\n\n", monitor_channel);
        return -1;
    }

retry:

    if (rpmsg_handle_local->ept_fd < 0 || rpmsg_handle_local->ctl_fd < 0) {
        rpmsg_handle_local->rp_op.ept_id = RPMSG_INVALID_ID;

        rpmsg_handle_local->ctl_fd = open_rpmsg_ctl_fd((char *)monitor_channel,
                                     &(rpmsg_handle_local->rp_op));

        if (rpmsg_handle_local->ctl_fd < 0) {
            PRINTF_CRITICAL("Failed to open ctl fd! errno=%d(%s), retry cnt = =%d\n\n",
                            errno,
                            strerror(errno), retry_cnt);
            goto fail;
        }

        rpmsg_handle_local->ept_fd = open_rpmsg_ept_fd((char *)monitor_channel,
                                     rpmsg_handle_local->ctl_fd, &(rpmsg_handle_local->rp_op));
        rpmsg_handle_local->count = 1;

        if (rpmsg_handle_local->ept_fd < 0) {
            PRINTF_CRITICAL("Failed to get endpoint fd, retry_cnt = %d\n\n", retry_cnt);
            goto fail;
        }
    }
    else {
        rpmsg_handle_local->count++;
    }

    return rpmsg_handle_local->ept_fd;

fail:

    if (retry_cnt-- > 0) {
        goto retry;
    }

    return -1;
}
#else
#define KERNEL_VERSION_LEN 512
#define KERNEL_VERSION_STR "Linux version"

static uint32_t get_kernel_version_major(void)
{
    FILE* fp = NULL;
    size_t num_read = 0;
    char *major_str = NULL;
    char *token_temp = NULL;
    char *version_start = NULL;
    uint32_t kernel_major = 0;
    char line[KERNEL_VERSION_LEN] = {0};

    fp = fopen("/proc/version", "r");
    if (NULL == fp)
    {
        PRINTF_CRITICAL("Failed to open /proc/version\n");
        goto out;
    }

    num_read = fread(line, sizeof(char), sizeof(line) - 1, fp);
    if (num_read <= 0)
    {
        PRINTF_CRITICAL("Failed to read kernel version\n");
        goto out;
    }

    version_start = strstr(line, KERNEL_VERSION_STR);
    if (version_start == NULL)
    {
        PRINTF_CRITICAL("Failed to get string:%s\n", KERNEL_VERSION_STR);
        goto out;
    }

    version_start += strlen(KERNEL_VERSION_STR);
    major_str = strtok_r(version_start, ".", &token_temp);
    token_temp = NULL;
    kernel_major = strtoul(major_str,&token_temp ,10);
    PRINTF_INFO("kernel version major:%u\n", kernel_major);
out:
    if (fp != NULL)
        fclose(fp);

    return kernel_major;
}

static bool is_rpmsg_legacy_bind(void)
{
    return (get_kernel_version_major() < 6u);
}

static int rpmsg_create_ept(int rpfd, struct rpmsg_endpoint_info *eptinfo)
{
    int ret;
    ret = ioctl(rpfd, RPMSG_CREATE_EPT_IOCTL, eptinfo);

    if (ret)
        perror("Failed to create endpoint.\n");

    return ret;
}

static char *rpmsg_get_ept_dev_name(const char *rpmsg_char_name,
                                    const char *ept_name, char *ept_dev_name)
{
    char sys_rpmsg_ept_name_path[64] = {0};
    char svc_name[64] = {0};
    char *sys_rpmsg_path = "/sys/class/rpmsg";
    FILE *fp;
    int i;
    int ept_name_len;

    for (i = 0; i < 128; i++) {
        sprintf(sys_rpmsg_ept_name_path, "%s/%s/rpmsg%d/name",
                sys_rpmsg_path, rpmsg_char_name, i);

        PRINTF_INFO("checking %s\n", sys_rpmsg_ept_name_path);

        if (access(sys_rpmsg_ept_name_path, F_OK) < 0)
            continue;

        fp = fopen(sys_rpmsg_ept_name_path, "r");

        if (!fp) {
            PRINTF_CRITICAL("failed to open %s\n", sys_rpmsg_ept_name_path);
            break;
        }

        fseek(fp, 0, SEEK_SET);
        fgets(svc_name, sizeof(svc_name), fp);
        PRINTF_INFO("svc_name: %s.\n", svc_name);
        fclose(fp);

        ept_name_len = strlen(ept_name);

        if (ept_name_len > sizeof(svc_name))
            ept_name_len = sizeof(svc_name);

        if (!strncmp(svc_name, ept_name, ept_name_len)) {
            sprintf(ept_dev_name, "rpmsg%d", i);
            return ept_dev_name;
        }
    }

    PRINTF_INFO("Not able to RPMsg endpoint file for %s:%s.\n", rpmsg_char_name,
                ept_name);
    return NULL;
}

static int rpmsg_bind_chrdev(const char *rpmsg_dev_name)
{
    char fpath[FILE_PATH_LEN + 64] = {0};
    char *rpmsg_chdrv;
    int fd;
    int ret;

    rpmsg_chdrv = (is_rpmsg_legacy_bind()) ? "rpmsg_chrdev":"rpmsg_ctrl";
    /* rpmsg dev overrides path */
    sprintf(fpath, "%s/devices/%s/driver_override",
            RPMSG_BUS_SYS, rpmsg_dev_name);
    fd = open(fpath, O_WRONLY);

    if (fd < 0) {
        PRINTF_CRITICAL("Failed to open %s, %s\n", fpath, strerror(errno));
        return -EINVAL;
    }

    ret = write(fd, rpmsg_chdrv, strlen(rpmsg_chdrv) + 1);

    if (ret < 0) {
        PRINTF_CRITICAL("Failed to write %s to %s, %s\n",
                        rpmsg_chdrv, fpath, strerror(errno));
        close(fd);
        return -EINVAL;
    }

    close(fd);
    /* bind the rpmsg device to rpmsg char driver */
    sprintf(fpath, "%s/drivers/%s/bind", RPMSG_BUS_SYS, rpmsg_chdrv);
    fd = open(fpath, O_WRONLY);

    if (fd < 0) {
        PRINTF_CRITICAL("Failed to open %s, %s\n", fpath, strerror(errno));
        return -EINVAL;
    }

    ret = write(fd, rpmsg_dev_name, strlen(rpmsg_dev_name) + 1);

    if (ret < 0) {
        PRINTF_CRITICAL("Failed to write %s to %s, %s\n",
                        rpmsg_dev_name, fpath, strerror(errno));
        PRINTF_CRITICAL("If it's already bind, please unbind with below command, then try again\n");
        PRINTF_CRITICAL("echo %s > %s/drivers/%s/unbind\n", rpmsg_dev_name,
                        RPMSG_BUS_SYS, rpmsg_chdrv);
        close(fd);
        return -EINVAL;
    }

    close(fd);
    return 0;
}

static int rpmsg_unbind_chrdev(const char *rpmsg_dev_name)
{
    char fpath[FILE_PATH_LEN] = {0};
    char *rpmsg_chdrv;
    int fd;
    int ret;

    rpmsg_chdrv = (is_rpmsg_legacy_bind()) ? "rpmsg_chrdev":"rpmsg_ctrl";
    /* unbind the rpmsg device to rpmsg char driver */
    sprintf(fpath, "%s/drivers/%s/unbind", RPMSG_BUS_SYS, rpmsg_chdrv);
    fd = open(fpath, O_WRONLY);

    if (fd < 0) {
        PRINTF_CRITICAL("Failed to open %s, %s\n", fpath, strerror(errno));
        return -EINVAL;
    }

    ret = write(fd, rpmsg_dev_name, strlen(rpmsg_dev_name) + 1);

    if (ret < 0) {
        close(fd);
        return -EINVAL;
    }

    close(fd);
    return 0;
}


static int rpmsg_get_chrdev_fd(const char *rpmsg_dev_name,
                               char *rpmsg_ctrl_name)
{
    char *rpmsg_ctrl_prefix = "rpmsg_ctrl";
    DIR *dir;
    struct dirent *ent;
    int fd;
    char dpath[FILE_PATH_LEN + 64] = {0};
    char fpath[FILE_PATH_LEN_L + 64] = {0};

    sprintf(dpath, "%s/devices/%s/rpmsg", RPMSG_BUS_SYS, rpmsg_dev_name);
    dir = opendir(dpath);

    if (dir == NULL) {
        PRINTF_CRITICAL("Failed to open dir %s %s\n", dpath, strerror(errno));
        return -EINVAL;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (!strncmp(ent->d_name, rpmsg_ctrl_prefix, strlen(rpmsg_ctrl_prefix))) {
            printf("Opening file %s.\n", ent->d_name);
            sprintf(fpath, "/dev/%s", ent->d_name);
            fd = open(fpath, O_RDWR | O_NONBLOCK);

            if (fd < 0) {
                PRINTF_CRITICAL("Failed to open rpmsg char dev %s,%s\n", fpath,
                                strerror(errno));
                return -EINVAL;
            }

            sprintf(rpmsg_ctrl_name, "%s", ent->d_name);
            return fd;
        }
    }

    PRINTF_CRITICAL("No rpmsg char dev file is found\n");
    return -EINVAL;
}

int rpmsg_init(storage_device_t *storage_dev)
{
    int ret = -1;
    int charfd = -1;
    int fd = -1;
    char rpmsg_char_name[16] = {0};
    char ept_dev_name[16] = {0};
    char ept_dev_path[32] = {0};
    struct rpmsg_endpoint_info eptinfo;
    char fpath[FILE_PATH_LEN + 64] = {0};
    int try_cnt = 30;
    const char *monitor_channel = storage_dev->dev_name;
    sprintf(fpath, "%s/devices/%s", RPMSG_BUS_SYS, monitor_channel);

retry:
    PRINTF_INFO("try %d access rpmsg device %s\n", try_cnt, fpath);

    if (access(fpath, F_OK)) {
        PRINTF_INFO("try %d Not able to access rpmsg device %s, %s\n", try_cnt, fpath,
                    strerror(errno));
        goto end;
    }

    /* unbind first */
    rpmsg_unbind_chrdev(monitor_channel);
    /* bind */
    ret = rpmsg_bind_chrdev(monitor_channel);

    if (ret < 0) {
        PRINTF_CRITICAL("Failed to bind rpmsg device %s\n", fpath);
        goto end;
    }

    usleep(100000);
    charfd = rpmsg_get_chrdev_fd(monitor_channel, rpmsg_char_name);

    if (charfd < 0) {
        PRINTF_INFO("failed to get chrdev fd %d\n", charfd);
        goto end;
    }

    /* Create endpoint from rpmsg char driver */
    strcpy(eptinfo.name, "rpmsg-update-monitor-channel");
    eptinfo.src = 81;
    eptinfo.dst = 81;
    ret = rpmsg_create_ept(charfd, &eptinfo);

    if (ret) {
        PRINTF_INFO("failed to create RPMsg endpoint.\n");
        goto end;
    }

    if (!rpmsg_get_ept_dev_name(rpmsg_char_name, eptinfo.name, ept_dev_name)) {
        goto end;
    }

    if (strlen(ept_dev_name) == 0) {
        PRINTF_CRITICAL("ept_dev_name length error\n");
    }

    /* TODO polling /dev/rpmsgX */
    usleep(100000);
    sprintf(ept_dev_path, "/dev/%s", ept_dev_name);
    fd = open(ept_dev_path, O_RDWR);

    if (fd < 0) {
        PRINTF_CRITICAL("Failed to open rpmsg device, %s\n", strerror(errno));
    }

end:

    if (charfd >= 0) {
        close(charfd);
    }

    if (fd < 0) {
        if (try_cnt-- > 0) {
            usleep(100000);
            goto retry;
        }
    }

    return fd;
}
#endif


int remote_init(storage_device_t *storage_dev)
{
    int fd_rpmsg = -1;
    int ret = -1;
    char const *rpmsg_name = storage_dev->dev_name;

    if ((!storage_dev) || (!rpmsg_name)) {
        PRINTF_CRITICAL("remote init para error");
        return -1;
    }

    /* rpmsg init */
    fd_rpmsg = rpmsg_init(storage_dev);

    if (fd_rpmsg < 0) {
        PRINTF_CRITICAL("init %s device failed\n", rpmsg_name);
        goto unbind;
    }

    ret = remote_start(storage_dev, fd_rpmsg);

    if (ret < 0) {
        PRINTF_CRITICAL("failed to start communicate with update monitor\n");
        goto unbind;
    }

#if SET_REMOTE_HIGH_PRIO
    /* set remote safet update thread's priority, 0: default 1: highest */
    ret = remote_set_priority(fd_rpmsg, 1);

    if (ret < 0) {
        PRINTF_CRITICAL("failed to set the priority of update monitor in safety\n");
        goto unbind;
    }

#endif
    storage_dev->dev_fd = fd_rpmsg;
    ret = 0;
    goto end;

unbind:

#if RUN_IN_ANDROID && !RUN_IN_HOST
    rpmsg_close_channel(storage_dev->rpmsg_handler);
    storage_dev->rpmsg_handler = NULL;

#elif RUN_IN_QNX
    release_rpmsg_handle(storage_dev);
#else //linux
    /* unbind rgmsg */
    if (rpmsg_unbind_chrdev(rpmsg_name) < 0) {
        PRINTF_CRITICAL("Failed to unbind rpmsg device %s\n", rpmsg_name);
    }

    if (fd_rpmsg >= 0)
        close(fd_rpmsg);
#endif

end:
    return ret;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
