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

#ifdef SELF_TEST_MODE
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#if !RUN_IN_QNX
#include <linux/fs.h>
#endif
#include <sys/types.h>
#include <getopt.h>
#include <malloc.h>
#include <libgen.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "slots_parse.h"
#include <assert.h>
#include "communication.h"
#if RUN_IN_QNX
#include <qcrypto/qcrypto.h>
#endif

#define LBA_SIZE 512
#define MAX_CALLOC_SIZE (512*1024)
#define USE_RW
#define FILE_NAME_MAX (MAX_GPT_NAME_SIZE + 256)
#define MAX_PARTITION_NUM 64
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef UNIT_TEST_PRINTF
#define UNIT_TEST_PRINTF PRINTF_CRITICAL
#define SLOT_CHECK      true
#define NO_SLOT_CHECK   false
#define FILE_CHECK      true
#define NO_FILE_CHECK   false
#define NOT_WRITE_TEST  0
#define WRITE_TEST      1

bool write_with_check_mode = false;
int        flag;
int        flags = (O_RDWR | O_NONBLOCK);
int        file_slot = 0;
uint64_t test_addr = 0;
uint64_t test_len = 0;
static const char *short_opt = "pt:s:wf:m:a:l:d:";
static char test_digest[128] = {0};

static const struct option long_options[] = {
    { "print", no_argument, NULL, 'p'        },
    { "test", required_argument, NULL,  't'  },
    { "slot", required_argument, &flag, 's'  },
    { "wcheck", no_argument, NULL,      'w'  },
    { "file", required_argument, NULL,  'f'  },
    { "mode", required_argument, NULL,  'm'  },
    { "addr", required_argument, NULL,  'a'  },
    { "len", required_argument, NULL,   'l'  },
    { "digest", required_argument, NULL, 'd' },
    { NULL, 0, NULL, 0 }
};
static uint8_t file_cnt = 0;
static char *file_name[FILE_NAME_MAX];

static int read_file(char *file, uint64_t src, uint8_t *read_buf,
                     uint64_t size);
static int unit_test_open_close(int argc, char *argv[]);
static int unit_test_seek(int argc, char *argv[]);
static int unit_test_read(int argc, char *argv[]);
static int unit_test_write(int argc, char *argv[]);
static int unit_remote_ospi_ptdev_test(int argc, char *argv[]);
static int unit_test_A_B_copy(int argc, char *argv[]);
static int unit_test_boot_control_all_a(int argc, char *argv[]);
static int unit_test_boot_control_all_b(int argc, char *argv[]);
static int unit_test_mem_test(int argc, char *argv[]);
static int unit_test_mem_erase(int argc, char *argv[]);
static int unit_test_check_partition(int argc, char *argv[]);
static int unit_remote_emmc_ptdev_test(int argc, char *argv[]);
static int unit_test_read_a_partition_to_a_file(int argc, char *argv[]);
static int unit_test_read_and_print(int argc, char *argv[]);
static int unit_test_pread(int argc, char *argv[]);
static int unit_test_pwrite(int argc, char *argv[]);
static int unit_tcp_server(int argc, char *argv[]);
static int unit_tcp_client(int argc, char *argv[]);
static int flash_read_write(int argc, char *argv[]);
static int emmc_read_write(int argc, char *argv[]);
static int unit_test_read_time(int argc, char *argv[]);
static int unit_test_wrtie_time(int argc, char *argv[]);
static int unit_test_digest(int argc, char *argv[]);
#endif

typedef struct testcase {
    int test_num;
    int test_slot;
    int test_storage;
    char *test_fun_str;
    int (*test_fun)(int argc, char *argv[]);
    bool slot_check;
    bool file_check;
} testcase_t;

testcase_t testcase_list[] = {
    {0,  2, DEV_MAX, "0:unit_test_open_close",                     unit_test_open_close,                  SLOT_CHECK,        FILE_CHECK},
    {1,  2, DEV_MAX, "1:unit_test_seek",                           unit_test_seek,                        SLOT_CHECK,        FILE_CHECK},
    {2,  2, DEV_MAX, "2:unit_test_read",                           unit_test_read,                        SLOT_CHECK,        FILE_CHECK},
    {3,  2, DEV_MAX, "3:unit_test_write",                          unit_test_write,                       SLOT_CHECK,        FILE_CHECK},
    {4,  2, DEV_MAX, "4:unit_remote_ospi_ptdev_test",              unit_remote_ospi_ptdev_test,           SLOT_CHECK,        FILE_CHECK},
    {5,  2, DEV_MAX, "5:unit_test_A_B_copy",                       unit_test_A_B_copy,                    SLOT_CHECK,        FILE_CHECK},
    {6,  0, DEV_MAX, "6a:unit_test_boot_control_all_a",            unit_test_boot_control_all_a,          SLOT_CHECK,        FILE_CHECK},
    {6,  1, DEV_MAX, "6b:unit_test_boot_control_all_b",            unit_test_boot_control_all_b,          SLOT_CHECK,        FILE_CHECK},
    {7,  2, DEV_MAX, "7:unit_test_mem_test",                       unit_test_mem_test,                    SLOT_CHECK,        FILE_CHECK},
    {8,  2, DEV_MAX, "8:unit_test_mem_erase",                      unit_test_mem_erase,                   SLOT_CHECK,        FILE_CHECK},
    {9,  2, DEV_MAX, "9:unit_test_check_partition",                unit_test_check_partition,             SLOT_CHECK,        FILE_CHECK},
    {10, 2, DEV_MAX, "10:unit_remote_emmc_ptdev_test",             unit_remote_emmc_ptdev_test,           SLOT_CHECK,        FILE_CHECK},
    {11, 2, DEV_MAX, "11:unit_test_read_a_partition_to_a_file",    unit_test_read_a_partition_to_a_file,  NO_SLOT_CHECK,     NO_FILE_CHECK},
    {12, 2, DEV_MAX, "12:unit_test_read_and_print",                unit_test_read_and_print,              SLOT_CHECK,     NO_FILE_CHECK},
    {13, 2, DEV_MAX, "13:unit_test_pread",                         unit_test_pread,                       SLOT_CHECK,     NO_FILE_CHECK},
    {14, 2, DEV_MAX, "14:unit_test_pwrite",                        unit_test_pwrite,                      SLOT_CHECK,     NO_FILE_CHECK},
    {15, 2, DEV_MAX, "15:unit_tcp_server",                         unit_tcp_server,                       NO_SLOT_CHECK,     NO_FILE_CHECK},
    {16, 2, DEV_MAX, "16:unit_tcp_client",                         unit_tcp_client,                       NO_SLOT_CHECK,     NO_FILE_CHECK},
    {17, 2, DEV_MAX, "17:flash_read_write",                        flash_read_write,                      NO_SLOT_CHECK,     NO_FILE_CHECK},
    {18, 2, DEV_MAX, "18:emmc_read_write",                         emmc_read_write,                       NO_SLOT_CHECK,     NO_FILE_CHECK},
    {19, 2, DEV_MAX, "19:unit_test_read_time",                     unit_test_read_time,                   NO_SLOT_CHECK,     NO_FILE_CHECK},
    {20, 2, DEV_MAX, "20:unit_test_wrtie_time",                    unit_test_wrtie_time,                  NO_SLOT_CHECK,     NO_FILE_CHECK},
    {21, 2, DEV_MAX, "21:unit_test_digest",                        unit_test_digest,                      NO_SLOT_CHECK,     NO_FILE_CHECK},
};

int main(int argc, char *argv[])
{
    int ret = -1;
    int option_index = 0;
    int c = -1;
    file_cnt = 0;
    optind = 2;
    int test = 0;
    int slot = 2;
    int storage_id = DEV_MAX;
    int count = 0;
    count = sizeof(testcase_list) / sizeof(testcase_list[0]);

    while (1) {
        c = getopt_long_only(argc, argv, short_opt, long_options, &option_index);

        if (-1 == c) {
            break;
        }

        switch (c) {
            case 's':
                if (!strcmp((char *)optarg, "b")) {
                    slot = 1;
                    file_slot = 1;
                }
                else {
                    slot = 0;
                    file_slot = 0;
                }

                UNIT_TEST_PRINTF("slot %d\n", slot);
                break;

            case 'p':
                UNIT_TEST_PRINTF("testcase_list : \n");

                for (int i = 0; i < count; i++) {
                    UNIT_TEST_PRINTF("%s\n", testcase_list[i].test_fun_str);
                }

                ret = 0;
                goto end;

            case 't':
                assert((uint8_t)atoi(optarg) < (sizeof(testcase_list) / sizeof(
                                                    testcase_list[0])));
                test |= (0x1 << (uint8_t)atoi(optarg));
                UNIT_TEST_PRINTF("testcase %s , test = %x\n", optarg, test);
                break;

            case 'f':
                if (file_cnt >= MAX_PARTITION_NUM) {
                    UNIT_TEST_PRINTF("too many file input\n");
                    goto end;
                }

                file_name[file_cnt] = optarg;
                UNIT_TEST_PRINTF("get file %s\n", file_name[file_cnt]);
                file_cnt++;
                break;

            case 'w':
                write_with_check_mode = true;
                UNIT_TEST_PRINTF("wirte with check mode on\n");
                break;

            case 'm':
                if (!strcmp((char *)optarg, "ro")) {
                    flags = (O_RDONLY | O_NONBLOCK);
                }
                else if (!strcmp((char *)optarg, "wo")) {
                    flags = (O_WRONLY | O_NONBLOCK);
                }
                else {
                    flags = (O_RDWR | O_NONBLOCK);
                }

                UNIT_TEST_PRINTF("flags = 0x%08x\n", flags);
                break;

            case 'a':
                test_addr =  strtoul((char *)optarg, NULL, 16);
                UNIT_TEST_PRINTF("get test addr = 0x%llx\n", (unsigned long long)test_addr);
                break;

            case 'l':
                test_len =  strtoul((char *)optarg, NULL, 16);
                UNIT_TEST_PRINTF("get test length = 0x%llx\n", (unsigned long long)test_len);
                break;

            case 'd':
                if (strlen((char *)optarg) > 100) {
                    UNIT_TEST_PRINTF("digest length error\n");
                    goto end;
                }

                strcpy((char *)test_digest, (char *)optarg);
                UNIT_TEST_PRINTF("test_digest = %s\n", test_digest);
                break;

            case '?':
                UNIT_TEST_PRINTF("unknow input arg\n");

            default:
                ret = -1;
                goto end;
                break;
        }
    }

    count = sizeof(testcase_list) / sizeof(testcase_list[0]);

    for (int i = 0; i < count; i++) {
        if ((test & (1 << testcase_list[i].test_num))
                && (storage_id == testcase_list[i].test_storage)
                &&  testcase_list[i].test_fun) {
            /* slot check */
            if (testcase_list[i].slot_check && (testcase_list[i].test_slot != slot)) {
                continue;
            }

            /* file check */
            if (testcase_list[i].file_check && (file_cnt > 0)) {
                for (int f = 0; f < file_cnt; f++) {
                    if (access(file_name[f], F_OK)) {
                        UNIT_TEST_PRINTF("Not able to access %s\n", file_name[f]);
                        continue;
                    }
                }
            }

            /* test start */
            UNIT_TEST_PRINTF("============= test case: %s ============= \n",
                             testcase_list[i].test_fun_str);
            UNIT_TEST_PRINTF("test num    : %d\n", testcase_list[i].test_num);
            UNIT_TEST_PRINTF("test slot   : %d\n", testcase_list[i].test_slot);
            UNIT_TEST_PRINTF("test storage: %d\n", testcase_list[i].test_storage);
            UNIT_TEST_PRINTF("test argc   : %d\n", argc);
            UNIT_TEST_PRINTF("=========================================  \n");
            ret = testcase_list[i].test_fun(argc, argv);

            if (ret < 0) {
                UNIT_TEST_PRINTF("============= testcase [%s] error ============= \n",
                                 testcase_list[i].test_fun_str);
                goto end;
            }

            UNIT_TEST_PRINTF("============= testcase [%s]  successful ============= \n",
                             testcase_list[i].test_fun_str);
        }
    }

    ret = 0;
end:
    return ret;
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

static int read_file(char *file, uint64_t src, uint8_t *read_buf, uint64_t size)
{
    int ret = -1;
    int fd = 0;
    struct stat fstat;
    uint64_t read_size;

    if (!read_buf) {
        UNIT_TEST_PRINTF("read_file buffer is NULL\n");
        goto end;
    }

    if (stat(file, &fstat) < 0) {
        UNIT_TEST_PRINTF("stat %s error\n", file);
        goto end;
    }

    if (fstat.st_size < size) {
        UNIT_TEST_PRINTF("original size = %lld too large, limited file size = %lld\n",
                         (unsigned long long)size, (unsigned long long)fstat.st_size);
        size = fstat.st_size;
    }

    fd = open(file, O_RDONLY);

    if (fd <= 0) {
        UNIT_TEST_PRINTF("open file %s error %s\n", file, strerror(errno));
        goto end;
    }

#if RUN_IN_QNX

    if (lseek(fd, src, SEEK_SET) < 0)
#else
    if (lseek64(fd, src, SEEK_SET) < 0)
#endif

    {
        UNIT_TEST_PRINTF("file lseek failed: err = %s\n", strerror(errno));
        goto end;
    }

    read_size = read(fd, read_buf, size);

    if (size != read_size) {
        UNIT_TEST_PRINTF("file read failed err = %s\n", strerror(errno));
        UNIT_TEST_PRINTF("size = %ld, read size = %ld\n", (unsigned long)size,
                         (unsigned long)read_size);
        UNIT_TEST_PRINTF("read_buf as:\n");
        hexdump8((uint8_t *)read_buf, size);
        goto end;
    }

    ret = 0;

end:

    if (fd > 0)
        close(fd);

    return ret;
}

static int write_file_to_partition(char *file, int partition_fd,
                                   uint64_t partition_size, int mode)
{
    uint64_t cnt = 0;
    uint64_t left = 0;
    uint8_t *read_buf = NULL;
    uint8_t *read_buf2 = NULL;
    uint64_t read_len = FILE_READ_LENGTH;
    uint64_t read_len_array[3] = {FILE_READ_LENGTH, 0xAABB, 0x1234};
    int write_cnt = 0;
    int ret = -1;
    uint64_t i = 0;
    int fd = 0;
    struct stat fstat;
    uint64_t file_size = 0;

    if (stat(file, &fstat) < 0) {
        UNIT_TEST_PRINTF("stat %s error\n", file);
        goto end;
    }

    if (fstat.st_size > partition_size) {
        UNIT_TEST_PRINTF("file = %lld too large, limited file size = %lld\n",
                         (unsigned long long)fstat.st_size, (unsigned long long)partition_size);
        goto end;
    }

    file_size = fstat.st_size;
    fd = open(file, O_RDONLY);

    if (fd <= 0) {
        UNIT_TEST_PRINTF("open file %s error %s\n", file, strerror(errno));
        goto end;
    }

    for (write_cnt = 0;
            write_cnt < (sizeof(read_len_array) / sizeof(read_len_array[0])); write_cnt++) {
        read_len = read_len_array[write_cnt];
        UNIT_TEST_PRINTF("write file to partition write size = %lld\n",
                         (unsigned long long)read_len);
        read_buf = (uint8_t *)MEM_ALIGN(512, read_len);
        read_buf2 = (uint8_t *)MEM_ALIGN(512, read_len);

        if (!read_buf || !read_buf2) {
            UNIT_TEST_PRINTF("blk_write_with_check calloc failed\n");
            goto end;
        }

        cnt = file_size / read_len;
        left = file_size % read_len;

#if RUN_IN_QNX

        if (lseek(fd, 0, SEEK_SET) < 0)
#else
        if (lseek64(fd, 0, SEEK_SET) < 0)
#endif

        {
            UNIT_TEST_PRINTF("file lseek failed: err = %s\n", strerror(errno));
            goto end;
        }

        if (0 != partition_dev_seek(partition_fd, 0, SEEK_SET)) {
            UNIT_TEST_PRINTF("partition_dev_seek fd[%d] failed\n", partition_fd);
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
                UNIT_TEST_PRINTF("file read failed err = %s\n", strerror(errno));
                goto end;
            }

            UNIT_TEST_PRINTF("write addr is %lld\n",
                             (unsigned long long)partition_dev_seek(partition_fd, 0, SEEK_CUR));

            if (read_len != partition_dev_write(partition_fd, read_buf, read_len)) {
                UNIT_TEST_PRINTF("write failed\n");
                goto end;
            }

            if (partition_dev_seek(partition_fd, read_len * (-1), SEEK_CUR) < 0) {
                UNIT_TEST_PRINTF("partition_dev_seek fd[%d] failed\n", partition_fd);
                goto end;
            }

            UNIT_TEST_PRINTF("read back addr is %lld\n",
                             (unsigned long long)partition_dev_seek(partition_fd, 0, SEEK_CUR));

            if (read_len != partition_dev_read(partition_fd, read_buf2, read_len)) {
                UNIT_TEST_PRINTF("read failed\n");
                goto end;
            }

            if (memcmp(read_buf, read_buf2, read_len)) {
                UNIT_TEST_PRINTF("memcmp fd[%d] failed\n", partition_fd);
                UNIT_TEST_PRINTF("read_buf as:\n");
                hexdump8((uint8_t *)read_buf, read_len);
                UNIT_TEST_PRINTF("read_buf2 as:\n");
                hexdump8((uint8_t *)read_buf2, read_len);
                goto end;
            }
        }

        if (read_buf) {
            FREE(read_buf);
            read_buf = NULL;
        }

        if (read_buf2) {
            FREE(read_buf2);
            read_buf2 = NULL;
        }

        if (NOT_WRITE_TEST == mode) {
            break;
        }
    }

    ret = 0;

end:

    if (read_buf)
        FREE(read_buf);

    if (read_buf2)
        FREE(read_buf2);

    if (fd > 0)
        close(fd);

    return ret;
}

/*----------------------------------------------------------
    Test Number         :   testcase 1

    Test Purposes       :   test the following partition syscall
                            interface [open] & [close] & [offset]
                            & [size]

    Test Description    :   First read the partition table
                            corresponding to the update device as
                            the local partition table. Then open each
                            partition through the system call interface,
                            and obtain the size and offset of the
                            partition through the system call interface.
                            Calculate and compare the values of
                            size and offset with the local partition
                            table to judge consistency.
                            Finally close all opened partition devices
 ----------------------------------------------------------*/
static int unit_test_open_close(int argc, char *argv[])
{
    int ret = -1;
    int fd[NUM_PARTITIONS] = {0};
    partition_device_t *ptdev = NULL;
    unsigned i = 0;
    unsigned partition_count;
    struct partition_entry *partition_entries;
    int mode = SYSCALL_AUTO;

    if ((1 == argc) || (!strcmp(argv[1], "emmc"))) {
        ret = switch_storage_dev(&ptdev, DEV_EMMC0);
        mode = SYSCALL_FORCE_LOCAL;
    }
    else if (!strcmp(argv[1], "ospi")) {
        ret = switch_storage_dev_force_local_flexible(&ptdev, DEV_SPI_NOR0);
        mode = SYSCALL_FORCE_REMOTE;
    }
    else if (!strcmp(argv[1], "emmc1")) {
        ret = switch_storage_dev_force_local_flexible(&ptdev, DEV_EMMC1);
        mode = SYSCALL_FORCE_REMOTE;
    }
    else if (!strcmp(argv[1], "emmc2")) {
        ret = switch_storage_dev_force_local_flexible(&ptdev, DEV_EMMC2);
        mode = SYSCALL_FORCE_REMOTE;
    }

    if (0 != ret) {
        UNIT_TEST_PRINTF("failed to setup ptdev\n");
        goto end;
    }

    ret = -1;

    if ((argc > 2) && strncmp(argv[2], "-", 1)) {
        UNIT_TEST_PRINTF("useage error\n");
        goto end;
    }

    if ((!ptdev) || (!ptdev->partition_entries)) {
        UNIT_TEST_PRINTF("Invalid partition dev\n");
        goto end;
    }

    partition_count = ptdev->count;
    partition_entries = ptdev->partition_entries;

    for (i = 0; i < partition_count; i++) {
        UNIT_TEST_PRINTF("ptn[%d]:Name[%s] Size[%llu] Type[%u] First[%llu] Last[%llu]\n",
                         i, partition_entries[i].name, partition_entries[i].size,
                         partition_entries[i].dtype,
                         partition_entries[i].first_lba,
                         partition_entries[i].last_lba);

        if (!strcmp((const char *)partition_entries[i].name, "vbmeta_a"))
            continue;

        if (!strcmp((const char *)partition_entries[i].name, "vbmeta_b"))
            continue;

        if (strstr((const char *)partition_entries[i].name, "$"))
            continue;

        fd[i] = partition_dev_open((const char *)partition_entries[i].name, flags,
                                   mode);

        if (fd[i] < 0) {
            UNIT_TEST_PRINTF("failed to open %s\n", partition_entries[i].name);
            goto end;
        }

        partition_dev_dump(fd[i]);
        UNIT_TEST_PRINTF("unit test open %s ok, fd = %d\n", partition_entries[i].name,
                         fd[i]);
    }

#if 0
    /* dump all the fd belong to the same update device */
    partition_dev_dump_all(fd[0]);
#endif

    for (i = 0; i < partition_count; i++) {
        if (fd[i] <= 0)
            continue;

        if ((partition_entries[i].size * 512) != partition_dev_blockdevsize(fd[i])) {
            UNIT_TEST_PRINTF("unit test partition size check error\n");
            UNIT_TEST_PRINTF("partition_entries[%d].size *512 = 0x%llx\n", i,
                             (unsigned long long)(partition_entries[i].size * 512));
            UNIT_TEST_PRINTF("partition_dev_blockdevsize(%d) = 0x%llx", fd[i],
                             (unsigned long long)partition_dev_blockdevsize(fd[i]));
            goto end;
        }
        else {
            UNIT_TEST_PRINTF("unit test partition size check ok\n");
        }

        if (((partition_entries[i].first_lba) * 512 + ptdev->gpt_offset) !=
                partition_dev_blockdevoffset(fd[i])) {
            UNIT_TEST_PRINTF("unit test partition offset check erro\n");
            UNIT_TEST_PRINTF("partition_entries[%d].first_lba *512 = 0x%llx\n", i,
                             (unsigned long long)((partition_entries[i].first_lba) * 512 +
                                                  ptdev->gpt_offset));
            UNIT_TEST_PRINTF("partition_dev_blockdevsize(%d) = 0x%llx\n", fd[i],
                             (unsigned long long)partition_dev_blockdevoffset(fd[i]));

            goto end;
        }
        else {
            UNIT_TEST_PRINTF("unit test partition offset check ok\n");
        }
    }

    for (i = 0; i < partition_count; i++) {
        if (fd[i] <= 0)
            continue;

        if (partition_dev_close(fd[i])) {
            UNIT_TEST_PRINTF("unit test failed to close %s\n", partition_entries[i].name);
            goto end;
        }

        UNIT_TEST_PRINTF("unit test close %s ok, fd = %d\n", partition_entries[i].name,
                         fd[i]);
    }

    ret = 0;

end:

    if (ptdev)
        free_storage_dev_force_local(ptdev);

    return ret;
}

/*----------------------------------------------------------
    Test Number         :   testcase 2

    Test Purposes       :   test the following partition syscall
                            interface [seek]

    Test Description    :   The test method is similar to testcase1,
                            and it is tested for the seek interface.
                            Including SEEK_CUR, SEEK_SET, SEEK_END
                            and other modes and wrong parameters
                            for testing
 ----------------------------------------------------------*/
static int unit_test_seek(int argc, char *argv[])
{
    int ret = -1;
    int fd[NUM_PARTITIONS] = {0};
    partition_device_t *ptdev = NULL;
    unsigned i = 0;
    unsigned partition_count;
    struct partition_entry *partition_entries;
    off64_t offset = 0;
    off64_t offset_ret = 0;
    int mode = SYSCALL_AUTO;

    if ((1 == argc) || (!strcmp(argv[1], "emmc"))) {
        ret = switch_storage_dev_force_local(&ptdev, DEV_EMMC0);
        mode = SYSCALL_FORCE_LOCAL;
    }
    else if (!strcmp(argv[1], "ospi")) {
        ret = switch_storage_dev_force_local_flexible(&ptdev, DEV_SPI_NOR0);
        mode = SYSCALL_FORCE_REMOTE;
    }
    else if (!strcmp(argv[1], "emmc1")) {
        ret = switch_storage_dev_force_local_flexible(&ptdev, DEV_EMMC1);
        mode = SYSCALL_FORCE_REMOTE;
    }
    else if (!strcmp(argv[1], "emmc2")) {
        ret = switch_storage_dev_force_local_flexible(&ptdev, DEV_EMMC2);
        mode = SYSCALL_FORCE_REMOTE;
    }

    if (0 != ret) {
        UNIT_TEST_PRINTF("failed to setup ptdev\n");
        ret = -1;
        goto end;
    }

    ret = -1;

    if ((argc > 2) && strncmp(argv[2], "-", 1)) {
        UNIT_TEST_PRINTF("useage error\n");
        goto end;
    }

    if ((!ptdev) || (!ptdev->partition_entries)) {
        UNIT_TEST_PRINTF("Invalid partition dev\n");
        goto end;
    }

    partition_count = ptdev->count;
    partition_entries = ptdev->partition_entries;

    for (i = 0; i < partition_count; i++) {

        if (!strcmp((const char *)partition_entries[i].name, "vbmeta_a"))
            continue;

        if (!strcmp((const char *)partition_entries[i].name, "vbmeta_b"))
            continue;

        if (strstr((const char *)partition_entries[i].name, "$"))
            continue;

        UNIT_TEST_PRINTF("ptn[%d]:Name[%s] Size[%llu] Type[%u] First[%llu] Last[%llu]\n",
                         i, partition_entries[i].name, partition_entries[i].size,
                         partition_entries[i].dtype,
                         partition_entries[i].first_lba,
                         partition_entries[i].last_lba);

        fd[i] = partition_dev_open((const char *)partition_entries[i].name, flags,
                                   mode);

        if (fd[i] < 0) {
            UNIT_TEST_PRINTF("failed to open %s\n", partition_entries[i].name);
            goto end;
        }
    }

    UNIT_TEST_PRINTF("-------------SEEK_SET test begin-------------------\n");

    for (i = 0; i < partition_count; i++) {
        if (fd[i] <= 0)
            continue;

        for (int j = 0; j < 5; j++) {
            if (0 == j)
                offset = partition_dev_blockdevsize(fd[i]) >> 1; //size ok

            if (1 == j)
                offset = partition_dev_blockdevsize(fd[i]) - 1; //size ok

            if (2 == j)
                offset = 0;                                     //size ok

            if (3 == j)
                offset = partition_dev_blockdevsize(fd[i]);     //size error

            if (4 == j)
                offset = partition_dev_blockdevsize(fd[i]) * 2; //size error

            offset_ret = partition_dev_seek(fd[i], offset, SEEK_SET);

            if (j < 3) {
                if (offset != offset_ret) {
                    UNIT_TEST_PRINTF("SEEK_SET test %d-%d offset_ret = %lld, offset = %lld\n", i, j,
                                     (long long)offset_ret, (long long)offset);
                    goto end;
                }
                else {
                    UNIT_TEST_PRINTF("SEEK_SET test %d-%d ok\n", i, j);
                }
            }
            else {
                if (-1 == offset_ret) {
                    UNIT_TEST_PRINTF("SEEK_SET test %d-%d ok\n", i, j);
                }
                else {
                    UNIT_TEST_PRINTF("SEEK_SET test %d-%d  offset_ret = %lld, offset = %lld\n", i,
                                     j, (long long)offset_ret, (long long)offset);
                    goto end;
                }
            }
        }
    }

    UNIT_TEST_PRINTF("-------------SEEK_CUR test begin-------------------\n");

    for (i = 0; i < partition_count; i++) {
        if (fd[i] <= 0)
            continue;

        for (int j = 0; j < 5; j++) {
            if (0 == j)
                offset = partition_dev_blockdevsize(fd[i]) >> 2; //size ok

            if (1 == j)
                offset = partition_dev_blockdevsize(fd[i]) >> 2; //size ok

            if (2 == j)
                offset = partition_dev_blockdevsize(fd[i]) >> 2; //size ok

            if (3 == j)
                offset = partition_dev_blockdevsize(fd[i]) >> 2; //size error

            if (4 == j)
                offset = (partition_dev_blockdevsize(fd[i]) >> 2) * (-1); //size ok

            offset_ret = partition_dev_seek(fd[i], offset, SEEK_CUR);

            if (j < 3) {
                if (offset * (j + 1) != offset_ret) {
                    UNIT_TEST_PRINTF("SEEK_CUR test %d-%d offset_ret = %lld, offset = %lld\n", i, j,
                                     (long long)offset_ret, (long long)offset);
                    goto end;
                }
                else {
                    UNIT_TEST_PRINTF("SEEK_CUR test %d-%d ok, currunt offset_ret = %lld\n", i, j,
                                     (long long)offset_ret);
                }
            }

            else if (3 == j) {
                if (-1 == offset_ret) {
                    UNIT_TEST_PRINTF("SEEK_CUR test %d-%d ok, currunt offset_ret = %lld\n", i, j,
                                     (long long)offset_ret);
                }
                else {
                    UNIT_TEST_PRINTF("SEEK_CUR test %d-%d offset_ret = %lld, offset = %lld\n", i, j,
                                     (long long)offset_ret, (long long)offset);
                    goto end;
                }
            }

            if (j == 4) {
                if (offset_ret == 2 * (-1)*offset_ret) {
                    UNIT_TEST_PRINTF("SEEK_CUR test %d-%d offset_ret = %lld, offset = %lld\n", i, j,
                                     (long long)offset_ret, (long long)offset);
                    goto end;
                }
                else {
                    UNIT_TEST_PRINTF("SEEK_CUR test %d-%d ok, currunt offset_ret = %lld\n", i, j,
                                     (long long)offset_ret);
                }
            }
        }
    }

    UNIT_TEST_PRINTF("-------------SEEK_END test begin-------------------\n");

    for (i = 0; i < partition_count; i++) {
        if (fd[i] <= 0)
            continue;

        for (int j = 0; j < 4; j++) {
            if (0 == j)
                offset = (partition_dev_blockdevsize(fd[i]) >> 2) * (-1); //size ok

            if (1 == j)
                offset = partition_dev_blockdevsize(fd[i]) * (-1);  //size ok

            if (2 == j)
                offset = partition_dev_blockdevsize(fd[i]) >> 2; //size error

            if (3 == j)
                offset = (partition_dev_blockdevsize(fd[i]) + 1) * (-1); //size error

            offset_ret = partition_dev_seek(fd[i], offset, SEEK_END);

            if (j < 1) {
                if (3 * (-1)*offset_ret == offset_ret) {
                    UNIT_TEST_PRINTF("SEEK_END test %d-%d offset_ret = %lld, offset = %lld\n", i, j,
                                     (long long)offset_ret, (long long)offset);
                    goto end;
                }
                else {
                    UNIT_TEST_PRINTF("SEEK_END test %d-%d ok, currunt offset_ret = %lld\n", i, j,
                                     (long long)offset_ret);
                }
            }
            else if (j == 1) {
                if (0 == offset_ret) {
                    UNIT_TEST_PRINTF("SEEK_END test %d-%d ok, currunt offset_ret = %lld\n", i, j,
                                     (long long)offset_ret);
                }
                else {
                    UNIT_TEST_PRINTF("SEEK_END test %d-%d offset_ret = %lld, offset = %lld\n", i, j,
                                     (long long)offset_ret, (long long)offset);
                    goto end;
                }
            }
            else {
                if (-1 == offset_ret) {
                    UNIT_TEST_PRINTF("SEEK_END test %d-%d ok, currunt offset_ret = %lld\n", i, j,
                                     (long long)offset_ret);
                }
                else {
                    UNIT_TEST_PRINTF("SEEK_END test %d-%d  offset_ret = %lld, offset = %lld\n", i,
                                     j, (long long)offset_ret, (long long)offset);
                    goto end;
                }
            }
        }
    }

    UNIT_TEST_PRINTF("-------------UNSUPPORTED test begin-------------------\n");

    for (i = 0; i < partition_count; i++) {
        if (fd[i] <= 0)
            continue;

        for (int j = 0; j < 4; j++) {
            if (0 == j)
                offset = (partition_dev_blockdevsize(fd[i]) >> 2) * (-1); //size ok

            if (1 == j)
                offset = partition_dev_blockdevsize(fd[i]) * (-1);  //size ok

            if (2 == j)
                offset = partition_dev_blockdevsize(fd[i]) >> 2; //size error

            if (3 == j)
                offset = (partition_dev_blockdevsize(fd[i]) + 1) * (-1); //size error

            offset_ret = partition_dev_seek(fd[i], offset, -1);

            if (-1 == offset_ret) {
                UNIT_TEST_PRINTF("SEEK_END test %d-%d ok, currunt offset_ret = %lld\n", i, j,
                                 (long long)offset_ret);
            }
            else {
                UNIT_TEST_PRINTF("SEEK_END test %d-%d  offset_ret = %lld, offset = %lld\n", i,
                                 j, (long long)offset_ret, (long long)offset);
                goto end;
            }
        }
    }

    for (i = 0; i < partition_count; i++) {
        if (fd[i] <= 0)
            continue;

        if (partition_dev_close(fd[i])) {
            UNIT_TEST_PRINTF("unit test failed to close %s\n", partition_entries[i].name);
            goto end;
        }
    }

    ret = 0;

end:

    if (ptdev)
        free_storage_dev_force_local(ptdev);

    return ret;
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 3

    Test Purposes       :   test the following partition syscall
                            interface [read]

    Test Description    :   1. First find an upgrade test file
                            corresponding to a partition in each
                            upgrade device (can be obtained from
                            the pac package)
                            2. For example, cluset_bootloader.bin
                            corresponds to the partition of AP2,
                            use the existing storage->write_file
                            interface to burn the file to the
                            corresponding partition(the inactive one)
                            of AP2. Then read the file through the
                            syscall interface and compare it with
                            the original programming file.
                            3. During the read process, the aligned
                            or unaligned read length will be used
                            for testing, so the read address is
                            not aligned

    Test Command    :       ./ota_self_test emmc2 -t 2 -f cluster_bootloader.bin
                            ./ota_self_test emmc1 -t 2 -f dil2.bin
 ----------------------------------------------------------------------------*/
static int unit_test_read(int argc, char *argv[])
{
    partition_device_t *ptdev = NULL;
    int slot_active[MAX_PARTITION_NUM] = {0};
    int slot_inactive[MAX_PARTITION_NUM] = {0};
    int active_slot = 0;
    int inactive_slot = 0;
    int len = 0;
    int ret = -1;
    unsigned long long file_off = 0;
    unsigned long long in = 0;
    unsigned long long out = 0;
    unsigned long long size = 0;
    unsigned long long left = 0;
    unsigned long long cnt = 0;
    char *pname = NULL;
    const char *suffix = NULL;
    int index = 0;
    int file_index[MAX_PARTITION_NUM] = {0};
    unsigned char *data = NULL;;
    unsigned char *data2 = NULL;;
    storage_device_t *storage;
    unsigned long long gpt_offset;
    char fname[FILE_NAME_MAX] = {0};
    char *file_base_name = NULL;
    bool update_from_file = false;
    int fd[NUM_PARTITIONS] = {0};
    unsigned i = 0;
    unsigned partition_count;
    struct partition_entry *partition_entries;
    int mode = SYSCALL_AUTO;
    unsigned long long  test_read_size = 0;
    unsigned long long  test_read_size_array[3] = {123456, 0xABCD,  262144};

    if ((1 == argc) || (!strcmp(argv[1], "emmc"))) {
        ret = switch_storage_dev_force_local(&ptdev, DEV_EMMC0);
        mode = SYSCALL_FORCE_LOCAL;
    }
    else if (!strcmp(argv[1], "ospi")) {
        ret = switch_storage_dev_force_local_flexible(&ptdev, DEV_SPI_NOR0);
        mode = SYSCALL_FORCE_REMOTE;
    }
    else if (!strcmp(argv[1], "emmc1")) {
        ret = switch_storage_dev_force_local_flexible(&ptdev, DEV_EMMC1);
        mode = SYSCALL_FORCE_REMOTE;
    }
    else if (!strcmp(argv[1], "emmc2")) {
        ret = switch_storage_dev_force_local_flexible(&ptdev, DEV_EMMC2);
        mode = SYSCALL_FORCE_REMOTE;
    }

    if (0 != ret) {
        UNIT_TEST_PRINTF("failed to setup ptdev\n");
        ret = -1;
        goto end;
    }

    ret = -1;

    if ((argc > 2) && strncmp(argv[2], "-", 1)) {
        UNIT_TEST_PRINTF("useage error\n");
        ret = -1;
        goto end;
    }

    if (file_cnt == 0) {
        UNIT_TEST_PRINTF("useage error, need to specify file(aka, -f xxx.img)\n");
        ret = -1;
        goto end;
    }

    partition_count = ptdev->count;
    partition_entries = ptdev->partition_entries;
    storage = ptdev->storage;
    gpt_offset = ptdev->gpt_offset;

    for (i = 0; i < partition_count; i++) {
        if (!strcmp((const char *)partition_entries[i].name, "vbmeta_a"))
            continue;

        if (!strcmp((const char *)partition_entries[i].name, "vbmeta_b"))
            continue;

        if (strstr((const char *)partition_entries[i].name, "$"))
            continue;

        fd[i] = partition_dev_open((const char *)partition_entries[i].name, flags,
                                   mode);

        if (fd[i] < 0) {
            UNIT_TEST_PRINTF("failed to open %s\n", partition_entries[i].name);
            ret = -1;
            goto fail;
        }
    }

    active_slot = get_current_slot(ptdev);
    suffix = get_suffix(ptdev, active_slot);

    if (partition_count > 2 * MAX_PARTITION_NUM) {
        UNIT_TEST_PRINTF("too many partition\n");
        goto fail;
    }

    for (int i = 0; i < MAX_PARTITION_NUM; i++) {
        file_index[i] = -1;
    }

    for (int i = 0; i < partition_count; i++) {
        if (fd[i] <= 0)
            continue;

        pname = (char *)partition_entries[i].name;
        len = strlen(pname);

        if (len < 4)
            continue; /* too few, ignore */

        if (strcmp((char *)(pname + len - 2), suffix_slot[0])
                && strcmp((char *)(pname + len - 2), suffix_slot[1])) {
            continue;
        }

        for (int j = i + 1; j < partition_count; j++) {
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

                for (int k = 0; k < file_cnt; k++) {
                    if (!strlen(file_name[k]) || (strlen(file_name[k]) >= FILE_NAME_MAX)) {
                        UNIT_TEST_PRINTF("file_name[%d] = %s length error\n", k, file_name[k]);
                        continue;
                    }

                    memset(fname, 0, FILE_NAME_MAX);
                    file_base_name = NULL;
                    strncpy(fname, file_name[k], MIN(strlen(file_name[k]), FILE_NAME_MAX - 1));
                    file_base_name = basename(fname);

                    if ((strlen(file_base_name) < (len - 2))
                            || ((strlen(file_base_name) > (len - 2)) &&  file_base_name[len - 2] != '.'))
                        continue;

                    if (!strncmp(file_base_name, pname, len - 2)) {
                        file_index[k] = index;
                        UNIT_TEST_PRINTF("basename = %s\n", file_base_name);
                        UNIT_TEST_PRINTF("find file input num %d, A/B partition index=%d, file name = %s\n",
                                         k, index, fname);
                    }
                }

                index++;
            }
        }
    }

    for (int i = 0; i < index; i++) {
        active_slot = slot_active[i];
        inactive_slot = slot_inactive[i];
        in = (partition_entries[active_slot].first_lba) * LBA_SIZE;
        out = (partition_entries[inactive_slot].first_lba) * LBA_SIZE;
        size = (partition_entries[active_slot].last_lba -
                partition_entries[active_slot].first_lba + 1) * LBA_SIZE;

        in += gpt_offset;
        out += gpt_offset;

        update_from_file = false;
        char *temp_file_name;

        for (int k = 0; k < file_cnt; k++) {
            if (file_index[k] == i) {
                UNIT_TEST_PRINTF("i=%d\n", i);
                UNIT_TEST_PRINTF("active_slot=%s\n", partition_entries[active_slot].name);
                UNIT_TEST_PRINTF("inactive_slot=%s\n", partition_entries[inactive_slot].name);
                UNIT_TEST_PRINTF("in=%p out=%p size=%lld\n", (void *)in, (void *)out, size);
                UNIT_TEST_PRINTF("update from file %s\n", file_name[k]);
                UNIT_TEST_PRINTF("storage->dev_name = %s\n", storage->dev_name);
                ret = storage->write_file(storage, out, size, file_name[k],
                                          write_with_check_mode);

                if (ret < 0) {
                    UNIT_TEST_PRINTF("unit_read_write_test write_file failed\n");
                    ret = -1;
                    goto fail;
                }

                update_from_file = true;
                temp_file_name = file_name[k];
                break;
            }
        }

        if (update_from_file != true) {
            continue;
        }

        struct stat fstat;

        if (stat(temp_file_name, &fstat) < 0) {
            UNIT_TEST_PRINTF("stat %s error\n", temp_file_name);
            ret = -1;
            goto fail;
        }

        if (fstat.st_size < size) {
            UNIT_TEST_PRINTF("original size = %lld too large, limited file size = %lld\n",
                             (unsigned long long)size, (unsigned long long)fstat.st_size);
            size = fstat.st_size;
        }

        for (int readcnt = 0;
                readcnt < (sizeof(test_read_size_array) / sizeof(test_read_size_array[0]));
                readcnt++) {
            file_off = 0;
            test_read_size = test_read_size_array[readcnt];
            UNIT_TEST_PRINTF("test_read_size = %lld\n", test_read_size);
            cnt =  (size / test_read_size);
            left = (size % test_read_size);
            data = (unsigned char *)MEM_ALIGN(512, (cnt != 0 ? (test_read_size) : size));
            data2 = (unsigned char *)MEM_ALIGN(512, (cnt != 0 ? (test_read_size) : size));

            if (!data || !data2) {
                UNIT_TEST_PRINTF("unit_read_write_test calloc failed\n");
                ret = -1;
                goto fail;
            }

            UNIT_TEST_PRINTF("seek begin\n");

            if (0 != partition_dev_seek(fd[inactive_slot], 0, SEEK_SET)) {
                UNIT_TEST_PRINTF("partition_dev_seek fd[%d] failed\n", inactive_slot);
                ret = -1;
                goto fail;
            }

            for (unsigned long long n = 0; n < cnt; n++) {
                ret = read_file(temp_file_name, file_off, data, test_read_size);

                if (ret < 0) {
                    UNIT_TEST_PRINTF("unit_read_write_test storage->read failed\n");
                    ret = -1;
                    goto fail;
                }

                UNIT_TEST_PRINTF("read addr is %lld\n",
                                 (unsigned long long)partition_dev_seek(fd[inactive_slot], 0, SEEK_CUR));
                ret = partition_dev_read(fd[inactive_slot], data2, test_read_size);

                if (ret < 0) {
                    UNIT_TEST_PRINTF("unit_read_write_test partition_dev_read fd[%d] failed\n",
                                     fd[inactive_slot]);
                    ret = -1;
                    goto fail;
                }

                if (memcmp(data, data2, test_read_size)) {
                    UNIT_TEST_PRINTF("memcmp fd[%d] failed\n", fd[inactive_slot]);
                    UNIT_TEST_PRINTF("data as:\n");
                    hexdump8((uint8_t *)data, test_read_size > 4096 ? 4096 : test_read_size);
                    UNIT_TEST_PRINTF("data2 as:\n");
                    hexdump8((uint8_t *)data2, test_read_size > 4096 ? 4096 : test_read_size);
                    ret = -1;
                    goto fail;
                }

                file_off += test_read_size;
            }

            if (0 != left) {
                ret = read_file(temp_file_name, file_off, data, left);

                if (ret < 0) {
                    UNIT_TEST_PRINTF("unit_read_write_test storage->read failed\n");
                    ret = -1;
                    goto fail;
                }

                UNIT_TEST_PRINTF("read addr is %lld\n",
                                 (unsigned long long)partition_dev_seek(fd[inactive_slot], 0, SEEK_CUR));
                ret = partition_dev_read(fd[inactive_slot], data2, left);

                if (ret < 0) {
                    UNIT_TEST_PRINTF("unit_read_write_test partition_dev_read fd[%d] failed\n",
                                     fd[inactive_slot]);
                    ret = -1;
                    goto fail;
                }

                if (memcmp(data, data2, left)) {
                    UNIT_TEST_PRINTF("memcmp fd[%d] failed\n", fd[inactive_slot]);
                    UNIT_TEST_PRINTF("data as:\n");
                    hexdump8((uint8_t *)data, left);
                    UNIT_TEST_PRINTF("data2 as:\n");
                    hexdump8((uint8_t *)data2, left);
                    ret = -1;
                    goto fail;
                }
            }

            FREE(data);
            FREE(data2);
            data = NULL;
            data2 = NULL;
        }
    }

    ret = 0;

fail:

    for (i = 0; i < partition_count; i++) {
        if (fd[i] > 0) {
            partition_dev_close(fd[i]);
        }
    }

end:

    if (data)
        FREE(data);

    if (data2)
        FREE(data2);

    if (ptdev)
        free_storage_dev_force_local(ptdev);

    return ret;
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 4

    Test Purposes       :   test the following partition syscall
                            interface [write]

    Test Description    :   1. First find an upgrade test file
                            corresponding to a partition in each
                            upgrade device (can be obtained from
                            the pac package)
                            2. Write the upgrade file to its
                            corresponding partition (inactive partition)
                            with aligned or unaligned write length,
                            and read back to compare whether the
                            written data is consistent with the
                            read-back data during the writing process
                            3. After writing, the partition
                            will be read back as a whole and
                            compared with the upgrade file

    Test Command    :       ./ota_self_test emmc2 -t 3 -f cluster_bootloader.bin
                            ./ota_self_test emmc1 -t 3 -f dil2.bin

 ----------------------------------------------------------------------------*/
static int unit_test_write(int argc, char *argv[])
{
    partition_device_t *ptdev = NULL;
    int slot_active[MAX_PARTITION_NUM] = {0};
    int slot_inactive[MAX_PARTITION_NUM] = {0};
    int active_slot = 0;
    int inactive_slot = 0;
    int len = 0;
    int ret = -1;
    unsigned long long file_off = 0;
    unsigned long long in = 0;
    unsigned long long out = 0;
    unsigned long long size = 0;
    unsigned long long left = 0;
    unsigned long long cnt = 0;
    char *pname = NULL;
    const char *suffix = NULL;
    int index = 0;
    int file_index[MAX_PARTITION_NUM] = {0};
    unsigned char *data = NULL;
    unsigned char *data2 = NULL;
    unsigned long long gpt_offset;
    char fname[FILE_NAME_MAX] = {0};
    char *file_base_name = NULL;
    bool update_from_file = false;
    int fd[NUM_PARTITIONS] = {0};
    unsigned i = 0;
    unsigned partition_count;
    struct partition_entry *partition_entries;
    int mode = SYSCALL_AUTO;

    if ((1 == argc) || (!strcmp(argv[1], "emmc"))) {
        ret = switch_storage_dev_force_local(&ptdev, DEV_EMMC0);
        mode = SYSCALL_FORCE_LOCAL;
    }
    else if (!strcmp(argv[1], "ospi")) {
        ret = switch_storage_dev_force_local_flexible(&ptdev, DEV_SPI_NOR0);
        mode = SYSCALL_FORCE_REMOTE;
    }
    else if (!strcmp(argv[1], "emmc1")) {
        ret = switch_storage_dev_force_local_flexible(&ptdev, DEV_EMMC1);
        mode = SYSCALL_FORCE_REMOTE;
    }
    else if (!strcmp(argv[1], "emmc2")) {
        ret = switch_storage_dev_force_local_flexible(&ptdev, DEV_EMMC2);
        mode = SYSCALL_FORCE_REMOTE;
    }

    if (0 != ret) {
        UNIT_TEST_PRINTF("failed to setup ptdev\n");
        ret = -1;
        goto end;
    }

    ret = -1;

    if ((argc > 2) && strncmp(argv[2], "-", 1)) {
        UNIT_TEST_PRINTF("useage error\n");
        ret = -1;
        goto end;
    }

    if (file_cnt == 0) {
        UNIT_TEST_PRINTF("useage error, need to specify file(aka, -f xxx.img)\n");
        ret = -1;
        goto end;
    }

    partition_count = ptdev->count;
    partition_entries = ptdev->partition_entries;
    gpt_offset = ptdev->gpt_offset;

    for (i = 0; i < partition_count; i++) {
        if (!strcmp((const char *)partition_entries[i].name, "vbmeta_a"))
            continue;

        if (!strcmp((const char *)partition_entries[i].name, "vbmeta_b"))
            continue;

        if (strstr((const char *)partition_entries[i].name, "$"))
            continue;

        fd[i] = partition_dev_open((const char *)partition_entries[i].name, flags,
                                   mode);

        if (fd[i] < 0) {
            UNIT_TEST_PRINTF("failed to open %s\n", partition_entries[i].name);
            ret = -1;
            goto fail;
        }
    }

    active_slot = get_current_slot(ptdev);
    suffix = get_suffix(ptdev, active_slot);

    if (partition_count > 2 * MAX_PARTITION_NUM) {
        UNIT_TEST_PRINTF("too many partition\n");
        goto fail;
    }

    for (int i = 0; i < MAX_PARTITION_NUM; i++) {
        file_index[i] = -1;
    }

    for (int i = 0; i < partition_count; i++) {
        if (fd[i] <= 0)
            continue;

        pname = (char *)partition_entries[i].name;
        len = strlen(pname);

        if (len < 4)
            continue; /* too few, ignore */

        if (strcmp((char *)(pname + len - 2), suffix_slot[0])
                && strcmp((char *)(pname + len - 2), suffix_slot[1])) {
            continue;
        }

        for (int j = i + 1; j < partition_count; j++) {
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

                for (int k = 0; k < file_cnt; k++) {
                    if (!strlen(file_name[k]) || (strlen(file_name[k]) >= FILE_NAME_MAX)) {
                        UNIT_TEST_PRINTF("file_name[%d] = %s length error\n", k, file_name[k]);
                        continue;
                    }

                    memset(fname, 0, FILE_NAME_MAX);
                    file_base_name = NULL;
                    strncpy(fname, file_name[k], MIN(strlen(file_name[k]), FILE_NAME_MAX - 1));
                    file_base_name = basename(fname);

                    if ((strlen(file_base_name) < (len - 2))
                            || ((strlen(file_base_name) > (len - 2)) &&  file_base_name[len - 2] != '.'))
                        continue;

                    if (!strncmp(file_base_name, pname, len - 2)) {
                        file_index[k] = index;
                        UNIT_TEST_PRINTF("basename = %s\n", file_base_name);
                        UNIT_TEST_PRINTF("find file input num %d, A/B partition index=%d, file name = %s\n",
                                         k, index, fname);
                    }
                }

                index++;
            }
        }
    }

    for (int i = 0; i < index; i++) {
        active_slot = slot_active[i];
        inactive_slot = slot_inactive[i];
        in = (partition_entries[active_slot].first_lba) * LBA_SIZE;
        out = (partition_entries[inactive_slot].first_lba) * LBA_SIZE;
        size = (partition_entries[active_slot].last_lba -
                partition_entries[active_slot].first_lba + 1) * LBA_SIZE;

        in += gpt_offset;
        out += gpt_offset;

        update_from_file = false;
        char *temp_file_name;

        for (int k = 0; k < file_cnt; k++) {
            if (file_index[k] == i) {
                UNIT_TEST_PRINTF("i=%d\n", i);
                UNIT_TEST_PRINTF("active_slot=%s\n", partition_entries[active_slot].name);
                UNIT_TEST_PRINTF("inactive_slot=%s\n", partition_entries[inactive_slot].name);
                UNIT_TEST_PRINTF("in=%p out=%p size=%lld\n", (void *)in, (void *)out, size);
                UNIT_TEST_PRINTF("update from file %s\n", file_name[k]);
                ret = write_file_to_partition(file_name[k], fd[inactive_slot], size,
                                              WRITE_TEST);

                if (ret < 0) {
                    UNIT_TEST_PRINTF("write_file failed\n");
                    ret = -1;
                    goto fail;
                }

                update_from_file = true;
                temp_file_name = file_name[k];
                break;
            }
        }

        if (update_from_file != true) {
            continue;
        }

        file_off = 0;

        struct stat fstat;

        if (stat(temp_file_name, &fstat) < 0) {
            UNIT_TEST_PRINTF("stat %s error\n", temp_file_name);
            ret = -1;
            goto fail;
        }

        if (fstat.st_size < size) {
            UNIT_TEST_PRINTF("original size = %lld too large, limited file size = %lld\n",
                             (unsigned long long)size, (unsigned long long)fstat.st_size);
            size = fstat.st_size;
        }

        cnt =  (size / MAX_CALLOC_SIZE);
        left = (size % MAX_CALLOC_SIZE);
        data = (unsigned char *)MEM_ALIGN(512, (cnt != 0 ? (MAX_CALLOC_SIZE) : size));
        data2 = (unsigned char *)MEM_ALIGN(512, (cnt != 0 ? (MAX_CALLOC_SIZE) : size));

        if (!data || !data2) {
            UNIT_TEST_PRINTF("calloc failed\n");
            ret = -1;
            goto fail;
        }

        if (0 != partition_dev_seek(fd[inactive_slot], 0, SEEK_SET)) {
            UNIT_TEST_PRINTF("partition_dev_seek fd[%d] failed\n", inactive_slot);
            ret = -1;
            goto fail;
        }

        for (unsigned long long n = 0; n < cnt; n++) {
            ret = read_file(temp_file_name, file_off, data, MAX_CALLOC_SIZE);

            if (ret < 0) {
                UNIT_TEST_PRINTF("read_file failed\n");
                ret = -1;
                goto fail;
            }

            ret = partition_dev_read(fd[inactive_slot], data2, MAX_CALLOC_SIZE);

            if (ret < 0) {
                UNIT_TEST_PRINTF("partition_dev_read fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto fail;
            }

            if (memcmp(data, data2, MAX_CALLOC_SIZE)) {
                UNIT_TEST_PRINTF("memcmp fd[%d] failed\n", fd[inactive_slot]);
                UNIT_TEST_PRINTF("data as:\n");
                hexdump8((uint8_t *)data, MAX_CALLOC_SIZE > 4096 ? 4096 : MAX_CALLOC_SIZE);
                UNIT_TEST_PRINTF("data2 as:\n");
                hexdump8((uint8_t *)data2, MAX_CALLOC_SIZE > 4096 ? 4096 : MAX_CALLOC_SIZE);
                ret = -1;
                goto fail;
            }

            in  += MAX_CALLOC_SIZE;
            out += MAX_CALLOC_SIZE;
            file_off += MAX_CALLOC_SIZE;
        }

        if (0 != left) {
            ret = read_file(temp_file_name, file_off, data, left);

            if (ret < 0) {
                UNIT_TEST_PRINTF("read_file failed\n");
                ret = -1;
                goto fail;
            }

            ret = partition_dev_read(fd[inactive_slot], data2, left);

            if (ret < 0) {
                UNIT_TEST_PRINTF("partition_dev_read fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto fail;
            }

            if (memcmp(data, data2, left)) {
                UNIT_TEST_PRINTF("memcmp fd[%d] failed\n", fd[inactive_slot]);
                UNIT_TEST_PRINTF("data as:\n");
                hexdump8((uint8_t *)data, left > 4096 ? 4096 : MAX_CALLOC_SIZE);
                UNIT_TEST_PRINTF("data2 as:\n");
                hexdump8((uint8_t *)data2, left > 4096 ? 4096 : MAX_CALLOC_SIZE);
                ret = -1;
                goto fail;
            }
        }

        FREE(data);
        FREE(data2);
        data = NULL;
        data2 = NULL;
    }

    ret = 0;

fail:

    for (i = 0; i < partition_count; i++) {
        if (fd[i] > 0) {
            partition_dev_close(fd[i]);
        }
    }

end:

    if (data) {
        FREE(data);
    }

    if (data2) {
        FREE(data2);
    }

    if (ptdev)
        free_storage_dev_force_local(ptdev);

    return ret;
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 5

    Test Purposes       :   test remote storage interface for [ospi]

    Test Description    :   The main purpose is to verify the partition
                            table-related operations in the storage interface.
                            These partition table operations are remotely
                            operated partition tables in safety os or ssystem

    Test Command    :       ./ota_self_test ospi -t 4
 ----------------------------------------------------------------------------*/
static int unit_remote_ospi_ptdev_test(int argc, char *argv[])
{
    int ret = -1;
    storage_device_t *storage = NULL;
    update_device_t  *update_device = NULL;

    update_device = setup_update_dev(DEV_SPI_NOR0);

    if (!update_device || !(update_device->storage)) {
        UNIT_TEST_PRINTF("failed to setup storage dev\n");
        goto end;
    }

    storage = get_update_device_storage(DEV_SPI_NOR0);
    ret = storage->setup_ptdev(storage, "ospi1");

    if (ret) {
        UNIT_TEST_PRINTF("failed to storage->setup_ptdev\n");
        goto end;
    }

    int index = storage->get_partition_index(storage, "ospi1", "safety_os_a");

    if (index == -1) {
        UNIT_TEST_PRINTF("failed to remote_get_partition_index\n");
        ret = -1;
        goto end;
    }

    UNIT_TEST_PRINTF("index = %d\n", index);

    uint64_t size = storage->get_partition_size(storage, "ospi1", "safety_os_a");

    if (!size) {
        UNIT_TEST_PRINTF("failed to remote_get_partition_size\n");
        goto end;
    }

    UNIT_TEST_PRINTF("size = 0x%llx\n", (unsigned long long)size);

    uint64_t offset = storage->get_partition_offset(storage, "ospi1",
                      "safety_os_a");

    if (!offset) {
        UNIT_TEST_PRINTF("failed to remote_get_partition_offset\n");
        goto end;
    }

    UNIT_TEST_PRINTF("offset = 0x%llx\n", (unsigned long long)offset);

    int slot_number;
    slot_number = storage->get_slot_number(storage, "ospi1");

    if (slot_number != 2) {
        UNIT_TEST_PRINTF("failed to get_slot_number\n");
        goto end;
    }

    UNIT_TEST_PRINTF("slot_number = %x\n", slot_number);

    int current_slot;
    current_slot = storage->get_current_slot(storage, "ospi1");

    if ((current_slot != 0) && (current_slot != 1)) {

        UNIT_TEST_PRINTF("failed to remote_get_current_slot, current_slot %d\n",
                         current_slot);
        goto end;
    }

    UNIT_TEST_PRINTF("current_slot = %s\n", SUFFIX_SLOT(current_slot));
    int active_attr[2];
    int unbootable_attr[2];
    int successful_attr[2];
    int retry_cnt[2];
    int attr = ATTR_ACTIVE;

    for (int i = 0; i < 2; i ++) {
        attr = ATTR_ACTIVE;
        active_attr[i] = storage->get_slot_attr(storage, "ospi1", i, attr);

        if ((0 != active_attr[i]) && (1 != active_attr[i])) {
            UNIT_TEST_PRINTF("get_slot_attr, attr = %d, value = %d\n", attr,
                             active_attr[i]);
            goto end;
        }

        UNIT_TEST_PRINTF("active_attr slot %s = %d\n", SUFFIX_SLOT(i), active_attr[i]);
        attr = ATTR_UNBOOTABLE;
        unbootable_attr[i] = storage->get_slot_attr(storage, "ospi1", i, attr);

        if ((0 != unbootable_attr[i]) && (1 != unbootable_attr[i])) {
            UNIT_TEST_PRINTF("get_slot_attr, attr = %d, value = %d\n", attr,
                             unbootable_attr[i]);
            goto end;
        }

        UNIT_TEST_PRINTF("unbootable_attr %s = %d\n", SUFFIX_SLOT(i),
                         unbootable_attr[i]);
        attr = ATTR_SUCCESSFUL;
        successful_attr[i] = storage->get_slot_attr(storage, "ospi1", i, attr);

        if ((0 != successful_attr[i]) && (1 != successful_attr[i])) {
            UNIT_TEST_PRINTF("get_slot_attr, attr = %d, value = %d\n", attr,
                             successful_attr[i]);
            goto end;
        }

        UNIT_TEST_PRINTF("successful_attr %s  = %d\n", SUFFIX_SLOT(i),
                         successful_attr[i]);
        attr = ATTR_RETRY;
        retry_cnt[i] = storage->get_slot_attr(storage, "ospi1", i, attr);

        if ((retry_cnt[i] < 0) || (retry_cnt[i] >= 4)) {
            UNIT_TEST_PRINTF("get_slot_attr, attr = %d, value = %d\n", attr, retry_cnt[i]);
            goto end;
        }

        UNIT_TEST_PRINTF("retry_cnt %s = %d\n", SUFFIX_SLOT(i), retry_cnt[i]);
    }


    active_attr[0] = 1;
    active_attr[1] = 0;
    unbootable_attr[0] = 0;
    unbootable_attr[1] = 1;
    successful_attr[0] = 1;
    successful_attr[1] = 1;
    retry_cnt[0] = 2;
    retry_cnt[1] = 2;


    for (int i = 0; i < 2; i ++) {
        attr = ATTR_ACTIVE;

        if (0 != storage->set_slot_attr(storage, "ospi1", i, attr, active_attr[i])) {
            UNIT_TEST_PRINTF("set_slot_attr, attr = %d, value = %d\n", attr,
                             active_attr[i]);
            goto end;
        }

        UNIT_TEST_PRINTF("active_attr slot %s = %d\n", SUFFIX_SLOT(i), active_attr[i]);
        attr = ATTR_UNBOOTABLE;

        if (0 != storage->set_slot_attr(storage, "ospi1", i, attr,
                                        unbootable_attr[i])) {
            UNIT_TEST_PRINTF("set_slot_attr, attr = %d, value = %d\n", attr,
                             unbootable_attr[i]);
            goto end;
        }

        UNIT_TEST_PRINTF("unbootable_attr %s = %d\n", SUFFIX_SLOT(i),
                         unbootable_attr[i]);
        attr = ATTR_SUCCESSFUL;

        if (0 != storage->set_slot_attr(storage, "ospi1", i, attr,
                                        successful_attr[i])) {
            UNIT_TEST_PRINTF("set_slot_attr, attr = %d, value = %d\n", attr,
                             successful_attr[i]);
            goto end;
        }

        UNIT_TEST_PRINTF("successful_attr %s  = %d\n", SUFFIX_SLOT(i),
                         successful_attr[i]);
        attr = ATTR_RETRY;

        if (0 != storage->set_slot_attr(storage, "ospi1", i, attr, retry_cnt[i])) {
            UNIT_TEST_PRINTF("set_slot_attr, attr = %d, value = %d\n", attr, retry_cnt[i]);
            goto end;
        }

        UNIT_TEST_PRINTF("retry_cnt %s = %d\n", SUFFIX_SLOT(i), retry_cnt[i]);
    }

    ret = storage->update_slot_attr(storage, "ospi1");

    if (ret) {
        UNIT_TEST_PRINTF("failed to storage->update_slot_attr\n");
        ret = -1;
        goto end;
    }

    ret = storage->destroy_ptdev(storage, "ospi1");

    if (ret) {
        UNIT_TEST_PRINTF("failed to storage->destroy_ptdev\n");
        ret = -1;
        goto end;
    }

end:

    if (update_device)
        destroy_update_dev(DEV_SPI_NOR0);

    return ret;
}


/*----------------------------------------------------------------------------
    Test Number         :   testcase 6

    Test Purposes       :   copy active slot to inactive slot

    Test Description    :   copy the active slot to the inactive slot
                            and set the partition table attribute to
                            set the inactive slot to active

    Test Command    :       ./ota_self_test emmc2 -t 5
 ----------------------------------------------------------------------------*/
static int unit_test_A_B_copy(int argc, char *argv[])
{
    partition_device_t *ptdev = NULL;
    int slot_active[MAX_PARTITION_NUM] = {0};
    int slot_inactive[MAX_PARTITION_NUM] = {0};
    int active_slot = 0;
    int inactive_slot = 0;
    int len = 0;
    int ret = -1;
    unsigned long long in = 0;
    unsigned long long out = 0;
    unsigned long long size = 0;
    unsigned long long left = 0;
    unsigned long long cnt = 0;
    char *pname = NULL;
    const char *suffix = NULL;
    int index = 0;
    int file_index[MAX_PARTITION_NUM] = {0};
    unsigned char *data = NULL;
    unsigned long long gpt_offset;
    char fname[FILE_NAME_MAX] = {0};
    char *file_base_name = NULL;
    bool update_from_file = false;
    int fd[NUM_PARTITIONS] = {0};
    unsigned i = 0;
    unsigned partition_count;
    struct partition_entry *partition_entries;
    int mode = SYSCALL_AUTO;

    if ((1 == argc) || (!strcmp(argv[1], "emmc"))) {
        ret = switch_storage_dev(&ptdev, DEV_EMMC0);
        mode = SYSCALL_FORCE_LOCAL;
    }
    else if (!strcmp(argv[1], "ospi")) {
        ret = switch_storage_dev(&ptdev, DEV_SPI_NOR0);
        mode = SYSCALL_FORCE_REMOTE;
    }
    else if (!strcmp(argv[1], "emmc1")) {
        ret = switch_storage_dev(&ptdev, DEV_EMMC1);
        mode = SYSCALL_FORCE_REMOTE;
    }
    else if (!strcmp(argv[1], "emmc2")) {
        ret = switch_storage_dev(&ptdev, DEV_EMMC2);
        mode = SYSCALL_FORCE_REMOTE;
    }

    if (0 != ret) {
        UNIT_TEST_PRINTF("failed to setup ptdev\n");
        ret = -1;
        goto end;
    }

    ret = -1;

    if ((argc > 2) && strncmp(argv[2], "-", 1)) {
        UNIT_TEST_PRINTF("useage error\n");
        ret = -1;
        goto end;
    }

    int slot, inactive_slot_l;
    const char *suffix_l;

    ret = get_number_slots(ptdev);
    UNIT_TEST_PRINTF("slots count %d\n", ret);
    slot = get_current_slot(ptdev);
    UNIT_TEST_PRINTF("corrent slot %d\n", slot);

    if (slot == INVALID) {
        UNIT_TEST_PRINTF("bad slot %d\n", slot);
        ret = -1;
        goto end;
    }

    suffix_l = get_suffix(ptdev, slot);
    UNIT_TEST_PRINTF("active slot %s\n", suffix_l);

    inactive_slot_l = get_inverse_slot(ptdev, slot);
    suffix_l = get_suffix(ptdev, inactive_slot_l);
    UNIT_TEST_PRINTF("inactive_slot_l %s\n", suffix_l);

    /* dump current part */
    UNIT_TEST_PRINTF("first bootup dump ptdev\n");
    ptdev_dump(ptdev);
    ptdev_attr_dump(ptdev);

    partition_count = ptdev->count;
    partition_entries = ptdev->partition_entries;
    gpt_offset = ptdev->gpt_offset;

    /* mark bootup successfully if necessary */
    ret = is_slot_marked_successful(ptdev, slot);

    if (ret != 1) {
        if (0 != mark_boot_successful(ptdev)) {
            UNIT_TEST_PRINTF("mark boot successful failed\n");
            ret = -1;
            goto fail;
        }
    }

    /* mark inactive slot as unbootable */
    if (0 != set_slot_as_unbootable(ptdev, inactive_slot_l)) {
        UNIT_TEST_PRINTF("mark inactive slot as unbootable failed\n");
        ret = -1;
        goto fail;
    }

    for (i = 0; i < partition_count; i++) {
        if (!strcmp((const char *)partition_entries[i].name, "vbmeta_a"))
            continue;

        if (!strcmp((const char *)partition_entries[i].name, "vbmeta_b"))
            continue;

        if (strstr((const char *)partition_entries[i].name, "$"))
            continue;

        fd[i] = partition_dev_open((const char *)partition_entries[i].name, flags,
                                   mode);

        if (fd[i] < 0) {
            UNIT_TEST_PRINTF("failed to open %s\n", partition_entries[i].name);
            ret = -1;
            goto fail;
        }

        partition_dev_dump(fd[i]);
    }

    active_slot = get_current_slot(ptdev);
    suffix = get_suffix(ptdev, active_slot);

    if (partition_count > 2 * MAX_PARTITION_NUM) {
        UNIT_TEST_PRINTF("too many partition\n");
        goto fail;
    }

    for (int i = 0; i < MAX_PARTITION_NUM; i++) {
        file_index[i] = -1;
    }

    for (int i = 0; i < partition_count; i++) {
        if (fd[i] <= 0)
            continue;

        pname = (char *)partition_entries[i].name;
        len = strlen(pname);

        if (len < 4)
            continue; /* too few, ignore */

        if (strcmp((char *)(pname + len - 2), suffix_slot[0])
                && strcmp((char *)(pname + len - 2), suffix_slot[1])) {
            continue;
        }

        for (int j = i + 1; j < partition_count; j++) {
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

                for (int k = 0; k < file_cnt; k++) {
                    if (!strlen(file_name[k]) || (strlen(file_name[k]) >= FILE_NAME_MAX)) {
                        UNIT_TEST_PRINTF("file_name[%d] = %s length error\n", k, file_name[k]);
                        continue;
                    }

                    memset(fname, 0, FILE_NAME_MAX);
                    file_base_name = NULL;
                    strncpy(fname, file_name[k], MIN(strlen(file_name[k]), FILE_NAME_MAX - 1));
                    file_base_name = basename(fname);

                    if ((strlen(file_base_name) < (len - 2))
                            || ((strlen(file_base_name) > (len - 2)) &&  file_base_name[len - 2] != '.'))
                        continue;

                    if (!strncmp(file_base_name, pname, len - 2)) {
                        file_index[k] = index;
                        UNIT_TEST_PRINTF("basename = %s\n", file_base_name);
                        UNIT_TEST_PRINTF("find file input num %d, A/B partition index=%d, file name = %s\n",
                                         k, index, fname);
                    }
                }

                index++;
            }
        }
    }

    for (int i = 0; i < index; i++) {
        active_slot = slot_active[i];
        inactive_slot = slot_inactive[i];
        in = (partition_entries[active_slot].first_lba) * LBA_SIZE;
        out = (partition_entries[inactive_slot].first_lba) * LBA_SIZE;
        size = (partition_entries[active_slot].last_lba -
                partition_entries[active_slot].first_lba + 1) * LBA_SIZE;

        in += gpt_offset;
        out += gpt_offset;

        update_from_file = false;

        UNIT_TEST_PRINTF("i=%d\n", i);
        UNIT_TEST_PRINTF("active_slot=%s\n", partition_entries[active_slot].name);
        UNIT_TEST_PRINTF("inactive_slot=%s\n", partition_entries[inactive_slot].name);
        UNIT_TEST_PRINTF("in=%p out=%p size=%lld\n", (void *)in, (void *)out, size);

        for (int k = 0; k < file_cnt; k++) {
            if (file_index[k] == i) {
                UNIT_TEST_PRINTF("update from file %s\n", file_name[k]);
                ret = write_file_to_partition(file_name[k], fd[inactive_slot], size,
                                              NOT_WRITE_TEST);

                if (ret < 0) {
                    UNIT_TEST_PRINTF("write_file failed\n");
                    ret = -1;
                    goto fail;
                }

                update_from_file = true;
                break;
            }
        }

        if (update_from_file != true) {
            cnt =  (size / MAX_CALLOC_SIZE);
            left = (size % MAX_CALLOC_SIZE);
            data = (unsigned char *)MEM_ALIGN(512, (cnt != 0 ? (MAX_CALLOC_SIZE) : size));

            if (!data) {
                UNIT_TEST_PRINTF("OTA_programming calloc failed\n");
                return -1;
            }

            /* active slot seek 0 */
            if (0 != partition_dev_seek(fd[active_slot], 0, SEEK_SET)) {
                UNIT_TEST_PRINTF("partition_dev_seek fd[%d] failed\n", active_slot);
                ret = -1;
                goto fail;
            }

            /* inactive slot seek 0 */
            if (0 != partition_dev_seek(fd[inactive_slot], 0, SEEK_SET)) {
                UNIT_TEST_PRINTF("partition_dev_seek fd[%d] failed\n", inactive_slot);
                ret = -1;
                goto fail;
            }

            /* copy active slot to inactive slot*/
            for (unsigned long long n = 0; n < cnt; n++) {
                ret = partition_dev_read(fd[active_slot], data, MAX_CALLOC_SIZE);

                if (ret < 0) {
                    UNIT_TEST_PRINTF("unit_read_write_test partition_dev_read fd[%d] failed\n",
                                     fd[inactive_slot]);
                    ret = -1;
                    goto fail;
                }

                ret = partition_dev_write(fd[inactive_slot], data, MAX_CALLOC_SIZE);

                if (ret < 0) {
                    UNIT_TEST_PRINTF("unit_read_write_test partition_dev_read fd[%d] failed\n",
                                     fd[inactive_slot]);
                    ret = -1;
                    goto fail;
                }
            }

            if (0 != left) {
                ret = partition_dev_read(fd[active_slot], data, left);

                if (ret < 0) {
                    UNIT_TEST_PRINTF("unit_read_write_test partition_dev_read fd[%d] failed\n",
                                     fd[inactive_slot]);
                    ret = -1;
                    goto fail;
                }

                ret = partition_dev_write(fd[inactive_slot], data, left);

                if (ret < 0) {
                    UNIT_TEST_PRINTF("unit_read_write_test partition_dev_read fd[%d] failed\n",
                                     fd[inactive_slot]);
                    ret = -1;
                    goto fail;
                }

            }

            FREE(data);
            data = NULL;
        }
    }

    /* mark inactive slot as active and bootable */
    if (set_active_boot_slot(ptdev, inactive_slot_l)) {
        UNIT_TEST_PRINTF("mark inactive slot as active and bootable failed");
        ret = -1;
        goto fail;
    }

    ret = 0;
    ptdev_dump(ptdev);
    ptdev_attr_dump(ptdev);
    UNIT_TEST_PRINTF("OTA finish, try reboot to take effect \n");

fail:

    for (i = 0; i < partition_count; i++) {
        if (fd[i] <= 0)
            continue;

        partition_dev_close(fd[i]);
    }

end:

    if (data) {
        FREE(data);
    }

    if (ptdev)
        free_storage_dev(ptdev);

    return ret;
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 7a

    Test Purposes       :   set properties for all partitions
                            A is acitve

    Test Description    :   Simulate the operation of all partition attributes
                            in the bootctrl interface, set all A partitions to
                            active, and B partitions to inactive

    Test Command    :       ./ota_self_test xxx -t 6 -s a
 ----------------------------------------------------------------------------*/
static int unit_test_boot_control_all_a(int argc, char *argv[])
{
    int ret = -1;
    int value = -1;
    const char *suffix = NULL;

    value = boot_control_init_all();

    if (value != 0) {
        goto end;
    }

    value = get_number_slots_all();
    UNIT_TEST_PRINTF("get_number_slots_all = %d\n", value);

    if ((value != 1) && (value != 2)) {
        goto end;
    }

    value = set_active_boot_slot_all(SLOT_A);
    UNIT_TEST_PRINTF("set_active_boot_slot_all = %d\n", value);

    if (value != 0) {
        goto end;
    }

    value = is_slot_bootable_all(SLOT_A);
    UNIT_TEST_PRINTF("SLOT_A bootable = %d\n", value);

    if (value != 1) {
        UNIT_TEST_PRINTF("expect SLOT_A bootable = 1\n");
        goto end;
    }

    value = set_slot_as_unbootable_all(SLOT_B);
    UNIT_TEST_PRINTF("set_active_boot_slot_all = %d\n", value);

    if (value != 0) {
        goto end;
    }

    value = is_slot_bootable_all(SLOT_B);
    UNIT_TEST_PRINTF("SLOT_B bootable = %d\n", value);

    if (value != 0) {
        UNIT_TEST_PRINTF("expect SLOT_B bootable = 0\n");
        goto end;
    }

    suffix = get_suffix_all(SLOT_A);
    UNIT_TEST_PRINTF("SLOT_A suffix = %s\n", suffix);
    suffix = get_suffix_all(SLOT_B);
    UNIT_TEST_PRINTF("SLOT_B suffix = %s\n", suffix);


    value = get_current_slot_all();
    UNIT_TEST_PRINTF("get_current_slot_all = %s\n", get_suffix_all(value));

    value = mark_boot_successful_all();
    UNIT_TEST_PRINTF("mark ACTIVE successful = %d\n", value);

    if (value != 0) {
        goto end;
    }

    value = is_slot_marked_successful_all(SLOT_A);
    UNIT_TEST_PRINTF("SLOT_A successful = %d\n", value);

    if (value != 1) {
        UNIT_TEST_PRINTF("expect SLOT_A successful = 1\n");
        goto end;
    }

    value = is_slot_marked_successful_all(SLOT_B);
    UNIT_TEST_PRINTF("SLOT_B successful = %d\n", value);

    if (value != 0) {
        UNIT_TEST_PRINTF("expect SLOT_B successful = 0\n");
        goto end;
    }

    value = check_partition_local_or_remote("/dev/block/vendor", 0);

    if (value == STORAGE_LOCAL) {
        UNIT_TEST_PRINTF("%s is storage local\n", argv[1]);
        ret = 0;
        goto end;
    }

    if (value == STORAGE_REMOTE) {
        UNIT_TEST_PRINTF("%s is storage remote\n", argv[1]);
        ret = 0;
        goto end;
    }

    UNIT_TEST_PRINTF("%s error\n", argv[1]);


end:
    //ptdev_dump_all();
    return ret;
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 7b

    Test Purposes       :   set properties for all partitions
                            B is acitve

    Test Description    :   Simulate the operation of all partition attributes
                            in the bootctrl interface, set all B partitions to
                            active, and A partitions to inactive

    Test Command    :       ./ota_self_test xxx -t 6 -s b
 ----------------------------------------------------------------------------*/
static int unit_test_boot_control_all_b(int argc, char *argv[])
{
    int ret = -1;
    int value = -1;
    const char *suffix = NULL;

    value = boot_control_init_all();

    if (value != 0) {
        goto end;
    }

    value = get_number_slots_all();
    UNIT_TEST_PRINTF("get_number_slots_all = %d\n", value);

    if ((value != 1) && (value != 2)) {
        goto end;
    }

    value = set_active_boot_slot_all(SLOT_B);
    UNIT_TEST_PRINTF("set_active_boot_slot_all = %d\n", value);

    if (value != 0) {
        goto end;
    }

    value = is_slot_bootable_all(SLOT_B);
    UNIT_TEST_PRINTF("SLOT_B bootable = %d\n", value);

    if (value != 1) {
        UNIT_TEST_PRINTF("expect SLOT_B bootable = 1\n");
        goto end;
    }

    value = set_slot_as_unbootable_all(SLOT_A);
    UNIT_TEST_PRINTF("set_active_boot_slot_all = %d\n", value);

    if (value != 0) {
        goto end;
    }

    value = is_slot_bootable_all(SLOT_A);
    UNIT_TEST_PRINTF("SLOT_A bootable = %d\n", value);

    if (value != 0) {
        UNIT_TEST_PRINTF("expect SLOT_A bootable = 0\n");
        goto end;
    }

    suffix = get_suffix_all(SLOT_A);
    UNIT_TEST_PRINTF("SLOT_A suffix = %s\n", suffix);
    suffix = get_suffix_all(SLOT_B);
    UNIT_TEST_PRINTF("SLOT_B suffix = %s\n", suffix);


    value = get_current_slot_all();
    UNIT_TEST_PRINTF("get_current_slot_all = %s\n", get_suffix_all(value));

    value = mark_boot_successful_all();
    UNIT_TEST_PRINTF("mark ACTIVE successful = %d\n", value);

    if (value != 0) {
        goto end;
    }

    value = is_slot_marked_successful_all(SLOT_B);
    UNIT_TEST_PRINTF("SLOT_B successful = %d\n", value);

    if (value != 1) {
        UNIT_TEST_PRINTF("expect SLOT_B successful = 1\n");
        goto end;
    }

    value = is_slot_marked_successful_all(SLOT_A);
    UNIT_TEST_PRINTF("SLOT_A successful = %d\n", value);

    if (value != 0) {
        UNIT_TEST_PRINTF("expect SLOT_A successful = 0\n");
        goto end;
    }

    value = check_partition_local_or_remote("/dev/block/vendor", 0);

    if (value == STORAGE_LOCAL) {
        UNIT_TEST_PRINTF("%s is storage local\n", argv[1]);
        ret = 0;
        goto end;
    }

    if (value == STORAGE_REMOTE) {
        UNIT_TEST_PRINTF("%s is storage remote\n", argv[1]);
        ret = 0;
        goto end;
    }

    UNIT_TEST_PRINTF("%s error\n", argv[1]);


end:
    //ptdev_dump_all();
    return ret;
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 8

    Test Purposes       :   memory leak test

    Test Description    :   1. set macro MEM_TEST_MODE to 1
                            2. Run the test case and observe the print

    Test Command    :       ./ota_self_test xxx -t 7
 ----------------------------------------------------------------------------*/
static int unit_test_mem_test(int argc, char *argv[])
{
    partition_device_t *ptdev = NULL;
    int slot_active[MAX_PARTITION_NUM] = {0};
    int slot_inactive[MAX_PARTITION_NUM] = {0};
    int active_slot = 0;
    int inactive_slot = 0;
    int len = 0;
    int ret = -1;
    unsigned long long in = 0;
    unsigned long long out = 0;
    char *pname = NULL;
    const char *suffix = NULL;
    int index = 0;
    unsigned long long gpt_offset;
    char fname[FILE_NAME_MAX] = {0};
    char *file_base_name = NULL;
    int fd[NUM_PARTITIONS] = {0};
    unsigned i = 0;
    unsigned partition_count;
    struct partition_entry *partition_entries;
    int mode = SYSCALL_AUTO;

    int testcnt = 10;

    while (testcnt--) {

        if ((1 == argc) || (!strcmp(argv[1], "emmc"))) {
            ret = switch_storage_dev(&ptdev, DEV_EMMC0);
            mode = SYSCALL_FORCE_LOCAL;
        }
        else if (!strcmp(argv[1], "ospi")) {
            ret = switch_storage_dev(&ptdev, DEV_SPI_NOR0);
            mode = SYSCALL_FORCE_REMOTE;
        }
        else if (!strcmp(argv[1], "emmc1")) {
            ret = switch_storage_dev(&ptdev, DEV_EMMC1);
            mode = SYSCALL_FORCE_REMOTE;
        }
        else if (!strcmp(argv[1], "emmc2")) {
            ret = switch_storage_dev(&ptdev, DEV_EMMC2);
            mode = SYSCALL_FORCE_REMOTE;
        }

        if (0 != ret) {
            UNIT_TEST_PRINTF("failed to setup ptdev\n");
            ret = -1;
            goto end;
        }

        ret = -1;

        if ((argc > 2) && strncmp(argv[2], "-", 1)) {
            UNIT_TEST_PRINTF("useage error\n");
            ret = -1;
            goto end;
        }

        int slot, inactive_slot_l;
        const char *suffix_l;

        /* All slots are zeroed, mark SLOT 0, active & bootable */
        ret = get_number_slots(ptdev);
        UNIT_TEST_PRINTF("slots count %d\n", ret);
        slot = get_current_slot(ptdev);
        UNIT_TEST_PRINTF("corrent slot %d\n", slot);

        if (slot == INVALID) {
            UNIT_TEST_PRINTF("bad slot %d\n", slot);
            ret = -1;
            goto end;
        }

        suffix_l = get_suffix(ptdev, slot);
        UNIT_TEST_PRINTF("active slot %s\n", suffix_l);

        inactive_slot_l = get_inverse_slot(ptdev, slot);
        suffix_l = get_suffix(ptdev, inactive_slot_l);
        UNIT_TEST_PRINTF("inactive_slot_l %s\n", suffix_l);

        /* dump current part */
        UNIT_TEST_PRINTF("first bootup dump ptdev.\n");
        ptdev_dump(ptdev);
        ptdev_attr_dump(ptdev);

        partition_count = ptdev->count;
        partition_entries = ptdev->partition_entries;
        gpt_offset = ptdev->gpt_offset;

        for (i = 0; i < partition_count; i++) {
            /*
                if(!strcmp((const char *)partition_entries[i].name, "vbmeta_a"))
                    continue;

                if(!strcmp((const char *)partition_entries[i].name, "vbmeta_b"))
                    continue;
            */

            assert(ptdev->storage->get_partition_index);
            fd[i] = partition_dev_open((const char *)partition_entries[i].name, flags,
                                       mode);

            if (fd[i] < 0) {
                UNIT_TEST_PRINTF("failed to open %s\n", partition_entries[i].name);
                ret = -1;
                goto fail;
            }
        }

        active_slot = get_current_slot(ptdev);
        suffix = get_suffix(ptdev, active_slot);

        if (partition_count > 2 * MAX_PARTITION_NUM) {
            UNIT_TEST_PRINTF("too many partition\n");
            goto fail;
        }

        for (int i = 0; i < partition_count; i++) {
            /*
                if(!strcmp((const char *)partition_entries[i].name, "vbmeta_a"))
                    continue;

                if(!strcmp((const char *)partition_entries[i].name, "vbmeta_b"))
                    continue;
            */

            pname = (char *)partition_entries[i].name;
            len = strlen(pname);

            if (len < 4)
                continue; /* too few, ignore */

            if (strcmp((char *)(pname + len - 2), suffix_slot[0])
                    && strcmp((char *)(pname + len - 2), suffix_slot[1])) {
                continue;
            }

            for (int j = i + 1; j < partition_count; j++) {
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

                    for (int k = 0; k < file_cnt; k++) {
                        if (!strlen(file_name[k]) || (strlen(file_name[k]) >= FILE_NAME_MAX)) {
                            UNIT_TEST_PRINTF("file_name[%d] = %s length error\n", k, file_name[k]);
                            continue;
                        }

                        memset(fname, 0, FILE_NAME_MAX);
                        file_base_name = NULL;
                        strncpy(fname, file_name[k], MIN(strlen(file_name[k]), FILE_NAME_MAX - 1));
                        file_base_name = basename(fname);

                        if ((strlen(file_base_name) < (len - 2))
                                || ((strlen(file_base_name) > (len - 2)) &&  file_base_name[len - 2] != '.'))
                            continue;

                        if (!strncmp(file_base_name, pname, len - 2)) {
                            UNIT_TEST_PRINTF("basename = %s\n", file_base_name);
                            UNIT_TEST_PRINTF("find file input num %d, A/B partition index=%d, file name = %s\n",
                                             k, index, fname);
                        }
                    }

                    index++;
                }
            }
        }

        for (int i = 0; i < index; i++) {
            active_slot = slot_active[i];
            inactive_slot = slot_inactive[i];
            in = (partition_entries[active_slot].first_lba) * LBA_SIZE;
            out = (partition_entries[inactive_slot].first_lba) * LBA_SIZE;
            in += gpt_offset;
            out += gpt_offset;
        }

        ret = 0;
        ptdev_dump(ptdev);
        ptdev_attr_dump(ptdev);

        UNIT_TEST_PRINTF("vendor in %d\n",
                         check_partition_local_or_remote("/dev/block/vendor", 0));
        UNIT_TEST_PRINTF("dil in %d\n",
                         check_partition_local_or_remote("/dev/block/dil", 0));
        UNIT_TEST_PRINTF("vbmeta in %d\n",
                         check_partition_local_or_remote("/dev/block/vbmeta", 0));

fail:

        for (i = 0; i < partition_count; i++) {
            if (fd[i] <= 0)
                continue;

            partition_dev_close(fd[i]);
        }

end:

        if (ptdev)
            free_storage_dev(ptdev);
    }

#if MEM_TEST_MODE
    extern int malloc_cnt;
    UNIT_TEST_PRINTF("malloc_cnt = %d\n", malloc_cnt);
#endif

    return ret;
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 9

    Test Purposes       :   emmc/flash erase test

    Test Description    :   After erasing, read back the data to judge whether
                            the erasure is correct. Note that this test cannot
                            be performed on the emmc update device of AP1,
                            because the data of eMMC after discard is uncertain.
                            Here only test the use of remote update device
                            Both "BLKDISCARD" and "BLKZEROOUT" commands are covered
                            by this test.

    Test Command    :       ./ota_self_test emmc2 -t 8
 ----------------------------------------------------------------------------*/
static int unit_test_mem_erase(int argc, char *argv[])
{
#if 0
    partition_device_t *ptdev = NULL;
    int slot_active[MAX_PARTITION_NUM] = {0};
    int slot_inactive[MAX_PARTITION_NUM] = {0};
    int active_slot = 0;
    int inactive_slot = 0;
    int len = 0;
    int ret = -1;
    unsigned long long file_off = 0;
    unsigned long long in = 0;
    unsigned long long out = 0;
    unsigned long long size = 0;
    unsigned long long left = 0;
    unsigned long long cnt = 0;
    char *pname = NULL;
    const char *suffix = NULL;
    int index = 0;
    int file_index[MAX_PARTITION_NUM] = {0};
    unsigned char *data = NULL;;
    unsigned char *data2 = NULL;;
    storage_device_t *storage;
    unsigned long long gpt_offset;
    char fname[FILE_NAME_MAX] = {0};
    char *file_base_name = NULL;
    bool update_from_file = false;
    int fd[NUM_PARTITIONS] = {0};
    unsigned i = 0;
    unsigned partition_count;
    struct partition_entry *partition_entries;
    int mode = SYSCALL_AUTO;
    int request = BLKDISCARD;
    uint8_t discard_default = 0;

    if ((1 == argc) || (!strcmp(argv[1], "emmc1"))) {
        ret = switch_storage_dev(&ptdev, DEV_EMMC1);
        mode = SYSCALL_FORCE_REMOTE;
        discard_default = 0;
    }

    if (!strcmp(argv[1], "emmc2")) {
        ret = switch_storage_dev(&ptdev, DEV_EMMC2);
        mode = SYSCALL_FORCE_REMOTE;
        discard_default = 0;
    }
    else if (!strcmp(argv[1], "ospi")) {
        ret = switch_storage_dev(&ptdev, DEV_SPI_NOR0);
        mode = SYSCALL_FORCE_REMOTE;
        discard_default = 0xFF;
    }

    if (0 != ret) {
        UNIT_TEST_PRINTF("failed to setup ptdev\n");
        ret = -1;
        goto end;
    }

    ret = -1;

    if ((argc > 2) && strncmp(argv[2], "-", 1)) {
        UNIT_TEST_PRINTF("useage error\n");
        ret = -1;
        goto end;
    }

    ptdev_dump(ptdev);
    ptdev_attr_dump(ptdev);
    partition_count = ptdev->count;
    partition_entries = ptdev->partition_entries;
    storage = ptdev->storage;
    gpt_offset = ptdev->gpt_offset;

    for (i = 0; i < partition_count; i++) {
        if (!strcmp((const char *)partition_entries[i].name, "vbmeta_a"))
            continue;

        if (!strcmp((const char *)partition_entries[i].name, "vbmeta_b"))
            continue;

        if (strstr((const char *)partition_entries[i].name, "$"))
            continue;

        fd[i] = partition_dev_open((const char *)partition_entries[i].name, flags,
                                   mode);

        if (fd[i] < 0) {
            UNIT_TEST_PRINTF("failed to open %s\n", partition_entries[i].name);
            ret = -1;
            goto fail;
        }
    }

    active_slot = get_current_slot(ptdev);
    suffix = get_suffix(ptdev, active_slot);

    if (partition_count > 2 * MAX_PARTITION_NUM) {
        UNIT_TEST_PRINTF("too many partition\n");
        goto fail;
    }

    for (int i = 0; i < MAX_PARTITION_NUM; i++) {
        file_index[i] = -1;
    }

    for (int i = 0; i < partition_count; i++) {
        if (fd[i] <= 0)
            continue;

        pname = (char *)partition_entries[i].name;
        len = strlen(pname);

        if (len < 4)
            continue; /* too few, ignore */

        if (strcmp((char *)(pname + len - 2), suffix_slot[0])
                && strcmp((char *)(pname + len - 2), suffix_slot[1])) {
            continue;
        }

        for (int j = i + 1; j < partition_count; j++) {
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

                for (int k = 0; k < file_cnt; k++) {
                    if (!strlen(file_name[k]) || (strlen(file_name[k]) >= FILE_NAME_MAX)) {
                        UNIT_TEST_PRINTF("file_name[%d] = %s length error\n", k, file_name[k]);
                        continue;
                    }

                    memset(fname, 0, FILE_NAME_MAX);
                    file_base_name = NULL;
                    strncpy(fname, file_name[k], strlen(file_name[k]));
                    file_base_name = basename(fname);

                    if ((strlen(file_base_name) < (len - 2))
                            || ((strlen(file_base_name) > (len - 2)) &&  file_base_name[len - 2] != '.'))
                        continue;

                    if (!strncmp(file_base_name, pname, len - 2)) {
                        file_index[k] = index;
                        UNIT_TEST_PRINTF("basename = %s\n", file_base_name);
                        UNIT_TEST_PRINTF("find file input num %d, A/B partition index=%d, file name = %s\n",
                                         k, index, fname);
                    }
                }

                index++;
            }
        }
    }

    for (int i = 0; i < index; i++) {
        active_slot = slot_active[i];
        inactive_slot = slot_inactive[i];
        in = (partition_entries[active_slot].first_lba) * LBA_SIZE;
        out = (partition_entries[inactive_slot].first_lba) * LBA_SIZE;
        size = (partition_entries[active_slot].last_lba -
                partition_entries[active_slot].first_lba + 1) * LBA_SIZE;

        in += gpt_offset;
        out += gpt_offset;

        update_from_file = false;
        UNIT_TEST_PRINTF("i=%d\n", i);
        UNIT_TEST_PRINTF("active_slot=%s\n", partition_entries[active_slot].name);
        UNIT_TEST_PRINTF("inactive_slot=%s\n", partition_entries[inactive_slot].name);
        UNIT_TEST_PRINTF("in=%p out=%p size=%lld\n", (void *)in, (void *)out, size);

        cnt =  (size / MAX_CALLOC_SIZE);
        left = (size % MAX_CALLOC_SIZE);
        data = (unsigned char *)MEM_ALIGN(512, (cnt != 0 ? (MAX_CALLOC_SIZE) : size));
        data2 = (unsigned char *)MEM_ALIGN(512, (cnt != 0 ? (MAX_CALLOC_SIZE) : size));

        if (!data || !data2) {
            UNIT_TEST_PRINTF("unit_read_write_test calloc failed\n");
            ret = -1;
            goto fail;
        }

        if (0 != partition_dev_seek(fd[inactive_slot], 0, SEEK_SET)) {
            UNIT_TEST_PRINTF("partition_dev_seek fd[%d] failed\n", inactive_slot);
            ret = -1;
            goto fail;
        }

        int error = 0;

        for (unsigned long long n = 0; n < cnt; n++) {
            memset(data,  (uint8_t)((n + 1) & 0xFF), MAX_CALLOC_SIZE);
            ret = partition_dev_write(fd[inactive_slot], data, MAX_CALLOC_SIZE);

            if (ret < 0) {
                UNIT_TEST_PRINTF("partition_dev_write fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto fail;
            }

            if (partition_dev_seek(fd[inactive_slot], MAX_CALLOC_SIZE * (-1),
                                   SEEK_CUR) < 0) {
                UNIT_TEST_PRINTF("partition_dev_seek fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto fail;
            }

            ret = partition_dev_read(fd[inactive_slot], data2, MAX_CALLOC_SIZE);

            if (ret < 0) {
                UNIT_TEST_PRINTF("partition_dev_read fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto fail;
            }

            if (memcmp(data, data2, MAX_CALLOC_SIZE)) {
                UNIT_TEST_PRINTF("memcmp fd[%d] failed\n", fd[inactive_slot]);
                UNIT_TEST_PRINTF("data as:\n");
                hexdump8((uint8_t *)data, MAX_CALLOC_SIZE > 4096 ? 4096 : MAX_CALLOC_SIZE);
                UNIT_TEST_PRINTF("data2 as:\n");
                hexdump8((uint8_t *)data2, MAX_CALLOC_SIZE > 4096 ? 4096 : MAX_CALLOC_SIZE);
                ret = -1;
                goto fail;
            }

            if ((n & 0x1) == 0) {
                if (discard_default) {
                    memset(data, 0xFF, MAX_CALLOC_SIZE);
                }
                else {
                    memset(data, 0, MAX_CALLOC_SIZE);
                }

                request = BLKDISCARD;
            }
            else {
                memset(data, 0, MAX_CALLOC_SIZE);
                request = BLKZEROOUT;
            }

            if (partition_dev_seek(fd[inactive_slot], MAX_CALLOC_SIZE * (-1),
                                   SEEK_CUR) < 0) {
                UNIT_TEST_PRINTF("partition_dev_seek fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto end;
            }

            partition_dev_blkioctl(fd[inactive_slot], request, n * MAX_CALLOC_SIZE,
                                   MAX_CALLOC_SIZE, &error);

            if (error < 0) {
                UNIT_TEST_PRINTF("partition dev blkioctl fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto fail;
            }

            ret = partition_dev_read(fd[inactive_slot], data2, MAX_CALLOC_SIZE);

            if (ret < 0) {
                UNIT_TEST_PRINTF("partition_dev_read fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto fail;
            }

            if (memcmp(data, data2, MAX_CALLOC_SIZE)) {
                UNIT_TEST_PRINTF("memcmp fd[%d] failed\n", fd[inactive_slot]);
                UNIT_TEST_PRINTF("data as:\n");
                hexdump8((uint8_t *)data, MAX_CALLOC_SIZE > 4096 ? 4096 : MAX_CALLOC_SIZE);
                UNIT_TEST_PRINTF("data2 as:\n");
                hexdump8((uint8_t *)data2, MAX_CALLOC_SIZE > 4096 ? 4096 : MAX_CALLOC_SIZE);
                ret = -1;
                goto fail;
            }

            in  += MAX_CALLOC_SIZE;
            out += MAX_CALLOC_SIZE;
            file_off += MAX_CALLOC_SIZE;
        }

        if (0 != left) {
            memset(data,  (uint8_t)(cnt & 0xFF), left);
            ret = partition_dev_write(fd[inactive_slot], data, left);

            if (ret < 0) {
                UNIT_TEST_PRINTF("partition_dev_read fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto fail;
            }

            if (partition_dev_seek(fd[inactive_slot], left * (-1), SEEK_CUR) < 0) {
                UNIT_TEST_PRINTF("partition_dev_seek fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto fail;
            }

            ret = partition_dev_read(fd[inactive_slot], data2, left);

            if (ret < 0) {
                UNIT_TEST_PRINTF("partition_dev_read fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto fail;
            }

            if (memcmp(data, data2, left)) {
                UNIT_TEST_PRINTF("memcmp fd[%d] failed\n", fd[inactive_slot]);
                UNIT_TEST_PRINTF("data as:\n");
                hexdump8((uint8_t *)data, left > 4096 ? 4096 : left);
                UNIT_TEST_PRINTF("data2 as:\n");
                hexdump8((uint8_t *)data2, left > 4096 ? 4096 : left);
                ret = -1;
                goto fail;
            }

            if ((left & 0x1) == 0) {
                if (discard_default) {
                    memset(data, 0xFF, MAX_CALLOC_SIZE);
                }
                else {
                    memset(data, 0, MAX_CALLOC_SIZE);
                }

                request = BLKDISCARD;
            }
            else {
                memset(data, 0, MAX_CALLOC_SIZE);
                request = BLKZEROOUT;
            }

            partition_dev_blkioctl(fd[inactive_slot], request, cnt * MAX_CALLOC_SIZE, left,
                                   &error);

            if (error < 0) {
                UNIT_TEST_PRINTF("partition_dev_blkioctl fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto fail;
            }

            if (partition_dev_seek(fd[inactive_slot], left * (-1), SEEK_CUR) < 0) {
                UNIT_TEST_PRINTF("partition_dev_seek fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto end;
            }

            ret = partition_dev_read(fd[inactive_slot], data2, left);

            if (ret < 0) {
                UNIT_TEST_PRINTF("partition_dev_read fd[%d] failed\n", fd[inactive_slot]);
                ret = -1;
                goto fail;
            }

            if (memcmp(data, data2, left)) {
                UNIT_TEST_PRINTF("memcmp fd[%d] failed\n", fd[inactive_slot]);
                UNIT_TEST_PRINTF("data as:\n");
                hexdump8((uint8_t *)data, left > 4096 ? 4096 : left);
                UNIT_TEST_PRINTF("data2 as:\n");
                hexdump8((uint8_t *)data2, left > 4096 ? 4096 : left);
                ret = -1;
                goto fail;
            }
        }

        FREE(data);
        FREE(data2);
        data = NULL;
        data2 = NULL;
    }

    ret = 0;


fail:

    for (i = 0; i < partition_count; i++) {
        if (fd[i] <= 0)
            continue;

        partition_dev_close(fd[i]);
    }

end:

    if (data)
        FREE(data);

    if (data2)
        FREE(data2);

    if (ptdev)
        free_storage_dev(ptdev);

    return ret;
#else
    return 0;
#endif
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 10

    Test Purposes       :   test check_partition_local_or_remote interface

    Test Description    :   This interface can determine whether a partition
                            name belongs to a local partition table or a remote
                            partition table. The upper layer application can
                            judge whether to call the system call interface
                            provided by this library according to the return
                            value of this interface. Note that the first parameter
                            of the test can be filled in with the name of the partition
                            to be checked

    Test Command    :       ./ota_self_test [partition_name] -t 9
                            for example : ./ota_self_test dil2_a -t 9
 ----------------------------------------------------------------------------*/
static int unit_test_check_partition(int argc, char *argv[])
{

    UNIT_TEST_PRINTF("vendor in %d\n",
                     check_partition_local_or_remote("/dev/block/vendor", 0));
    UNIT_TEST_PRINTF("dil in %d\n",
                     check_partition_local_or_remote("/dev/block/dil", 0));
    UNIT_TEST_PRINTF("vbmeta in %d\n",
                     check_partition_local_or_remote("/dev/block/vbmeta", 0));
    UNIT_TEST_PRINTF("ddr_fw_b in %d\n",
                     check_partition_local_or_remote("/dev/block/ddr_fw_b", 0));
    UNIT_TEST_PRINTF("ap2$cluster_preloader_b in %d\n",
                     check_partition_local_or_remote("/dev/block/ap2$cluster_preloader_b", 0));
    UNIT_TEST_PRINTF("cluster_preloader_b in %d\n",
                     check_partition_local_or_remote("/dev/block/cluster_preloader_b", 0));
    UNIT_TEST_PRINTF("%s in %d\n", argv[1], check_partition_local_or_remote(argv[1],
                     0));



    return 0;
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 11

    Test Purposes       :   test remote storage's ptdev interface

    Test Description    :   The main purpose is to verify the partition
                            table-related operations in the storage interface.
                            These partition table operations are remotely
                            operated partition tables in safety os or ssystem

    Test Command    :       ./ota_self_test emmc2 -t 10
 ----------------------------------------------------------------------------*/
static int unit_remote_emmc_ptdev_test(int argc, char *argv[])
{
    int ret = -1;
    storage_device_t *storage = NULL;
    update_device_t  *update_device = NULL;
    int test_dev = DEV_EMMC2;
    char test_partition_name[MAX_GPT_NAME_SIZE] = {0};
    int active_attr[2];
    int unbootable_attr[2];
    int successful_attr[2];
    int retry_cnt[2];
    int attr_list[ATTR_NUM] = {ATTR_ACTIVE, ATTR_UNBOOTABLE, ATTR_SUCCESSFUL, ATTR_RETRY};
    char *attr_list_char[ATTR_NUM] = {"ATTR_ACTIVE", "ATTR_UNBOOTABLE", "ATTR_SUCCESSFUL", "ATTR_RETRY"};
    int *attr_res_temp[ATTR_NUM] = {active_attr, unbootable_attr, successful_attr, retry_cnt};
    int attr = ATTR_ACTIVE;
    int temp;

    if ((1 == argc) || (!strcmp(argv[1], "emmc1"))) {
        test_dev = DEV_EMMC1;
        snprintf(test_partition_name, MAX_GPT_NAME_SIZE, "%s", "vbmeta_top_a");
    }

    if (!strcmp(argv[1], "emmc2")) {
        test_dev = DEV_EMMC2;
        snprintf(test_partition_name, MAX_GPT_NAME_SIZE, "%s", "cluster_kernel_a");
    }
    else if (!strcmp(argv[1], "ospi")) {
        test_dev = DEV_SPI_NOR0;
        snprintf(test_partition_name, MAX_GPT_NAME_SIZE, "%s", "safety_os_a");
    }

    update_device = setup_update_dev(test_dev);

    if (!update_device || !(update_device->storage)) {
        UNIT_TEST_PRINTF("failed to setup storage dev\n");
        goto end;
    }

    storage = get_update_device_storage(test_dev);

    if (storage->setup_ptdev(storage, update_device->name)) {
        UNIT_TEST_PRINTF("failed to storage->setup_ptdev\n");
        ret = -1;
        goto end;
    }

    int index = storage->get_partition_index(storage, update_device->name,
                test_partition_name);

    if (index == -1) {
        UNIT_TEST_PRINTF("failed to remote_get_partition_index\n");
        ret = -1;
        goto end;
    }

    UNIT_TEST_PRINTF("index = %d\n", index);

    uint64_t size = storage->get_partition_size(storage, update_device->name,
                    test_partition_name);

    if (!size) {
        UNIT_TEST_PRINTF("failed to remote_get_partition_size\n");
        goto end;
    }

    UNIT_TEST_PRINTF("size = 0x%llx\n", (unsigned long long)size);

    uint64_t offset = storage->get_partition_offset(storage, update_device->name,
                      test_partition_name);

    if (!offset) {
        UNIT_TEST_PRINTF("failed to remote_get_partition_offset\n");
        goto end;
    }

    UNIT_TEST_PRINTF("offset = 0x%llx\n", (unsigned long long)offset);

    int slot_number;
    slot_number = storage->get_slot_number(storage, update_device->name);

    if (slot_number != 2) {
        UNIT_TEST_PRINTF("failed to get_slot_number\n");
        goto end;
    }

    UNIT_TEST_PRINTF("slot_number = %x\n", slot_number);

    int current_slot;
    current_slot = storage->get_current_slot(storage, update_device->name);

    if ((current_slot != 0) && (current_slot != 1)) {
        UNIT_TEST_PRINTF("failed to remote_get_current_slot, current_slot %d\n",
                         current_slot);
        goto end;
    }

    UNIT_TEST_PRINTF("current_slot = %s\n", SUFFIX_SLOT(current_slot));

    for (int i = 0; i < 2; i ++) {
        attr = ATTR_ACTIVE;
        active_attr[i] = storage->get_slot_attr(storage, update_device->name, i, attr);

        if ((0 != active_attr[i]) && (1 != active_attr[i])) {
            UNIT_TEST_PRINTF("get_slot_attr, attr = %d, value = %d\n", attr,
                             active_attr[i]);
            goto end;
        }

        UNIT_TEST_PRINTF("active_attr slot %s = %d\n", SUFFIX_SLOT(i), active_attr[i]);
        attr = ATTR_UNBOOTABLE;
        unbootable_attr[i] = storage->get_slot_attr(storage, update_device->name, i,
                             attr);

        if ((0 != unbootable_attr[i]) && (1 != unbootable_attr[i])) {
            UNIT_TEST_PRINTF("get_slot_attr, attr = %d, value = %d\n", attr,
                             unbootable_attr[i]);
            goto end;
        }

        UNIT_TEST_PRINTF("unbootable_attr %s = %d\n", SUFFIX_SLOT(i),
                         unbootable_attr[i]);
        attr = ATTR_SUCCESSFUL;
        successful_attr[i] = storage->get_slot_attr(storage, update_device->name, i,
                             attr);

        if ((0 != successful_attr[i]) && (1 != successful_attr[i])) {
            UNIT_TEST_PRINTF("get_slot_attr, attr = %d, value = %d\n", attr,
                             successful_attr[i]);
            goto end;
        }

        UNIT_TEST_PRINTF("successful_attr %s  = %d\n", SUFFIX_SLOT(i),
                         successful_attr[i]);
        attr = ATTR_RETRY;
        retry_cnt[i] = storage->get_slot_attr(storage, update_device->name, i, attr);

        if ((retry_cnt[i] < 0) || (retry_cnt[i] >= 4)) {
            UNIT_TEST_PRINTF("get_slot_attr, attr = %d, value = %d\n", attr, retry_cnt[i]);
            goto end;
        }

        UNIT_TEST_PRINTF("retry_cnt %s = %d\n", SUFFIX_SLOT(i), retry_cnt[i]);
    }

    active_attr[0] = 1;
    active_attr[1] = 0;
    unbootable_attr[0] = 0;
    unbootable_attr[1] = 1;
    successful_attr[0] = 1;
    successful_attr[1] = 1;
    retry_cnt[0] = 2;
    retry_cnt[1] = 2;

    for (int i = 0; i < 2; i ++) {
        for (int j = 0; j < ATTR_NUM; j++) {
            attr = attr_list[j];

            if (0 != storage->set_slot_attr(storage, update_device->name, i, attr,
                                            attr_res_temp[j][i])) {
                UNIT_TEST_PRINTF("set_slot_attr, attr = %s, value = %d\n", attr_list_char[j],
                                 attr_res_temp[j][i]);
                goto end;
            }

            UNIT_TEST_PRINTF("%s slot %s = %d\n", attr_list_char[j], SUFFIX_SLOT(i),
                             attr_res_temp[j][i]);

            temp = storage->get_slot_attr(storage, update_device->name, i, attr);

            if (attr_res_temp[j][i] != temp) {
                UNIT_TEST_PRINTF("get_slot_attr, attr = %s, value = %d, expected value = %d\n",
                                 attr_list_char[j], temp, attr_res_temp[j][i]);
                goto end;
            }
        }
    }

    if (storage->update_slot_attr(storage, update_device->name)) {
        UNIT_TEST_PRINTF("failed to storage->update_slot_attr\n");
        goto end;
    }

    if (storage->destroy_ptdev(storage, update_device->name)) {
        UNIT_TEST_PRINTF("failed to storage->destroy_ptdev\n");
        goto end;
    }

    ret = 0;

end:

    if (update_device)
        destroy_update_dev(test_dev);

    return ret;
}

static int write_to_file(char *file, char *partition_name,
                         uint64_t partition_size, int flags, int mode)
{
    uint64_t cnt = 0;
    uint64_t left = 0;
    uint8_t *read_buf = NULL;
    uint8_t *read_buf2 = NULL;
    uint64_t read_len = FILE_READ_LENGTH;
    int ret = -1;
    uint64_t i = 0;
    int fd = 0;
    struct stat fstat;
    uint64_t file_size = 0;
    int partition_fd = -1;

    partition_fd = partition_dev_open((const char *)partition_name, flags, mode);

    if (partition_fd < 0) {
        UNIT_TEST_PRINTF("failed to open %s\n", partition_name);
        goto end;
    }

    fd = open(file, O_RDWR | O_CREAT | O_TRUNC, 0777);

    if (fd <= 0) {
        UNIT_TEST_PRINTF("open file %s error %s\n", file, strerror(errno));
        goto end;
    }

    if (stat(file, &fstat) < 0) {
        UNIT_TEST_PRINTF("stat %s error\n", file);
        goto end;
    }

    file_size = partition_size;
    read_buf = (uint8_t *)MEM_ALIGN(512, FILE_READ_LENGTH);
    read_buf2 = (uint8_t *)MEM_ALIGN(512, FILE_READ_LENGTH);

    if (!read_buf || !read_buf2) {
        UNIT_TEST_PRINTF("blk_write_with_check calloc failed\n");
        goto end;
    }

    cnt = file_size / FILE_READ_LENGTH;
    left = file_size % FILE_READ_LENGTH;
    read_len = FILE_READ_LENGTH;

#if RUN_IN_QNX

    if (lseek(fd, 0, SEEK_SET) < 0)
#else
    if (lseek64(fd, 0, SEEK_SET) < 0)
#endif
    {
        UNIT_TEST_PRINTF("file lseek failed: err = %s\n", strerror(errno));
        goto end;
    }

    if (0 != partition_dev_seek(partition_fd, 0, SEEK_SET)) {
        UNIT_TEST_PRINTF("partition_dev_seek fd[%d] failed\n", partition_fd);
        goto end;
    }

    for (i = 0; i < cnt + 1; i++) {
        if (i == cnt) {
            if (left)
                read_len = left;
            else
                break;
        }

        if (read_len != partition_dev_read(partition_fd, read_buf, read_len)) {
            UNIT_TEST_PRINTF("write failed\n");
            goto end;
        }

        if (read_len != write(fd, read_buf, read_len)) {
            UNIT_TEST_PRINTF("file read failed err = %s\n", strerror(errno));
            goto end;
        }

    }

    ret = 0;

end:

    if (read_buf)
        FREE(read_buf);

    if (read_buf2)
        FREE(read_buf2);

    if (fd > 0)
        close(fd);

    return ret;
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 12

    Test Purposes       :   read a paritition to a file

    Test Description    :   This test case is just a tool, the purpose is to
                            read the content of a certain partition, not to
                            verify the interface.Use this use case under
                            the condition that the previous test system
                            call interface is guaranteed to be valid.

    Test Command    :       ./ota_self_test emmc1 -t 11 -f /test/dil2 -s a
                            ./ota_self_test emmc2 -t 11 -f cluster_bootloader -s b

    Tips:

    Do write file and readback file test:
    1. Write a file to a partition (write to the inactive partition) use:
    ./ota_self_test emmc2 -t 3 -f cluster_bootloader.bin

    2. Read back use(assume that we know partition b is inactive):
    ./ota_self_test emmc2 -t 11 -f cluster_bootloader -s b
    we get cluster_bootloader_b.bin

    3. Compare the original file(cluster_bootloader.bin) with readback file
    (cluster_bootloader_b.bin) in our Computer
 ----------------------------------------------------------------------------*/
static int unit_test_read_a_partition_to_a_file(int argc, char *argv[])
{
    partition_device_t *ptdev = NULL;
    int slot_active[MAX_PARTITION_NUM] = {0};
    int slot_inactive[MAX_PARTITION_NUM] = {0};
    int active_slot = 0;
    int inactive_slot = 0;
    int len = 0;
    int ret = -1;
    unsigned long long in = 0;
    unsigned long long out = 0;
    unsigned long long size = 0;
    char *pname = NULL;
    const char *suffix = NULL;
    int index = 0;
    int file_index[MAX_PARTITION_NUM] = {0};
    unsigned long long gpt_offset;
    char fname[FILE_NAME_MAX] = {0};
    char *file_base_name = NULL;
    unsigned partition_count;
    struct partition_entry *partition_entries;
    int mode = SYSCALL_AUTO;
    char filepath[256] = {0};
    int target_slot;

    if ((1 == argc) || (!strcmp(argv[1], "emmc"))) {
        ret = switch_storage_dev_force_local(&ptdev, DEV_EMMC0);
        mode = SYSCALL_FORCE_LOCAL;
    }
    else if (!strcmp(argv[1], "ospi")) {
        ret = switch_storage_dev_force_local(&ptdev, DEV_SPI_NOR0);
        mode = SYSCALL_FORCE_REMOTE;
    }
    else if (!strcmp(argv[1], "emmc1")) {
        ret = switch_storage_dev_force_local(&ptdev, DEV_EMMC1);
        mode = SYSCALL_FORCE_REMOTE;
    }
    else if (!strcmp(argv[1], "emmc2")) {
        ret = switch_storage_dev_force_local(&ptdev, DEV_EMMC2);
        mode = SYSCALL_FORCE_REMOTE;
    }

    if (0 != ret) {
        UNIT_TEST_PRINTF("failed to setup ptdev\n");
        ret = -1;
        goto end;
    }

    ret = -1;

    if ((argc > 2) && strncmp(argv[2], "-", 1)) {
        UNIT_TEST_PRINTF("useage error\n");
        ret = -1;
        goto end;
    }

    if (file_cnt == 0) {
        UNIT_TEST_PRINTF("useage error, need to specify one partition(aka, -f safety_os)\n");
        ret = -1;
        goto end;
    }

    partition_count = ptdev->count;
    partition_entries = ptdev->partition_entries;
    gpt_offset = ptdev->gpt_offset;

    active_slot = get_current_slot(ptdev);
    suffix = get_suffix(ptdev, active_slot);

    if (partition_count > 2 * MAX_PARTITION_NUM) {
        UNIT_TEST_PRINTF("too many partition\n");
        goto end;
    }

    for (int i = 0; i < MAX_PARTITION_NUM; i++) {
        file_index[i] = -1;
    }

    for (int i = 0; i < partition_count; i++) {
        if (strstr((const char *)partition_entries[i].name, "$"))
            continue;

        pname = (char *)partition_entries[i].name;
        len = strlen(pname);

        if (len < 4)
            continue; /* too few, ignore */

        if (strcmp((char *)(pname + len - 2), suffix_slot[0])
                && strcmp((char *)(pname + len - 2), suffix_slot[1])) {
            continue;
        }

        for (int j = i + 1; j < partition_count; j++) {
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

                for (int k = 0; k < file_cnt; k++) {
                    if (!strlen(file_name[k]) || (strlen(file_name[k]) >= FILE_NAME_MAX)) {
                        UNIT_TEST_PRINTF("file_name[%d] = %s length error\n", k, file_name[k]);
                        continue;
                    }

                    memset(fname, 0, FILE_NAME_MAX);
                    file_base_name = NULL;
                    strncpy(fname, file_name[k], MIN(strlen(file_name[k]), FILE_NAME_MAX - 1));
                    file_base_name = basename(fname);

                    if ((strlen(file_base_name) < (len - 2))
                            || ((strlen(file_base_name) > (len - 2)) &&  file_base_name[len - 2] != '.'))
                        continue;

                    if (!strncmp(file_base_name, pname, len - 2)) {
                        file_index[k] = index;
                        UNIT_TEST_PRINTF("basename = %s\n", file_base_name);
                        UNIT_TEST_PRINTF("find file input num %d, A/B partition index=%d, file name = %s\n",
                                         k, index, fname);
                    }
                }

                index++;
            }
        }
    }

    for (int i = 0; i < index; i++) {
        active_slot = slot_active[i];
        inactive_slot = slot_inactive[i];
        in = (partition_entries[active_slot].first_lba) * LBA_SIZE;
        out = (partition_entries[inactive_slot].first_lba) * LBA_SIZE;
        size = (partition_entries[active_slot].last_lba -
                partition_entries[active_slot].first_lba + 1) * LBA_SIZE;

        in += gpt_offset;
        out += gpt_offset;

        for (int k = 0; k < file_cnt; k++) {
            if (file_index[k] == i) {
                UNIT_TEST_PRINTF("i=%d\n", i);
                UNIT_TEST_PRINTF("active_slot=%s\n", partition_entries[active_slot].name);
                UNIT_TEST_PRINTF("inactive_slot=%s\n", partition_entries[inactive_slot].name);
                UNIT_TEST_PRINTF("in=%p out=%p size=%lld\n", (void *)in, (void *)out, size);

                if (file_slot == 1) {
                    target_slot = (active_slot > inactive_slot) ? active_slot : inactive_slot;
                }
                else {
                    target_slot = (active_slot < inactive_slot) ? active_slot : inactive_slot;
                }

                pname = (char *)partition_entries[target_slot].name;
                snprintf(filepath, 256, "%s%s.bin", file_name[k], pname + strlen(pname) - 2);
                UNIT_TEST_PRINTF("slot %s write to %s\n", pname, filepath);
                ret = write_to_file(filepath, pname, size, flags, mode);

                if (ret < 0) {
                    UNIT_TEST_PRINTF("unit_read_write_test write_file failed\n");
                    ret = -1;
                    goto end;
                }

                break;
            }
        }
    }

    ret = 0;

end:

    if (ptdev)
        free_storage_dev_force_local(ptdev);

    return ret;
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 13

    Test Purposes       :   Read and print a piece of data directly

    Test Description    :   a lightweight read test

    Test Command        :   ./ota_self_test res_a  -t 12 -a 0x1 -l 0x100
 ----------------------------------------------------------------------------*/
static int unit_test_read_and_print(int argc, char *argv[])
{
    int ret = -1;
    uint64_t cnt = 0;
    uint64_t left = 0;
    uint64_t read_size = 0;
    char partition_name[MAX_GPT_NAME_SIZE] = {0};
    uint64_t addr = test_addr;
    uint64_t len =  test_len;
    uint8_t *buf = NULL;
    int64_t seek_addr = 0;
    int fd = -1;

    snprintf(partition_name, MAX_GPT_NAME_SIZE, "%s", argv[1]);
    cnt = len / MAX_CALLOC_SIZE;
    left = len % MAX_CALLOC_SIZE;
    UNIT_TEST_PRINTF("read %s addr = %llx len = %lld cnt %lld\n", partition_name,
                     (unsigned long long)addr, (unsigned long long)len, (unsigned long long)cnt);

    buf = (uint8_t *)MEM_ALIGN(512, MAX_CALLOC_SIZE);

    if (!buf) {
        UNIT_TEST_PRINTF("memalign failed\n");
        goto end;
    }

    fd = partition_dev_open(partition_name, flags,  0);

    if (fd <= 0) {
        UNIT_TEST_PRINTF("partition_dev_open failed");
        goto end;
    }

    seek_addr = partition_dev_seek(fd, addr, SEEK_SET);
    UNIT_TEST_PRINTF("seek_addr = 0x%llx\n", (unsigned long long)seek_addr);

    if (addr != seek_addr) {
        UNIT_TEST_PRINTF("seek error\n");
        goto end;
    }

    for (int i = 0; i <= cnt; i++) {
        read_size = (i != cnt) ? MAX_CALLOC_SIZE : left;

        if (read_size) {
            if (read_size != partition_dev_read(fd, buf, read_size)) {
                UNIT_TEST_PRINTF("read error");
                goto end;
            }

            UNIT_TEST_PRINTF("dump len = 0x%llx\n", (unsigned long long)read_size);
            hexdump8(buf, read_size);
        }
    }

    ret = 0;
end:

    if (buf)
        free(buf);

    if (fd > 0)
        partition_dev_close(fd);

    return ret;
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 14

    Test Purposes       :   pread a partition to a file

    Test Description    :   a lightweight pread test

    Test Command        :   ./ota_self_test res_a -t 13
 ----------------------------------------------------------------------------*/
static int unit_test_pread(int argc, char *argv[])
{
    int ret = -1;
    uint64_t cnt = 0;
    uint64_t left = 0;
    uint64_t read_size = 0;
    char partition_name[MAX_GPT_NAME_SIZE] = {0};
    char file[MAX_GPT_NAME_SIZE + 4] = {0};
    uint64_t read_len = 0;
    uint64_t len =  test_len;
    uint8_t *buf = NULL;
    int fd = -1;
    int fd2 = -1;
    int fd_file = -1;
    struct stat fstat;
    uint64_t each_read_size = MAX_CALLOC_SIZE;

    snprintf(partition_name, MAX_GPT_NAME_SIZE, "%s", argv[1]);
    snprintf(file, MAX_GPT_NAME_SIZE + 4, "%s%s", argv[1], ".bin");

    fd = partition_dev_open(partition_name, flags,  0);

    if (fd <= 0) {
        UNIT_TEST_PRINTF("partition_dev_open failed");
        goto end;
    }

    /* seek is just a disturbance term for pwrite, 0x123321 is a test value */
    partition_dev_seek(fd, 0x123321, SEEK_SET);
    len = partition_dev_blockdevsize(fd);

    if (!len) {
        UNIT_TEST_PRINTF("partition_dev_blockdevsize failed");
        goto end;
    }

    fd_file = open(file, O_RDWR | O_CREAT | O_TRUNC, 0777);

    if (fd_file <= 0) {
        UNIT_TEST_PRINTF("open file %s error %s\n", file, strerror(errno));
        goto end;
    }

    if (stat(file, &fstat) < 0) {
        UNIT_TEST_PRINTF("stat %s error\n", file);
        goto end;
    }

#if RUN_IN_QNX

    if (lseek(fd_file, 0, SEEK_SET) < 0)
#else
    if (lseek64(fd_file, 0, SEEK_SET) < 0)
#endif

    {
        UNIT_TEST_PRINTF("file lseek failed: err = %s\n", strerror(errno));
        goto end;
    }

    cnt = len / each_read_size;
    left = len % each_read_size;
    UNIT_TEST_PRINTF("read %s len = %lld cnt %lld\n", partition_name,
                     (unsigned long long)len, (unsigned long long)cnt);

    buf = (uint8_t *)MEM_ALIGN(512, each_read_size);

    if (!buf) {
        UNIT_TEST_PRINTF("memalign failed\n");
        goto end;
    }

    /* use reopen as a disturbance */
    fd2 = partition_dev_open(partition_name, flags,  0);

    if (fd2 <= 0) {
        UNIT_TEST_PRINTF("partition dev reopen failed");
        goto end;
    }

    read_len = 0;

    for (int i = 0; i <= cnt; i++) {
        read_size = (i != cnt) ? each_read_size : left;

        if (read_size) {
            UNIT_TEST_PRINTF("i = %d\n", i);

            /* use read as a disturbance to make a offset in fd */
            if (read_size != partition_dev_read(fd, buf, read_size)) {
                UNIT_TEST_PRINTF("read error");
                goto end;
            }

            memset(buf, 0, read_size);

            /* pread */
            if (read_size != partition_dev_pread(fd2, buf, read_size, read_len)) {
                UNIT_TEST_PRINTF("pread error");
                goto end;
            }

            /* write file */
            if (read_size != write(fd_file, buf, read_size)) {
                UNIT_TEST_PRINTF("write file");
                goto end;
            }

            read_len += read_size;
        }
    }

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

/*----------------------------------------------------------------------------
    Test Number         :   testcase 15

    Test Purposes       :   pwrite a file to partition

    Test Description    :   a lightweight pwrite test

    Test Command        :   ./ota_self_test res_b -t 14 (prepare a res_b.bin first)
 ----------------------------------------------------------------------------*/
static int unit_test_pwrite(int argc, char *argv[])
{
    int ret = -1;
    uint64_t cnt = 0;
    uint64_t left = 0;
    uint64_t read_size = 0;
    char partition_name[MAX_GPT_NAME_SIZE] = {0};
    char file[MAX_GPT_NAME_SIZE + 4] = {0};
    uint64_t read_len = 0;
    uint64_t len =  test_len;
    uint8_t *buf = NULL;
    int fd = -1;
    int fd2 = -1;
    int fd_file = -1;
    struct stat fstat;
    uint64_t each_read_size = MAX_CALLOC_SIZE;

    snprintf(partition_name, MAX_GPT_NAME_SIZE, "%s", argv[1]);
    snprintf(file, MAX_GPT_NAME_SIZE + 4, "%s%s", argv[1], ".bin");

    fd = partition_dev_open(partition_name, flags,  0);

    if (fd <= 0) {
        UNIT_TEST_PRINTF("partition_dev_open failed");
        goto end;
    }

    /* seek is just a disturbance term for pwrite, 0x123321 is a test value */
    partition_dev_seek(fd, 0x123321, SEEK_SET);
    len = partition_dev_blockdevsize(fd);

    if (!len) {
        UNIT_TEST_PRINTF("partition_dev_blockdevsize failed");
        goto end;
    }

    if (stat(file, &fstat) < 0) {
        UNIT_TEST_PRINTF("stat %s error\n", file);
        goto end;
    }

    fd_file = open(file, O_RDONLY);

    if (fd_file <= 0) {
        UNIT_TEST_PRINTF("open file %s error %s\n", file, strerror(errno));
        goto end;
    }

#if RUN_IN_QNX

    if (lseek(fd_file, 0, SEEK_SET) < 0)
#else
    if (lseek64(fd_file, 0, SEEK_SET) < 0)
#endif
    {
        UNIT_TEST_PRINTF("file lseek failed: err = %s\n", strerror(errno));
        goto end;
    }

    UNIT_TEST_PRINTF("partition size = %lld , file size = %lld\n",
                     (unsigned long long)len, (unsigned long long)fstat.st_size);

    if (fstat.st_size > len) {
        UNIT_TEST_PRINTF("file too large\n");
        goto end;
    }

    len = fstat.st_size;

    cnt = len / each_read_size;
    left = len % each_read_size;
    UNIT_TEST_PRINTF("read %s len = %lld cnt %lld\n", partition_name,
                     (unsigned long long)len, (unsigned long long)cnt);

    buf = (uint8_t *)MEM_ALIGN(512, each_read_size);

    if (!buf) {
        UNIT_TEST_PRINTF("memalign failed\n");
        goto end;
    }

    /* use reopen as a disturbance */
    fd2 = partition_dev_open(partition_name, flags,  0);

    if (fd2 <= 0) {
        UNIT_TEST_PRINTF("partition dev reopen failed");
        goto end;
    }

    read_len = 0;

    for (uint64_t i = 0; i <= cnt; i++) {
        read_size = (i != cnt) ? each_read_size : left;

        if (read_size) {
            UNIT_TEST_PRINTF("i = %lld\n", (unsigned long long)i);

            /* use read as a disturbance to make a offset in fd */
            if (read_size != partition_dev_read(fd, buf, read_size)) {
                UNIT_TEST_PRINTF("read error");
                goto end;
            }

            memset(buf, 0, read_size);

            /* read file */
            if (read_size != read(fd_file, buf, read_size)) {
                UNIT_TEST_PRINTF("write file");
                goto end;
            }

            /* pwrite */
            if (read_size != partition_dev_pwrite(fd2, buf, read_size, read_len)) {
                UNIT_TEST_PRINTF("pread error");
                goto end;
            }

            read_len += read_size;
        }
    }

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

/*----------------------------------------------------------------------------
    Test Number         :   testcase 16

    Test Purposes       :   tcp server listen

    Test Description    :

    Test Command        :
 ----------------------------------------------------------------------------*/
static int unit_tcp_server(int argc, char *argv[])
{
    tcp_listen();
    tcp_poll_enable();

    while (1);

    return 0;
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 17

    Test Purposes       :   tcp client listen

    Test Description    :

    Test Command        :
 ----------------------------------------------------------------------------*/
static int unit_tcp_client(int argc, char *argv[])
{
    tcp_client_init(0);
    tcp_poll_enable();
    client_handshake_to_server();
    return 0;
}

static int storage_read_write(int argc, char *argv[], storage_device_t *storage)
{
#define DATA_LENGTH 512
    int ret = -1;
    uint64_t addr = test_addr;
    uint64_t len =  test_len;
    int i = 0;
    uint8_t buf[DATA_LENGTH] = {0};
    uint64_t cnt = len / DATA_LENGTH;
    uint64_t left = len % DATA_LENGTH;
    sync();

    if (init_storage(storage, NULL)) {
        UNIT_TEST_PRINTF("init storage error\n");
        return -1;
    }

    if (!strcmp(argv[1], "read")) {
        if (len == 0) {
            UNIT_TEST_PRINTF("para error\n");
            return -1;
        }

        for (i = 0; i < cnt; i++) {
            ret = storage->read(storage, addr, buf, DATA_LENGTH);

            if (ret) {
                UNIT_TEST_PRINTF( "Failed to read\n");
                return -1;
            }

            hexdump8(buf, DATA_LENGTH);
            addr += DATA_LENGTH;
        }

        if (left) {
            ret = storage->read(storage, addr, buf, left);

            if (ret) {
                UNIT_TEST_PRINTF( "Failed to read\n");
                return -1;
            }

            hexdump8(buf, left);
        }
    }
    else if (!strcmp(argv[1], "write")) {
        ret = storage->write_file(storage, addr, UINT_MAX, file_name[0], 0);

        if (ret < 0) {
            UNIT_TEST_PRINTF("write_file failed\n");
            return -1;
        }
    }
    else {
        UNIT_TEST_PRINTF( "Failed to read\n");
        return -1;
    }

    sync();
    return 0;
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 18

    Test Purposes       :   flash

    Test Description    :   read or write a remote flash area

    Test Command        :   read:
                            ./ota_self_test read -t 17 -a 0x2200 -l 0x200
                            write:
                            step1 : dd if=/dev/zero of=/data/test.bin bs=512 count=1
                            step2 : ./ota_self_test write -t 17 -a 0x2000 -f test.bin
 ----------------------------------------------------------------------------*/
static int flash_read_write(int argc, char *argv[])
{
    return storage_read_write(argc, argv, &saf_update_monitor);
}


/*----------------------------------------------------------------------------
    Test Number         :   testcase 19

    Test Purposes       :   flash

    Test Description    :   read or write a local emmc area

    Test Command        :   read:
                            step1: ./ota_self_test read -t 18 -a 0x0 -l 0x200
                            write:
                            step1 : dd if=/dev/zero of=/data/test.bin bs=512 count=1
                            step2 : ./ota_self_test write -t 18 -a 0x0 -f test.bin
 ----------------------------------------------------------------------------*/
static int emmc_read_write(int argc, char *argv[])
{
    return storage_read_write(argc, argv, &mmc1);
}

/*----------------------------------------------------------------------------
    Test Number         :   testcase 20

    Test Purposes       :   read time

    Test Description    :   we want to know the time of read a partition to a file

    Test Command        :   read:
                            step1: ./ota_self_test [partition name] -t 19 -l 0x200
 ----------------------------------------------------------------------------*/
static int unit_test_read_time(int argc, char *argv[])
{
    int ret = -1;
    uint64_t cnt = 0;
    uint64_t left = 0;
    uint64_t read_size = 0;
    char partition_name[MAX_GPT_NAME_SIZE] = {0};
    char file[MAX_GPT_NAME_SIZE + 4] = {0};
    uint64_t len =  0;
    uint8_t *buf = NULL;
    int fd = -1;
    int fd_file = -1;
    struct stat fstat;
    uint64_t each_read_size = MAX_CALLOC_SIZE;
    time_t start_time, end_time;

    snprintf(partition_name, MAX_GPT_NAME_SIZE, "%s", argv[1]);
    snprintf(file, MAX_GPT_NAME_SIZE + 4, "%s%s", argv[1], ".bin");

    fd = partition_dev_open(partition_name, flags,  0);

    if (fd <= 0) {
        UNIT_TEST_PRINTF("partition_dev_open failed");
        goto end;
    }

    len = partition_dev_blockdevsize(fd);

    if (!len) {
        UNIT_TEST_PRINTF("partition_dev_blockdevsize failed");
        goto end;
    }

    fd_file = open(file, O_RDWR | O_CREAT | O_TRUNC, 0777);

    if (fd_file <= 0) {
        UNIT_TEST_PRINTF("open file %s error %s\n", file, strerror(errno));
        goto end;
    }

    if (stat(file, &fstat) < 0) {
        UNIT_TEST_PRINTF("stat %s error\n", file);
        goto end;
    }

#if RUN_IN_QNX

    if (lseek(fd_file, 0, SEEK_SET) < 0)
#else
    if (lseek64(fd_file, 0, SEEK_SET) < 0)
#endif
    {
        UNIT_TEST_PRINTF("file lseek failed: err = %s\n", strerror(errno));
        goto end;
    }

    if (test_len != 0) {
        each_read_size = test_len;
    }

    cnt = len / each_read_size;
    left = len % each_read_size;
    UNIT_TEST_PRINTF("read %s len = %lld cnt %lld\n", partition_name,
                     (unsigned long long)len, (unsigned long long)cnt);

    buf = (uint8_t *)MEM_ALIGN(512, each_read_size);

    if (!buf) {
        UNIT_TEST_PRINTF("memalign failed\n");
        goto end;
    }

    UNIT_TEST_PRINTF("start to read...\n");
    start_time = time( NULL );

    /* seek to 0 */
    partition_dev_seek(fd, 0, SEEK_SET);

    for (uint64_t i = 0; i <= cnt; i++) {
        read_size = (i != cnt) ? each_read_size : left;

        if (read_size) {
            /* read */
            if (read_size != partition_dev_read(fd, buf, read_size)) {
                UNIT_TEST_PRINTF("read error");
                goto end;
            }

            /* write file */
            if (read_size != write(fd_file, buf, read_size)) {
                UNIT_TEST_PRINTF("write file");
                goto end;
            }
        }
    }

    end_time = time( NULL );

    UNIT_TEST_PRINTF( "Elapsed time: %f seconds\n",  difftime(end_time,
                      start_time));

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

/*----------------------------------------------------------------------------
    Test Number         :   testcase 21

    Test Purposes       :   write time

    Test Description    :   we want to know the time of write a partition to a file

    Test Command        :   write:
                            step1: ./ota_self_test [partition name] -t 20
 ----------------------------------------------------------------------------*/
static int unit_test_wrtie_time(int argc, char *argv[])
{
    int ret = -1;
    uint64_t cnt = 0;
    uint64_t left = 0;
    uint64_t read_size = 0;
    char partition_name[MAX_GPT_NAME_SIZE] = {0};
    char file[MAX_GPT_NAME_SIZE + 4] = {0};
    uint64_t len =  test_len;
    uint8_t *buf = NULL;
    int fd = -1;
    int fd_file = -1;
    struct stat fstat;
    uint64_t each_read_size = MAX_CALLOC_SIZE;
    time_t start_time, end_time;

    snprintf(partition_name, MAX_GPT_NAME_SIZE, "%s", argv[1]);
    snprintf(file, MAX_GPT_NAME_SIZE + 4, "%s%s", argv[1], ".bin");

    fd = partition_dev_open(partition_name, flags,  0);

    if (fd <= 0) {
        UNIT_TEST_PRINTF("partition_dev_open failed");
        goto end;
    }

    len = partition_dev_blockdevsize(fd);

    if (!len) {
        UNIT_TEST_PRINTF("partition_dev_blockdevsize failed");
        goto end;
    }

    if (stat(file, &fstat) < 0) {
        UNIT_TEST_PRINTF("stat %s error\n", file);
        goto end;
    }

    fd_file = open(file, O_RDONLY);

    if (fd_file <= 0) {
        UNIT_TEST_PRINTF("open file %s error %s\n", file, strerror(errno));
        goto end;
    }

#if RUN_IN_QNX

    if (lseek(fd_file, 0, SEEK_SET) < 0)
#else
    if (lseek64(fd_file, 0, SEEK_SET) < 0)
#endif
    {
        UNIT_TEST_PRINTF("file lseek failed: err = %s\n", strerror(errno));
        goto end;
    }

    UNIT_TEST_PRINTF("partition size = %lld , file size = %lld\n",
                     (unsigned long long)len, (unsigned long long)fstat.st_size);

    if (fstat.st_size > len) {
        UNIT_TEST_PRINTF("file too large\n");
        goto end;
    }

    len = fstat.st_size;

    cnt = len / each_read_size;
    left = len % each_read_size;
    UNIT_TEST_PRINTF("read %s len = %lld cnt %lld\n", partition_name,
                     (unsigned long long)len, (unsigned long long)cnt);

    buf = (uint8_t *)MEM_ALIGN(512, each_read_size);

    if (!buf) {
        UNIT_TEST_PRINTF("memalign failed\n");
        goto end;
    }

    UNIT_TEST_PRINTF("start to write...\n");
    start_time = time( NULL );

    /* seek to 0 */
    partition_dev_seek(fd, 0, SEEK_SET);

    for (uint64_t i = 0; i <= cnt; i++) {
        read_size = (i != cnt) ? each_read_size : left;

        if (read_size) {
            /* read file */
            if (read_size != read(fd_file, buf, read_size)) {
                UNIT_TEST_PRINTF("write file");
                goto end;
            }

            /* write */
            if (read_size != partition_dev_write(fd, buf, read_size)) {
                UNIT_TEST_PRINTF("pread error");
                goto end;
            }
        }
    }

    end_time = time( NULL );

    UNIT_TEST_PRINTF( "Elapsed time: %f seconds\n",  difftime(end_time,
                      start_time));

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

/*----------------------------------------------------------------------------
    Test Number         :   testcase 22

    Test Purposes       :   write time

    Test Description    :   test use qnx crypto

    Test Command        :   write:
                            step1: ./ota_self_test [file name without .bin] -t 21 -d sha256
                            ota_self_test ddr_init_seq_a -t 21 -d md5
                            ota_self_test ddr_init_seq_a -t 21 -d sha256
                            ota_self_test ddr_init_seq_a -t 21 -d sha1
                            ota_self_test ddr_init_seq_a -t 21 -d sha512
 ----------------------------------------------------------------------------*/
static int unit_test_digest(int argc, char *argv[])
{
#if RUN_IN_QNX

    int ret = -1;
    uint64_t cnt = 0;
    uint64_t left = 0;
    uint64_t read_size = 0;
    char file[MAX_GPT_NAME_SIZE + 4] = {0};
    uint64_t len =  test_len;
    uint8_t *buf = NULL;
    int fd_file = -1;
    struct stat fstat;
    uint64_t each_read_size = MAX_CALLOC_SIZE;
    time_t start_time, end_time;

    qcrypto_ctx_t *ctx = NULL;
    size_t dsize;
    uint8_t *output_buffer = NULL;

    snprintf(file, MAX_GPT_NAME_SIZE + 4, "%s%s", argv[1], ".bin");

    if (stat(file, &fstat) < 0) {
        UNIT_TEST_PRINTF("stat %s error\n", file);
        goto end;
    }

    fd_file = open(file, O_RDONLY);

    if (fd_file <= 0) {
        UNIT_TEST_PRINTF("open file %s error %s\n", file, strerror(errno));
        goto end;
    }

    if (lseek(fd_file, 0, SEEK_SET) < 0) {
        UNIT_TEST_PRINTF("file lseek failed: err = %s\n", strerror(errno));
        goto end;
    }

    UNIT_TEST_PRINTF("file size = %lld\n", (unsigned long long)fstat.st_size);

    /* Initializing the qcrypto library */
    ret = qcrypto_init(QCRYPTO_INIT_LAZY, NULL);

    if (ret != QCRYPTO_R_EOK) {
        fprintf(stderr, "qcrypto_init() failed (%d:%s)\n", ret, qcrypto_strerror(ret));
        goto end;
    }

    /* Checking if a digest is supported */
    ret = qcrypto_digest_supported((const char *)test_digest, NULL, 0);

    if (ret != QCRYPTO_R_EOK) {
        fprintf(stderr, "qcrypto_digest_supported() failed (%d:%s)\n", ret,
                qcrypto_strerror(ret));
        goto end;
    }

    /* Requesting the digest */
    ret = qcrypto_digest_request((const char *)test_digest, NULL, 0, &ctx);

    if (ret != QCRYPTO_R_EOK) {
        fprintf(stderr, "qcrypto_digest_request() failed (%d:%s)\n", ret,
                qcrypto_strerror(ret));
        goto end;
    }

    /* Querying the digest size */
    dsize = qcrypto_digestsize(ctx);
    printf("digest size =  %ld\n", dsize);

    output_buffer = malloc(dsize);

    if (output_buffer == NULL) {
        fprintf(stderr, "output size not defined (%d:%s)\n", ret,
                qcrypto_strerror(ret));
        goto end;
    }

    ret = qcrypto_digest_init(ctx);

    if (ret != QCRYPTO_R_EOK) {
        fprintf(stderr, "digest init failed (%d:%s)\n", ret, qcrypto_strerror(ret));
        goto end;
    }

    len = fstat.st_size;
    cnt = len / each_read_size;
    left = len % each_read_size;
    UNIT_TEST_PRINTF("read %s len = %lld cnt %lld\n", file, (unsigned long long)len,
                     (unsigned long long)cnt);

    buf = (uint8_t *)MEM_ALIGN(512, each_read_size);

    if (!buf) {
        UNIT_TEST_PRINTF("memalign failed\n");
        goto end;
    }

    UNIT_TEST_PRINTF("start to calc...\n");
    start_time = time( NULL );

    for (uint64_t i = 0; i <= cnt; i++) {
        read_size = (i != cnt) ? each_read_size : left;

        if (read_size) {
            /* read file */
            if (read_size != read(fd_file, buf, read_size)) {
                UNIT_TEST_PRINTF("write file");
                goto end;
            }

            ret = qcrypto_digest_update(ctx, buf, read_size);

            if (ret != QCRYPTO_R_EOK) {
                fprintf(stderr, "qcrypto_digest_update() %ld failed (%d:%s)\n", i, ret,
                        qcrypto_strerror(ret));
                goto end;
            }
        }
    }

    ret = qcrypto_digest_final(ctx, output_buffer, &dsize);

    if (ret != QCRYPTO_R_EOK) {
        fprintf(stderr, "qcrypto_digest_final() failed (%d:%s)\n", ret,
                qcrypto_strerror(ret));
        goto end;
    }

    end_time = time( NULL );

    UNIT_TEST_PRINTF( "Elapsed time: %f seconds\n",  difftime(end_time,
                      start_time));

    ret = 0;

    printf("%s for %s = ", (const char *)test_digest, file);

    for (int i = 0; i < dsize; i++) {
        printf("%02x", output_buffer[i]);
    }

    printf("\n");


end:

    if (buf)
        free(buf);

    if (fd_file > 0)
        close(fd_file);

    /* free the allocated memory */
    if (output_buffer) {
        free(output_buffer);
    }

    /* Releasing the context */
    qcrypto_release_ctx(ctx);

    /* Uninitializing the qcrypto library */
    qcrypto_uninit();

    return ret;


#else
    UNIT_TEST_PRINTF( "This test is just for QNX system\n");
    return 0;
#endif
}
#endif