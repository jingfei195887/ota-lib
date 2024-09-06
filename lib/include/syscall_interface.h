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

#ifndef __SYSCALL_INTERFACE_H__
#define __SYSCALL_INTERFACE_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum syscall_flag {
    SYSCALL_AUTO,
    SYSCALL_FORCE_LOCAL,
    SYSCALL_FORCE_REMOTE,
    SYSCALL_FLAG_MAX,
} syscall_flag_e;

/*
 * Opens the partition and gets the file descriptor for that partition
 *
 * Input parameter
 *  partition_name: name of the partition you want to open
 *  flags: include one of the following access
       modes: O_RDONLY, O_WRONLY, or O_RDWR.  These request opening the
       file read-only, write-only, or read/write, respectively.
 *  mode:          mode of query, contains the following options:
 *      SYSCALL_AUTO,         Indicates that all partition tables are automatically searched
 *      SYSCALL_FORCE_LOCAL,  Indicates that only the partition table on local core(aka, AP1) is searched
 *      SYSCALL_FORCE_REMOTE, Indicates that only the partition table on remote core is searched
 *
 * Return: a fd(file descriptor) is returned. if fd >= 0 means successfully, otherwise -1 means failed;
 **/
int partition_dev_open(const char *path, int flags, mode_t mode);

/*
 * Read a partition
 *
 * Input parameter
 *  dev_fd: file descriptor obtained by partition_dev_open
 *  buf: read buffer
 *  count: read size
 *
 * Return: -1 means read failed, otherwise return the read size;
 **/
ssize_t partition_dev_read(int dev_fd, void *buf, size_t count);


/*
 * Read a partition
 *
 * Input parameter
 *  dev_fd: file descriptor obtained by partition_dev_open
 *  buf: read buffer
 *  count: read size
 *  WARNING:
 *  pread is an atomic operation, and the positioning and reading operations
 *  are completed in one atomic operation, which cannot be interrupted.
 *  But the separate lseek and read may be interrupted by other programs.
 *  pread does not change the pointer of the current file, that is to say,
 *  it does not change the current file offset. The offset in pread is an
 *  absolute quantity, relative to the absolute quantity at the beginning
 *  of the file, and has nothing to do with the current file pointer position.
 * Return: -1 means read failed, otherwise return the read size;
 **/
ssize_t partition_dev_pread(int dev_fd, void *buf, size_t count,
                            int64_t offset);


/*
 * Write a partition
 *
 * Input parameter
 *  dev_fd: file descriptor obtained by partition_dev_open
 *  buf: write buffer
 *  count: write size
 *
 * Return: -1 means write failed, otherwise return the write size;
 **/
ssize_t partition_dev_write(int dev_fd, const void *buf, size_t count);

/*
 * Write a partition use pwrite. Writes up to count bytes from the buffer
 * starting at buf to the file descriptor fd at offset offset.
 * The file offset is not changed.
 * Input parameter
 *  dev_fd: file descriptor obtained by partition_dev_open
 *  buf: write buffer
 *  count: write size
 *  offset: offset from start
 *
 *  WARNING:
 *  pwrite is an atomic operation, and the positioning and reading operations
 *  are completed in one atomic operation, which cannot be interrupted.
 *  But the separate lseek and read may be interrupted by other programs.
 *  pwrite does not change the pointer of the current file, that is to say,
 *  it does not change the current file offset. The offset in pwrite is an
 *  absolute quantity, relative to the absolute quantity at the beginning
 *  of the file, and has nothing to do with the current file pointer position.
 *
 * Return: -1 means write failed, otherwise return the write size;
 **/
ssize_t partition_dev_pwrite(int dev_fd, const void *buf, size_t count,
                             int64_t offset);


/*
 * Write a file to a partition
 *
 * Input parameter
 *  dev_fd: file descriptor obtained by partition_dev_open
 *  buf: file path
 *
 * Return: -1 means write failed, otherwise return the write size;
 **/
ssize_t partition_dev_write_file(int dev_fd, char *file);

/*
 * Reposition read/write file offset
 * repositions the offset of the open file
 * description associated with the file descriptor fd to the value
 *
 * Input parameter
 *  dev_fd: file descriptor obtained by partition_dev_open
 *  offset: Offset value
 *  whence:
       SEEK_SET
              The file offset is set to offset bytes.
       SEEK_CUR
              The file offset is set to its current location plus offset
              bytes.
       SEEK_END
              The file offset is set to the size of the file plus offset
              bytes.
 *
 * Return: Upon successful completion, partition_dev_seek() returns the resulting
 * offset location as measured in bytes from the beginning of the file.
 * On error, the value -1 is returned
 **/
int64_t partition_dev_seek(int dev_fd, int64_t offset, int whence);

/*
 * Get a partition's size
 *
 * Input parameter
 *  dev_fd: file descriptor obtained by partition_dev_open
 *
 * Return: 0 means write failed, otherwise return the partition's size;
 **/
uint64_t partition_dev_blockdevsize(int dev_fd);

/*
 * TBD
 **/
int partition_dev_blkioctl(int dev_fd, int request, uint64_t start,
                           uint64_t length, int *result);

/*
 * Flush a partition's data
 *
 * Input parameter
 *  dev_fd: file descriptor obtained by partition_dev_open
 *
 * Return: -1 means write failed, 0 is success;
 **/
int partition_dev_flush(int dev_fd);

/*
 * Close a partition
 *
 * Input parameter
 *  dev_fd: file descriptor obtained by partition_dev_open
 *
 **/
int partition_dev_close(int dev_fd);

/*
    not used
*/
int partition_dev_issettingerrno(int dev_fd);

/*
 * Determine whether the partition is open
 *
 * Input parameter
 *  dev_fd: file descriptor obtained by partition_dev_open
 *
 * Return: 0 means not open, 1 is opened, the value -1 is error
 **/
int partition_dev_isopen(int dev_fd);

/*
 * Dump a partition's information
 *
 * Input parameter
 *  dev_fd: file descriptor obtained by partition_dev_open
 *
 **/
void partition_dev_dump(int dev_fd);

/*
 * Dump all partition's information in the same storage
 *
 * Input parameter
 *  dev_fd: file descriptor obtained by partition_dev_open
 *
 **/
void partition_dev_dump_all(int dev_fd);

/*
 * Get a partition's offset in storage
 *
 * Input parameter
 *  dev_fd: file descriptor obtained by partition_dev_open
 *
 * Return: 0 means write failed, otherwise return the partition's offset;
 **/
uint64_t partition_dev_blockdevoffset(int dev_fd);

/*
 * Determine whether the partition is local core(aka, AP1) or remote core
 *
 * Input parameter
 * partition_name: name of the partition you want to query
 * mode:          mode of query, contains the following options:
 *      SYSCALL_AUTO,         Indicates that all partition tables are automatically searched
 *      SYSCALL_FORCE_LOCAL,  Indicates that only the partition table on local core(aka, AP1) is searched
 *      SYSCALL_FORCE_REMOTE, Indicates that only the partition table on remote core is searched
 *
 * Return:
 *      STORAGE_LOCAL,  the partition you want to query is in local core's partition table
 *      STORAGE_REMOTE, the partition you want to query is in remote core's partition table
 **/
extern int check_partition_local_or_remote(char const *partition_name,
        int mode);

/*
* Set the partition device to read only
* Input parameter
*  dev_fd: file descriptor obtained by partition_dev_open
*  read_only : true means set to read only, false means do not set to read only
* Return: 0 is success , -1 is fail
*/
extern int partition_dev_set_readonly(int dev_fd, bool read_only);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif