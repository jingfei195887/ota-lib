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

#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include "crc32.h"
#include "partition_parser.h"
#include "ab_partition_parser.h"
#include "storage_device.h"
#include "system_cfg.h"
#define SKIP_MBR 1

#define ERROR(format, args...) PRINTF_CRITICAL(\
                               "[ERROR]GPT: %s %d "format"\n", __func__, __LINE__,  ##args);

#define DBG(format, args...) PRINTF_INFO(\
                               "[DEBUG]GPT: %s %d "format"\n", __func__, __LINE__,  ##args);

#define ASSERT(condition) \
    if (!(condition)) { \
       abort(); \
    }

/* just for debug */
int ptdev_read_table_remote(partition_device_t *part_dev)
{
    unsigned i = 0;
    unsigned partition_count;
    struct partition_entry *partition_entries;

    if (!part_dev) {
        PRINTF_CRITICAL("Invalid partition dev\n");
        goto fail;
    }

    if (part_dev->partition_entries) {
        FREE(part_dev->partition_entries);
        part_dev->partition_entries = NULL;
    }

    partition_count = (part_dev->count > NUM_PARTITIONS) ? NUM_PARTITIONS :
                      part_dev->count;
    part_dev->partition_entries = (struct partition_entry *) CALLOC(
                                      partition_count, sizeof(struct partition_entry));

    if (!part_dev->partition_entries) {
        goto fail;
    }

    partition_entries = part_dev->partition_entries;

    for (i = 0; i < partition_count; i++) {
        if (0 != part_dev->storage->get_partition_info(part_dev->storage,
                (const char *)part_dev->name, i, &partition_entries[i])) {
            PRINTF_CRITICAL("get partition %s info error\n", (const char *)part_dev->name);
            goto fail;
        }

        partition_entries[i].size = (partition_entries[i].last_lba + 1 -
                                     partition_entries[i].first_lba);
    }

    return 0;

fail:

    if (part_dev && part_dev->partition_entries) {
        FREE(part_dev->partition_entries);
        part_dev->partition_entries = NULL;
    }

    return -1;
}

/* just for debug: Print all parsed partitions */
void ptdev_dump_remote(partition_device_t *part_dev)
{
    unsigned i = 0;
    unsigned partition_count;

    if (!part_dev) {
        PRINTF_CRITICAL("Invalid partition dev\n");
        return;
    }

    if (0 != ptdev_read_table_remote(part_dev)) {
        PRINTF_CRITICAL("read remote partiton error\n");
        return;
    }

    partition_count = part_dev->count;

    for (i = 0; i < partition_count; i++) {
        PRINTF_CRITICAL("ptn[%d]:Name[%s] Size[%llu] Type[%u] First[%llu] Last[%llu]\n",
                        i, (const char *)(part_dev->partition_entries[i].name),
                        part_dev->partition_entries[i].size,
                        part_dev->partition_entries[i].dtype,
                        part_dev->partition_entries[i].first_lba,
                        part_dev->partition_entries[i].last_lba);
    }
}

/* just for debug: Print all parsed partitions flag */
void ptdev_attr_dump_remote(partition_device_t *part_dev)
{
    const char *a, *b, *s;
    unsigned long long retry = 0;
    unsigned long long priority = 0;
    unsigned partition_count;

    if (!part_dev) {
        PRINTF_CRITICAL("Invalid partition dev\n");
        return;
    }

    if (0 != ptdev_read_table_remote(part_dev)) {
        PRINTF_CRITICAL("read remote partiton error\n");
        return;
    }

    partition_count = part_dev->count;
    PRINTF_INFO("active  bootable  success  retry   priority    name\n");

    for (int i = 0; i < partition_count; i++) {
        a = (!!(part_dev->partition_entries[i].attribute_flag & PART_ATT_ACTIVE_VAL)) ?
            "Y" : "N";
        b = (!!(part_dev->partition_entries[i].attribute_flag &
                PART_ATT_UNBOOTABLE_VAL)) ? "N" :
            "Y";
        s = (!!(part_dev->partition_entries[i].attribute_flag &
                PART_ATT_SUCCESSFUL_VAL)) ? "Y" :
            "N";
        retry = (part_dev->partition_entries[i].attribute_flag &
                 PART_ATT_MAX_RETRY_COUNT_VAL) >>
                PART_ATT_MAX_RETRY_CNT_BIT;
        priority = (part_dev->partition_entries[i].attribute_flag &
                    PART_ATT_PRIORITY_VAL) >>
                   PART_ATT_PRIORITY_BIT;
        PRINTF_INFO("  %s       %s         %s        %llx      %llx     %s\n",
                    a, b, s, retry, priority, (const char *)(part_dev->partition_entries[i].name));
    }
}

/*
 * Find index of parition in array of partition entries
 */
unsigned int ptdev_get_index_remote(partition_device_t *part_dev,
                                    const char *name)
{
    unsigned int index = INVALID_PTN;

    if (!part_dev || !name  || !part_dev->storage->get_partition_size) {
        PRINTF_CRITICAL("Invalide partition dev\n");
        return INVALID_PTN;
    }

    index = part_dev->storage->get_partition_index(part_dev->storage,
            (const char * )(part_dev->name), name);
    return index;
}

/* Get size of the partition */
unsigned long long ptdev_get_size_remote(partition_device_t *part_dev,
        const char *name)
{
    unsigned long long size = 0;

    if (!part_dev || !name || !part_dev->storage->get_partition_size) {
        PRINTF_CRITICAL("Invalide partition dev\n");
        return 0;
    }

    size = part_dev->storage->get_partition_size(part_dev->storage,
            (const char * )(part_dev->name), name);
    return size;
}

/* Get offset of the partition */
unsigned long long ptdev_get_offset_remote(partition_device_t *part_dev,
        const char *name)
{
    unsigned long long offset = 0;

    if (!part_dev || !name || !part_dev->storage->get_partition_offset) {
        PRINTF_CRITICAL("Invalide partition dev\n");
        return 0;
    }

    offset = part_dev->storage->get_partition_offset(part_dev->storage,
             (const char * )(part_dev->name), name);
    return offset;
}

/* Function to find if multislot is supported */
bool ptdev_multislot_is_supported_remote(partition_device_t *part_dev)
{
    if (!part_dev) {
        PRINTF_CRITICAL("Invalide partition dev\n");
        return false;
    }

    return part_dev->multislot_support;
}

/*
    This function returns the most priority and active slot,
    also you need to update the global state seperately.

 */
int ptdev_find_active_slot_remote(partition_device_t *part_dev)
{
    signed active_slot = -1;

    if (!part_dev || !part_dev->storage || !part_dev->storage->get_current_slot) {
        PRINTF_CRITICAL("Invalide partition dev\n");
        return -1;
    }

    active_slot = part_dev->storage->get_current_slot(part_dev->storage, \
                  (const char *)part_dev->name);

    return active_slot;
}

int ptdev_mark_slot_attr_noupdate_remote(partition_device_t *part_dev,
        unsigned slot, int attr)
{
    uint8_t value = 1;

    if (!part_dev || !part_dev->storage || !part_dev->storage->set_slot_attr) {
        PRINTF_CRITICAL("Invalide partition dev\n");
        return -1;
    }

    if (attr == ATTR_RETRY)
        value = 3;

    if (0 != part_dev->storage->set_slot_attr(part_dev->storage,
            (const char *)part_dev->name, (uint8_t)slot, attr, value)) {
        PRINTF_CRITICAL("ptdev mark slot attr noupdate remote failed\n");
        return -1;
    }

    return 0;
}

int ptdev_clean_slot_attr_noupdate_remote(partition_device_t *part_dev,
        unsigned slot, int attr)
{
    uint8_t value = 0;

    if (!part_dev || !part_dev->storage || !part_dev->storage->set_slot_attr) {
        PRINTF_CRITICAL("Invalide partition dev\n");
        return -1;
    }

    if (0 != part_dev->storage->set_slot_attr(part_dev->storage,
            (const char *)part_dev->name, (uint8_t)slot, attr, value)) {
        PRINTF_CRITICAL("ptdev clean slot attr noupdate remote failed\n");
        return -1;
    }

    return 0;
}

int ptdev_attributes_update_remote(partition_device_t *part_dev)
{
    if (!part_dev || !part_dev->storage || !part_dev->storage->update_slot_attr) {
        PRINTF_CRITICAL("Invalide partition dev\n");
        return -1;
    }

    if (0 != part_dev->storage->update_slot_attr(part_dev->storage,
            (const char *)part_dev->name)) {
        PRINTF_CRITICAL("ptdev update slot attr remote failed\n");
        return -1;
    }

    return 0;
}

int ptdev_mark_slot_attr_remote(partition_device_t *part_dev, unsigned slot,
                                int attr)
{
    uint8_t value = 1;

    if (!part_dev || !part_dev->storage || !part_dev->storage->set_slot_attr) {
        PRINTF_CRITICAL("Invalide partition dev\n");
        return -1;
    }

    if (attr == ATTR_RETRY)
        value = 3;

    if (0 != part_dev->storage->set_slot_attr(part_dev->storage,
            (const char *)part_dev->name, (uint8_t)slot, attr, value)) {
        return -1;
    }

    if (0 != ptdev_attributes_update_remote(part_dev)) {
        return -1;
    }

    return 0;
}

int ptdev_clean_slot_attr_remote(partition_device_t *part_dev, unsigned slot,
                                 int attr)
{
    uint8_t value = 0;

    if (!part_dev || !part_dev->storage || !part_dev->storage->set_slot_attr) {
        PRINTF_CRITICAL("Invalide partition dev\n");
        return -1;
    }

    if (0 != part_dev->storage->set_slot_attr(part_dev->storage,
            (const char *)part_dev->name, (uint8_t)slot, attr, value)) {
        return -1;
    }

    if (0 != ptdev_attributes_update_remote(part_dev)) {
        return -1;
    }

    return 0;
}

int ptdev_get_slot_attr_remote(partition_device_t *part_dev, unsigned slot,
                               int attr)
{
    int ret = -1;

    if (!part_dev || !part_dev->storage || !part_dev->storage->get_slot_attr) {
        PRINTF_CRITICAL("Invalide partition dev\n");
        return -1;
    }

    ret = part_dev->storage->get_slot_attr(part_dev->storage,
                                           (const char *)part_dev->name, (uint8_t)slot, attr);
    return ret;
}

partition_device_t *setup_ptdev_remote(storage_device_t *storage,
                                       const char *ptdev_name, uint64_t gpt_offset)
{
    int slot = -1;
    int count = -1;

    if (!storage || !ptdev_name) {
        PRINTF_CRITICAL("storage or ptdev_name pointer is null\n");
        return NULL;
    }

    if (strlen(ptdev_name) >= MAX_GPT_NAME_SIZE) {
        PRINTF_CRITICAL("partition table name too long\n");
        return NULL;
    }

    partition_device_t *part_dev = CALLOC(1, sizeof(partition_device_t));

    if (!part_dev) {
        PRINTF_CRITICAL("partition table name too long\n");
        return NULL;
    }

    part_dev->storage = storage;
    part_dev->gpt_offset = gpt_offset;

    if (storage->setup_ptdev(storage, ptdev_name)) {
        FREE(part_dev);
        PRINTF_CRITICAL("failed to setup remote ptdev\n");
        return NULL;
    }

    slot = storage->get_slot_number(storage, ptdev_name);

    if (-1 == slot) {
        FREE(part_dev);
        PRINTF_CRITICAL("get slot number error\n");
        return NULL;
    }

    count = storage->get_partition_number(storage, ptdev_name);

    if (-1 == count) {
        FREE(part_dev);
        PRINTF_CRITICAL("get partition number error\n");
        return NULL;
    }

    snprintf((char *)(part_dev->name), MAX_GPT_NAME_SIZE, "%s", ptdev_name);
    part_dev->multislot_support = (slot == AB_SUPPORTED_SLOTS) ? true : false;
    part_dev->count = count;
    part_dev->partition_entries = NULL;
    part_dev->local = false;

    return part_dev;
}

unsigned int ptdev_destroy_remote(partition_device_t *part_dev)
{
    if (part_dev->storage->destroy_ptdev(part_dev->storage,
                                         (char *)(part_dev->name))) {
        PRINTF_CRITICAL("failed to destroy remote ptdev\n");
    }

    if (part_dev->partition_entries) {
        FREE(part_dev->partition_entries);
    }

    if (part_dev) {
        FREE(part_dev);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
