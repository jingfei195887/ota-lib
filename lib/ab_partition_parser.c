/*
 * Copyright (c) 2017-2018, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of The Linux Foundation nor
 *       the names of its contributors may be used to endorse or promote
 *       products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NON-INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <assert.h>
#include "crc32.h"
#include "ab_partition_parser.h"
#include "partition_parser.h"
#include "system_cfg.h"
//#define AB_DEBUG

#define PT_WARN PRINTF_CRITICAL
#define PT_INFO PRINTF_INFO
/* Slot suffix */
#define SUFFIX_LEN 2
const char *suffix_slot[] = {"_a",
                             "_b"
                            };
const char *suffix_delimiter = "_";

uint64_t att_val_array[ATTR_NUM] = {
    [ATTR_UNBOOTABLE] = PART_ATT_UNBOOTABLE_VAL,
    [ATTR_ACTIVE] = PART_ATT_ACTIVE_VAL | PART_ATT_PRIORITY_VAL,
    [ATTR_SUCCESSFUL] = PART_ATT_SUCCESSFUL_VAL,
    [ATTR_RETRY] = PART_ATT_MAX_RETRY_COUNT_VAL,
};

static char *ptdev_scan_for_multislot_byname(partition_device_t *part_dev,
        char *name);
static uint32_t find_char(const uint8_t *buf, uint32_t buf_len, const char c)
{
    for (uint32_t i = 0; i < buf_len; i++) {
        if (buf[i] == (uint8_t)c)
            return 1;
    }

    return 0;
}
#if 0
static size_t memscpy(void *dest, size_t dst_size, const void *src,
                      size_t src_size)
{
    size_t copy_size = MIN(dst_size, src_size);
    memcpy(dest, src, copy_size);
    return copy_size;
}
#endif

static void strrev_l(unsigned char *str)
{
    int i;
    int j;
    unsigned char a;
    unsigned len = strlen((const char *)str);

    for (i = 0, j = len - 1; i < j; i++, j--) {
        a = str[i];
        str[i] = str[j];
        str[j] = a;
    }
}

static int itoa_l(int num, unsigned char *str, int len, int base)
{
    int sum = num;
    int i = 0;
    int digit;

    if (len == 0)
        return -1;

    do {
        digit = sum % base;

        if (digit < 0xA)
            str[i++] = '0' + digit;
        else
            str[i++] = 'A' + digit - 0xA;

        sum /= base;
    }
    while (sum && (i < (len - 1)));

    if (i == (len - 1) && sum)
        return -1;

    str[i] = '\0';
    strrev_l(str);
    return 0;
}

/* local functions. */
static void mark_all_partitions_active(partition_device_t *part_dev,
                                       unsigned slot);
void ptdev_mark_active_slot(partition_device_t *part_dev, int slot);

static void
swap_guid(partition_device_t *part_dev, int new_slot);
static char *ptdev_scan_for_multislot_byname(partition_device_t *part_dev,
        char *name);
/*
    Function: To read slot attribute of
        of the partition_entry
*/
static inline bool slot_is_active(struct partition_entry *partition_entries,
                                  unsigned index)
{
    return !!(partition_entries[index].attribute_flag & PART_ATT_ACTIVE_VAL);
}

static inline bool slot_is_sucessful(struct partition_entry *partition_entries,
                                     unsigned index)
{
    return !!(partition_entries[index].attribute_flag &
              PART_ATT_SUCCESSFUL_VAL);
}

static inline uint8_t slot_retry_count(struct partition_entry
                                       *partition_entries,
                                       unsigned index)
{
    return (((partition_entries[index].attribute_flag
              & PART_ATT_MAX_RETRY_COUNT_VAL) >> PART_ATT_MAX_RETRY_CNT_BIT) & 0xFF);
}

static inline uint8_t slot_priority(struct partition_entry *partition_entries,
                                    unsigned index)
{
    return (((partition_entries[index].attribute_flag
              & PART_ATT_PRIORITY_VAL) >> PART_ATT_PRIORITY_BIT) & 0xFF);
}

static inline bool slot_is_bootable(struct partition_entry *partition_entries,
                                    unsigned index)
{
    return !((partition_entries[index].attribute_flag &
              PART_ATT_UNBOOTABLE_VAL) >> PART_ATT_UNBOOTABLE_BIT);
}

static inline uint8_t get_slot_attribute(struct partition_entry
        *partition_entries,
        unsigned index)
{
    return ((partition_entries[index].attribute_flag >> PART_ATT_PRIORITY_BIT) &
            0xFF);
}

int get_inverse_slot(partition_device_t *part_dev, int slot)
{
    if (part_dev->multislot_support)
        return (slot == SLOT_A) ? SLOT_B : SLOT_A;

    return INVALID;
}


int get_ab_slot_attribute(partition_device_t *part_dev, uint32_t *attr)
{
    uint8_t attr_a = 0;
    uint8_t attr_b = 0;
    uint16_t attr_a_b = 0;
    uint16_t attr_a_b_inverse = 0;
    struct partition_entry *partition_entries = ptdev_get_partition_entries(
                part_dev);

    if (!part_dev || !partition_entries || !attr) {
        PT_WARN("Invalide partition dev or attr addr\n");
        return INVALID;
    }

    /* AB slot */
    if (part_dev->multislot_support) {
        attr_a = get_slot_attribute(partition_entries,
                                    part_dev->boot_slot_index[SLOT_A]);
        attr_b = get_slot_attribute(partition_entries,
                                    part_dev->boot_slot_index[SLOT_B]);
    }
    /* for Non-AB slot , attr value is 0 */
    else {
        attr_a = 0;
        attr_b = 0;
    }

    attr_a_b =  attr_a + ((attr_b << 8) & 0xFF00);
    attr_a_b_inverse = PTDEV_AB_SLOT_MASK - attr_a_b;

    /* attr_a_b_inverse + attr_a_b = PTDEV_AB_SLOT_MASK */
    *attr = attr_a_b + ((attr_a_b_inverse << 16) & 0xFFFF0000);

    return 0;
}

static int gpr_attr_check(uint32_t attr)
{
    uint8_t attr_a = 0;
    uint8_t attr_b = 0;
    uint16_t attr_a_b = 0;
    uint16_t attr_a_b_inverse = 0;
    bool actvie_a = 0;
    bool actvie_b = 0;

    attr_a_b = attr & 0xFFFF;
    attr_a_b_inverse = (attr >> 16) & 0xFFFF;

    if (PTDEV_AB_SLOT_MASK != (attr_a_b + attr_a_b_inverse)) {
        PT_WARN("gpr attr value check error, attr = 0x%x, check value = 0x%x\n",
                attr_a_b, attr_a_b_inverse);
        return INVALID;
    }

    attr_a = attr_a_b & 0xFF;
    attr_b = (attr_a_b >> 8) & 0xFF;
    actvie_a = !!(((uint64_t)attr_a << PART_ATT_START_BIT) & PART_ATT_ACTIVE_VAL);
    actvie_b = !!(((uint64_t)attr_b << PART_ATT_START_BIT) & PART_ATT_ACTIVE_VAL);

    if ((true == actvie_a) && (true == actvie_b)) {
        PT_WARN("gpr attr value check error, both a and b is active\n");
        return INVALID;
    }

    return 0;
}

int set_ab_slot_attribute(partition_device_t *part_dev, uint32_t attr)
{
    char *pname = NULL;
    char *suffix_str = NULL;
    int i = 0;
    uint8_t attr_a = 0;
    uint8_t attr_b = 0;
    int partition_count = ptdev_get_partition_count(part_dev);
    struct partition_entry *partition_entries = ptdev_get_partition_entries(
                part_dev);

    if (!part_dev || !partition_entries || !partition_count) {
        PT_WARN("Invalide partition dev addr\n");
        return INVALID;
    }

    /* skip if we have a Non-AB partition */
    if (false == part_dev->multislot_support) {
        PT_INFO("skip attributes setting: partition is Non-AB\n");
        return 0;
    }

    if (0 != gpr_attr_check(attr)) {
        PT_WARN("skip attributes setting: gpr attr check error\n");
        return INVALID;
    }

    attr_a = attr & 0xFF;
    attr_b = (attr >> 8) & 0xFF;

    for (i = 0; i < partition_count; i++) {
        pname = (char *)partition_entries[i].name;
        /* Find partition, if it is A/B enabled */
        suffix_str = ptdev_scan_for_multislot_byname(part_dev, pname);

        if (suffix_str) {
            if (!strcmp(suffix_str, suffix_slot[SLOT_A])) {
                if (get_slot_attribute(partition_entries, i) != attr_a) {
                    partition_entries[i].attribute_flag &= ~PART_ATT_ALL;
                    partition_entries[i].attribute_flag |= ((uint64_t)attr_a << PART_ATT_START_BIT);
                    part_dev->attributes_updated = true;
                }
            }
            else if (!strcmp(suffix_str, suffix_slot[SLOT_B])) {
                if (get_slot_attribute(partition_entries, i) != attr_b) {
                    partition_entries[i].attribute_flag &= ~PART_ATT_ALL;
                    partition_entries[i].attribute_flag |= ((uint64_t)attr_b << PART_ATT_START_BIT);
                    part_dev->attributes_updated = true;
                }
            }
        }
        else {
            if (get_slot_attribute(partition_entries, i) == 0) {
                CLR_BIT(partition_entries[i].attribute_flag,
                        PART_ATT_UNBOOTABLE_BIT);
                CLR_BIT(partition_entries[i].attribute_flag, PART_ATT_SUCCESS_BIT);
                SET_BIT(partition_entries[i].attribute_flag, PART_ATT_ACTIVE_BIT);
                partition_entries[i].attribute_flag |= (PART_ATT_PRIORITY_VAL |
                                                        PART_ATT_MAX_RETRY_COUNT_VAL);
                part_dev->attributes_updated = true;
            }
        }
    }

    if (true == part_dev->attributes_updated) {
        PT_INFO("slot attributes setting to slot_a = 0x%x, attr_b = 0x%x\n", attr_a,
                attr_b);
    }
    else {
        PT_INFO("skip attributes setting: do not need update\n");
    }

    /* update the active slot */
    ptdev_find_active_slot(part_dev);

    if (part_dev->attributes_updated) {
        ptdev_attributes_update(part_dev);
        part_dev->attributes_updated = false;
    }

    return 0;
}

/*
    Function: decrease the slot retry cnt
*/
static void
decrease_slot_retrycnt(partition_device_t *part_dev, unsigned slot)
{
    int i;
    char *pname = NULL;
    char *suffix_str = NULL;
    uint64_t boot_retry_count;
    struct partition_entry *partition_entries;
    int partition_count = 0;

    if (NULL == part_dev) {
        PT_WARN("Invalide partition dev\n");
        return;
    }

    if ( (slot != SLOT_A) && (slot != SLOT_B)) {
        PT_WARN("mark_slot_attr:slot =%d unknown\n", slot);
        return;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);
    partition_count = ptdev_get_partition_count(part_dev);

    for (i = 0; i < partition_count; i++) {
        pname = (char *)partition_entries[i].name;
#ifdef AB_DEBUG
        PT_INFO("Transversing partition %s\n", pname);
#endif

        /* Find partition, if it is A/B enabled */
        suffix_str = ptdev_scan_for_multislot_byname(part_dev, pname);

        if (suffix_str) {
            if (!strcmp(suffix_str, SUFFIX_SLOT(slot))) {
                boot_retry_count = slot_retry_count(partition_entries, i);

                if ((boot_retry_count > 0) && (boot_retry_count < MAX_RETRY_COUNT)) {
                    partition_entries[i].attribute_flag &= ~PART_ATT_MAX_RETRY_COUNT_VAL;
                    partition_entries[i].attribute_flag |= ((boot_retry_count - 1) <<
                                                            PART_ATT_MAX_RETRY_CNT_BIT);
                    part_dev->attributes_updated = true;
                }
            }
        }
    }
}

/*
    Function: Deactive a slot by cleaning all attributes
*/
void
ptdev_deactivate_slot(partition_device_t *part_dev, int slot)
{
    struct partition_entry *partition_entries;
    int count;
    char *pname;
    char *suffix_str = NULL;

    if ((!part_dev) || (!part_dev->partition_entries)) {
        PT_WARN("Invalide partition dev\n");
        return;
    }

    if ((slot != SLOT_A) && (slot != SLOT_B)) {
        PT_WARN("ERROR: slot= %d  wrong slot number\n", slot);
        return;
    }

    count = part_dev->count;
    partition_entries = ptdev_get_partition_entries(part_dev);

    for (int i = 0; i < count; i++) {
        pname = (char *)partition_entries[i].name;

        /* Find partition, if it is A/B enabled */
        suffix_str = ptdev_scan_for_multislot_byname(part_dev, pname);

        if (suffix_str) {
            if (!strcmp(suffix_str, SUFFIX_SLOT(slot))) {
                /* Set Unbootable bit */
                SET_BIT(partition_entries[i].attribute_flag,
                        PART_ATT_UNBOOTABLE_BIT);

                /* Clear Sucess bit and Active bits */
                CLR_BIT(partition_entries[i].attribute_flag, PART_ATT_SUCCESS_BIT);
                CLR_BIT(partition_entries[i].attribute_flag, PART_ATT_ACTIVE_BIT);

                /* Clear Max retry count and priority value */
                partition_entries[i].attribute_flag &= (~PART_ATT_PRIORITY_VAL &
                                                        ~PART_ATT_MAX_RETRY_COUNT_VAL);
                part_dev->attributes_updated = true;
            }
        }
    }

    return;
}

/*
Useage : Active a new slot. use after fisrt start up or after OTA update
*/
void
ptdev_activate_slot(partition_device_t *part_dev, int slot)
{
    struct partition_entry *partition_entries;
    int count;
    char *pname;
    char *suffix_str = NULL;

    if ((!part_dev) || (!part_dev->partition_entries)) {
        PT_WARN( "Invalide partition dev\n");
        return;
    }

    if ((slot != SLOT_A) && (slot != SLOT_B)) {
        PT_WARN( "ERROR: slot= %d  wrong slot number\n", slot);
        return;
    }

    count = part_dev->count;
    partition_entries = ptdev_get_partition_entries(part_dev);

    for (int i = 0; i < count; i++) {
        pname = (char *)partition_entries[i].name;

        /* Find partition, if it is A/B enabled */
        suffix_str = ptdev_scan_for_multislot_byname(part_dev, pname);

        if (suffix_str) {
            if (!strcmp(suffix_str, SUFFIX_SLOT(slot))) {
                /* CLR Unbootable bit and Sucess bit*/
                CLR_BIT(partition_entries[i].attribute_flag, PART_ATT_UNBOOTABLE_BIT);
                CLR_BIT(partition_entries[i].attribute_flag, PART_ATT_SUCCESS_BIT);

                /* Set Active bits */
                SET_BIT(partition_entries[i].attribute_flag, PART_ATT_ACTIVE_BIT);

                /* Set Max retry count and priority value */
                partition_entries[i].attribute_flag |= (PART_ATT_PRIORITY_VAL |
                                                        PART_ATT_MAX_RETRY_COUNT_VAL);
            }
            else {
                /* Clear Active bits and priority value */
                CLR_BIT(partition_entries[i].attribute_flag, PART_ATT_ACTIVE_BIT);
                partition_entries[i].attribute_flag &= (~PART_ATT_PRIORITY_VAL);
            }
        }
        else {
            /* If it isn't A/B enabled, Mark partition as well */
            CLR_BIT(partition_entries[i].attribute_flag,
                    PART_ATT_UNBOOTABLE_BIT);
            CLR_BIT(partition_entries[i].attribute_flag, PART_ATT_SUCCESS_BIT);
            /* Set Active bits */
            SET_BIT(partition_entries[i].attribute_flag, PART_ATT_ACTIVE_BIT);
            /* Set Max retry count and priority value */
            partition_entries[i].attribute_flag |= (PART_ATT_PRIORITY_VAL |
                                                    PART_ATT_MAX_RETRY_COUNT_VAL);
        }

        part_dev->attributes_updated = true;
    }

    return;
}

/*
    Function scan boot partition to find SLOT_A/SLOT_B suffix.
    If found than make multislot_boot flag true and
    scans another partition.
*/
bool ptdev_scan_for_multislot(partition_device_t *part_dev)
{
    uint32_t j, len, count;
    char *tmp1, *tmp2;
    uint32_t partition_count;
    struct partition_entry *partition_entries;

    if ((!part_dev) || (!part_dev->partition_entries)) {
        PT_WARN("Invalide partition dev\n");
        return false;
    }

    partition_count = ptdev_get_partition_count(part_dev);
    partition_entries = ptdev_get_partition_entries(part_dev);

    /* Intialize all slot specific variables */
    part_dev->multislot_support = false;
    part_dev->active_slot = INVALID;
    part_dev->attributes_updated = false;
    part_dev->boot_slot_index[0] = 0;
    part_dev->boot_slot_index[1] = 0;

    if (partition_count > NUM_PARTITIONS) {
        PT_WARN( "ERROR: partition_count more than supported.\n");
        return part_dev->multislot_support;
    }

    int scan_nr = partition_count > MAX_NR_SCAN_FOR_SLOT ? MAX_NR_SCAN_FOR_SLOT
                  : partition_count;

    for (int m = 0; m < scan_nr; m++) {
        tmp1 = (char *)partition_entries[m].name;
        len = strlen(tmp1);

        if (len < 3)
            continue; /* too few, ignore */

        for (int x = m + 1; x < scan_nr; x++) {
            if (!strncmp((const char *)tmp1, (char *)partition_entries[x].name,
                         len - SUFFIX_LEN) && (len == strlen((char *)partition_entries[x].name))) {
                tmp1 = tmp1 + len - SUFFIX_LEN;
                tmp2 = (char *)(partition_entries[x].name + len - SUFFIX_LEN);
                count = 0;

                for (j = 0; j < AB_SUPPORTED_SLOTS; j++) {
                    if (!strcmp(tmp1, suffix_slot[j]) || !strcmp(tmp2, suffix_slot[j]))
                        count++;
                }

                /* Break out of loop if all slot index are found*/
                if (count == AB_SUPPORTED_SLOTS) {
                    part_dev->multislot_support = true;
                    part_dev->boot_slot_index[0] = m;
                    part_dev->boot_slot_index[1] = x;
                    break;
                }
            }
        }

        if (part_dev->multislot_support)
            break;
    }

    return part_dev->multislot_support;
}

/*
    Function scan a partition name to find SLOT_A/SLOT_B suffix.
*/
char *ptdev_scan_for_multislot_byname(partition_device_t *part_dev, char *name)
{
    uint32_t x, j, len, count;
    char *tmp1, *tmp2;
    uint32_t partition_count;
    struct partition_entry *partition_entries;

    if ((!part_dev) || (!part_dev->partition_entries) || (!name)) {
        PT_WARN("Invalide partition dev\n");
        return NULL;
    }

    partition_count = ptdev_get_partition_count(part_dev);
    partition_entries = ptdev_get_partition_entries(part_dev);

    len = strlen(name);

    if (len < 3)
        return NULL;

    for (x = 0; x < partition_count; x++) {
        tmp1 = name;

        if (!strncmp((const char *)tmp1, (char *)partition_entries[x].name,
                     len - SUFFIX_LEN) && (len == strlen((char *)partition_entries[x].name))) {
            tmp1 = tmp1 + len - SUFFIX_LEN;
            tmp2 = (char *)(partition_entries[x].name + len - SUFFIX_LEN);
            count = 0;

            for (j = 0; j < AB_SUPPORTED_SLOTS; j++) {
                if (!strcmp(tmp1, suffix_slot[j]) || !strcmp(tmp2, suffix_slot[j]))
                    count++;
            }

            if (count == AB_SUPPORTED_SLOTS) {
                return tmp1;
            }
        }
    }

    return NULL;
}

/*
    Function: To reset partition attributes
    This function reset partition_priority, retry_count
    and clear successful and bootable bits.
*/
void ptdev_reset_attributes(partition_device_t *part_dev, unsigned index)
{
    struct partition_entry *partition_entries;

    if ((!part_dev) || (!part_dev->partition_entries)) {
        PT_WARN("Invalide partition dev\n");
        return;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);

    partition_entries[index].attribute_flag |= (PART_ATT_PRIORITY_VAL |
            PART_ATT_MAX_RETRY_COUNT_VAL);

    partition_entries[index].attribute_flag &= ((~PART_ATT_SUCCESSFUL_VAL) &
            (~PART_ATT_UNBOOTABLE_VAL));

    if (!part_dev->attributes_updated)
        part_dev->attributes_updated = true;

    /* Make attributes persistant */
    ptdev_mark_active_slot(part_dev, part_dev->active_slot);
}

/*
    Function: Switch active partitions.
*/
static void ptdev_switch_slots(partition_device_t *part_dev, int old_slot,
                               int new_slot)
{
    struct partition_entry *partition_entries;
    int count;
    char *pname;
    char *suffix_str = NULL;

    if ((!part_dev) || (!part_dev->partition_entries)) {
        PT_WARN("Invalide partition dev\n");
        return;
    }

    if ( (old_slot != SLOT_A) && (old_slot != SLOT_B)) {
        PT_WARN("ERROR: old_slot= %d  wrong slot number\n", old_slot);
        return;
    }

    if ( (new_slot != SLOT_A) && (new_slot != SLOT_B)) {
        PT_WARN( "ERROR: new_slot= %d  wrong slot number\n", new_slot);
        return;
    }

    if (new_slot == old_slot) {
        return;
    }

    count = ptdev_get_partition_count(part_dev);
    partition_entries = ptdev_get_partition_entries(part_dev);

    for (int i = 0; i < count; i++) {
        pname = (char *)partition_entries[i].name;

        /* Find partition, if it is A/B enabled */
        suffix_str = ptdev_scan_for_multislot_byname(part_dev, pname);

        if (suffix_str) {
            /*old active slot */
            if (!strcmp(suffix_str, SUFFIX_SLOT(old_slot))) {
                /* Set Unbootable bit */
                SET_BIT(partition_entries[i].attribute_flag,
                        PART_ATT_UNBOOTABLE_BIT);
                /* Clear Sucess bit and Active bits */
                CLR_BIT(partition_entries[i].attribute_flag, PART_ATT_SUCCESS_BIT);
                CLR_BIT(partition_entries[i].attribute_flag, PART_ATT_ACTIVE_BIT);

                /* Clear Max retry count and priority value */
                partition_entries[i].attribute_flag &= (~PART_ATT_PRIORITY_VAL &
                                                        ~PART_ATT_MAX_RETRY_COUNT_VAL);
            }
            /*new active slot */
            else if (!strcmp(suffix_str, SUFFIX_SLOT(new_slot))) {
                /* CLR Unbootable bit*/
                CLR_BIT(partition_entries[i].attribute_flag, PART_ATT_UNBOOTABLE_BIT);
                //CLR_BIT(partition_entries[i].attribute_flag, PART_ATT_SUCCESS_BIT);

                /* Set Active bits */
                SET_BIT(partition_entries[i].attribute_flag, PART_ATT_ACTIVE_BIT);

                /* Set Max retry count and priority value */
                partition_entries[i].attribute_flag |= (PART_ATT_PRIORITY_VAL |
                                                        PART_ATT_MAX_RETRY_COUNT_VAL);
            }
        }
        else {
            CLR_BIT(partition_entries[i].attribute_flag,
                    PART_ATT_UNBOOTABLE_BIT);
            //CLR_BIT(partition_entries[i].attribute_flag, PART_ATT_SUCCESS_BIT);
            SET_BIT(partition_entries[i].attribute_flag, PART_ATT_ACTIVE_BIT);
            partition_entries[i].attribute_flag |= (PART_ATT_PRIORITY_VAL |
                                                    PART_ATT_MAX_RETRY_COUNT_VAL);
        }

        part_dev->attributes_updated = true;
    }

    swap_guid(part_dev, new_slot);
    part_dev->active_slot = new_slot;
    return;
}
/*
    This function returns the most priority and active slot,
    also you need to update the global state seperately.

*/
int ptdev_find_active_slot(partition_device_t *part_dev)
{
    uint8_t current_priority;
    int i, count = 0;
    bool current_active_bit;
    unsigned boot_priority;
    struct partition_entry *partition_entries;
    bool current_bootable_bit;

    if ((!part_dev) || (!part_dev->partition_entries)) {
        PT_WARN("Invalide partition dev\n");
        goto out;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);
#ifdef AB_DEBUG
    PT_INFO( "ptdev_find_active_slot() called\n");
#endif

    /* Return current active slot if already found */
    if (part_dev->active_slot != INVALID)
        goto out;

    for (boot_priority = (MAX_PRIORITY - 1);
            boot_priority >= 0; boot_priority--) {
        /* Search valid boot slot with highest priority */
        for (i = 0; i < AB_SUPPORTED_SLOTS; i++) {
            current_priority = slot_priority(partition_entries,
                                             part_dev->boot_slot_index[i]);
            current_active_bit = slot_is_active(partition_entries,
                                                part_dev->boot_slot_index[i]);
            current_bootable_bit = slot_is_bootable(partition_entries,
                                                    part_dev->boot_slot_index[i]);

            /* Count number of slots with all attributes as zero */
            if ( !current_priority &&
                    !current_active_bit &&
                    current_bootable_bit) {
                count ++;
                continue;
            }

#ifdef AB_DEBUG
            PT_INFO("Slot:Priority:Active:Bootable %s:%d:%d:%d\n",
                    partition_entries[part_dev->boot_slot_index[i]].name,
                    current_priority,
                    current_active_bit,
                    current_bootable_bit);
#endif

            if (boot_priority == current_priority) {
                if (current_active_bit) {
#ifdef AB_DEBUG
                    PT_INFO( "Slot (%s) is Valid High Priority Slot\n", SUFFIX_SLOT(i));
#endif
                    part_dev->active_slot = i;
                    goto out;
                }
            }
        }

        /* All slots are zeroed, this is first bootup */
        /* Marking and trying SLOT 0 as default */
        if (count == AB_SUPPORTED_SLOTS) {
            /* Update the priority of the boot slot */
            ptdev_activate_slot(part_dev, SLOT_A);

            part_dev->active_slot = SLOT_A;

            /* This is required to mark all bits as active,
            for fresh boot post fresh flash */
            part_dev->attributes_updated = true;
            goto out;
        }
    }

out:
    return part_dev->active_slot;
}

/*
   This function check if a slot is bootable
   1 is bootable, 0 is unbootable, -1 is error
*/
int ptdev_check_slot_bootable_attr(partition_device_t *part_dev, unsigned slot)
{
    if ((!part_dev) || (!part_dev->partition_entries)) {
        PT_WARN("Invalide partition dev!\n");
        return -1;
    }

    if ((slot != SLOT_A) && (slot != SLOT_B)) {
        PT_WARN("an INVALID active_slot slot!\n");
        return -1;
    }

    return slot_is_bootable(part_dev->partition_entries,
                            part_dev->boot_slot_index[slot]);
}

/*
    This function check if the system needs roll back
*/
void ptdev_roll_back_check(partition_device_t *part_dev)
{
    int active_slot = INVALID;
    int other_slot;
    uint8_t boot_retry_count = 0;
    struct partition_entry *partition_entries;

    if ((!part_dev) || (!part_dev->partition_entries)) {
        PT_WARN("Invalide partition dev!\n");
        goto out;
    }

    active_slot = ptdev_find_active_slot(part_dev);
    other_slot = get_inverse_slot(part_dev, active_slot);

    if ((active_slot != SLOT_A) && (active_slot != SLOT_B)) {
        PT_WARN("an INVALID active_slot slot!\n");
        goto out;
    }

    if ((other_slot != SLOT_A) && (other_slot != SLOT_B)) {
        PT_WARN("an INVALID inactive_slot slot!\n");
        goto out;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);

#ifndef ALWAYS_ROLL_BACK_CHECK

    /*Do not need fallback, if a active slot's partition flag is set to sucessful and bootable*/
    if ( slot_is_bootable(partition_entries,
                          part_dev->boot_slot_index[active_slot]) &&
            slot_is_sucessful(partition_entries, part_dev->boot_slot_index[active_slot])) {
        PT_INFO("Rollback skip! Active slot%s is Successful and Bootable\n",
                SUFFIX_SLOT(active_slot));
        goto check_update;
    }

    /*Do not need fallback, if a inactive slot's partition flag is not set to sucessful and bootable */
    if ( (!slot_is_bootable(partition_entries,
                            part_dev->boot_slot_index[other_slot])) ||
            (!slot_is_sucessful(partition_entries,
                                part_dev->boot_slot_index[other_slot]))) {
        PT_INFO("Rollback skip! Inactive slot%s is not Successful or not Bootable\n",
                SUFFIX_SLOT(other_slot));
        goto check_update;
    }

    boot_retry_count = slot_retry_count(partition_entries,
                                        part_dev->boot_slot_index[active_slot]);

    if ((boot_retry_count != 0) && (boot_retry_count < MAX_RETRY_COUNT)) {
        /* Decrement retry count, boot from active slot */
        PT_INFO("Rollback decrement Retrycount from %d to %d, boot from slot%s\n",
                boot_retry_count, (boot_retry_count - 1), SUFFIX_SLOT(active_slot));
        decrease_slot_retrycnt(part_dev, active_slot);
    }
    else {
        PT_INFO("Rollback from slot%s to slot%s!\n", SUFFIX_SLOT(active_slot),
                SUFFIX_SLOT(other_slot));
        ptdev_switch_slots(part_dev, active_slot, other_slot);
    }

#else

    if (slot_is_bootable(partition_entries,
                         part_dev->boot_slot_index[active_slot])) {

        boot_retry_count = slot_retry_count(partition_entries,
                                            part_dev->boot_slot_index[active_slot]);

        if ((boot_retry_count != 0) && (boot_retry_count < MAX_RETRY_COUNT)) {
            /* Decrement retry count, boot from active slot */
            PT_INFO("Rollback decrement Retrycount from %d to %d, boot from slot%s\n",
                    boot_retry_count, (boot_retry_count - 1), SUFFIX_SLOT(active_slot));
            decrease_slot_retrycnt(part_dev, active_slot);
            goto check_update;
        }
        else if (slot_is_bootable(partition_entries,
                                  part_dev->boot_slot_index[other_slot])) {
            PT_INFO("Rollback from slot%s to slot%s, decrease retry cnt from 3 to 2!\n",
                    SUFFIX_SLOT(active_slot),
                    SUFFIX_SLOT(other_slot));
            ptdev_switch_slots(part_dev, active_slot, other_slot);
            decrease_slot_retrycnt(part_dev, other_slot);
            goto check_update;

        }
        else {
            PT_INFO("Both slots are unbootable, boot from slot%s!\n", SUFFIX_SLOT(SLOT_A));
            part_dev->attributes_updated = true;
            ptdev_deactivate_slot(part_dev, active_slot);
            part_dev->active_slot = INVALID;
            ptdev_mark_active_slot(part_dev, SLOT_A);
            goto check_update;
        }
    }

    else if (slot_is_bootable(partition_entries,
                              part_dev->boot_slot_index[other_slot])) {
        PT_INFO("slot%s is active but not bootable, Rollback to slot%s, decrease retry cnt from 3 to 2!\n",
                SUFFIX_SLOT(active_slot),
                SUFFIX_SLOT(other_slot));
        ptdev_switch_slots(part_dev, active_slot, other_slot);
        decrease_slot_retrycnt(part_dev, other_slot);
        goto check_update;
    }

    else {
        PT_INFO("slot%s is active and both slots are unbootable, boot from slot_a!\n",
                SUFFIX_SLOT(active_slot));
        ptdev_mark_active_slot(part_dev, SLOT_A);
        goto check_update;
    }

#endif

check_update:

    if (part_dev->attributes_updated) {
        ptdev_attributes_update(part_dev);
        part_dev->attributes_updated = false;
    }

out:
    return;
}

/*
    find the a slot to bootup
*/
int ptdev_find_boot_slot(partition_device_t *part_dev)
{
    int boot_slot = INVALID;

    if (part_dev == NULL) {
        PT_WARN("Invalide partition dev!\n");
        return INVALID;
    }

    boot_slot = ptdev_find_active_slot(part_dev);

    if (boot_slot == INVALID) {
        PT_WARN("can't find a bootable slot!\n");
        return INVALID;
    }

    return boot_slot;
}

int ptdev_find_bootable_slot(partition_device_t *part_dev)
{
    int boot_slot = NOT_FIND, unboot_slot = NOT_FIND;
    int slt_index;
    struct partition_entry *partition_entries;

    if (NULL == part_dev) {
        PT_WARN("part_dev is NULL\n");
        return INVALID;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);

    if (!part_dev->multislot_support) {
        PT_WARN("can't find boot slot, multislot not support.\n");
        return INVALID;
    }

    for (int i = 0; i < AB_SUPPORTED_SLOTS; i++) {
        slt_index = part_dev->boot_slot_index[i];

        if (partition_entries[slt_index].attribute_flag & PART_ATT_UNBOOTABLE_VAL) {
            unboot_slot = i;
            continue;
        }

        boot_slot = i;
    }

    if (unboot_slot == NOT_FIND) {
        PT_INFO("both slots mark as bootable\n");
        return AB_SUPPORTED_SLOTS;
    }

    return boot_slot;
}

int ptdev_find_successfull_slot(partition_device_t *part_dev)
{
    int valid = NOT_FIND, invalid = NOT_FIND;
    int slt_index;
    struct partition_entry *partition_entries;

    if (NULL == part_dev) {
        PT_WARN("part_dev is NULL\n");
        return INVALID;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);

    if (!part_dev->multislot_support) {
        PT_WARN("can't find boot slot, multislot not support.\n");
        return INVALID;
    }

    for (int i = 0; i < AB_SUPPORTED_SLOTS; i++) {
        slt_index = part_dev->boot_slot_index[i];

        if (partition_entries[slt_index].attribute_flag & PART_ATT_SUCCESSFUL_VAL) {
            valid = i;
            continue;
        }

        invalid = i;
    }

    if (invalid == NOT_FIND) {
        PT_INFO("both slots marked as successfull\n");
        return AB_SUPPORTED_SLOTS;
    }

    return valid;

}

int ptdev_get_slot_retrycnt(partition_device_t *part_dev, int slot)
{
    struct partition_entry *partition_entries;
    int boot_retry_count = -1;

    if (NULL == part_dev) {
        PT_WARN("part_dev is NULL\n");
        return INVALID;
    }

    if ((slot != SLOT_A) && (slot != SLOT_B)) {
        PT_WARN("an INVALID slot!\n");
        return INVALID;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);

    if (!part_dev->multislot_support || !partition_entries) {
        PT_WARN("can't find boot slot, multislot not support.\n");
        return INVALID;
    }

    boot_retry_count = slot_retry_count(partition_entries,
                                        part_dev->boot_slot_index[slot]);

    if ((boot_retry_count >= MAX_RETRY_COUNT) || (boot_retry_count < 0)) {
        PT_WARN("boot_retry_count = %d, error\n", boot_retry_count);
        return INVALID;
    }

    return boot_retry_count;
}

/*
    Function: set the slot retry cnt
*/
int set_slot_retrycnt(partition_device_t *part_dev, int slot,
                      uint8_t boot_retry_count)
{
    int i;
    char *pname = NULL;
    char *suffix_str = NULL;
    struct partition_entry *partition_entries;
    int partition_count = 0;
    uint64_t retry_count = boot_retry_count;

    if (NULL == part_dev) {
        PT_WARN("Invalide partition dev\n");
        return INVALID;
    }

    if ( (slot != SLOT_A) && (slot != SLOT_B)) {
        PT_WARN("mark_slot_attr:slot =%d unknown\n", slot);
        return INVALID;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);
    partition_count = ptdev_get_partition_count(part_dev);

    for (i = 0; i < partition_count; i++) {
        pname = (char *)partition_entries[i].name;

        /* Find partition, if it is A/B enabled */
        suffix_str = ptdev_scan_for_multislot_byname(part_dev, pname);

        if (suffix_str) {
            if (!strcmp(suffix_str, SUFFIX_SLOT(slot))) {
                if ((retry_count >= 0) && (retry_count < MAX_RETRY_COUNT)) {
                    partition_entries[i].attribute_flag &= ~PART_ATT_MAX_RETRY_COUNT_VAL;
                    partition_entries[i].attribute_flag |= (retry_count <<
                                                            PART_ATT_MAX_RETRY_CNT_BIT);
                    part_dev->attributes_updated = true;
                }
            }
        }
    }

    return 0;
}

static
void guid_update(struct partition_entry *partition_entries,
                 unsigned old_index,
                 unsigned new_index)
{
    unsigned char tmp_guid[PARTITION_TYPE_GUID_SIZE];

#ifdef AB_DEBUG
    PT_INFO( "Swapping GUID (%s) --> (%s) \n",
             partition_entries[old_index].name,
             partition_entries[new_index].name);
#endif
    memcpy(tmp_guid, partition_entries[old_index].type_guid,
           PARTITION_TYPE_GUID_SIZE);
    memcpy(partition_entries[old_index].type_guid,
           partition_entries[new_index].type_guid,
           PARTITION_TYPE_GUID_SIZE);
    memcpy(partition_entries[new_index].type_guid, tmp_guid,
           PARTITION_TYPE_GUID_SIZE);
    return;
}

/*
    Function to swap guids of slots
*/
static void
swap_guid(partition_device_t *part_dev, int new_slot)
{
    unsigned i, j, tmp_strlen;
    unsigned partition_cnt;
    struct partition_entry *partition_entries;
    const char *ptr_pname, *ptr_suffix;
    int old_slot;

    if (NULL == part_dev) {
        PT_WARN("Invalide partition dev\n");
        return;
    }

    if ((new_slot != SLOT_A) && (new_slot != SLOT_B)) {
        PT_WARN("ERROR: slot= %d  wrong slot number\n", new_slot);
        return;
    }

    if ((part_dev->active_slot != SLOT_B) && (part_dev->active_slot != SLOT_A)) {
        PT_WARN("first set Active, do not need swap guid\n");
        return;
    }

    partition_cnt = ptdev_get_partition_count(part_dev);
    partition_entries = ptdev_get_partition_entries(part_dev);
    old_slot = part_dev->active_slot;

    if ( old_slot == new_slot)
        return;

    for (i = 0; i < partition_cnt; i++) {
        ptr_pname = (const char *)partition_entries[i].name;
        ptr_suffix = ptdev_scan_for_multislot_byname(part_dev, (char *)ptr_pname);

        if (ptr_suffix) {
            /* Search for suffix in partition name */
            if (!strcmp(ptr_suffix, SUFFIX_SLOT(new_slot))) {
                for (j = i + 1; j < partition_cnt; j++) {
                    tmp_strlen = strlen(ptr_pname) - strlen(SUFFIX_SLOT(new_slot));

                    if (!strncmp((const char *)partition_entries[j].name, ptr_pname,
                                 tmp_strlen) &&
                            strstr((const char *)partition_entries[j].name, SUFFIX_SLOT(old_slot))
                            && strlen(ptr_pname) == strlen((char *)partition_entries[j].name))
                        guid_update(partition_entries, j, i);
                }
            }
            else if (!strcmp(ptr_suffix, SUFFIX_SLOT(old_slot))) {
                for (j = i + 1; j < partition_cnt; j++) {
                    tmp_strlen = strlen(ptr_pname) - strlen(SUFFIX_SLOT(old_slot));

                    if (!strncmp((const char *)partition_entries[j].name, ptr_pname,
                                 tmp_strlen) &&
                            strstr((const char *)partition_entries[j].name, SUFFIX_SLOT(new_slot))
                            && strlen(ptr_pname) == strlen((char *)partition_entries[j].name))
                        guid_update(partition_entries, i, j);
                }
            }
        }
    }
}

/*
Function: To set active bit of all partitions of actve slot.
    also, unset active bits of all other slot
*/
void
mark_all_partitions_active(partition_device_t *part_dev, unsigned slot)
{
    int i;
    char *pname = NULL;
    char *suffix_str = NULL;
    struct partition_entry *partition_entries =
        ptdev_get_partition_entries(part_dev);
    int partition_count = ptdev_get_partition_count(part_dev);

    for (i = 0; i < partition_count; i++) {
        pname = (char *)partition_entries[i].name;
#ifdef AB_DEBUG
        PT_INFO( "Transversing partition %s\n", pname);
#endif

        /* Find partition, if it is A/B enabled */
        suffix_str = ptdev_scan_for_multislot_byname(part_dev, pname);

        if (suffix_str) {
            if (!strcmp(suffix_str, SUFFIX_SLOT(slot)))
                /* 2a. Mark matching partition as active. */
                partition_entries[i].attribute_flag |= PART_ATT_ACTIVE_VAL;
            else
                /* 2b. Unset active bit for all other partitions. */
                partition_entries[i].attribute_flag &= ~PART_ATT_ACTIVE_VAL;
        }
        else {
            /* 3. If it isn't A/B enabled, Mark partition as active as well */
            partition_entries[i].attribute_flag |= PART_ATT_ACTIVE_VAL;
        }

        part_dev->attributes_updated = true;
    }
}

/*
    Function: Mark the slot to be active and also conditionally
    update the slot parameters if there is a change.
*/
void ptdev_mark_active_slot(partition_device_t *part_dev, int slot)
{
    if (!part_dev) {
        PT_WARN("Invalide partition dev\n");
        goto out;
    }

    if (part_dev->active_slot == slot)
        goto out;

    if (slot != INVALID) {
        PT_WARN( "Marking (%s) as active\n", SUFFIX_SLOT(slot));

        /* 1. Swap GUID's to new slot */
        swap_guid(part_dev, slot);

        /* 2. Set Active bit for all partitions of active slot */
        mark_all_partitions_active(part_dev, slot);
    }

    part_dev->active_slot = slot;

out:

    if (part_dev->attributes_updated) {
        ptdev_attributes_update(part_dev);
        part_dev->attributes_updated = false;
    }

    return;
}

/*
Function: To mark bit of all partitions of specific slot.
 */
static int mark_slot_attr(partition_device_t *part_dev, int slot,
                          int attr)
{
    int i;
    char *pname = NULL;
    char *suffix_str = NULL;
    uint64_t part_att_val;
    struct partition_entry *partition_entries;
    int partition_count;
    bool attribute_flag_changed = false;

    if (!part_dev || !(part_dev->partition_entries)) {
        PT_WARN("part_dev is NULL\n");
        return INVALID;
    }

    if (attr >= ATTR_NUM) {
        PT_WARN("mark_slot_attr:bad part attribute\n");
        return INVALID;
    }

    if ((slot != SLOT_A) && (slot != SLOT_B)) {
        PT_WARN("mark_slot_attr:slot =%d unknown\n", slot);
        return INVALID;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);
    partition_count = ptdev_get_partition_count(part_dev);

    part_att_val = att_val_array[attr];

    for (i = 0; i < partition_count; i++) {
        pname = (char *)partition_entries[i].name;
#ifdef AB_DEBUG
        PT_INFO("Transversing partition %s\n", pname);
#endif
        /* Find partition, if it is A/B enabled */
        suffix_str = ptdev_scan_for_multislot_byname(part_dev, pname);

        if (suffix_str) {
            if (!strcmp(suffix_str, SUFFIX_SLOT(slot))) {
                /* 2. Mark matching partition as active. */
                if ((partition_entries[i].attribute_flag & part_att_val) != part_att_val) {
                    partition_entries[i].attribute_flag |= part_att_val;
                    attribute_flag_changed = true;
                }
            }
        }
        else if (attr == ATTR_SUCCESSFUL) {
            /* 3. Allow marking none A/B partition ATTR_SUCCESSFUL attr*/
            if ((partition_entries[i].attribute_flag & part_att_val) != part_att_val) {
                partition_entries[i].attribute_flag |= part_att_val;
                attribute_flag_changed = true;
            }
        }
    }

    if (attribute_flag_changed)
        part_dev->attributes_updated = true;

    return 0;
}

/*
Function: To mark bit of all partitions of specific slot.
 */
static int clean_slot_attr(partition_device_t *part_dev, int slot,
                           int attr)
{
    int i;
    char *pname = NULL;
    char *suffix_str = NULL;
    uint64_t part_att_val;
    struct partition_entry *partition_entries;
    int partition_count;
    bool attribute_flag_changed = false;

    if (!part_dev || !(part_dev->partition_entries)) {
        PT_WARN("part_dev is NULL\n");
        return INVALID;
    }

    if (attr >= ATTR_NUM) {
        PT_WARN("clean_slot_attr:bad part attribute\n");
        return INVALID;
    }

    if ((slot != SLOT_A) && (slot != SLOT_B)) {
        PT_WARN("clean_slot_attr:slot =%d unknown\n", slot);
        return INVALID;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);
    partition_count = ptdev_get_partition_count(part_dev);
    part_att_val = att_val_array[attr];

    for (i = 0; i < partition_count; i++) {
        pname = (char *)partition_entries[i].name;
#ifdef AB_DEBUG
        PT_INFO("Transversing partition %s\n", pname);
#endif

        /* Find partition, if it is A/B enabled */
        suffix_str = ptdev_scan_for_multislot_byname(part_dev, pname);

        if (suffix_str) {
            if (!strcmp(suffix_str, SUFFIX_SLOT(slot))) {
                /* Clean matching partition. */
                if ((partition_entries[i].attribute_flag & (~part_att_val)) !=
                        partition_entries[i].attribute_flag) {
                    partition_entries[i].attribute_flag &= ~part_att_val;
                    attribute_flag_changed = true;
                }
            }
        }
    }

    if (attribute_flag_changed)
        part_dev->attributes_updated = true;

    return 0;
}

int
ptdev_mark_slot_attr_noupdate(partition_device_t *part_dev, int slot,
                              int attr)
{
    int inverse_slot;
    int ret = INVALID;

    if (NULL == part_dev) {
        PT_WARN("part_dev is NULL\n");
        goto end;
    }

    if ((slot != SLOT_A) && (slot != SLOT_B)) {
        PT_WARN("slot is error\n");
        goto end;
    }

    if (attr >= ATTR_NUM) {
        PT_WARN("bad part attribute\n");
        goto end;
    }

    if (attr == ATTR_ACTIVE) {
        /* do not need mark */
        if (part_dev->active_slot == slot) {
            ret = 0;
            goto end;
        }

        inverse_slot = get_inverse_slot(part_dev, slot);
        /* 1. Swap GUID's to new slot */
        swap_guid(part_dev, slot);

        /* 2. Set slot as Active */
        if (0 != mark_slot_attr(part_dev, slot, attr))
            goto end;

        /* 3. Set inverse_slot as Inactive */
        if (0 != clean_slot_attr(part_dev, inverse_slot, attr))
            goto end;

        part_dev->active_slot = slot;
    }
    else {
        /* Set attribute for all partitions */
        if (0 != mark_slot_attr(part_dev, slot, attr))
            goto end;
    }

    ret = 0;
end:
    return ret;
}

/*
Function: To mark bit of all partitions of specific slot.
 */
int
ptdev_clean_slot_attr_noupdate(partition_device_t *part_dev, int slot,
                               int attr)
{
    int inverse_slot;
    int ret = INVALID;

    if (NULL == part_dev) {
        PT_WARN("part_dev is NULL\n");
        goto end;
    }

    if ((slot != SLOT_A) && (slot != SLOT_B)) {
        PT_WARN("slot is error\n");
        goto end;
    }

    if (attr >= ATTR_NUM) {
        PT_WARN("bad part attribute\n");
        goto end;
    }

    if (attr == ATTR_ACTIVE) {
        inverse_slot = get_inverse_slot(part_dev, slot);

        /* do not need mark */
        if ((part_dev->active_slot != slot)
                && (part_dev->active_slot == inverse_slot)) {
            ret = 0;
            goto end;
        }

        /* 1. Swap GUID's to new slot */
        swap_guid(part_dev, inverse_slot);

        /* 2. slot mark Active */
        if (0 != clean_slot_attr(part_dev, slot, attr))
            goto end;

        /* 3. inverse_slot mark Inactive */
        if (0 != mark_slot_attr(part_dev, inverse_slot, attr))
            goto end;

        part_dev->active_slot = inverse_slot;
    }
    else {
        /* Set attribute for all partitions */
        if (0 != clean_slot_attr(part_dev, slot, attr))
            goto end;
    }

    ret = 0;
end:
    return ret;
}


/*
Function: To mark bit of all partitions of specific slot.
 */
int ptdev_mark_part_attr(partition_device_t *part_dev, int slot,
                         char *partName, int attr)
{
    int i;
    char *pname = NULL;
    char buf[128] = {0};
    uint64_t part_att_val;
    struct partition_entry *partition_entries;
    int partition_count;

    if (NULL == part_dev) {
        PT_WARN("part_dev is NULL\n");
        return INVALID;
    }

    if (attr >= ATTR_NUM) {
        PT_WARN("bad part attribute\n");
        return INVALID;
    }

    if (slot >= AB_SUPPORTED_SLOTS) {
        PT_WARN("bad slot\n");
        return INVALID;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);
    partition_count = ptdev_get_partition_count(part_dev);
    sprintf(buf, "%s%s", partName, SUFFIX_SLOT(slot));
    part_att_val = att_val_array[attr];

    for (i = 0; i < partition_count; i++) {
        pname = (char *)partition_entries[i].name;
#ifdef AB_DEBUG
        PT_INFO("Transversing partition %s\n", pname);
#endif

        if (!strcmp(pname, buf)) {
            partition_entries[i].attribute_flag |= part_att_val;
            part_dev->attributes_updated = true;
            break;
        }

    }

    if (part_dev->attributes_updated) {
        ptdev_attributes_update(part_dev);
        part_dev->attributes_updated = false;
        return 0;
    }
    else {
        PT_INFO("part %s no found\n", buf);
        return INVALID;
    }
}

/*
Function: To mark bit of all partitions of specific slot.
 */
int ptdev_clean_part_attr(partition_device_t *part_dev, int slot,
                          char *partName, int attr)
{
    int i;
    char *pname = NULL;
    char buf[128] = {0};
    uint64_t part_att_val;
    struct partition_entry *partition_entries;
    int partition_count;

    if (NULL == part_dev) {
        PT_WARN("part_dev is NULL\n");
        return INVALID;
    }

    if (attr > ATTR_NUM) {
        PT_WARN("bad part attribute\n");
        return INVALID;
    }

    if (slot > AB_SUPPORTED_SLOTS) {
        PT_WARN("bad slot\n");
        return INVALID;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);
    partition_count = ptdev_get_partition_count(part_dev);
    sprintf(buf, "%s%s", partName, SUFFIX_SLOT(slot));
    part_att_val = att_val_array[attr];

    for (i = 0; i < partition_count; i++) {
        pname = (char *)partition_entries[i].name;
#ifdef AB_DEBUG
        PT_WARN("Transversing partition %s\n", pname);
#endif

        if (!strcmp(pname, buf)) {
            /* Clean matching partition. */
            partition_entries[i].attribute_flag &= ~part_att_val;
            part_dev->attributes_updated = true;
            break;
        }
    }

    if (part_dev->attributes_updated) {
        ptdev_attributes_update(part_dev);
        part_dev->attributes_updated = false;
        return 0;
    }
    else {
        PT_INFO("part %s no found\n", buf);
        return INVALID;
    }
}

/*
    Function: Mark the slot attribute and update to the
    storage device if there is a change.
 */
int ptdev_mark_slot_attr(partition_device_t *part_dev, int slot, int attr)
{
    if (NULL == part_dev) {
        PT_WARN("part_dev is NULL\n");
        return INVALID;
    }

    if ((slot != SLOT_A) && (slot != SLOT_B)) {
        PT_WARN("slot is error\n");
        return INVALID;
    }

    if (attr > ATTR_NUM) {
        PT_WARN("bad part attribute\n");
        return INVALID;
    }

    if (0 != ptdev_mark_slot_attr_noupdate(part_dev, slot, attr)) {
        return INVALID;
    }

    if (part_dev->attributes_updated) {
        ptdev_attributes_update(part_dev);
        part_dev->attributes_updated = false;
    }

    return 0;
}

/*
    Function: Clean the slot attribute and update to the
    storage device if there is a change.
 */
int ptdev_clean_slot_attr(partition_device_t *part_dev, int slot, int attr)
{
    if (NULL == part_dev) {
        PT_WARN("part_dev is NULL\n");
        return INVALID;
    }

    if ((slot != SLOT_A) && (slot != SLOT_B)) {
        PT_WARN("slot is error\n");
        return INVALID;
    }

    if (attr > ATTR_NUM) {
        PT_WARN("bad part attribute\n");
        return INVALID;
    }

    if (0 != ptdev_clean_slot_attr_noupdate(part_dev, slot, attr)) {
        return INVALID;
    }

    if (part_dev->attributes_updated) {
        ptdev_attributes_update(part_dev);
        part_dev->attributes_updated = false;
    }

    return 0;
}


/* Function to find if multislot is supported */
bool ptdev_multislot_is_supported(partition_device_t *part_dev)
{
    if (!part_dev) {
        PT_WARN("Invalide partition dev\n");
        return false;
    }

    return part_dev->multislot_support;
}

/*
    Function to populate partition meta used
    for fastboot get var info publication.

    Input partition_entries, partition_count and
    buffer to fill information.

 */
int ptdev_fill_partition_meta(partition_device_t *part_dev,
                              char has_slot_pname[][MAX_GET_VAR_NAME_SIZE],
                              char has_slot_reply[][MAX_RSP_SIZE],
                              int array_size)
{
    int i, tmp;
    int count = 0;
    char *pname = NULL;
    int pname_size;
    struct partition_entry *partition_entries;
    int partition_count;
    char *suffix_str;

    if ((!part_dev) || (!part_dev->partition_entries)) {
        PT_WARN("Invalide partition dev\n");
        return 0;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);
    partition_count = ptdev_get_partition_count(part_dev);

    for (i = 0; i < partition_count; i++) {
        pname = (char *)partition_entries[i].name;
        pname_size = strlen(pname);
        suffix_str = NULL;
#ifdef AB_DEBUG
        PT_INFO( "Transversing partition %s\n", pname);
#endif

        /* Find partition, if it is A/B enabled */
        suffix_str = ptdev_scan_for_multislot_byname(part_dev, pname);

        if (suffix_str) {
            if (!strcmp(suffix_str, SUFFIX_SLOT(SLOT_A))) {
                /* 2. put the partition name in array */
                tmp = pname_size - strlen(suffix_str);
                memset(has_slot_pname[count], 0x0, MAX_GET_VAR_NAME_SIZE);
                strncpy(has_slot_pname[count], pname, tmp + 1);
                strncpy(has_slot_reply[count], " Yes", MAX_RSP_SIZE);
                count++;
            }
        }
        else {
            memset(has_slot_pname[count], 0x0, MAX_GET_VAR_NAME_SIZE);
            strncpy(has_slot_pname[count], pname, MAX_GET_VAR_NAME_SIZE);
            strncpy(has_slot_reply[count], " No", MAX_RSP_SIZE);
            count++;
        }

        /* Avoid over population of array provided */
        if (count >= array_size) {
            PT_WARN( "ERROR: Not able to parse all partitions\n");
            return count;
        }
    }

#ifdef AB_DEBUG

    for (i = 0; i < count; i++)
        PT_INFO( "has-slot:%s:%s\n", has_slot_pname[i], has_slot_reply[i]);

#endif
    return count;
}

/*
    Function to populate the slot meta used
    for fastboot get var info publication.
 */
void ptdev_fill_slot_meta(partition_device_t *part_dev,
                          struct ab_slot_info *slot_info)
{
    int i, current_slot_index;
    struct partition_entry *ptn_entries;
    char buff[3];

    if ((!part_dev) || (!part_dev->partition_entries)) {
        PT_WARN("Invalide partition dev\n");
        return;
    }

    if (NULL == slot_info) {
        PT_WARN("slot_info is NULL\n");
        return;
    }

    ptn_entries = ptdev_get_partition_entries(part_dev);

    /* Update slot info */
    for (i = 0; i < AB_SUPPORTED_SLOTS; i++) {
        current_slot_index = part_dev->boot_slot_index[i];
        strncpy(slot_info[i].slot_is_unbootable_rsp,
                slot_is_bootable(ptn_entries, current_slot_index) ? "No" : "Yes",
                MAX_RSP_SIZE);
        strncpy(slot_info[i].slot_is_active_rsp,
                slot_is_active(ptn_entries, current_slot_index) ? "Yes" : "No",
                MAX_RSP_SIZE);
        strncpy(slot_info[i].slot_is_succesful_rsp,
                slot_is_sucessful(ptn_entries, current_slot_index) ? "Yes" : "No",
                MAX_RSP_SIZE);
        itoa_l(slot_retry_count(ptn_entries, current_slot_index),
               (unsigned char *)buff, 2, 10);
        strncpy(slot_info[i].slot_retry_count_rsp, buff, MAX_RSP_SIZE);
    }
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

/*
 * Parse the gpt header and entry's CRC
 * Return 0 on valid signature
 */
static uint32_t
check_gpt(partition_device_t *part_dev, uint8_t *head_buffer,
          uint8_t *entry_buffer,
          struct partition_entry *parent_entry,
          bool secondary_gpt)
{
    uint32_t ret = 1;
    uint32_t crc_val = 0;
    uint32_t crc_val_org = 0;
    unsigned long long last_usable_lba = 0;
    unsigned long long partition_0 = 0;
    unsigned long long current_lba = 0;
    storage_device_t *storage = part_dev->storage;
    uint32_t block_size = storage->block_size;
    uint32_t blocks_for_entries =
        (NUM_PARTITIONS * PARTITION_ENTRY_SIZE) / block_size;
    uint64_t first_usable_lba = 0;
    uint32_t partition_entry_size = 0;
    uint32_t header_size = 0;
    uint32_t max_partition_count = 0;
    uint64_t device_capacity = 0;

    if (!entry_buffer || !head_buffer) {
        PT_WARN( "Input para error\n");
        return 1;
    }

    if (!parent_entry) {
        assert(storage->get_capacity(storage) > part_dev->gpt_offset);
        device_capacity = storage->get_capacity(storage) - part_dev->gpt_offset;
    }
    else {
        device_capacity = (parent_entry->last_lba -
                           parent_entry->first_lba + 1) * block_size;
    }

    /* Check GPT Signature */
    if (((uint32_t *) head_buffer)[0] != GPT_SIGNATURE_2 ||
            ((uint32_t *) head_buffer)[1] != GPT_SIGNATURE_1) {
        PT_WARN("GPT: (WARNING) signature invalid\n");
        return 1;
    }

    header_size = GET_LWORD_FROM_BYTE(&head_buffer[HEADER_SIZE_OFFSET]);

    /* check for header size too small */
    if (header_size < GPT_HEADER_SIZE) {
        PT_WARN("GPT Header size is too small, %d\n", header_size);
        return 1;
    }

    /* check for header size too large */
    if (header_size > block_size) {
        PT_WARN("GPT Header size %d is too large, block size %d, \n", header_size,
                block_size);
        return 1;
    }

    crc_val_org = GET_LWORD_FROM_BYTE(&head_buffer[HEADER_CRC_OFFSET]);

    /* Write CRC to 0 before we calculate the crc of the GPT header */
    crc_val = 0;
    PUT_LONG(&head_buffer[HEADER_CRC_OFFSET], crc_val);
    crc_val  = crc32(0, head_buffer, header_size);

    if (crc_val != crc_val_org) {
        PT_WARN("Header crc mismatch crc_val = 0x%08x with crc_val_org = 0x%08x\n",
                crc_val, crc_val_org);
        return 1;
    }
    else {
        PUT_LONG(&head_buffer[HEADER_CRC_OFFSET], crc_val);
    }

    current_lba =
        GET_LLWORD_FROM_BYTE(&head_buffer[PRIMARY_HEADER_OFFSET]);
    first_usable_lba =
        GET_LLWORD_FROM_BYTE(&head_buffer[FIRST_USABLE_LBA_OFFSET]);
    max_partition_count =
        GET_LWORD_FROM_BYTE(&head_buffer[PARTITION_COUNT_OFFSET]);
    partition_entry_size =
        GET_LWORD_FROM_BYTE(&head_buffer[PENTRY_SIZE_OFFSET]);
    last_usable_lba =
        GET_LLWORD_FROM_BYTE(&head_buffer[LAST_USABLE_LBA_OFFSET]);

    /* current lba and GPT lba should be same */
    if (!secondary_gpt) {
        if (current_lba != GPT_LBA) {
            PT_WARN("Primary GPT first usable LBA mismatch\n");
            return 1;
        }
    }
    else {
        /*
          Check only in case of reading, skip for flashing as this is patched
          in patch_gpt() later in flow.
        */
        if (current_lba != ((device_capacity / block_size) - 1)) {
            PT_WARN("Secondary GPT first usable LBA mismatch\n");
            return 1;
        }
    }

    /* check for first lba should be with in the valid range */
    if (first_usable_lba > (device_capacity / block_size)) {
        PT_WARN("Invalid first usable lba\n");
        PT_WARN("block size = %d\n",  block_size);
        PT_WARN("device capacity = %lld\n", (unsigned long long)device_capacity);
        PT_WARN("first usable_ ba = %lld\n", (unsigned long long)first_usable_lba);
        return 1;
    }

    /* check for last lba should be with in the valid range */
    if (last_usable_lba > (device_capacity / block_size)) {
        PT_WARN("Invalid last usable lba\n");
        PT_WARN("block size = %d\n",  block_size);
        PT_WARN("device capacity = %lld\n", (unsigned long long)device_capacity);
        PT_WARN("last usable lba = %lld\n", (unsigned long long)last_usable_lba);
        return 1;
    }

    /* check for partition entry size */
    if (partition_entry_size != PARTITION_ENTRY_SIZE) {
        PT_WARN("Invalid parition entry size %ld\n",
                (unsigned long)partition_entry_size);
        return 1;
    }

    if ((max_partition_count) > (MIN_PARTITION_ARRAY_SIZE /
                                 (partition_entry_size))) {
        PT_WARN("Invalid parition cont %ld\n", (unsigned long)max_partition_count);
        return 1;
    }

    partition_0 = GET_LLWORD_FROM_BYTE(&head_buffer[PARTITION_ENTRIES_OFFSET]);

    /* start LBA should always be 2 in primary GPT */
    if (!secondary_gpt) {
        if (partition_0 != 0x2) {
            PT_WARN("PrimaryGPT starting LBA mismatch\n");
            return 1;
        }
    }
    else {
        if (partition_0 != ((device_capacity / block_size) -
                            (blocks_for_entries + GPT_HEADER_BLOCKS))) {
            PT_WARN("BackupGPT starting LBA mismatch\n");
            return 1;
        }
    }

    crc_val_org = GET_LWORD_FROM_BYTE(&head_buffer[PARTITION_CRC_OFFSET]);
    crc_val = 0x0;
    crc_val  = crc32(crc_val, entry_buffer,
                     max_partition_count * partition_entry_size);

    if (crc_val != crc_val_org) {
        PT_WARN("Partition entires crc mismatch crc_val= 0x%08x with crc_val_org= 0x%08x\n",
                crc_val, crc_val_org);
        return 1;
    }

    ret = 0;
    return ret;
}

/*
    Function to read and update the attributes of
    GPT
 */
static int
update_gpt(partition_device_t *part_dev, uint64_t gpt_start_addr,
           uint64_t gpt_hdr_offset,
           uint64_t gpt_entries_offset)
{
    uint8_t *gpt_buffer = NULL;
    uint8_t *mbr_buffer = NULL;
    uint8_t *write_buffer = NULL;
    uint8_t *buffer = NULL;
    uint8_t *gpt_entries_ptr, *gpt_hdr_ptr, *tmp = NULL;
    struct partition_entry *partition_entries;
    uint32_t partition_count = 0;
    uint32_t max_partition_count = 0;
    uint32_t partition_entry_size = 0;
    storage_device_t *storage = NULL;
    uint32_t block_size;
    uint32_t crc_val = 0;
    uint32_t crc_read_back = 0;
    int ret = 0;
    uint64_t offset;
    uint64_t max_gpt_size_bytes;
    unsigned char UTF16_name[MAX_GPT_NAME_SIZE] = {0};
    unsigned char name[MAX_GPT_NAME_SIZE] = {0};

    uint32_t mbr_size = 0;
    bool secondary_gpt = (gpt_hdr_offset == 0) ? false : true;
    bool mbr_need_restore = false;
    uint64_t write_addr;
    uint64_t write_size;
    uint32_t partition_type = UINT_MAX;

    if (NULL == part_dev) {
        PT_WARN("part_dev is NULL\n");
        goto out;
    }

    partition_entries = ptdev_get_partition_entries(part_dev);
    partition_count = ptdev_get_partition_count(part_dev);
    storage = part_dev->storage;
    block_size = storage->block_size;
    offset = part_dev->gpt_offset;
    max_gpt_size_bytes =
        (PARTITION_ENTRY_SIZE * NUM_PARTITIONS + GPT_HEADER_BLOCKS * block_size);

    mbr_size = GPT_PMBR_BLOCKS * block_size;

    /* Get Current LUN for UFS target */
    buffer = MEM_ALIGN(block_size, ROUNDUP((max_gpt_size_bytes + mbr_size),
                                           block_size));

    if (!buffer) {
        PT_WARN("update gpt: Failed at memory allocation\n");
        ret = -1;
        goto out;
    }

    mbr_buffer = buffer;
    gpt_buffer = buffer + mbr_size;

    if (!secondary_gpt) {
        /* read mbr */
        ret = read_partition(storage, gpt_start_addr + offset - mbr_size,
                            (uint8_t *)mbr_buffer, mbr_size);

        if (ret) {
            PT_WARN("Failed to read MBR\n");
            ret = -1;
            goto out;
        }
    }
    else {
        /* No offset for Secondary GPT */
        offset = 0;
    }

    ret = read_partition(storage, gpt_start_addr + offset,
                        (uint8_t *)gpt_buffer,
                        max_gpt_size_bytes);

    if (ret) {
        PT_WARN("Failed to read GPT\n");
        ret = -1;
        goto out;
    }

    /* Intialise ptrs for header and entries */
    gpt_entries_ptr = gpt_buffer + gpt_entries_offset * block_size;
    gpt_hdr_ptr = gpt_buffer + gpt_hdr_offset * block_size;

    ret = check_gpt(part_dev, (uint8_t *)gpt_hdr_ptr, (uint8_t *)gpt_entries_ptr,
                    NULL, secondary_gpt);

    if (ret) {
        PT_WARN("Check the read back GPT failed\n");
        ret = -1;
        goto out;
    }

    /* Update attributes_flag of partition entry */
    tmp = gpt_entries_ptr;

    for (unsigned i = 0; i < partition_count; i++) {
        /* Skip sub-partition table entry's guid,
         * because we only write gpt entries to the corresponding gpt table.
         * sub-partition table entries belong to its parent's partition gpt.
         * And there is really no '$' in GPT table.
         * It is not required that partition name is NUL terminated, so it is not appropriate to use strchr here.
         * */
        if (find_char(partition_entries[i].name, MAX_GPT_NAME_SIZE, '$'))
            continue;

        if (memcmp(&tmp[TYPE_GUID_OFFSET], (uint8_t *)(partition_entries[i].type_guid),
                   PARTITION_TYPE_GUID_SIZE)) {
            PT_WARN("type guid not match\n");
            PT_WARN("read:\n");
            hexdump8(&tmp[TYPE_GUID_OFFSET], PARTITION_TYPE_GUID_SIZE);
            PT_WARN("local partition entry:\n");
            hexdump8((uint8_t *)(partition_entries[i].type_guid), PARTITION_TYPE_GUID_SIZE);
            ret = -1;
            goto out;
        }

        if (memcmp(&tmp[UNIQUE_GUID_OFFSET],
                   (uint8_t *)(partition_entries[i].unique_partition_guid),
                   UNIQUE_PARTITION_GUID_SIZE)) {
            PT_WARN("unique guid not match\n");
            PT_WARN("read:\n");
            hexdump8(&tmp[UNIQUE_GUID_OFFSET], UNIQUE_PARTITION_GUID_SIZE);
            PT_WARN("local partition entry:\n");
            hexdump8((uint8_t *)(partition_entries[i].unique_partition_guid),
                     UNIQUE_PARTITION_GUID_SIZE);
            ret = -1;
            goto out;
        }

        memcpy(UTF16_name, &tmp[PARTITION_NAME_OFFSET], MAX_GPT_NAME_SIZE);

        for (uint32_t n = 0; n < MAX_GPT_NAME_SIZE / 2; n++) {
            name[n] = UTF16_name[n * 2];
        }

        if (strcmp((const char *)name, (const char *)(partition_entries[i].name))) {
            PT_WARN("name not match\n");
            PT_WARN("read name %s\n", name);
            PT_WARN("local partition entry name %s\n", (char *)(partition_entries[i].name));
            ret = -1;
            goto out;
        }

        //PT_WARN("read name %s\n", name);

        /* Update the partition attributes */
        PUT_LONG_LONG(&tmp[ATTRIBUTE_FLAG_OFFSET],
                      partition_entries[i].attribute_flag);

        /* point to the next partition entry */
        tmp += PARTITION_ENTRY_SIZE;
    }

    /* Calculate and update CRC of partition entries array */
    max_partition_count =
        GET_LWORD_FROM_BYTE(&gpt_hdr_ptr[PARTITION_COUNT_OFFSET]);
    partition_entry_size =
        GET_LWORD_FROM_BYTE(&gpt_hdr_ptr[PENTRY_SIZE_OFFSET]);

    /* Check for partition entry size */
    if (partition_entry_size != PARTITION_ENTRY_SIZE) {
        PT_WARN( "Invalid parition entry size\n");
        ret = -1;
        goto out;
    }

    /* Check for maximum partition size */
    if ((max_partition_count) > (MIN_PARTITION_ARRAY_SIZE /
                                 (partition_entry_size))) {
        PT_WARN( "Invalid maximum partition count\n");
        ret = -1;
        goto out;
    }

    crc_val  = crc32(0U, gpt_entries_ptr, ((max_partition_count) *
                                           (partition_entry_size)));
    PUT_LONG(&gpt_hdr_ptr[PARTITION_CRC_OFFSET], crc_val);

    /* Write CRC to 0 before we calculate the crc of the GPT header */
    crc_val = 0;
    PUT_LONG(&gpt_hdr_ptr[HEADER_CRC_OFFSET], crc_val);
    crc_val  = crc32(0U, gpt_hdr_ptr, GPT_HEADER_SIZE);
    PUT_LONG(&gpt_hdr_ptr[HEADER_CRC_OFFSET], crc_val);

    if (!secondary_gpt) {
        assert(storage->get_capacity(storage) > part_dev->gpt_offset);

        if (ptdev_get_type(block_size, mbr_buffer, &partition_type)
                || (partition_type != PARTITION_TYPE_GPT)) {
            ret = restore_pmbr_data((struct MBRPartitionTable *)mbr_buffer, \
                                    (storage->get_capacity(storage) - part_dev->gpt_offset), block_size);

            if (ret) {
                PT_WARN("restore pmbr failed\n");
                ret = -1;
                goto out;
            }

            PT_WARN("MBR data restored\n");
            /* primary gpt we write mbr + gpt */
            mbr_need_restore = true;
        }

#if 0
        else {
            PT_WARN("MBR check ok\n");
        }

#endif

        if (storage->need_erase && storage->need_erase(storage)) {
            /* In this case,  MBR will be erased, so need to restore anyway */
            mbr_need_restore = true;
        }

    }

    if (mbr_need_restore) {
        write_addr = gpt_start_addr + offset - mbr_size;
        write_size = max_gpt_size_bytes + mbr_size;
        write_buffer = buffer;
    }
    else {
        write_addr = gpt_start_addr + offset;
        write_size = max_gpt_size_bytes;
        write_buffer = gpt_buffer;
    }

    crc_val  = crc32(0U, write_buffer, write_size);
    /* write to storage */
    ret = write_partition(storage, write_addr,
                         (uint8_t *)write_buffer, write_size);

    if (ret) {
        PT_WARN( "Failed to write gpt\n");
        ret = -1;
        goto out;
    }

    sync();
    memset((uint8_t *)write_buffer, 0, write_size);

    /* readback */
    ret = read_partition(storage, write_addr,
                        (uint8_t *)write_buffer, write_size);

    if (ret) {
        PT_WARN( "Failed to read back gpt\n");
        ret = -1;
        goto out;
    }

    crc_read_back = crc32(0U, write_buffer, write_size);

    if (crc_val != crc_read_back) {
        PT_WARN("crc mismatch : crc write = 0x%08x with crc read back = 0x%08x\n",
                crc_val, crc_read_back);
        ret = -1;
        goto out;
    }

out:

    if (buffer)
        FREE(buffer);

    return ret;
}

/* *
    Function to update the backup and primary gpt
    partition.
* */
int ptdev_attributes_update(partition_device_t *part_dev)
{
    uint64_t offset;
    uint64_t gpt_entries_offset, gpt_hdr_offset;
    uint64_t gpt_start_addr;
    int ret;
    storage_device_t *storage;
    uint32_t block_size;
    unsigned max_entries_size_bytes;
    unsigned max_entries_blocks;
    unsigned max_gpt_blocks;

    if (!part_dev || !part_dev->storage) {
        PT_WARN("part_dev is NULL\n");
        return INVALID;
    }

    storage = part_dev->storage;
    block_size = storage->block_size;
    max_entries_size_bytes = PARTITION_ENTRY_SIZE * NUM_PARTITIONS;
    max_entries_blocks = max_entries_size_bytes / block_size;
    max_gpt_blocks = GPT_HEADER_BLOCKS + max_entries_blocks;
    /* Update Primary GPT */
    offset = 0x01;  /*  offset is 0x1 for primary GPT */
    gpt_start_addr = offset * block_size;
    /* Take gpt_start_addr as start and calculate offset from that in block sz */
    gpt_hdr_offset = 0; /* For primary partition offset is zero */
    gpt_entries_offset = GPT_HEADER_BLOCKS;

    ret = update_gpt(part_dev, gpt_start_addr, gpt_hdr_offset,
                     gpt_entries_offset);

    if (ret) {
        PT_WARN("Failed to update Primary GPT\n");
        return INVALID;
    }

    sync();

    /* Update Secondary GPT */
    offset = ((storage->get_capacity(storage) / block_size) - max_gpt_blocks);
    gpt_start_addr = offset * block_size;
    gpt_hdr_offset = max_entries_blocks;
    gpt_entries_offset = 0; /* For secondary GPT entries offset is zero */

    ret = update_gpt(part_dev, gpt_start_addr, gpt_hdr_offset,
                     gpt_entries_offset);

    if (ret) {
        PT_WARN("Failed to update Secondary GPT\n");
        return INVALID;
    }

    sync();
    return 0;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */