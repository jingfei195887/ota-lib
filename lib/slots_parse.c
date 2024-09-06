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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <malloc.h>
#if RUN_IN_ANDROID
#include <cutils/properties.h>
#endif
#include "system_cfg.h"
#include "ab_partition_parser.h"
#include "slots_parse.h"
#include "storage_device.h"
#include "storage_dev_ospi.h"
#include "update_device.h"

#ifdef RUN_IN_QNX
#include <sys/dcmd_cam.h>
#include <hw/dcmd_sim_sdmmc.h>
#include <sys/dcmd_blk.h>
#include <sd_prop.h>
#else
#include <linux/fs.h>
#endif

#define BOOT_SLOT_PROP_ANDROID     "ro.boot.slot_suffix"
#define BOOT_SUFFIX_STR(x)         "slot_suffix=_"#x""
#define BOOT_SUFFIX_LEN            15  //length of string :"slot_suffix=_a" is 14
#define BOOT_SUFFIX_SCAN_FORMAT    "%14s"
#define BOOT_SUFFIX_FIND_LIMIT     200

#if !RUN_IN_ANDROID && SUPPORT_PROPERTY_LIB
#include "libprop.h"
#endif

signed get_slot_suffix_info()
{
#if RUN_IN_ANDROID && (RUN_IN_HOST == 0)
    unsigned i = 0;
    char boot_slot_property[PROPERTY_VALUE_MAX] = {'\0'};
    property_get(BOOT_SLOT_PROP_ANDROID, boot_slot_property, "N/A");

    for (i = 0; i < AB_SUPPORTED_SLOTS ; i++) {
        if (!strcmp((char *)boot_slot_property, SUFFIX_SLOT(i))) {
            PRINTF_INFO("get slots suffix = %s\n", SUFFIX_SLOT(i));
            return i;
        }
    }

#else
    FILE *fp;
#ifndef RUN_IN_QNX
    const char *cmdline = "/proc/cmdline";
#else
    const char *cmdline = "/dev/scmdline";
#endif
    char boot_slot_property[BOOT_SUFFIX_LEN] = {'\0'};
    int limit = BOOT_SUFFIX_FIND_LIMIT;

    fp = fopen(cmdline, "r");

    if (fp == NULL) {
        PRINTF_CRITICAL("open %s error %s\n", cmdline, strerror(errno));
        return -1;
    }

    fseek(fp, 0, SEEK_SET);

    do {
        memset(boot_slot_property, 0, BOOT_SUFFIX_LEN);

        if (fscanf(fp, BOOT_SUFFIX_SCAN_FORMAT, boot_slot_property) < 0) {
            PRINTF_INFO("scan cmdline error\n");
            fclose(fp);
            return -1;
        }

        //PRINTF_INFO("slot_suffix = %s\n", boot_slot_property);
        if (!strcmp(boot_slot_property, BOOT_SUFFIX_STR(a))) {
            PRINTF_INFO("%s\n", boot_slot_property);
            fclose(fp);
            return 0;
        }

        if (!strcmp(boot_slot_property, BOOT_SUFFIX_STR(b))) {
            PRINTF_INFO("%s\n", boot_slot_property);
            fclose(fp);
            return 1;
        }
    }
    while (limit--);

    fclose(fp);
#endif

    PRINTF_INFO("current suffix %s can not be identified\n", boot_slot_property);
    return -1;
}

unsigned get_number_slots(partition_device_t *ptdev)
{
    signed ret = -1;
    ret = get_slot_suffix_info();

    if ((ret != SLOT_A) && (ret != SLOT_B)) {
        PRINTF_CRITICAL("ret %d error, slot number is 1\n", ret);
        return 1;
    }

    return AB_SUPPORTED_SLOTS;
}

#ifdef SUPPORT_PART_UPDATE_ISOLATED
unsigned get_current_slot(partition_device_t *ptdev)
{
    if(!ptdev) {
        PRINTF_CRITICAL("partition error\n");
        return INVALID;
    }

    /* logical slot, not physics */
    if (ptdev_multislot_is_supported(ptdev)) {
        return SLOT_A;
    }

    return INVALID;
}
#else
unsigned get_current_slot(partition_device_t *ptdev)
{
    signed ret = -1;

    if(!ptdev) {
        PRINTF_CRITICAL("partition error\n");
        return UINT_MAX;
    }

    ret = get_slot_suffix_info();

    if ((ret != SLOT_A) && (ret != SLOT_B)) {
        PRINTF_CRITICAL("get current slot %d error\n", ret);
        return UINT_MAX;
    }

    return ret;
}
#endif

int mark_boot_successful(partition_device_t *ptdev)
{
    signed active_slot;

    if(!ptdev) {
        PRINTF_CRITICAL("partition error\n");
        return INVALID;
    }

    active_slot = get_current_slot(ptdev);

    if ((active_slot != SLOT_A) && (active_slot != SLOT_B)) {
        PRINTF_CRITICAL("active_slot %d error\n", active_slot);
        return INVALID;
    }

    return set_slot_as_successful(ptdev, active_slot);
}

int set_slot_as_successful(partition_device_t *ptdev, unsigned slot)
{
    partition_device_t ptdev_inst = {0};
    partition_device_t* ptdev_temp = &ptdev_inst;
    struct partition_entry* entry_temp;

    if(!ptdev) {
        PRINTF_CRITICAL("partition error\n");
        return INVALID;
    }

    if (true == ptdev->local) {
        /*copy ptdev, copy entry*/
        if(ptdev->count > NUM_PARTITIONS) {
            PRINTF_CRITICAL("ptdev->count %d error\n", ptdev->count);
            return INVALID;
        }

        entry_temp = (struct partition_entry*)MEM_ALIGN(CACHE_LINE, sizeof(struct partition_entry) * ptdev->count);
        if(!entry_temp) {
            PRINTF_CRITICAL("entry temp calloc failed\n");
            return INVALID;
        }

        memcpy(ptdev_temp, ptdev, sizeof(partition_device_t));
        memset(entry_temp, 0, sizeof(struct partition_entry) * ptdev->count);
        memcpy(entry_temp, ptdev->partition_entries, sizeof(struct partition_entry) * ptdev->count);
        ptdev_temp->partition_entries = entry_temp;

        if (0 != ptdev_mark_slot_attr_noupdate(ptdev_temp, slot, ATTR_SUCCESSFUL)) {
            PRINTF_CRITICAL("set local slot %d for ATTR_SUCCESSFUL error\n", slot);
            FREE(entry_temp);
            return INVALID;
        }

        if (0 != ptdev_mark_slot_attr_noupdate(ptdev_temp, slot, ATTR_RETRY)) {
            PRINTF_CRITICAL("set local slot %d for ATTR_RETRY error\n", slot);
            FREE(entry_temp);
            return INVALID;
        }

        if (0 != ptdev_clean_slot_attr_noupdate(ptdev_temp, slot, ATTR_UNBOOTABLE)) {
            PRINTF_CRITICAL("clr local slot %d for ATTR_UNBOOTABLE error\n", slot);
            FREE(entry_temp);
            return INVALID;
        }

        if (ptdev_temp->attributes_updated) {
            if (0 != ptdev_attributes_update(ptdev_temp)) {
                PRINTF_CRITICAL("update local partition error\n");
                FREE(entry_temp);
                return INVALID;
            }

            ptdev_temp->attributes_updated = false;
            /* copy entry and active slot */
            ptdev->active_slot = ptdev_temp->active_slot;
            memcpy(ptdev->partition_entries, entry_temp, sizeof(struct partition_entry) * ptdev->count);
            FREE(entry_temp);
        }
    }

    else if ((false == ptdev->local) && (STORAGE_REMOTE == ptdev->storage->type)) {
        if (0 != ptdev_mark_slot_attr_noupdate_remote(ptdev, slot,
                ATTR_SUCCESSFUL)) {
            PRINTF_CRITICAL("set remote slot %d for ATTR_SUCCESSFUL error\n", slot);
            return INVALID;
        }

        if (0 != ptdev_mark_slot_attr_noupdate_remote(ptdev, slot, ATTR_RETRY)) {
            PRINTF_CRITICAL("set remote slot %d for ATTR_RETRY error\n", slot);
            return INVALID;
        }

        if (0 != ptdev_clean_slot_attr_noupdate_remote(ptdev, slot,
                ATTR_UNBOOTABLE)) {
            PRINTF_CRITICAL("clr remote slot %d for ATTR_UNBOOTABLE error\n", slot);
            return INVALID;
        }

        if (0 != ptdev_attributes_update_remote(ptdev)) {
            PRINTF_CRITICAL("update remote partition error\n");
            return INVALID;
        }
    }

    else {
        PRINTF_CRITICAL("invalid partition type\n");
        return INVALID;
    }

    return 0;
}

int set_active_boot_slot(partition_device_t *ptdev, unsigned slot)
{
    partition_device_t ptdev_inst = {0};
    partition_device_t* ptdev_temp = &ptdev_inst;
    struct partition_entry* entry_temp;

    if(!ptdev) {
        PRINTF_CRITICAL("partition error\n");
        return INVALID;
    }

    if (true == ptdev->local) {
        /*copy ptdev, copy entry*/
        if(ptdev->count > NUM_PARTITIONS) {
            PRINTF_CRITICAL("ptdev->count %d error\n", ptdev->count);
            return INVALID;
        }

        entry_temp = (struct partition_entry*)MEM_ALIGN(CACHE_LINE, sizeof(struct partition_entry) * ptdev->count);
        if(!entry_temp) {
            PRINTF_CRITICAL("entry temp calloc failed\n");
            return INVALID;
        }

        memcpy(ptdev_temp, ptdev, sizeof(partition_device_t));
        memset(entry_temp, 0, sizeof(struct partition_entry) * ptdev->count);
        memcpy(entry_temp, ptdev->partition_entries, sizeof(struct partition_entry) * ptdev->count);
        ptdev_temp->partition_entries = entry_temp;

        if (0 != ptdev_mark_slot_attr_noupdate(ptdev_temp, slot, ATTR_ACTIVE)) {
            PRINTF_CRITICAL("set local slot %d for ATTR_ACTIVE error\n", slot);
            FREE(entry_temp);
            return INVALID;
        }

        if (0 != ptdev_mark_slot_attr_noupdate(ptdev_temp, slot, ATTR_RETRY)) {
            PRINTF_CRITICAL("set local slot %d for ATTR_RETRY error\n", slot);
            FREE(entry_temp);
            return INVALID;
        }

        if (0 != ptdev_clean_slot_attr_noupdate(ptdev_temp, slot, ATTR_UNBOOTABLE)) {
            PRINTF_CRITICAL("clr local slot %d for ATTR_UNBOOTABLE error\n", slot);
            FREE(entry_temp);
            return INVALID;
        }

        if (ptdev_temp->attributes_updated) {
            if (0 != ptdev_attributes_update(ptdev_temp)) {
                PRINTF_CRITICAL("update local partition error\n");
                FREE(entry_temp);
                return INVALID;
            }

            ptdev_temp->attributes_updated = false;
            /* copy entry and active slot */
            ptdev->active_slot = ptdev_temp->active_slot;
            memcpy(ptdev->partition_entries, entry_temp, sizeof(struct partition_entry) * ptdev->count);
            FREE(entry_temp);
        }
    }
    else if ((false == ptdev->local) && (STORAGE_REMOTE == ptdev->storage->type)) {
        if (0 != ptdev_mark_slot_attr_noupdate_remote(ptdev, slot, ATTR_ACTIVE)) {
            PRINTF_CRITICAL("set remote slot %d for ATTR_ACTIVE error\n", slot);
            return INVALID;
        }

        if (0 != ptdev_mark_slot_attr_noupdate_remote(ptdev, slot, ATTR_RETRY)) {
            PRINTF_CRITICAL("set remote slot %d for ATTR_RETRY error\n", slot);
            return INVALID;
        }

        if (0 != ptdev_clean_slot_attr_noupdate_remote(ptdev, slot, ATTR_UNBOOTABLE)) {
            PRINTF_CRITICAL("clr remote slot %d for ATTR_UNBOOTABLE error\n", slot);
            return INVALID;
        }

        if (0 != ptdev_attributes_update_remote(ptdev)) {
            PRINTF_CRITICAL("update remote partition error\n");
            return INVALID;
        }
    }
    else {
        PRINTF_CRITICAL("invalid partition type\n");
        return INVALID;
    }

    return 0;
}

int set_slot_as_unbootable(partition_device_t *ptdev, unsigned slot)
{
    partition_device_t ptdev_inst = {0};
    partition_device_t* ptdev_temp = &ptdev_inst;
    struct partition_entry* entry_temp;

    if(!ptdev) {
        PRINTF_CRITICAL("partition error\n");
        return INVALID;
    }

    if (true == ptdev->local) {
        /*copy ptdev, copy entry*/
        if(ptdev->count > NUM_PARTITIONS) {
            PRINTF_CRITICAL("ptdev->count %d error\n", ptdev->count);
            return INVALID;
        }

        entry_temp = (struct partition_entry*)MEM_ALIGN(CACHE_LINE, sizeof(struct partition_entry) * ptdev->count);
        if(!entry_temp) {
            PRINTF_CRITICAL("entry temp calloc failed\n");
            return INVALID;
        }

        memcpy(ptdev_temp, ptdev, sizeof(partition_device_t));
        memset(entry_temp, 0, sizeof(struct partition_entry) * ptdev->count);
        memcpy(entry_temp, ptdev->partition_entries, sizeof(struct partition_entry) * ptdev->count);
        ptdev_temp->partition_entries = entry_temp;

        if (0 != ptdev_clean_slot_attr_noupdate(ptdev_temp, slot, ATTR_ACTIVE)) {
            PRINTF_CRITICAL("clr local slot %d for ATTR_ACTIVE error\n", slot);
            FREE(entry_temp);
            return INVALID;
        }

        if (0 != ptdev_clean_slot_attr_noupdate(ptdev_temp, slot, ATTR_RETRY)) {
            PRINTF_CRITICAL("clr local slot %d for ATTR_RETRY error\n", slot);
            FREE(entry_temp);
            return INVALID;
        }

        if (0 != ptdev_clean_slot_attr_noupdate(ptdev_temp, slot, ATTR_SUCCESSFUL)) {
            PRINTF_CRITICAL("clr local slot %d for ATTR_SUCCESSFUL error\n", slot);
            FREE(entry_temp);
            return INVALID;
        }

        if (0 != ptdev_mark_slot_attr_noupdate(ptdev_temp, slot, ATTR_UNBOOTABLE)) {
            PRINTF_CRITICAL("set local slot %d for ATTR_UNBOOTABLE error\n", slot);
            FREE(entry_temp);
            return INVALID;
        }

        if (ptdev_temp->attributes_updated) {
            if (0 != ptdev_attributes_update(ptdev_temp)) {
                PRINTF_CRITICAL("update local partition error\n");
                FREE(entry_temp);
                return INVALID;
            }

            ptdev_temp->attributes_updated = false;
            /* copy entry and active slot */
            ptdev->active_slot = ptdev_temp->active_slot;
            memcpy(ptdev->partition_entries, entry_temp, sizeof(struct partition_entry) * ptdev->count);
            FREE(entry_temp);
        }

    }

    else if ((false == ptdev->local) && (STORAGE_REMOTE == ptdev->storage->type)) {
        if (0 != ptdev_clean_slot_attr_noupdate_remote(ptdev, slot, ATTR_ACTIVE)) {
            PRINTF_CRITICAL("clr remote slot %d for ATTR_ACTIVE error\n", slot);
            return INVALID;
        }

        if (0 != ptdev_clean_slot_attr_noupdate_remote(ptdev, slot, ATTR_RETRY)) {
            PRINTF_CRITICAL("clr remote slot %d for ATTR_RETRY error\n", slot);
            return INVALID;
        }

        if (0 != ptdev_clean_slot_attr_noupdate_remote(ptdev, slot, ATTR_SUCCESSFUL)) {
            PRINTF_CRITICAL("clr remote slot %d for ATTR_SUCCESSFUL error\n", slot);
            return INVALID;
        }

        if (0 != ptdev_mark_slot_attr_noupdate_remote(ptdev, slot, ATTR_UNBOOTABLE)) {
            PRINTF_CRITICAL("set remote slot %d for ATTR_UNBOOTABLE error\n", slot);
            return INVALID;
        }

        if (0 != ptdev_attributes_update_remote(ptdev)) {
            PRINTF_CRITICAL("update remote partition error\n");
            return INVALID;
        }
    }

    else {
        PRINTF_CRITICAL("invalid partition type\n");
        return INVALID;
    }


    return 0;
}

int set_slot_as_unsuccessful(partition_device_t *ptdev, unsigned slot)
{
    partition_device_t ptdev_inst = {0};
    partition_device_t* ptdev_temp = &ptdev_inst;
    struct partition_entry* entry_temp;

    if(!ptdev) {
        PRINTF_CRITICAL("partition error\n");
        return INVALID;
    }

    if (true == ptdev->local) {
        /*copy ptdev, copy entry*/
        if(ptdev->count > NUM_PARTITIONS) {
            PRINTF_CRITICAL("ptdev->count %d error\n", ptdev->count);
            return INVALID;
        }

        entry_temp = (struct partition_entry*)MEM_ALIGN(CACHE_LINE, sizeof(struct partition_entry) * ptdev->count);
        if(!entry_temp) {
            PRINTF_CRITICAL("entry temp calloc failed\n");
            return INVALID;
        }

        memcpy(ptdev_temp, ptdev, sizeof(partition_device_t));
        memset(entry_temp, 0, sizeof(struct partition_entry) * ptdev->count);
        memcpy(entry_temp, ptdev->partition_entries, sizeof(struct partition_entry) * ptdev->count);
        ptdev_temp->partition_entries = entry_temp;

        if (0 != ptdev_clean_slot_attr_noupdate(ptdev_temp, slot, ATTR_SUCCESSFUL)) {
            PRINTF_CRITICAL("clr local slot %d for ATTR_SUCCESSFUL error\n", slot);
            FREE(entry_temp);
            return INVALID;
        }

        if (ptdev_temp->attributes_updated) {
            if (0 != ptdev_attributes_update(ptdev_temp)) {
                PRINTF_CRITICAL("update local partition error\n");
                FREE(entry_temp);
                return INVALID;
            }

            ptdev_temp->attributes_updated = false;
            /* copy entry and active slot */
            ptdev->active_slot = ptdev_temp->active_slot;
            memcpy(ptdev->partition_entries, entry_temp, sizeof(struct partition_entry) * ptdev->count);
            FREE(entry_temp);
        }
    }

    else if ((false == ptdev->local) && (STORAGE_REMOTE == ptdev->storage->type)) {
        if (0 != ptdev_clean_slot_attr_noupdate_remote(ptdev, slot, ATTR_SUCCESSFUL)) {
            PRINTF_CRITICAL("clr remote slot %d for ATTR_SUCCESSFUL error\n", slot);
            return INVALID;
        }

        if (0 != ptdev_attributes_update_remote(ptdev)) {
            PRINTF_CRITICAL("update remote partition error\n");
            return INVALID;
        }
    }

    else {
        PRINTF_CRITICAL("invalid partition type\n");
        return INVALID;
    }

    return 0;
}

int is_slot_bootable(partition_device_t *ptdev, unsigned slot)
{
    int ret = -1;

    if(!ptdev) {
        PRINTF_CRITICAL("partition error\n");
        return INVALID;
    }

    if (true == ptdev->local) {
        ret = ptdev_find_bootable_slot(ptdev);

        if (INVALID == ret) {
            return INVALID;
        }

        if (ret == AB_SUPPORTED_SLOTS)
            return 1;
        else
            return (ret == slot) ? 1 : 0;
    }

    else if ((false == ptdev->local) && (STORAGE_REMOTE == ptdev->storage->type)) {
        ret = ptdev_get_slot_attr_remote(ptdev,  (uint8_t)slot, ATTR_UNBOOTABLE);

        if (INVALID == ret) {
            return INVALID;
        }

        PRINTF_INFO("return %d\n", (ret == 1) ? 0 : 1);
        return (ret == 1) ? 0 : 1;

    }

    else {
        PRINTF_CRITICAL("invalid partition type\n");
        return INVALID;
    }

    return ret;
}

const char *get_suffix(partition_device_t *ptdev, unsigned slot)
{
    if (slot < AB_SUPPORTED_SLOTS)
        return suffix_slot[slot];

    return NULL;
}


static const char *_get_suffix_(unsigned slot)
{
    if (slot < AB_SUPPORTED_SLOTS)
        return suffix_slot[slot];

    return NULL;
}

int is_slot_marked_successful(partition_device_t *ptdev, unsigned slot)
{
    int ret = -1;

    if(!ptdev) {
        PRINTF_CRITICAL("partition error\n");
        return INVALID;
    }

    if (true == ptdev->local) {
        ret = ptdev_find_successfull_slot(ptdev);

        if (INVALID == ret) {
            return INVALID;
        }

        if (ret == AB_SUPPORTED_SLOTS)
            ret = 1;
        else if (ret == slot)
            ret = 1;
        else
            ret = 0;

        if (ret == 1) {
            if (0 != ptdev_mark_slot_attr(ptdev, slot, ATTR_RETRY)) {
                return INVALID;
            }
        }
    }
    else if ((false == ptdev->local) && (STORAGE_REMOTE == ptdev->storage->type)) {
        ret = ptdev_get_slot_attr_remote(ptdev,  (uint8_t)slot, ATTR_SUCCESSFUL);

        if (INVALID == ret) {
            return INVALID;
        }

        if (ret == 1) {
            if (0 != ptdev_mark_slot_attr_noupdate_remote(ptdev, slot, ATTR_RETRY)) {
                return INVALID;
            }

            if (0 != ptdev_attributes_update_remote(ptdev)) {
                return INVALID;
            }
        }
    }

    else {
        PRINTF_CRITICAL("invalid partition type\n");
        return INVALID;
    }

    return ret;
}

#if RUN_IN_QNX
static int flush_disk_cache_for_partition(storage_device_t *storage)
{
    int retry = 3;
    int ret = 0;
    //flush disk cache before read for QNX system with cmd DCMD_FSYS_PGCACHE_CTL
    pgcache_ctl_t ctl1 = {
        .op = DCMD_FSYS_PGCACHE_CTL_OP_DISCARD,
        .discard = {0,  0, 0x43FF},
    };

    pgcache_ctl_t ctl2 = {
        .op = DCMD_FSYS_PGCACHE_CTL_OP_DISCARD,
        .discard = {0,  storage->capacity - 0x4400, storage->capacity - 1},
    };

reflush:
    /* flush primary GPT */
    ret = devctl(storage->dev_fd, DCMD_FSYS_PGCACHE_CTL, &ctl1,
                 sizeof(struct pgcache_ctl), NULL);

    if (ret != EOK) {
        PRINTF_CRITICAL("block dev flush cache failed: %s %d\n", strerror(errno),
                        errno);

        if ((errno == EAGAIN) && retry--) {
            PRINTF_CRITICAL("flush again\n");
            goto reflush;
        }

        PRINTF_CRITICAL("block dev flush cache error\n");
        return INVALID;
    }

    /* flush secondary GPT */
    retry = 3;
    ret = devctl(storage->dev_fd, DCMD_FSYS_PGCACHE_CTL, &ctl2,
                 sizeof(struct pgcache_ctl), NULL);

    if (ret != EOK) {
        PRINTF_CRITICAL("block dev flush cache failed: %s %d\n", strerror(errno),
                        errno);

        if ((errno == EAGAIN) && retry--) {
            PRINTF_CRITICAL("flush again\n");
            goto reflush;
        }

        PRINTF_CRITICAL("block dev flush cache error\n");
        return INVALID;
    }

    return 0;
}
#else
static int flush_disk_cache_for_partition(storage_device_t *storage)
{
    sync();

    if (ioctl(storage->dev_fd, BLKFLSBUF) != 0) {
        PRINTF_CRITICAL("failed to flush dev\n");
        return -1;
    }

    return 0;
    /*
        int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
        if (fd == -1) {
            PRINTF_CRITICAL("Failed to open /proc/sys/vm/drop_caches");
            return -1;
        }

        if (write(fd, "1", 1) != 1) {
            PRINTF_CRITICAL("Failed to write to /proc/sys/vm/drop_caches");
            close(fd);
            return -1;
        }

        close(fd);
        return 0;
    */
}
#endif

int switch_storage_dev_force_local_flexible(partition_device_t **ptdev,
        storage_id_e dev)
{
    storage_device_t *storage = NULL;
    update_device_t *update_device;
    *ptdev = NULL;
    KEYNODE("setup local flexible ptdev for %s\n", get_update_device_name(dev));
    update_device = setup_update_dev(dev);

    if (!update_device) {
        if (get_update_device_is_active(dev)) {
            PRINTF_CRITICAL("failed to setup update device\n");
        }

        return INVALID;
    }

    storage = get_update_device_storage(dev);
    *ptdev = ptdev_setup(storage, update_device->gpt_offset);

    if (!*ptdev) {
        PRINTF_CRITICAL("failed to setup ptdev\n");
        return INVALID;
    }

    if (storage->type == STORAGE_LOCAL) {
        if (flush_disk_cache_for_partition(storage)) {
            PRINTF_CRITICAL("failed to flush disk cache\n");
            ptdev_destroy(*(partition_device_t **)ptdev);
            *ptdev = NULL;
            return INVALID;
        }
    }

    if (ptdev_read_table(*(partition_device_t **)ptdev)) {
        PRINTF_CRITICAL("failed to read ptdev\n");
        ptdev_destroy(*(partition_device_t **)ptdev);
        *ptdev = NULL;
        return INVALID;
    }

    KEYNODE("setup local flexible ptdev for %s success\n",
            get_update_device_name(dev));
    return 0;
}


int switch_storage_dev_force_local(partition_device_t **ptdev, storage_id_e dev)
{
    storage_device_t *storage = NULL;
    update_device_t *update_device;
    *ptdev = NULL;
    KEYNODE("setup local ptdev for %s\n", get_update_device_name(dev));
    update_device = setup_update_dev(dev);

    if (!update_device) {
        if (get_update_device_is_active(dev)) {
            PRINTF_CRITICAL("failed to setup update device\n");
        }

        return INVALID;
    }

    if (update_device->ptdev != NULL) {
        PRINTF_CRITICAL("alread have a ptdev in update_device %s destroy it\n",
                        update_device->name);
        free_storage_dev_force_local(update_device->ptdev);
        update_device->ptdev = NULL;
    }

    storage = get_update_device_storage(dev);
    *ptdev = ptdev_setup(storage, update_device->gpt_offset);

    if (!*ptdev) {
        PRINTF_CRITICAL("failed to setup ptdev\n");
        return INVALID;
    }

    if (storage->type == STORAGE_LOCAL) {
        if (flush_disk_cache_for_partition(storage)) {
            PRINTF_CRITICAL("failed to flush disk cache\n");
            ptdev_destroy(*(partition_device_t **)ptdev);
            *ptdev = NULL;
            return INVALID;
        }
    }

    if (ptdev_read_table(*(partition_device_t **)ptdev)) {
        PRINTF_CRITICAL("failed to read ptdev\n");
        ptdev_destroy(*(partition_device_t **)ptdev);
        *ptdev = NULL;
        return INVALID;
    }

    update_device->ptdev = *ptdev;
    return 0;
}

int switch_storage_dev(partition_device_t **ptdev, storage_id_e dev)
{
    storage_device_t *storage = NULL;
    update_device_t  *update_device = NULL;
    *ptdev = NULL;

    if (strlen(get_update_device_name(dev))) {
        KEYNODE("setup ptdev for %s\n", get_update_device_name(dev));
    }

    if (dev < 0 || dev >= DEV_MAX) {
        PRINTF_CRITICAL("storage id error %d\n", dev);
        return INVALID;
    }

    update_device = setup_update_dev(dev);

    if (!update_device || !(update_device->storage)) {
        if (get_update_device_is_active(dev)) {
            PRINTF_CRITICAL("failed to setup update dev\n");
        }

        return INVALID;
    }

    storage = get_update_device_storage(dev);

    if (update_device->ptdev != NULL) {
        PRINTF_CRITICAL("alread have a ptdev in update_device %s destroy it\n",
                        update_device->name);
        free_storage_dev(update_device->ptdev);
        update_device->ptdev = NULL;
    }

    if ((storage->type == STORAGE_LOCAL)
            || (!strcmp(get_update_device_name(dev), BASE_DEV_NAME_OSPI))) {
        *(partition_device_t **)ptdev = ptdev_setup(storage, update_device->gpt_offset);

        if (!*ptdev) {
            PRINTF_CRITICAL("failed to setup ptdev\n");
            return INVALID;
        }


        if (storage->type == STORAGE_LOCAL) {
            if (flush_disk_cache_for_partition(storage)) {
                PRINTF_CRITICAL("failed to flush disk cache\n");
                ptdev_destroy(*(partition_device_t **)ptdev);
                *ptdev = NULL;
                return INVALID;
            }
        }


        if (ptdev_read_table(*(partition_device_t **)ptdev)) {
            PRINTF_CRITICAL("failed to read ptdev\n");
            ptdev_destroy(*(partition_device_t **)ptdev);
            *ptdev = NULL;
            return INVALID;
        }
    }
    else {

        *(partition_device_t **)ptdev = \
                                        setup_ptdev_remote(storage, update_device->name, update_device->gpt_offset);

        if (!*ptdev) {
            PRINTF_CRITICAL("failed to setup ptdev\n");
            return INVALID;
        }
    }

    update_device->ptdev = *ptdev;

    /* need to holdup ap2 when non-ab OTA */
    if (is_in_android_recovery() && get_number_slots(*ptdev) == 1) {
        holdup_ap2();
    }

    return 0;
}

int free_storage_dev_force_local(partition_device_t *ptdev)
{
    if (!ptdev) {
        PRINTF_CRITICAL("ptdev is null\n");
        return INVALID;
    }

    for (int i = 0; i < DEV_MAX; i++) {
        if (get_update_device_ptdev(i) == ptdev) {
            set_update_device_ptdev(i, NULL);
        }

    }

    ptdev_destroy(ptdev);
    return 0;
}

int free_storage_dev(partition_device_t *ptdev)
{
    if (!ptdev) {
        PRINTF_CRITICAL("ptdev is null\n");
        return INVALID;
    }

    for (int i = 0; i < DEV_MAX; i++) {
        if (get_update_device_ptdev(i) == ptdev) {
            set_update_device_ptdev(i, NULL);
        }
    }

    if ((ptdev->storage) && (STORAGE_REMOTE == ptdev->storage->type)
            && (false == ptdev->local)) {
        ptdev_destroy_remote((partition_device_t *)ptdev);
    }
    else {
        ptdev_destroy((partition_device_t *)ptdev);
    }

    return 0;
}

int check_ptdev_exist(storage_id_e dev)
{
    partition_device_t **ptdev = get_update_device_ptdev_pointer(dev);

    if (NULL == *ptdev) {
        KEYNODE("new setup ptdev %s for partition check\n", get_update_device_name(dev));

        if (switch_storage_dev(ptdev, dev)) {
            PRINTF_CRITICAL("failed to init ptdev in %s\n", get_update_device_name(dev));
            free_storage_dev(*ptdev);
            *ptdev = NULL;
            return -1;
        }
    }

    return 0;
}

/* Debug: Print all parsed partitions */
void ptdev_dump(partition_device_t *ptdev)
{
    if (true == ptdev->local) {
        ptdev_dump_local(ptdev);
    }

    else if ((false == ptdev->local) && (STORAGE_REMOTE == ptdev->storage->type)) {
        ptdev_dump_remote(ptdev);
    }

    else {
        PRINTF_CRITICAL("invalid partition type\n");
    }
}

void ptdev_attr_dump(partition_device_t *ptdev)
{
    if (true == ptdev->local) {
        ptdev_attr_dump_local(ptdev);
    }

    else if ((false == ptdev->local) && (STORAGE_REMOTE == ptdev->storage->type)) {
        ptdev_attr_dump_remote(ptdev);
    }

    else {
        PRINTF_CRITICAL("invalid partition type\n");
    }
}

#ifdef SUPPORT_PART_UPDATE_ISOLATED
int setAttributeByPartition(partition_device_t *ptdev, unsigned slot,
                            char *partName, part_attr_t attr)
{
    /* TODO */
    return 0;
}

int clearAttributeByPartition(partition_device_t *ptdev, unsigned slot,
                              char *partName, part_attr_t attr)
{
    /* TODO */
    return 0;
}

#else

int setAttributeByPartition(partition_device_t *ptdev, unsigned slot,
                            char *partName, part_attr_t attr)
{
    return ptdev_mark_part_attr(ptdev, slot, partName, attr);
}

int clearAttributeByPartition(partition_device_t *ptdev, unsigned slot,
                              char *partName, part_attr_t attr)
{
    return ptdev_clean_part_attr(ptdev, slot, partName, attr);
}
#endif


void ptdev_dump_all()
{
    for (int i = 0; i < DEV_MAX; i++) {
        if (!get_update_device_is_active(i)) {
            continue;
        }

        if (get_update_device_ptdev(i)) {
            ptdev_dump(get_update_device_ptdev(i));
            ptdev_attr_dump(get_update_device_ptdev(i));
        }
    }
}

int boot_control_init_all(void)
{
    int ret = -1;
    int val = -1;
    int i = 0;
    PRINTF_INFO("---OTA lib version %s---\n", OTA_LIB_VERSION)

    for (i = 0; i < DEV_MAX; i++) {
        /* Call the partition table creation interface firstly,
        and then exclude the update device that is not activated,
        because the process of creating a partition table will
        trigger the update device self-test. The self-test process
        will activate some update devices.
        */
        val = switch_storage_dev(get_update_device_ptdev_pointer(i), i);

        if ((val || get_update_device_ptdev(i) == NULL)) {
            if (get_update_device_is_active(i) == true) {
                PRINTF_INFO("failed to setup ptdev %s\n", get_update_device_name(i));
                goto end;
            }
            else {
                continue;
            }
        }

#if 0
        /* dump ptdev */
        PRINTF_INFO("dump ptdev for %s.\n", get_update_device_name(i));
        ptdev_dump(get_update_device_ptdev(i));
        ptdev_attr_dump(get_update_device_ptdev(i));
#endif

    }

    /* make sure that there is at lease one GPT init success */
    if (i != 0) {
        ret = 0;
    }

end:

    if (0 == ret) {
        PRINTF_INFO("init boot control for all GPT success \n");
    }
    else {
        PRINTF_CRITICAL("failed to init boot control for all GPT\n");
        if(is_in_android_userdebug()) {
            PRINTF_CRITICAL("find system is in userdebug mode, return success anyway\n");
            ret = 0;
        }
    }

    if(AB_SUPPORTED_SLOTS != get_number_slots_all()) {
        PRINTF_INFO("partition is non-ab , try to stop safety wdt\n");
        stop_safety_wdt();
    }

    return ret;
}

unsigned get_number_slots_all(void)
{
    signed ret = -1;
    ret = get_slot_suffix_info();

    if ((ret != SLOT_A) && (ret != SLOT_B)) {
        return 1;
    }

    return AB_SUPPORTED_SLOTS;
}

unsigned get_current_slot_all(void)
{
    signed ret = -1;
    ret = get_slot_suffix_info();

    if ((ret != SLOT_A) && (ret != SLOT_B)) {
        return UINT_MAX;
    }

    return ret;
}

unsigned get_inverse_slot_all(unsigned slot)
{
    if ((slot != SLOT_A) && (slot != SLOT_B)) {
        return UINT_MAX;
    }

    return (slot == SLOT_A) ? SLOT_B : SLOT_A;
}

static int get_sub_system_status(char *sub_system_name)
{
#if CHECK_SUB_SYSTEM_SUCCESS_BY_PROPERTY
#if RUN_IN_ANDROID && (RUN_IN_HOST == 0)
    char boot_slot_property[PROPERTY_VALUE_MAX] = {'\0'};
#else
    char boot_slot_property[100] = {0};
#endif
    int retry_time = WAIT_STATUS_TIME;
    int ret = -1;

    do {

#if RUN_IN_ANDROID && !RUN_IN_HOST
        if (is_in_android_recovery()) {
            PRINTF_INFO("SKIP sub_system check for %s in recovery mode\n", sub_system_name);
            return 0;
        }
#endif

        if (!strcmp(sub_system_name, "mmc1_mpc")) {
#if !RUN_IN_HOST
            property_get(MP_SYSTEM_PROPERTY, boot_slot_property, "N/A");
#endif
        }
        else if (!strcmp(sub_system_name, "mmc1_ap2")) {
#if !RUN_IN_HOST
            property_get(AP2_SYSTEM_PROPERTY, boot_slot_property, "N/A");
#endif
        }
        else {
            PRINTF_INFO("get sub_system status for %s is skipped\n", sub_system_name);
            return 0;
        }

        if (!strcmp((char *)boot_slot_property, SUB_SYSTEM_OK)) {
            PRINTF_INFO("get sub_system status for %s ok\n", sub_system_name);
            ret = 0;
            break;
        }
        else {
            PRINTF_CRITICAL("get sub_system status for %s failed, value is %s, retry_time is %d(s)\n",
                            sub_system_name, boot_slot_property, retry_time);
            ret = -1;

            if (retry_time > 0) {
                usleep(1000000);
            }
        }
    }
    while (retry_time-- > 0);

#if RUN_IN_ANDROID && !RUN_IN_HOST

    if (ret != 0) {
        if (is_in_android_userdebug()) {
            PRINTF_INFO("SKIP sub_system check for %s, build type is userdebug\n", sub_system_name);
            return 0;
        }
        else {
            PRINTF_CRITICAL("check sub_system status for %s failed, build type not userdebug\n", sub_system_name);
        }
    }

#endif

    return ret;
#elif MP_SYSTEM_CHECK_BY_RPMSG
    int retry_time = WAIT_STATUS_TIME_BY_RPMSG;
    int ret = -1;

    do {
        if (!strcmp(sub_system_name, "mmc1_mpc")) {
            if (!check_mpc_status()) {
                PRINTF_INFO("get sub system status by rpmsg for %s ok\n", sub_system_name);
                ret = 0;
                break;
            }
            else {
                PRINTF_CRITICAL("get sub system status by rpmsg for %s failed, retry_time is %d(s)\n",
                                sub_system_name, retry_time);
                ret = -1;

                if (retry_time > 0) {
                    usleep(1000000);
                }
            }
        }
        else {
            PRINTF_INFO("get sub_system status for %s is skipped\n", sub_system_name);
            return 0;
        }
    }
    while (retry_time-- > 0);

    return ret;
#else
    return 0;
#endif
}

int mark_boot_successful_all(void)
{
    int i = 0;
    int ret;

    PRINTF_INFO("mark_boot_successful_all start\n");

    /* check sub-system status */
    for (i = 0; i < DEV_MAX; i++) {
        if (!get_update_device_is_active(i)) {
            continue;
        }

        if (get_sub_system_status(get_update_device_name(i))) {
            PRINTF_CRITICAL("get %s successful flag error\n", get_update_device_name(i));
            return -1;
        }
    }
    PRINTF_INFO("boot successful\n");

    if(is_uniform_rollback_need() && is_skip_uniform_rollback_need() == DO_NOT_SKIP_UNIFORM_ROLLBACK)
    {
        set_ota_status_property(STATUS_BOOT);
        if (wait_for_opposite_ota_status_property(4, STATUS_BOOT, STATUS_BOTH_BOOT, STATUS_MARK, WAIT_FOR_PROPERTY_ALWAYS) != 1)
        {
            return -1;
        }
        set_ota_status_property(STATUS_BOTH_BOOT);
        PRINTF_INFO("ur: opposite status is boot\n");
    }

    ret = set_slot_as_successful_all(get_current_slot_all());
    if(ret != 0)
    {
        return ret;
    }
    PRINTF_INFO("mark successful\n");

    if(is_uniform_rollback_need() && is_skip_uniform_rollback_need() == DO_NOT_SKIP_UNIFORM_ROLLBACK) {
        set_ota_status_property(STATUS_MARK);
        if(wait_for_opposite_ota_status_property(3, STATUS_MARK, STATUS_BOTH_MARK, WAIT_FOR_PROPERTY_ALWAYS) != 1) {
            return -1;
        }
        PRINTF_INFO("ur: opposite status is mark\n");
        set_local_uniform_rollback(LOCAL_UNIFORM_ROLLBACK_OPPOSITE_UNCONFIRMED);
        stop_safety_wdt();
        set_skip_uniform_rollback_value(SKIP_UNIFORM_ROLLBACK);
        set_ota_status_property(STATUS_BOTH_MARK);
        if(wait_for_opposite_ota_status_property(3, STATUS_BOTH_MARK, STATUS_END, 3*SLEEP_TIME_INTERVAL) != 1) {
            return 0;
        }
        set_local_uniform_rollback(LOCAL_UNIFORM_ROLLBACK_OFF);
        set_ota_status_property(STATUS_END);
        PRINTF_INFO("ur: opposite status is both mark\n");
    }
    else {
        stop_safety_wdt();
    }

    return 0;

}

const char *get_suffix_all(unsigned slot)
{
    int i = 0;
    const char *suffix[DEV_MAX] = {NULL};
    const char *first = NULL;
    bool get_first = false;

    for (i = 0; i < DEV_MAX; i++) {
        if (!get_update_device_is_active(i)) {
            continue;
        }

        if (get_update_device_ptdev(i) == NULL) {
            PRINTF_CRITICAL("ptdev %s is null\n", get_update_device_name(i));
            return NULL;
        }

        suffix[i] = get_suffix(get_update_device_ptdev(i), slot);
        PRINTF_INFO("slot suffix for %s is %s\n", get_update_device_name(i), suffix[i]);

        if (suffix[i] == NULL) {
            PRINTF_CRITICAL("results error, suffix[%d] is NULL\n", i);
            return NULL;
        }

        if (false == get_first) {
            get_first = true;
            first = suffix[i];
        }
        else {
            if (strcmp(first, suffix[i]) || (first == NULL)) {
                PRINTF_CRITICAL("get suffix results are inconsistent, first result = %s, suffix[%d] = %s\n",
                                first, i, suffix[i]);
                return NULL;
            }
        }
    }

    return first;
}

int set_active_boot_slot_all(unsigned slot)
{
    int ret[DEV_MAX];
    int i = 0;
    const char *suffix = _get_suffix_(slot);
    char *name = NULL;
    partition_device_t *ptdev = NULL;
    partition_device_t *ospi = NULL;
    partition_device_t *emmc_top = NULL;

    for (i = 0; i < DEV_MAX; i++) {
        if (!get_update_device_is_active(i)) {
            continue;
        }

        ptdev = get_update_device_ptdev(i);
        name = get_update_device_name(i);

        if (ptdev == NULL) {
            PRINTF_CRITICAL("ptdev %s is null\n", name);
            return -1;
        }

        if (!strcmp(name, BASE_DEV_NAME_MMC_REMOTE(top))) {
            emmc_top = ptdev;
            PRINTF_INFO("set active slot for %s later\n", name);
            continue;
        }

        if (!strcmp(name, BASE_DEV_NAME_OSPI)) {
            ospi = ptdev;
            PRINTF_INFO("set active slot for %s later\n", name);
            continue;
        }

        ret[i] = set_active_boot_slot(ptdev, slot);
        PRINTF_INFO("set slot %s active for %s result %d\n", suffix,
                    name, ret[i]);

        if (ret[i] != 0) {
            PRINTF_CRITICAL("error when set active slot for %s\n", name);
            return -1;
        }
    }

    /* Second last action : emmc level-one partition */
    if (emmc_top) {
        PRINTF_INFO("set active slot for %s\n", BASE_DEV_NAME_MMC_REMOTE(top));

        if (set_active_boot_slot(emmc_top, slot) != 0) {
            PRINTF_CRITICAL("error when set active slot for %s\n",
                            BASE_DEV_NAME_MMC_REMOTE(top));
            return -1;
        }
    }

    /* Last action : ospi flash */
    if (ospi) {
        PRINTF_INFO("set active slot for %s\n", BASE_DEV_NAME_OSPI);

        if (set_active_boot_slot(ospi, slot) != 0) {
            PRINTF_CRITICAL("error when set active slot for %s\n", BASE_DEV_NAME_OSPI);
            return -1;
        }
    }

    if (1 != is_slot_bootable_all(slot)) {
        PRINTF_CRITICAL("recheck slot error\n");
    }

    if (0 != i) {
        //set local uniform rollback property
        if (is_local_uniform_rollback_need_set()) {
            set_global_uniform_rollback(GLOBAL_UNIFORM_ROLLBACK_ON);
            set_local_uniform_rollback(LOCAL_UNIFORM_ROLLBACK_IN_PROGRESS);
        }
        return 0;
    }

    PRINTF_CRITICAL("set active and boot all for slot %s error\n", suffix);
    return -1;
}

int set_slot_as_unbootable_all(unsigned slot)
{
    int ret[DEV_MAX];
    int i = 0;
    const char *suffix = _get_suffix_(slot);
    char *name = NULL;
    partition_device_t *ptdev = NULL;
    partition_device_t *ospi = NULL;
    partition_device_t *emmc_top = NULL;

    for (i = 0; i < DEV_MAX; i++) {
        if (!get_update_device_is_active(i)) {
            continue;
        }

        ptdev = get_update_device_ptdev(i);
        name = get_update_device_name(i);

        if (ptdev == NULL) {
            PRINTF_CRITICAL("ptdev %s is null\n", name);
            return -1;
        }

        if (!strcmp(name, BASE_DEV_NAME_MMC_REMOTE(top))) {
            emmc_top = ptdev;
            PRINTF_INFO("set slot unbootable for %s later\n", name);
            continue;
        }

        if (!strcmp(name, BASE_DEV_NAME_OSPI)) {
            ospi = ptdev;
            PRINTF_INFO("set slot unbootable for %s later\n", name);
            continue;
        }

        ret[i] = set_slot_as_unbootable(ptdev, slot);
        PRINTF_INFO("set slot %s as unbootable for %s result %d\n", suffix,
                    name, ret[i]);

        if (ret[i] != 0) {
            PRINTF_CRITICAL("error when set slot unbootable for %s\n", name);
            return -1;
        }
    }

    /* Second last action : emmc level-one partition */
    if (emmc_top) {
        PRINTF_INFO("set slot unbootable for %s\n", BASE_DEV_NAME_MMC_REMOTE(top));

        if (set_slot_as_unbootable(emmc_top, slot) != 0) {
            PRINTF_CRITICAL("error when set slot unbootable for %s\n",
                            BASE_DEV_NAME_MMC_REMOTE(top));
            return -1;
        }
    }

    /* Last action : ospi flash */
    if (ospi) {
        PRINTF_INFO("set slot unbootable for %s\n", BASE_DEV_NAME_OSPI);

        if (set_slot_as_unbootable(ospi, slot) != 0) {
            PRINTF_CRITICAL("error when set slot unbootable for %s\n", BASE_DEV_NAME_OSPI);
            return -1;
        }
    }

    if (0 != is_slot_bootable_all(slot)) {
        PRINTF_CRITICAL("recheck slot error\n");
        return -1;
    }

    if (0 != i) {
        return 0;
    }

    PRINTF_CRITICAL("set unbootable attr all for slot %s error\n", suffix);
    return -1;
}

int is_slot_bootable_all(unsigned slot)
{
    int i = 0;
    int ret[DEV_MAX];
    int first = -1;
    bool get_first = false;
    const char *suffix = _get_suffix_(slot);

    for (i = 0; i < DEV_MAX; i++) {
        if (!get_update_device_is_active(i)) {
            continue;
        }

        if (get_update_device_ptdev(i) == NULL) {
            PRINTF_CRITICAL("ptdev %s is null\n", get_update_device_name(i));
            return -1;
        }

        ret[i] = is_slot_bootable(get_update_device_ptdev(i), slot);
        PRINTF_INFO("check slot %s's bootable attr for %s is %d\n", suffix,
                    get_update_device_name(i), ret[i]);

        if (ret[i] < 0) {
            PRINTF_CRITICAL("results error, ret[%d] = %d\n", i, ret[i]);
            return -1;
        }

        if (false == get_first) {
            get_first = true;
            first = ret[i];
        }
        else {
            if ((first != ret[i]) || (first < 0)) {
                PRINTF_CRITICAL("operation results are inconsistent, first result = %d, ret[%d] = %d\n",
                                first, i, ret[i]);
                return -1;
            }
        }
    }

    return first;
}

int is_slot_marked_successful_all(unsigned slot)
{
    int res;
    int ret;

    PRINTF_INFO("is_slot_marked_successful_all start\n");

    if(is_uniform_rollback_need() && is_skip_uniform_rollback_need() == DO_NOT_SKIP_UNIFORM_ROLLBACK) {
        PRINTF_INFO("ur: uniform rollback start\n");
        if(is_inactive_slot_successful_and_bootable_all(!slot) != 1) {
            PRINTF_INFO("ur: inactive slot is not successful and bootable all\n");
            set_local_uniform_rollback(LOCAL_UNIFORM_ROLLBACK_OFF);
            set_skip_uniform_rollback_value(SKIP_UNIFORM_ROLLBACK);
            set_ota_status_property(STATUS_END);
        }
        else {
            PRINTF_INFO("ur: inactive slot is successful and bootable all\n");
            res = wait_for_property(3, GLOBAL_UNIFORM_ROLLBACK_PROPERTY, GLOBAL_UNIFORM_ROLLBACK_OFF, 5*SLEEP_TIME_INTERVAL);
            if (res != 1) {
                PRINTF_INFO("ur: global uniform rollback is not off\n");
                res = wait_for_property(4, LOCAL_UNIFORM_ROLLBACK_PROPERTY, LOCAL_UNIFORM_ROLLBACK_OFF, LOCAL_UNIFORM_ROLLBACK_OPPOSITE_UNCONFIRMED, 5*SLEEP_TIME_INTERVAL);
            }

            if (res != 1) {
                PRINTF_INFO("ur: do not skip uniform rollback\n");
                set_skip_uniform_rollback_value(DO_NOT_SKIP_UNIFORM_ROLLBACK);
                set_ota_status_property(STATUS_START);
            }
            else {
                PRINTF_INFO("ur: skip uniform rollback\n");
                set_skip_uniform_rollback_value(SKIP_UNIFORM_ROLLBACK);
                if (wait_for_property(3, LOCAL_UNIFORM_ROLLBACK_PROPERTY, LOCAL_UNIFORM_ROLLBACK_OPPOSITE_UNCONFIRMED, WAIT_FOR_PROPERTY_NO_DELAY) == 1) {
                    PRINTF_INFO("ur: local uniform rollback property is opposite unconfirmed\n");
                    set_ota_status_property(STATUS_BOTH_MARK);
                }
                else {
                    PRINTF_INFO("ur: local uniform rollback property is off\n");
                    set_ota_status_property(STATUS_END);
                }
            }
        }
    }

    ret = is_slot_successful_all(slot);
    if(ret == -1) {
        PRINTF_CRITICAL("check all slot successful fail\n");
        return -1;
    }
    else if(ret == 1) {
        PRINTF_INFO("all slot is successful\n");
        if(is_uniform_rollback_need() && is_skip_uniform_rollback_need() == DO_NOT_SKIP_UNIFORM_ROLLBACK) {
            set_ota_status_property(STATUS_MARK);
            res = wait_for_opposite_ota_status_property(3, STATUS_MARK, STATUS_BOTH_MARK, 15*SLEEP_TIME_INTERVAL);
            if (res == 1) {
                PRINTF_INFO("ur: opposite status is mark or both mark\n");
                set_local_uniform_rollback(LOCAL_UNIFORM_ROLLBACK_OPPOSITE_UNCONFIRMED);
                set_skip_uniform_rollback_value(SKIP_UNIFORM_ROLLBACK);
                set_ota_status_property(STATUS_BOTH_MARK);
                stop_safety_wdt();
                return 1;
            }
            else {
                if (res == -1)
                {
                    PRINTF_CRITICAL("ur: opposite status is unknown\n");
                }
                else {
                    PRINTF_INFO("ur: opposite status is not mark or both mark\n");
                }
                //clear successful attribute
                set_slot_as_unsuccessful_all(slot);
                set_ota_status_property(STATUS_START);
                PRINTF_CRITICAL("ur: clear successful attribute\n");
                return 0;
            }
        }
        else {
            stop_safety_wdt();
            return 1;
        }
    }
    else{
        PRINTF_INFO("all slot is unsuccessful\n");
        return 0;
    }
}

int get_active_boot_slot(partition_device_t *ptdev)
{
    int active_slot = INVALID;

    if(!ptdev) {
        PRINTF_CRITICAL("partition error\n");
        return INVALID;
    }

    if (true == ptdev->local) {
        active_slot = ptdev_find_active_slot(ptdev);

        if ((active_slot != SLOT_A) && (active_slot != SLOT_B)) {
            PRINTF_CRITICAL("active_slot %d error\n", active_slot);
            return INVALID;
        }
    }

    else if ((false == ptdev->local) && (STORAGE_REMOTE == ptdev->storage->type)) {
        active_slot = ptdev_find_active_slot_remote(ptdev);

        if ((active_slot != SLOT_A) && (active_slot != SLOT_B)) {
            PRINTF_CRITICAL("active_slot %d error\n", active_slot);
            return INVALID;
        }
    }

    else {
        PRINTF_CRITICAL("invalid partition type\n");
        return INVALID;
    }

    return active_slot;
}

int get_active_boot_slot_all()
{
    int i = 0;
    int ret[DEV_MAX];
    int first = -1;
    bool get_first = false;

    for (i = 0; i < DEV_MAX; i++) {
        if (!get_update_device_is_active(i)) {
            continue;
        }

        if (get_update_device_ptdev(i) == NULL) {
            PRINTF_CRITICAL("ptdev %s is null\n", get_update_device_name(i));
            return -1;
        }

        ret[i] = get_active_boot_slot(get_update_device_ptdev(i));
        PRINTF_INFO("get active slot for %s is %d\n",
                    get_update_device_name(i), ret[i]);

        if ((ret[i] != SLOT_A) && (ret[i] != SLOT_B)) {
            PRINTF_CRITICAL("results error, ret[%d] = %d\n", i, ret[i]);
            return -1;
        }

        if (false == get_first) {
            get_first = true;
            first = ret[i];
        }
        else {
            if ((first != ret[i]) || (first < 0)) {
                PRINTF_CRITICAL("operation results are inconsistent, first result = %d, ret[%d] = %d\n",
                                first, i, ret[i]);
                return -1;
            }
        }
    }
    return first;
}

bool is_in_android_userdebug()
{
#if RUN_IN_ANDROID && !RUN_IN_HOST
    char build_type[PROPERTY_VALUE_MAX] = {'\0'};
    property_get(ANDROID_BUILD_TYPE_PROPERTY, build_type, "N/A");

    if (!strcmp((char *)build_type, ANDROID_BUILD_TYPE_USERDEBUG)) {
        return true;
    }

    return false;
#else
    return false;
#endif
}

bool is_in_android_recovery()
{
#if RUN_IN_ANDROID && !RUN_IN_HOST
    char recovery[PROPERTY_VALUE_MAX] = {'\0'};
    property_get(ANDROID_NORMAL_BOOT, recovery, "N/A");

    if (!strcmp((char *)recovery, ANDROID_RECOVERY_RUNNING)) {
        return true;
    }

    return false;
#else
    return false;
#endif
}

int set_slot_as_unsuccessful_all(unsigned slot)
{
    int ret[DEV_MAX];
    int i = 0;
    const char *suffix = _get_suffix_(slot);
    char *name = NULL;
    partition_device_t *ptdev = NULL;
    partition_device_t *ospi = NULL;
    partition_device_t *emmc_top = NULL;

    for (i = 0; i < DEV_MAX; i++) {
        if (!get_update_device_is_active(i)) {
            continue;
        }

        ptdev = get_update_device_ptdev(i);
        name = get_update_device_name(i);

        if (ptdev == NULL) {
            PRINTF_CRITICAL("ptdev %s is null\n", name);
            return -1;
        }

        if (!strcmp(name, BASE_DEV_NAME_MMC_REMOTE(top))) {
            emmc_top = ptdev;
            PRINTF_INFO("set slot unsuccessful for %s later\n", name);
            continue;
        }

        if (!strcmp(name, BASE_DEV_NAME_OSPI)) {
            ospi = ptdev;
            PRINTF_INFO("set slot unsuccessful for %s later\n", name);
            continue;
        }

        ret[i] = set_slot_as_unsuccessful(ptdev, slot);
        PRINTF_INFO("set slot %s as unsuccessful for %s result %d\n", suffix,
                    name, ret[i]);

        if (ret[i] != 0) {
            PRINTF_CRITICAL("error when set slot unsuccessful for %s\n", name);
            return -1;
        }
    }

    /* Second last action : emmc level-one partition */
    if (emmc_top) {
        PRINTF_INFO("set slot unsuccessful for %s\n", BASE_DEV_NAME_MMC_REMOTE(top));

        if (set_slot_as_unsuccessful(emmc_top, slot) != 0) {
            PRINTF_CRITICAL("error when set slot unsuccessful for %s\n",
                            BASE_DEV_NAME_MMC_REMOTE(top));
            return -1;
        }
    }

    /* Last action : ospi flash */
    if (ospi) {
        PRINTF_INFO("set slot unsuccessful for %s\n", BASE_DEV_NAME_OSPI);

        if (set_slot_as_unsuccessful(ospi, slot) != 0) {
            PRINTF_CRITICAL("error when set slot unsuccessful for %s\n", BASE_DEV_NAME_OSPI);
            return -1;
        }
    }

    if (0 != is_slot_successful_all(slot)) {
        PRINTF_CRITICAL("recheck slot error\n");
        return -1;
    }

    if (0 != i) {
        return 0;
    }

    PRINTF_CRITICAL("set unsuccessful attr all for slot %s error\n", suffix);
    return -1;
}

int is_slot_successful_all(unsigned slot)
{
    int i = 0;
    int ret[DEV_MAX];
    int first = -1;
    bool get_first = false;
    const char *suffix = _get_suffix_(slot);

    for (i = 0; i < DEV_MAX; i++) {
        if (!get_update_device_is_active(i)) {
            continue;
        }

        if (get_update_device_ptdev(i) == NULL) {
            PRINTF_CRITICAL("ptdev %s is null\n", get_update_device_name(i));
            return -1;
        }

        ret[i] = is_slot_marked_successful(get_update_device_ptdev(i), slot);
        PRINTF_INFO("check slot %s's successful attr for %s is %d\n", suffix,
                    get_update_device_name(i), ret[i]);

        if (ret[i] < 0) {
            PRINTF_CRITICAL("results error, ret[%d] = %d\n", i, ret[i]);
            return -1;
        }

        if (false == get_first) {
            get_first = true;
            first = ret[i];
        }
        else {
            if ((first != ret[i]) || (first < 0)) {
                PRINTF_CRITICAL("operation results are inconsistent, first result = %d, ret[%d] = %d\n",
                                first, i, ret[i]);
                return -1;
            }
        }
    }

    if(first == 1){
        return 1;
    }
    else{
        return 0;
    }
}

int set_slot_as_successful_all(unsigned slot)
{
    int ret[DEV_MAX];
    int i = 0;
    char *name = NULL;
    partition_device_t *ptdev = NULL;
    partition_device_t *ospi = NULL;
    partition_device_t *emmc_top = NULL;

    for (i = 0; i < DEV_MAX; i++) {
        if (!get_update_device_is_active(i)) {
            continue;
        }

        ptdev = get_update_device_ptdev(i);
        name = get_update_device_name(i);

        if (ptdev == NULL) {
            PRINTF_CRITICAL("ptdev %s is null\n", name);
            return -1;
        }

        if (!strcmp(name, BASE_DEV_NAME_MMC_REMOTE(top))) {
            emmc_top = ptdev;
            PRINTF_INFO("mark active slot successful for %s later\n", name);
            continue;
        }

        if (!strcmp(name, BASE_DEV_NAME_OSPI)) {
            ospi = ptdev;
            PRINTF_INFO("mark active slot successful for %s later\n", name);
            continue;
        }

        ret[i] = set_slot_as_successful(ptdev, slot);
        PRINTF_INFO("mark active slot successful for %s result %d\n",
                    name, ret[i]);

        if (ret[i] != 0) {
            PRINTF_CRITICAL("error when marking active slot for %s\n", name);
            return -1;
        }
    }

    if (0 == i) {
        return -1;
    }

    /* Second last action : emmc level-one partition */
    if (emmc_top) {
        PRINTF_INFO("mark active slot successful for %s\n",
                    BASE_DEV_NAME_MMC_REMOTE(top));

        if (set_slot_as_successful(emmc_top, slot) != 0) {
            PRINTF_CRITICAL("error when marking active slot successful for %s\n",
                            BASE_DEV_NAME_MMC_REMOTE(top));
            return -1;
        }
    }

    /* Last action : ospi flash */
    if (ospi) {
        PRINTF_INFO("mark active slot successful for %s", BASE_DEV_NAME_OSPI);

        if (set_slot_as_successful(ospi, slot) != 0) {
            PRINTF_CRITICAL("error when marking active slot successful for %s\n",
                            BASE_DEV_NAME_OSPI);
            return -1;
        }
    }

    if (1 != is_slot_successful_all(slot)) {
        PRINTF_CRITICAL("recheck success error\n");
        return -1;
    }

    return 0;
}

int is_inactive_slot_successful_and_bootable_all(unsigned slot)
{
   return (is_slot_successful_all(slot) == 1 && is_slot_bootable_all(slot) == 1);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
