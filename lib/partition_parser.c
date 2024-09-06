/* Copyright (c) 2011-2018, The Linux Foundation. All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of The Linux Foundation. nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

#define PT_WARN PRINTF_CRITICAL
#define PT_INFO PRINTF_INFO

/* Semidrive sub-partition support GUID */
/* type_guid: 7d06a189-1fef-4d89-8940-e8c2a6832ecf */
static const char sub_part_guid[PARTITION_TYPE_GUID_SIZE] = {
    0x89, 0xa1, 0x6, 0x7d,
    0xef, 0x1f, 0x89, 0x4d,
    0x89, 0x40, 0xe8, 0xc2,
    0xa6, 0x83, 0x2e, 0xcf
};

static const char invalid_guid[PARTITION_TYPE_GUID_SIZE] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

static uint32_t ptdev_read_gpt(partition_device_t *part_dev,
                               struct partition_entry *parent_entry, uint32_t block_size);
static uint32_t ptdev_read_mbr(partition_device_t *part_dev,
                               uint32_t block_size);
static void mbr_fill_name(struct partition_entry *partition_ent,
                          uint32_t type);
static uint32_t ptdev_verify_mbr_signature(uint32_t size,
        uint8_t *buffer);
static uint32_t mbr_partition_get_type(uint32_t size, uint8_t *partition,
                                       uint8_t *partition_type);

static uint32_t ptdev_parse_gpt_header(partition_device_t *part_dev,
                                       uint8_t *buffer,
                                       uint64_t *first_usable_lba,
                                       uint32_t *partition_entry_size,
                                       uint32_t *header_size,
                                       uint32_t *max_partition_count,
                                       struct partition_entry *parent_entry,
                                       bool secondary_gpt,
                                       uint64_t *partition_entries_offset,
                                       uint32_t *crc_entries_array,
                                       bool check_lba);

static uint32_t write_mbr(partition_device_t *part_dev, uint32_t,
                          uint8_t *mbrImage, uint32_t block_size);
static uint32_t write_gpt(partition_device_t *part_dev,
                          struct partition_entry *parent_entry,
                          uint32_t size, uint8_t *gptImage, uint32_t block_size,
                          bool last_part_extend);

static const char *partition_separator = "$";

static bool ptdev_sub_part_exist(struct partition_entry *partition_entries);

static uint64_t round_up(uint64_t size, uint64_t aligned)
{
    uint64_t mod = 0;

    if (aligned == 0 || size < aligned)
        return aligned;

    mod = size % aligned;

    size += mod ? aligned - mod : 0;
    return size;
}

static uint64_t round_down(uint64_t size, uint64_t aligned)
{
    uint64_t mod = 0;

    if (aligned == 0 || size < aligned)
        return 0;

    mod = size % aligned;
    size -= mod;
    return size;
}

int read_partition(storage_device_t *storage, uint64_t src, uint8_t *dst, uint64_t size)
{
    if(storage) {
        if (storage->switch_part(storage, SELECT_USERDATA) != 0) {
            PRINTF_CRITICAL("storage %s switch part to userdata failed\n", storage->dev_name);
            return -1;
        }

        return storage->read(storage, src, dst, size);
    }

    return -1;
}

int write_partition(storage_device_t *storage, uint64_t dst, const uint8_t *buf, uint64_t data_len)
{
    if(storage) {
        if (storage->switch_part(storage, SELECT_USERDATA) != 0) {
            PRINTF_CRITICAL("storage %s switch part to userdata failed\n", storage->dev_name);
            return -1;
        }

        return storage->write(storage, dst, buf, data_len);
    }

    return -1;
}

unsigned ptdev_get_partition_count(partition_device_t *part_dev)
{
    if (!part_dev) {
        PT_WARN("Invalid partition dev\n");
        return 0;
    }

    return part_dev->count;
}

struct partition_entry *ptdev_get_partition_entries(partition_device_t
        *part_dev)
{
    if (!part_dev) {
        PT_WARN("Invalid partition dev\n");
        return NULL;
    }

    return part_dev->partition_entries;
}

static uint32_t ptdev_get_entries_count(partition_device_t *part_dev)
{
    uint32_t block_size, count = 0;
    storage_device_t *storage = part_dev->storage;

    block_size = storage->block_size;
#if SKIP_MBR
    part_dev->gpt_partitions_exist = true;
#else

    if (ptdev_read_mbr(part_dev, block_size)) {
        PT_WARN("Boot: MBR read failed!\n");
        return 0;
    }

#endif

    /* Read GPT of the card if exist */
    if (part_dev->gpt_partitions_exist) {
        if (ptdev_read_gpt(part_dev, NULL, block_size)) {
            PT_WARN("read gpt fail!\n");
            goto out;
        }
    }

    count = part_dev->count;
out:
    part_dev->count = 0;
    part_dev->gpt_partitions_exist = false;

    return count;
}

int ptdev_read_table(partition_device_t *part_dev)
{
    uint32_t ret;
    uint32_t block_size;
    uint32_t partition_count = 0;
    struct partition_entry *partition_entries;
    storage_device_t *storage;

    if ((!part_dev) || (!part_dev->storage)) {
        PT_WARN("ptdev read para error!\n");
        return 1;
    }

    storage = part_dev->storage;
    block_size = storage->block_size;

    if (part_dev->partition_entries) {
        FREE(part_dev->partition_entries);
    }

    /* Before getting partition count, set count to 0 and set entries pointer to NULL */
    part_dev->count = 0;
    part_dev->partition_entries = NULL;
#if DEBUGMODE > 1
    PT_INFO("get partition count start\n");
#endif
    partition_count = ptdev_get_entries_count(part_dev);

    if (!partition_count) {
        PT_WARN("get partition count fail!\n");
        return 1;
    }

#if DEBUGMODE > 1
    PT_INFO("get partition count end , partition_count = %d\n", partition_count);
#endif
    partition_count = (partition_count > NUM_PARTITIONS) ? NUM_PARTITIONS :
                      partition_count;

    part_dev->partition_entries = (struct partition_entry *) CALLOC(
                                      partition_count, sizeof(struct partition_entry));
    ASSERT(part_dev->partition_entries);

#if SKIP_MBR
    part_dev->gpt_partitions_exist = true;
#else
    /* Read MBR of the card */
    ret = ptdev_read_mbr(part_dev, block_size);

    if (ret) {
        PT_WARN("Boot: MBR read failed!\n");
        return 1;
    }

#endif

    /* Read GPT of the card if exist */
    if (part_dev->gpt_partitions_exist) {
#if DEBUGMODE > 1
        PT_INFO("parse level-1 gpt\n");
#endif
        ret = ptdev_read_gpt(part_dev, NULL, block_size);

        if (ret) {
            PT_WARN("Boot: GPT read failed!\n");
            return 1;
        }

#if DEBUGMODE > 1
        PT_INFO("parse level-1 gpt finish\n");
#endif
    }

    partition_entries = part_dev->partition_entries;
    partition_count = part_dev->count;

    for (unsigned i = 0; i < partition_count; i++) {
        if (ptdev_sub_part_exist(partition_entries + i)) {
#if DEBUGMODE > 1
            PT_INFO("parse level-2 gpt\n");
#endif
            PT_INFO("%s may have sub partitions\n", partition_entries[i].name);

            if (ptdev_read_gpt(part_dev, &partition_entries[i], block_size)) {
                PT_WARN("read extral partition table failed\n");
            }

#if DEBUGMODE > 1
            PT_INFO("parse level-2 gpt finish\n");
#endif
        }
    }

    /* Scan of multislot support */
    ptdev_scan_for_multislot(part_dev);

    return 0;
}

/*
 * Read MBR from MMC card and fill partition table.
 */
static uint32_t ptdev_read_mbr(partition_device_t *part_dev,
                               uint32_t block_size)
{
    uint8_t *buffer = NULL;
    uint32_t dtype;
    uint32_t dfirstsec;
    uint32_t EBR_first_sec;
    uint32_t EBR_current_sec;
    int ret = 0;
    int idx, i;
    storage_device_t *storage = part_dev->storage;
    unsigned partition_count = part_dev->count;
    struct partition_entry *partition_entries = part_dev->partition_entries;
    struct partition_entry *current_entry;
    struct partition_entry pt_entry;

    buffer = (uint8_t *)MEM_ALIGN(block_size, ROUNDUP(block_size, block_size));

    if (!buffer) {
        PT_WARN("Error allocating memory while reading partition table\n");
        ret = -1;
        goto end;
    }

    /* Print out the MBR first */
    ret = read_partition(storage, part_dev->gpt_offset, (uint8_t *)buffer,
                        block_size);

    if (ret) {
        PT_WARN("Could not read partition from boot device\n");
        goto end;
    }

    /* Check to see if signature exists */
    ret = ptdev_verify_mbr_signature(block_size, buffer);

    if (ret) {
        goto end;
    }

    /*
     * Process each of the four partitions in the MBR by reading the table
     * information into our mbr table.
     */
    idx = TABLE_ENTRY_0;

    for (i = 0; i < 4; i++) {
        /* Type 0xEE indicates end of MBR and GPT partitions exist */
        dtype = buffer[idx + i * TABLE_ENTRY_SIZE + OFFSET_TYPE];

        if (dtype == MBR_PROTECTED_TYPE) {
            part_dev->gpt_partitions_exist = true;
            goto end;
        }

        current_entry = partition_entries ? &partition_entries[partition_count] :
                        &pt_entry;
        current_entry->dtype = dtype;
        current_entry->attribute_flag =
            buffer[idx + i * TABLE_ENTRY_SIZE + OFFSET_STATUS];
        current_entry->first_lba =
            GET_LWORD_FROM_BYTE(&buffer[idx +
                                            i * TABLE_ENTRY_SIZE +
                                            OFFSET_FIRST_SEC]);
        current_entry->size =
            GET_LWORD_FROM_BYTE(&buffer[idx +
                                            i * TABLE_ENTRY_SIZE +
                                            OFFSET_SIZE]);
        dfirstsec = current_entry->first_lba;
        mbr_fill_name(&partition_entries[partition_count],
                      current_entry->dtype);
        partition_count++;

        if (partition_count == NUM_PARTITIONS)
            goto end;
    }

    part_dev->count = partition_count;

    /* See if the last partition is EBR, if not, parsing is done */
    if (dtype != MBR_EBR_TYPE) {
        goto end;
    }

    EBR_first_sec = dfirstsec;
    EBR_current_sec = dfirstsec;

    ret = read_partition(storage,
                        (EBR_first_sec * block_size) + part_dev->gpt_offset,
                        (uint8_t *)buffer, block_size);

    if (ret)
        goto end;

    /* Loop to parse the EBR */
    for (i = 0;; i++) {
        ret = ptdev_verify_mbr_signature(block_size, buffer);

        if (ret) {
            ret = 0;
            break;
        }

        current_entry = partition_entries ? &partition_entries[partition_count] :
                        &pt_entry;
        current_entry->attribute_flag =
            buffer[TABLE_ENTRY_0 + OFFSET_STATUS];
        current_entry->dtype =
            buffer[TABLE_ENTRY_0 + OFFSET_TYPE];
        current_entry->first_lba =
            GET_LWORD_FROM_BYTE(&buffer[TABLE_ENTRY_0 +
                                                      OFFSET_FIRST_SEC]) +
            EBR_current_sec;
        current_entry->size =
            GET_LWORD_FROM_BYTE(&buffer[TABLE_ENTRY_0 + OFFSET_SIZE]);
        mbr_fill_name(&(partition_entries[partition_count]),
                      current_entry->dtype);
        partition_count++;

        if (partition_count == NUM_PARTITIONS)
            goto end;

        dfirstsec =
            GET_LWORD_FROM_BYTE(&buffer
                                [TABLE_ENTRY_1 + OFFSET_FIRST_SEC]);

        if (dfirstsec == 0) {
            /* Getting to the end of the EBR tables */
            break;
        }

        /* More EBR to follow - read in the next EBR sector */
        PT_INFO("Reading EBR block from 0x%X\n", EBR_first_sec
                + dfirstsec);
        ret = read_partition(storage, ((EBR_first_sec + dfirstsec) * block_size) +
                            part_dev->gpt_offset, (uint8_t *)buffer,
                            block_size);

        if (ret)
            goto end;

        EBR_current_sec = EBR_first_sec + dfirstsec;
    }

end:

    if (buffer)
        FREE(buffer);

    return ret;
}

#define NUM_HEADS (255)
#define NUM_SECTORS (63)

static void lba_to_chs(uint32_t lba, uint8_t *out_head, uint8_t *out_sector, \
                       uint8_t *out_cylinder)
{
    // for CHS address format, See https://en.wikipedia.org/wiki/Cylinder-head-sector
    uint32_t max_lba = 255 * NUM_HEADS * NUM_SECTORS;
    uint32_t head = 0;
    uint32_t sector = 0;
    uint32_t cylinder = 0;

    if (lba > max_lba) {
        *out_head = 0xFF;
        *out_sector = 0xFF;
        *out_cylinder = 0xFF;
    }

    cylinder = (uint32_t)(lba / (NUM_HEADS * NUM_SECTORS));
    head = (lba / NUM_SECTORS) % NUM_HEADS;
    sector = (uint32_t)(lba % NUM_SECTORS);

    *out_head = head;
    *out_sector = (uint8_t)((((cylinder >> 8) & 0x03) << 6) | (sector & 0x3f));
    *out_cylinder = (uint8_t)(cylinder & 0xFF);
}

uint32_t restore_pmbr_data(struct MBRPartitionTable *pmbr,
                           uint64_t device_capacity, uint32_t block_size)
{
    uint32_t ret = 1;

    if (!pmbr)  {
        PT_WARN("mbr buffer error\n");
        goto end;
    }

    memset(pmbr, 0, PMBR_SIZE);
    pmbr->flag1 = 0xfa;
    pmbr->flag2 = 0xeb;
    pmbr->flag3 = 0xfe;
    pmbr->partition_entries[0].system_id = 0xEE;
    pmbr->signature = 0xAA55;
    pmbr->partition_entries[0].start_lba = 1;
    pmbr->partition_entries[0].size = (uint32_t)(MIN((device_capacity / block_size -
                                      1), UINT_MAX));
    lba_to_chs(pmbr->partition_entries[0].start_lba,
               &(pmbr->partition_entries[0].start_head), \
               & (pmbr->partition_entries[0].start_sector),
               &(pmbr->partition_entries[0].start_cylinder));
    lba_to_chs(pmbr->partition_entries[0].size,
               &(pmbr->partition_entries[0].end_head), \
               & (pmbr->partition_entries[0].end_sector),
               &(pmbr->partition_entries[0].end_cylinder));
    ret = 0;
end:
    return ret;
}

#if 0
static uint32_t restore_pmbr(partition_device_t *part_dev,
                             struct partition_entry *parent_entry)
{
    uint32_t ret = 1;
    uint8_t *mbr_buffer = NULL;
    uint8_t *check_buffer = NULL;
    uint8_t *gpt_buffer = NULL;
    uint32_t partition_type = UINT_MAX;
    uint8_t *mbr_offset;
    uint32_t block_size;
    uint64_t device_capacity;
    uint64_t cur_gpt_offset;
    uint32_t erase_grp_sz;

    storage_device_t *storage = part_dev->storage;
    block_size = storage->block_size;
    erase_grp_sz = storage->erase_size;

    if (!part_dev || !part_dev->storage) {
        PT_WARN("partition device error!\n");
        goto end;
    }

    if (!parent_entry) {
        device_capacity = storage->get_capacity(storage) - part_dev->gpt_offset;
        cur_gpt_offset = part_dev->gpt_offset;
    }
    else {
        cur_gpt_offset = parent_entry->first_lba * block_size + part_dev->gpt_offset;
        device_capacity = (parent_entry->last_lba -
                           parent_entry->first_lba + 1) * block_size;
    }

    mbr_buffer = (uint8_t *)MEM_ALIGN(block_size, ROUNDUP(block_size,
                                      block_size));

    check_buffer = (uint8_t *)MEM_ALIGN(block_size, ROUNDUP(block_size,
                                        block_size));

    if (mbr_buffer && check_buffer) {
        if (!read_partition(storage, cur_gpt_offset, (uint8_t *)mbr_buffer,
                           block_size)) {
            if (ptdev_get_type(block_size, mbr_buffer, &partition_type)
                    || (partition_type != PARTITION_TYPE_GPT)) {
                ret = restore_pmbr((struct MBRPartitionTable *)mbr_buffer, device_capacity,
                                   block_size) ;

                if (ret) {
                    PT_WARN("restore pmbr failed\n");
                    goto end;
                }

                if (!storage->need_erase) {
                    ret = write_partition(storage, cur_gpt_offset, mbr_buffer, block_size);

                    if (ret) {
                        PT_WARN("fail to write pmbr\n");
                        goto end;
                    }

                    ret = read_partition(storage, cur_gpt_offset, check_buffer, block_size);

                    if (ret) {
                        PT_WARN("fail to readback pmbr\n");
                        goto end;
                    }

                    ret = memcmp(check_buf, mbr_buf, block_size)

                    if (ret) {
                        PT_WARN("memcmp failed for pmbr\n");
                        goto end;
                    }
                }
                else {
                    PT_WARN("can not restore mbr for flash\n");
                    goto end;
                }
            }
            else {
                PT_INFO( "GPT: MBR check ok\n");
                ret = 0;
            }
        }
        else {
            PT_WARN( "GPT: Could not read mbr from boot device\n");
        }
    }
    else {
        PT_WARN( "Failed to Allocate memory to read mbr\n");
    }

end:

    if (mbr_buffer)
        FREE(mbr_buffer)

        return ret;

}
#endif

typedef enum restore_direction {
    PRI2SEC = 0,
    SEC2PRI
} restore_direction;

static uint32_t
restore_gpt(partition_device_t *part_dev,
            enum restore_direction dir,
            struct partition_entry *parent_entry)
{
    uint32_t ret = 1;
    uint64_t device_capacity;
    uint8_t *header_buf = NULL;
    uint8_t *entries_buf = NULL;
    uint8_t *check_buf = NULL;
    uint8_t *mbr_buf = NULL;
    storage_device_t *storage;
    uint32_t block_size, gpt_size, erase_grp_sz, crc32_val, max_partition_count,
             crc_entries;
    uint32_t entries_cnt_per_block, blocks_to_read, header_size,
             partition_entry_size;
    uint64_t first_usable_lba, backup_header_lba, current_header_lba,
             entries_start_lba, cur_gpt_offset;
    uint64_t card_size_sec, ptn_src_header, ptn_dst_header, ptn_erase,
             ptn_dst_entries, partition_entries_offset;
    uint32_t partition_type = UINT_MAX;

    if (!part_dev || !part_dev->storage) {
        PT_WARN("partition device error!\n");
        goto end;
    }

#if SKIP_RESTORE_GPT
    PT_WARN("skip restore\n");
    goto end;
#endif

    storage = part_dev->storage;
    block_size = storage->block_size;
    erase_grp_sz = storage->erase_size;

    if (!parent_entry) {
        device_capacity = storage->get_capacity(storage) - part_dev->gpt_offset;
        cur_gpt_offset = part_dev->gpt_offset;
    }
    else {
        cur_gpt_offset = parent_entry->first_lba * block_size + part_dev->gpt_offset;
        device_capacity = (parent_entry->last_lba -
                           parent_entry->first_lba + 1) * block_size;
        DBG("name %s, first %llu, last %llu\n",
            parent_entry->name, parent_entry->first_lba,
            parent_entry->last_lba);
    }

    card_size_sec = (device_capacity) / block_size;
    ASSERT (card_size_sec > 0);

    header_buf = (uint8_t *)MEM_ALIGN(block_size, block_size);
    entries_buf = (uint8_t *)MEM_ALIGN(block_size, block_size);
    check_buf = (uint8_t *)MEM_ALIGN(block_size, block_size);

    if (!header_buf || !entries_buf || !check_buf) {
        PT_WARN("buffer calloc failed\n");
        goto end;
    }

    if (SEC2PRI == dir) {
        mbr_buf = (uint8_t *)MEM_ALIGN(block_size, block_size);

        if (!mbr_buf) {
            PT_WARN("fail to calloc mbr buffer\n");
            goto end;
        }

        ret = read_partition(storage, cur_gpt_offset, mbr_buf, block_size);

        if (ret) {
            PT_WARN("fail to read mbr\n");
            goto end;
        }

        ptn_src_header = (card_size_sec - 1) * block_size + cur_gpt_offset;
    }
    else {
        ptn_src_header = cur_gpt_offset + block_size;
    }

    ret = read_partition(storage, ptn_src_header, header_buf, block_size);

    if (ret) {
        PT_WARN("fail to read src gpt header!\n");
        goto end;
    }

    DBG("src header:%llu dir:%u!\n", (unsigned long long)ptn_src_header, dir);
    ret = ptdev_parse_gpt_header(part_dev, header_buf, &first_usable_lba,
                                 &partition_entry_size, &header_size,
                                 &max_partition_count, parent_entry, (dir == SEC2PRI),
                                 &partition_entries_offset,
                                 &crc_entries, true);

    if (ret) {
        PT_WARN("fail to parse src gpt header!\n");
        goto end;
    }

    entries_cnt_per_block = block_size / partition_entry_size;
    blocks_to_read = round_up(max_partition_count,
                              entries_cnt_per_block) / entries_cnt_per_block;

    backup_header_lba =
        GET_LLWORD_FROM_BYTE(&header_buf[PRIMARY_HEADER_OFFSET]);

    current_header_lba =
        GET_LLWORD_FROM_BYTE(&header_buf[BACKUP_HEADER_OFFSET]);

    if (SEC2PRI == dir) {
        ptn_dst_header = cur_gpt_offset;
        gpt_size = (1 + GPT_HEADER_BLOCKS + blocks_to_read) * block_size;
        ptn_erase = ptn_dst_header;
        ptn_dst_header += block_size;
        current_header_lba = GPT_LBA;
        ptn_dst_entries = ptn_dst_header + block_size;
        entries_start_lba = 0x2;
    }
    else {
        ptn_dst_header = (card_size_sec - 1) * block_size + cur_gpt_offset;
        gpt_size = (GPT_HEADER_BLOCKS + blocks_to_read) * block_size;
        ptn_erase = ptn_dst_header - blocks_to_read * block_size;
        ptn_dst_entries = ptn_erase;
        entries_start_lba = card_size_sec - 1 - blocks_to_read;
    }

    PUT_LONG_LONG(header_buf + PRIMARY_HEADER_OFFSET, current_header_lba);
    PUT_LONG_LONG(header_buf + BACKUP_HEADER_OFFSET, backup_header_lba);
    PUT_LONG_LONG(header_buf + PARTITION_ENTRIES_OFFSET, entries_start_lba);

    if (storage->need_erase && storage->need_erase(storage)) {
        if (storage->erase(storage,
                           round_down(ptn_erase, erase_grp_sz),
                           round_up(gpt_size, erase_grp_sz))) {
            PT_WARN("erase gpt header fail!\n");
            goto end;
        }
    }
    else {
        memset(check_buf, 0, block_size);
        ret = write_partition(storage, ptn_dst_header, \
                             check_buf, block_size);

        if (ret) {
            PT_WARN("fail to clear partition header\n");
            goto end;
        }
    }

    crc32_val = 0;
    partition_entries_offset += cur_gpt_offset;

    for (uint32_t i = 0; i < blocks_to_read; i++) {

        ret = read_partition(storage, partition_entries_offset + (i * block_size),
                            entries_buf, block_size);

        if (ret) {
            PT_WARN("fail to read partition entries\n");
            goto end;
        }

        ret = write_partition(storage, ptn_dst_entries + (i * block_size), entries_buf,
                             block_size);

        if (ret) {
            PT_WARN("fail to restore partition entries\n");
            goto end;
        }

        ret = read_partition(storage, ptn_dst_entries + (i * block_size), check_buf,
                            block_size);

        if (ret) {
            PT_WARN("fail to readback restore partition entries\n");
            goto end;
        }

        ret = memcmp(check_buf, entries_buf, block_size);

        if (ret) {
            PT_WARN("memcmp fild for read back\n");
            goto end;
        }

        crc32_val = crc32(crc32_val, entries_buf, block_size);
    }

    if (crc_entries != crc32_val) {
        PT_WARN("fail to check partition entries crc32\n");
        ret = 1;
        goto end;
    }

    PUT_LONG(header_buf + PARTITION_CRC_OFFSET, crc32_val);

    crc32_val = 0;
    PUT_LONG(header_buf + HEADER_CRC_OFFSET, crc32_val);
    crc32_val = crc32(0, header_buf, header_size);
    PUT_LONG(header_buf + HEADER_CRC_OFFSET, crc32_val);

    ret = write_partition(storage, ptn_dst_header, header_buf, block_size);

    if (ret) {
        PT_WARN("fail to restore partition header\n");
        goto end;
    }

    ret = read_partition(storage, ptn_dst_header, check_buf, block_size);

    if (ret) {
        PT_WARN("fail to readback restore header\n");
        goto end;
    }

    ret = memcmp(check_buf, header_buf, block_size);

    if (ret) {
        PT_WARN("memcmp fild for read back header\n");
        goto end;
    }

    /* restore_mbr */
    if (SEC2PRI == dir) {
        if (ptdev_get_type(block_size, mbr_buf, &partition_type)
                || (partition_type != PARTITION_TYPE_GPT)) {
            ret = restore_pmbr_data((struct MBRPartitionTable *)mbr_buf, device_capacity,
                                    block_size);

            if (ret) {
                PT_WARN("restore pmbr failed\n");
                goto end;
            }
        }

        ret = write_partition(storage, cur_gpt_offset, mbr_buf, block_size);

        if (ret) {
            PT_WARN("fail to write pmbr\n");
            goto end;
        }

        ret = read_partition(storage, cur_gpt_offset, check_buf, block_size);

        if (ret) {
            PT_WARN("fail to readback pmbr\n");
            goto end;
        }

        ret = memcmp(check_buf, mbr_buf, block_size);

        if (ret) {
            PT_WARN("memcmp failed for pmbr\n");
            goto end;
        }
    }

    ret = 0;
end:

    if (header_buf)
        FREE(header_buf);

    if (entries_buf)
        FREE(entries_buf);

    if (mbr_buf)
        FREE(mbr_buf);

    if (check_buf)
        FREE(check_buf);

    return ret;
}

static uint32_t
check_secondary_gpt(partition_device_t *part_dev,
                    struct partition_entry *parent_entry)
{
    uint32_t ret = 1;
    uint64_t device_capacity;
    uint8_t *header_buf = NULL;
    uint8_t *entries_buf = NULL;
    storage_device_t *storage;
    uint32_t block_size, crc32_val, max_partition_count, crc_entries;
    uint32_t entries_cnt_per_block, blocks_to_read, header_size,
             partition_entry_size;
    uint64_t first_usable_lba, cur_gpt_offset;
    uint64_t card_size_sec, ptn_src_header,  partition_entries_offset;

    if (!part_dev || !part_dev->storage) {
        PT_WARN("partition device error!\n");
        goto end;
    }

    storage = part_dev->storage;
    block_size = storage->block_size;

    if (!parent_entry) {
        device_capacity = storage->get_capacity(storage) - part_dev->gpt_offset;
        cur_gpt_offset = part_dev->gpt_offset;
    }
    else {
        cur_gpt_offset = parent_entry->first_lba * block_size + part_dev->gpt_offset;
        device_capacity = (parent_entry->last_lba -
                           parent_entry->first_lba + 1) * block_size;
        DBG("parent name %s, first %llu, last %llu\n",
            parent_entry->name, parent_entry->first_lba,
            parent_entry->last_lba);
    }

    card_size_sec = (device_capacity) / block_size;
    ASSERT (card_size_sec > 0);

    header_buf = (uint8_t *)MEM_ALIGN(block_size, block_size);
    entries_buf = (uint8_t *)MEM_ALIGN(block_size, block_size);

    if (!header_buf || !entries_buf) {
        PT_WARN("fail to allocate memory!\n");
        goto end;
    }


    ptn_src_header = (card_size_sec - 1) * block_size + cur_gpt_offset;
    ret = read_partition(storage, ptn_src_header, header_buf, block_size);

    if (ret) {
        PT_WARN("fail to read src gpt header!\n");
        goto end;
    }

    ret = ptdev_parse_gpt_header(part_dev, header_buf, &first_usable_lba,
                                 &partition_entry_size, &header_size,
                                 &max_partition_count, parent_entry, true,
                                 &partition_entries_offset,
                                 &crc_entries, true);

    if (ret) {
        PT_WARN("fail to parse src secondary gpt header!\n");
        goto end;
    }

    entries_cnt_per_block = block_size / partition_entry_size;
    blocks_to_read = round_up(max_partition_count,
                              entries_cnt_per_block) / entries_cnt_per_block;

    crc32_val = 0;
    partition_entries_offset += cur_gpt_offset;

    for (uint32_t i = 0; i < blocks_to_read; i++) {

        ret = read_partition(storage, partition_entries_offset + (i * block_size),
                            entries_buf, block_size);

        if (ret) {
            PT_WARN("fail to read partition entries\n");
            goto end;
        }

        crc32_val = crc32(crc32_val, entries_buf, block_size);

    }

    if (crc_entries != crc32_val) {
        PT_WARN("fail to check partition entries crc32\n");
        ret = 1;
        goto end;
    }

    ret = 0;
end:

    if (header_buf)
        FREE(header_buf);

    if (entries_buf)
        FREE(entries_buf);

    return ret;
}
/*
 * Read GPT from MMC and fill partition table
 */
static uint32_t ptdev_read_gpt(partition_device_t *part_dev,
                               struct partition_entry *parent_entry,
                               uint32_t block_size)
{
    int ret = 0;
    uint32_t crc_val = 0;
    uint32_t crc_entries = 0;
    uint32_t header_size;
    bool valid_entry_finish = false;
    uint64_t first_usable_lba;
    uint64_t backup_header_lba;
    uint64_t card_size_sec;
    uint32_t max_partition_count = 0;
    uint32_t partition_entry_size;
    uint32_t i = 0; /* Counter for each block */
    uint32_t j = 0; /* Counter for each entry in a block */
    uint32_t n = 0; /* Counter for UTF-16 -> 8 conversion */
    unsigned char UTF16_name[MAX_GPT_NAME_SIZE];
    /* LBA of first partition -- 1 Block after Protected MBR + 1 for PT */
    uint64_t device_capacity;
    uint8_t *data = NULL;
    uint8_t *gpt_header_ptr = NULL;
    uint8_t *entries_buffer = NULL;
    uint32_t blocks_for_entries =
        (NUM_PARTITIONS * PARTITION_ENTRY_SIZE) / block_size;
    uint32_t entries_cnt_per_block;
    uint32_t blocks_to_read;
    uint64_t lba_offset;
    unsigned long long cur_gpt_offset;
    uint64_t partition_entries_offset = 0;
    struct partition_entry *partition_entries = part_dev->partition_entries;
    struct partition_entry *current_entry;
    struct partition_entry pt_entry;
    unsigned partition_count = part_dev->count;
    const unsigned partition_count_reset = part_dev->count;
    storage_device_t *storage = part_dev->storage;
    bool re_parse_gpt = false;
#if SUPPORT_FULL_ENTRIES_BUF
    uint8_t *full_entries_buffer = NULL;
#endif

    /* Get the density of the boot device */

    if (!parent_entry) {
        device_capacity = storage->get_capacity(storage) - part_dev->gpt_offset;
        cur_gpt_offset = part_dev->gpt_offset;
        lba_offset = 0;
    }
    else {
        lba_offset = parent_entry->first_lba;
        cur_gpt_offset = parent_entry->first_lba * block_size + part_dev->gpt_offset;
        device_capacity = (parent_entry->last_lba -
                           parent_entry->first_lba + 1) * block_size;
        DBG("parent name %s, first %llu, last %llu\n",
            parent_entry->name, parent_entry->first_lba,
            parent_entry->last_lba);
    }

    gpt_header_ptr = (uint8_t *)MEM_ALIGN(block_size, ROUNDUP(block_size,
                                          block_size));

    if (!gpt_header_ptr) {
        PT_WARN( "Failed to Allocate memory to read partition table\n");
        ret = -1;
        goto end;
    }

    data = gpt_header_ptr;

    /* Print out the GPT first */
    ret = read_partition(storage, block_size + cur_gpt_offset, (uint8_t *)data,
                        block_size);

    if (ret) {
        PT_WARN( "GPT: Could not read primary gpt from boot device\n");
        goto end;
    }

    ret = ptdev_parse_gpt_header(part_dev, data, &first_usable_lba,
                                 &partition_entry_size, &header_size,
                                 &max_partition_count, parent_entry, false,
                                 &partition_entries_offset,
                                 &crc_entries, true);

    if (ret) {
        PT_WARN("GPT: (WARNING) Primary header invalid\n");

re_parse_gpt:
        re_parse_gpt = true;
        part_dev->count = partition_count_reset;
        partition_count = partition_count_reset;
        data = gpt_header_ptr;

        /* Check the backup gpt */

        /* Get size of MMC */
        card_size_sec = (device_capacity) / block_size;
        ASSERT (card_size_sec > 0);

        backup_header_lba = card_size_sec - 1;
        ret = read_partition(storage, (backup_header_lba * block_size) + cur_gpt_offset,
                            (uint8_t *)data, block_size);

        if (ret) {
            PT_WARN(
                "GPT: Could not read backup gpt from boot_device\n");
            goto end;
        }

        ret = ptdev_parse_gpt_header(part_dev, data, &first_usable_lba,
                                     &partition_entry_size,
                                     &header_size, &max_partition_count,
                                     parent_entry, true, &partition_entries_offset,
                                     &crc_entries, true);

        if (ret) {
            PT_WARN( "GPT: Primary and backup signatures invalid\n");
            goto end;
        }
    }

#if !SUPPORT_FULL_ENTRIES_BUF

    if (!entries_buffer)
        entries_buffer = (uint8_t *)MEM_ALIGN(block_size, block_size);

    if (!entries_buffer) {
        PT_WARN( "GPT: Allocate memory fail\n");
        ret = 1;
        goto end;
    }

#endif

    crc_val = 0;
    valid_entry_finish = false;

    entries_cnt_per_block = block_size / partition_entry_size;
    blocks_to_read = round_up(max_partition_count,
                              entries_cnt_per_block) / entries_cnt_per_block;
    partition_entries_offset += cur_gpt_offset;

#if DEBUGMODE > 1
    PT_INFO( "max_partition_count = %u\n", max_partition_count);
    PT_INFO( "cur_gpt_offset = %llu\n", (unsigned long long)cur_gpt_offset);
    PT_INFO( "partition_entries_offset = %llu\n",
             (unsigned long long)partition_entries_offset);
    PT_INFO( "blocks_to_read = %u\n", blocks_to_read);
#endif

#if SUPPORT_FULL_ENTRIES_BUF

    if (!full_entries_buffer)
        full_entries_buffer = (uint8_t *)MEM_ALIGN(block_size,
                              blocks_to_read * block_size);

    if (!full_entries_buffer) {
        PT_WARN( "GPT: Allocate memory fail\n");
        ret = 1;
        goto end;
    }

    ret = read_partition(storage, partition_entries_offset,
                        full_entries_buffer, blocks_to_read * block_size);

    if (ret) {
        PT_WARN( "GPT: read partition entries fail\n");
        goto end;
    }

#endif

    /* Read GPT Entries */
    for (i = 0; i < blocks_to_read; i++) {
        ASSERT(partition_count < NUM_PARTITIONS);

#if SUPPORT_FULL_ENTRIES_BUF
        entries_buffer = full_entries_buffer + (i * block_size);
#else
        ret = read_partition(storage, partition_entries_offset + (i * block_size),
                            entries_buffer, block_size);

        if (ret) {
            PT_WARN( "GPT: read partition entries fail\n");
            goto end;
        }

#endif

        data = entries_buffer;
        crc_val = crc32(crc_val, data, block_size);

        for (j = 0; j < entries_cnt_per_block && !valid_entry_finish; j++) {

            /*
             * If partition_entries is NULL,
             * it means that the caller only wants
             * to get partition entries count
             */
            current_entry = &pt_entry;
            memcpy(&(current_entry->type_guid),
                   &data[(j * partition_entry_size)],
                   PARTITION_TYPE_GUID_SIZE);

            if (!memcmp(invalid_guid, current_entry->type_guid, PARTITION_TYPE_GUID_SIZE)) {
                /*
                 * Here, the last valid partition has got,
                 * but needs to read remain data for crc32 of partition
                 * entries array
                 */
                //i = ROUNDUP(max_partition_count, entries_cnt_per_block);
                valid_entry_finish = true;
                break;
            }

#if DEBUGMODE > 1
            PT_INFO("partition_count = %llu\n", (unsigned long long)partition_count);
            PT_INFO("current_entry->type_guid[0] =  0x%x\n", current_entry->type_guid[0]);
            PT_INFO("current_entry->type_guid[1] =  0x%x\n", current_entry->type_guid[1]);
#endif

            if (partition_entries) {
                current_entry = &partition_entries[partition_count];
                memcpy(&(current_entry->type_guid), &(pt_entry.type_guid),
                       PARTITION_TYPE_GUID_SIZE);
            }

            memcpy(&(current_entry->unique_partition_guid),
                   &data[(j * partition_entry_size) + UNIQUE_GUID_OFFSET],
                   UNIQUE_PARTITION_GUID_SIZE);

            current_entry->first_lba =
                GET_LLWORD_FROM_BYTE(&data[(j * partition_entry_size) + FIRST_LBA_OFFSET]);
            current_entry->last_lba =
                GET_LLWORD_FROM_BYTE(&data[(j * partition_entry_size) + LAST_LBA_OFFSET]);

#if DEBUGMODE > 1
            PT_INFO("current_entry->first_lba %llu\n",
                    (unsigned long long)current_entry->first_lba);
            PT_INFO("first_usable_lba %llu\n", (unsigned long long)first_usable_lba);
            PT_INFO("current_entry->last_lba %llu\n",
                    (unsigned long long)current_entry->last_lba);
            PT_INFO("device_capacity 0x%llx\n", (unsigned long long)device_capacity);
            PT_INFO("blocks_for_entries %llu\n", (unsigned long long)blocks_for_entries);
            PT_INFO("device_capacity / block_size - (blocks_for_entries + GPT_HEADER_BLOCKS + 1) = %llu\n",
                    (unsigned long long)( device_capacity / block_size - \
                                          (blocks_for_entries + GPT_HEADER_BLOCKS + 1)));
#endif

            /* If partition entry LBA is not valid, skip this entry
                and parse next entry */
            if ((current_entry->first_lba) < first_usable_lba
                    || (current_entry->last_lba) >
                    ( device_capacity / block_size -
                      (blocks_for_entries + GPT_HEADER_BLOCKS + 1))
                    || current_entry->first_lba >
                    current_entry->last_lba) {
                PT_WARN( "Partition entry(%d), lba not valid\n", j);
                continue;
            }

            /* Here, save the actual lba */
            current_entry->first_lba += lba_offset;
            current_entry->last_lba += lba_offset;
            current_entry->size = current_entry->last_lba - current_entry->first_lba +
                                  1;
            current_entry->attribute_flag =
                GET_LLWORD_FROM_BYTE(&data[(j * partition_entry_size) +
                                                                      ATTRIBUTE_FLAG_OFFSET]);

            memcpy(UTF16_name, &data[(j * partition_entry_size) +
                                                                PARTITION_NAME_OFFSET],
                   MAX_GPT_NAME_SIZE);

            /*
             * Currently partition names in *.xml are UTF-8 and lowercase
             * Only supporting english for now so removing 2nd byte of UTF-16
             */
            for (n = 0; n < MAX_GPT_NAME_SIZE / 2; n++) {
                current_entry->name[n] = UTF16_name[n * 2];
            }

            if (parent_entry) {
                unsigned char *parent_name = parent_entry->name;
                char name[MAX_GPT_NAME_SIZE * 2 + 1] = {0};
                sprintf(name, "%s%s%s", parent_name, partition_separator,
                        current_entry->name);

                if (strlen(name) >= MAX_GPT_NAME_SIZE)
                    PT_WARN( "parent or sub partiton name is too long.\n");

                strncpy((char *)current_entry->name,
                        (const char *)&name, MAX_GPT_NAME_SIZE);
            }

            partition_count++;
            part_dev->count = partition_count;
#if DEBUGMODE > 1
            PT_INFO("1 part_dev->count %d\n", part_dev->count);
#endif

            if (!partition_entries
                    && ptdev_sub_part_exist(current_entry)) {
#if DEBUGMODE > 1
                PT_INFO("ptdev_read_gpt level 2 start\n");
#endif

                if (ptdev_read_gpt(part_dev, current_entry, block_size)) {
                    /* if parse sub partition fail, go on */
                    PT_WARN( "parse sub partition fail!\n");
                }
                else {
                    partition_count = part_dev->count;
                }

#if DEBUGMODE > 1
                PT_INFO("ptdev_read_gpt level 2 end\n");
#endif
            }

#if DEBUGMODE > 1
            PT_INFO("2 part_dev->count %d\n", part_dev->count);
#endif
        }
    }

    if (crc_val != crc_entries) {
        PT_WARN(
            "Partition entires crc mismatch crc_val= 0x%08x with crc_val_org= 0x%08x\n",
            crc_val, crc_entries);

        if (!re_parse_gpt) {
            /* Here, it means fail to check crc32 of primary gpt entries array!
            * We need to re-parse gpt from secondary gpt
            * */
            PT_WARN("re-parse gpt from secondary gpt!\n");

            goto re_parse_gpt;
        }
        else {
            /* Here, the primary and the sencondary
             * gpt are all error.*/
            ret = 1;
            goto end;
        }
    }

    if (re_parse_gpt) {
        PT_INFO("restore primary gpt!\n");
        ret = restore_gpt(part_dev, SEC2PRI, parent_entry);

        if (ret) {
            PT_WARN("fail to restore primary gpt!\n");
        }
        else {
            PT_INFO("restore primary gpt successfully!\n");
        }
    }
    else {
        if (check_secondary_gpt(part_dev, parent_entry)) {
            PT_INFO("secnodary gpt error!\n");

            if (restore_gpt(part_dev, PRI2SEC, parent_entry)) {
                PT_WARN("fail to restore secondary gpt!\n");
            }
            else {
                PT_INFO("restore secondary gpt successfully!\n");
            }
        }
        else {
            PT_INFO("check secondary gpt ok!\n");
        }
    }

    ret = 0;
end:

    if (gpt_header_ptr)
        FREE(gpt_header_ptr);

#if SUPPORT_FULL_ENTRIES_BUF

    if (full_entries_buffer) {
        FREE(full_entries_buffer);
    }

#else

    if (entries_buffer) {
        FREE(entries_buffer);
    }

#endif

    return ret;
}

static uint32_t write_mbr_in_blocks(partition_device_t *part_dev,
                                    uint32_t size, uint8_t *mbrImage, uint32_t block_size)
{
    uint32_t dtype;
    uint32_t dfirstsec;
    uint32_t ebrSectorOffset;
    unsigned char *ebrImage;
    unsigned char *lastAddress;
    int idx, i;
    uint32_t ret;
    storage_device_t *storage = part_dev->storage;

    /* Write the first block */
    ret = write_partition(storage, part_dev->gpt_offset, (uint8_t *)mbrImage,
                         block_size);

    if (ret) {
        PT_WARN( "Failed to write mbr partition\n");
        goto end;
    }

    PT_WARN("write of first MBR block ok\n");
    /*
       Loop through the MBR table to see if there is an EBR.
       If found, then figure out where to write the first EBR
     */
    idx = TABLE_ENTRY_0;

    for (i = 0; i < 4; i++) {
        dtype = mbrImage[idx + i * TABLE_ENTRY_SIZE + OFFSET_TYPE];

        if (MBR_EBR_TYPE == dtype) {
            PT_WARN("EBR found.\n");
            break;
        }
    }

    if (MBR_EBR_TYPE != dtype) {
        PT_WARN("No EBR in this image\n");
        goto end;
    }

    /* EBR exists.  Write each EBR block to boot_device */
    ebrImage = mbrImage + block_size;
    ebrSectorOffset =
        GET_LWORD_FROM_BYTE(&mbrImage
                            [idx + i * TABLE_ENTRY_SIZE +
                                 OFFSET_FIRST_SEC]);
    dfirstsec = 0;
    PT_WARN("first EBR to be written at sector 0x%X\n", dfirstsec);
    lastAddress = mbrImage + size;

    while (ebrImage < lastAddress) {
        PT_WARN("writing to 0x%X\n",
                (ebrSectorOffset + dfirstsec) * block_size);
        ret =
            write_partition(storage, (ebrSectorOffset + dfirstsec) * block_size +
                           part_dev->gpt_offset,
                           (uint8_t *)ebrImage, block_size);

        if (ret) {
            PT_WARN(
                "Failed to write EBR block to sector 0x%X\n",
                dfirstsec);
            goto end;
        }

        dfirstsec =
            GET_LWORD_FROM_BYTE(&ebrImage
                                [TABLE_ENTRY_1 + OFFSET_FIRST_SEC]);
        ebrImage += block_size;
    }

    PT_INFO("MBR written to boot device successfully\n");
end:
    return ret;
}

/* Write the MBR/EBR to the MMC. */
static uint32_t write_mbr(partition_device_t *part_dev, uint32_t size,
                          uint8_t *mbrImage, uint32_t block_size)
{
    uint32_t ret;
    uint64_t device_capacity;
    storage_device_t *storage = part_dev->storage;

    /* Verify that passed in block is a valid MBR */
    ret = ptdev_verify_mbr_signature(size, mbrImage);

    if (ret) {
        goto end;
    }

    device_capacity = storage->get_capacity(storage);

    /* Erasing the device before writing */
    ret = storage->erase(storage, part_dev->gpt_offset,
                         device_capacity - part_dev->gpt_offset);

    if (ret) {
        PT_WARN( "Failed to erase the eMMC card\n");
        goto end;
    }

    /* Write the MBR/EBR to boot device */
    ret = write_mbr_in_blocks(part_dev, size, mbrImage, block_size);

    if (ret) {
        PT_WARN( "Failed to write MBR block to boot device.\n");
        goto end;
    }

    /* Re-read the MBR partition into mbr table */
    ret = ptdev_read_mbr(part_dev, block_size);

    if (ret) {
        PT_WARN( "Failed to re-read mbr partition.\n");
        goto end;
    }

    ptdev_dump_local(part_dev);
end:
    return ret;
}

/*
 * A8h reflected is 15h, i.e. 10101000 <--> 00010101
*/
int reflect(int data, int len)
{
    int ref = 0;

    for (int i = 0; i < len; i++) {
        if (data & 0x1) {
            ref |= (1 << ((len - 1) - i));
        }

        data = (data >> 1);
    }

    return ref;
}

/*
 * Write the GPT Partition Entry Array to the MMC.
 */
static uint32_t
write_gpt_partition_array(partition_device_t *part_dev, uint8_t *header,
                          unsigned char *partition_array_start,
                          uint32_t array_size,
                          uint32_t block_size,
                          uint64_t parent_lba)
{
    uint32_t ret = 1;
    unsigned long long partition_entry_lba;
    unsigned long long partition_entry_array_start_location;
    storage_device_t *storage = part_dev->storage;

    partition_entry_lba =
        GET_LLWORD_FROM_BYTE(&header[PARTITION_ENTRIES_OFFSET]) + parent_lba;
    partition_entry_array_start_location = partition_entry_lba * block_size;

    ret = write_partition(storage, partition_entry_array_start_location +
                         part_dev->gpt_offset,
                         (uint8_t *)partition_array_start, array_size);

    if (ret) {
        PT_WARN("GPT: FAILED to write the partition entry array\n");
        goto end;
    }

end:
    return ret;
}

static void
patch_gpt(partition_device_t *part_dev, uint8_t *gptImage,
          uint64_t density, uint32_t array_size,
          uint32_t max_part_count, uint32_t part_entry_size, uint32_t block_size,
          struct partition_entry *parent_entry, bool last_part_extend)
{
    unsigned char *primary_gpt_header;
    unsigned char *secondary_gpt_header;
    unsigned long long *last_partition_entry;
    uint32_t offset;
    unsigned char *partition_entry_array_start;
    unsigned long long card_size_sec;
    int total_part = 0;
    uint32_t crc_value = 0;
    uint32_t last_part_offset;
    unsigned ptn_entries_blocks = (NUM_PARTITIONS * PARTITION_ENTRY_SIZE) /
                                  block_size;
    /* Get size of MMC */
    card_size_sec = (density) / block_size;

    /* Working around cap at 4GB */
    if (card_size_sec == 0) {
        card_size_sec = 4 * 1024 * 1024 * 2 - 1;
    }

    /* Patching primary header */
    primary_gpt_header = (gptImage + block_size);
    PUT_LONG_LONG(primary_gpt_header + BACKUP_HEADER_OFFSET,
                  ((long long)(card_size_sec - 1)));
    PUT_LONG_LONG(primary_gpt_header + LAST_USABLE_LBA_OFFSET,
                  ((long long)(card_size_sec -
                               (ptn_entries_blocks + GPT_HEADER_BLOCKS + 1))));
    /* Patching backup GPT */
    offset = (2 * array_size);
    secondary_gpt_header = offset + block_size + primary_gpt_header;
    PUT_LONG_LONG(secondary_gpt_header + PRIMARY_HEADER_OFFSET,
                  ((long long)(card_size_sec - 1)));
    PUT_LONG_LONG(secondary_gpt_header + LAST_USABLE_LBA_OFFSET,
                  ((long long)(card_size_sec -
                               (ptn_entries_blocks + GPT_HEADER_BLOCKS + 1))));
    PUT_LONG_LONG(secondary_gpt_header + PARTITION_ENTRIES_OFFSET,
                  ((long long)(card_size_sec -
                               (ptn_entries_blocks + GPT_HEADER_BLOCKS))));
    /* Find last partition */
    last_partition_entry = (unsigned long long *)
                           (primary_gpt_header + block_size + total_part * PARTITION_ENTRY_SIZE);

    //need check 128 bit for GUID
    while (*last_partition_entry != 0 ||
            *(last_partition_entry + 1) != 0) {
        total_part++;
        last_partition_entry = (unsigned long long *)
                               (primary_gpt_header + block_size + total_part * PARTITION_ENTRY_SIZE);
    }

    /* Patching last partition */
    if (last_part_extend) {
        last_part_offset =
            (total_part - 1) * PARTITION_ENTRY_SIZE + PARTITION_ENTRY_LAST_LBA;
        PUT_LONG_LONG(primary_gpt_header + block_size + last_part_offset,
                      (long long)(card_size_sec -
                                  (ptn_entries_blocks + GPT_HEADER_BLOCKS + 1)));
        PUT_LONG_LONG(primary_gpt_header + block_size + last_part_offset +
                      array_size, (long long)(card_size_sec -
                                              (ptn_entries_blocks + GPT_HEADER_BLOCKS + 1)));
    }

    /* Updating CRC of the Partition entry array in both headers */
    partition_entry_array_start = primary_gpt_header + block_size;
    crc_value = crc32(0, partition_entry_array_start,
                      max_part_count * part_entry_size);
    PUT_LONG(primary_gpt_header + PARTITION_CRC_OFFSET, crc_value);
    crc_value = crc32(0, partition_entry_array_start + array_size,
                      max_part_count * part_entry_size);
    PUT_LONG(secondary_gpt_header + PARTITION_CRC_OFFSET, crc_value);
    /* Clearing CRC fields to calculate */
    PUT_LONG(primary_gpt_header + HEADER_CRC_OFFSET, 0);
    crc_value = crc32(0, primary_gpt_header, GPT_HEADER_SIZE);
    PUT_LONG(primary_gpt_header + HEADER_CRC_OFFSET, crc_value);
    PUT_LONG(secondary_gpt_header + HEADER_CRC_OFFSET, 0);
    crc_value = crc32(0, secondary_gpt_header, GPT_HEADER_SIZE);
    PUT_LONG(secondary_gpt_header + HEADER_CRC_OFFSET, crc_value);
}

/*
 * Write the GPT to the device.
 */
static uint32_t write_gpt(partition_device_t *part_dev,
                          struct partition_entry *parent_entry,
                          uint32_t size, uint8_t *gptImage, uint32_t block_size,
                          bool last_part_extend)
{
    uint32_t ret = 1;
    uint32_t header_size;
    uint64_t first_usable_lba;
    uint64_t backup_header_lba;
    uint32_t max_partition_count = 0;
    uint32_t partition_entry_size;
    unsigned char *partition_entry_array_start;
    unsigned char *primary_gpt_header;
    unsigned char *secondary_gpt_header;
    uint32_t offset;
    uint32_t partition_entry_array_size;
    uint64_t
    primary_header_location; /* address on the boot device */
    uint64_t
    secondary_header_location;   /* address on the boot device */
    uint64_t device_capacity;
    uint64_t parent_lba = 0;
    uint64_t partition_offset = 0;
    storage_device_t *storage = part_dev->storage;

    /* Verify that passed block has a valid GPT primary header */
    primary_gpt_header = (gptImage + block_size);
    ret = ptdev_parse_gpt_header(part_dev, primary_gpt_header,
                                 &first_usable_lba,
                                 &partition_entry_size, &header_size,
                                 &max_partition_count, parent_entry, false, NULL, NULL, false);

    if (ret) {
        PT_WARN(
            "GPT: Primary signature invalid cannot write GPT\n");
        goto end;
    }

    /* Get the density of the mmc device */

    if (parent_entry) {
        device_capacity = (parent_entry->last_lba -
                           parent_entry->first_lba + 1) * block_size;
    }
    else {
        device_capacity = storage->get_capacity(storage) - part_dev->gpt_offset;
    }

    /* Verify that passed block has a valid backup GPT HEADER */
    partition_entry_array_size = partition_entry_size * max_partition_count;

    if (partition_entry_array_size < MIN_PARTITION_ARRAY_SIZE) {
        partition_entry_array_size = MIN_PARTITION_ARRAY_SIZE;
    }

    offset = (2 * partition_entry_array_size);
    secondary_gpt_header = offset + block_size + primary_gpt_header;
    ret =
        ptdev_parse_gpt_header(part_dev, secondary_gpt_header, &first_usable_lba,
                               &partition_entry_size, &header_size,
                               &max_partition_count, parent_entry, true, NULL, NULL, false);

    if (ret) {
        PT_WARN(
            "GPT: Backup signature invalid cannot write GPT\n");
        goto end;
    }

    /* Patching the primary and the backup header of the GPT table */
    patch_gpt(part_dev, gptImage, device_capacity, partition_entry_array_size,
              max_partition_count, partition_entry_size, block_size, parent_entry,
              last_part_extend);

    /* Writing protective MBR */
    if (parent_entry) {
        partition_offset = parent_entry->first_lba * block_size;
        parent_lba = parent_entry->first_lba;
    }

    ret = write_partition(storage, partition_offset + part_dev->gpt_offset,
                         (uint8_t *)gptImage, block_size);

    if (ret) {
        PT_WARN( "Failed to write Protective MBR\n");
        goto end;
    }

    /* Writing the primary GPT header */
    primary_header_location = block_size + partition_offset;

    ret = write_partition(storage,
                         primary_header_location + part_dev->gpt_offset,
                         (uint8_t *)primary_gpt_header, block_size);

    if (ret) {
        PT_WARN( "Failed to write GPT header\n");
        goto end;
    }

    /* Writing the backup GPT header */
    backup_header_lba = GET_LLWORD_FROM_BYTE
                        (&primary_gpt_header[BACKUP_HEADER_OFFSET]);
    secondary_header_location = (backup_header_lba + parent_lba) * block_size;
    ret = write_partition(storage,
                         secondary_header_location + part_dev->gpt_offset,
                         (uint8_t *)secondary_gpt_header, block_size);

    if (ret) {
        PT_WARN( "Failed to write GPT backup header\n");
        goto end;
    }

    /* Writing the partition entries array for the primary header */
    partition_entry_array_start = primary_gpt_header + block_size;
    ret = write_gpt_partition_array(part_dev, primary_gpt_header,
                                    partition_entry_array_start,
                                    partition_entry_array_size, block_size,
                                    parent_lba);

    if (ret) {
        PT_WARN(
            "GPT: Could not write GPT Partition entries array\n");
        goto end;
    }

    /*Writing the partition entries array for the backup header */
    partition_entry_array_start = primary_gpt_header + block_size +
                                  partition_entry_array_size;
    ret = write_gpt_partition_array(part_dev, secondary_gpt_header,
                                    partition_entry_array_start,
                                    partition_entry_array_size, block_size,
                                    parent_lba);

    if (ret) {
        PT_WARN(
            "GPT: Could not write GPT Partition entries array\n");
        goto end;
    }

    /* Re-read the GPT partition table */
    PT_INFO("Re-reading the GPT Partition Table\n");
    part_dev->count = 0;
    ptdev_read_table(part_dev);
    ptdev_dump_local(part_dev);
    PT_WARN( "GPT: Partition Table written\n");
    memset(primary_gpt_header, 0x00, size - block_size);

end:
    return ret;
}

int ptdev_write_table(partition_device_t *part_dev, const char *name,
                      unsigned size, unsigned char *ptable, bool last_part_extend)
{
    uint32_t ret = 1;
    uint32_t partition_type;
    uint32_t block_size;
    int index = INVALID_PTN;
    struct partition_entry *partition_entries;
    storage_device_t *storage;

    if (ptable == NULL) {
        PT_WARN("NULL partition table\n");
        return 1;
    }

    if ((!part_dev) || (!part_dev->storage) ) {
        PT_WARN( "Write Invalid partition\n");
        return 1;
    }

    partition_entries = part_dev->partition_entries;
    storage = part_dev->storage;

    if (name) {
        PT_INFO("write partition %s\n", name);
        index = ptdev_get_index(part_dev, name);

        if (index == INVALID_PTN) {
            PT_WARN("Invalide partition name or write global partiton first.\n");
            return 1;
        }
    }
    else {
        PT_INFO("write global parition\n");
    }

    block_size = storage->block_size;
    ret = ptdev_get_type(size, ptable, &partition_type);

    if (ret)
        return ret;

    switch (partition_type) {
        case PARTITION_TYPE_MBR:
            PT_INFO("Writing MBR partition\n");
            ret = write_mbr(part_dev, size, ptable, block_size);
            break;

        case PARTITION_TYPE_GPT:
            PT_INFO("Writing GPT partition\n");

            if (index == INVALID_PTN) {
                PT_WARN("Re-Flash the global partitions\n");
                ret = write_gpt(part_dev, NULL, size, ptable, block_size,
                                last_part_extend);
            }
            else {
                if (!partition_entries) {
                    PT_WARN( "Write Invalid extral partition\n");
                    ret = 1;
                    break;
                }

                PT_WARN( "Re-Flash the extral partition table %s\n", name);
                ret = write_gpt(part_dev, &partition_entries[index], size, ptable,
                                block_size,
                                last_part_extend);
            }

            PT_WARN( "Re-Flash all the partitions\n");
            break;

        default:
            PT_WARN( "Invalid partition\n");
            ret = 1;
            return ret;
    }

    return ret;
}

/*
 * Fill name for android partition found.
 */
static void
mbr_fill_name(struct partition_entry *partition_ent, uint32_t type)
{
    memset(partition_ent->name, 0, MAX_GPT_NAME_SIZE);

    switch (type) {
        case MBR_RPM_TYPE:
            strcpy((char *)partition_ent->name, "rpm");
            break;

        case MBR_TZ_TYPE:
            strcpy((char *)partition_ent->name, "tz");
            break;

        case MBR_BOOT_TYPE:
            strcpy((char *)partition_ent->name, "boot");
            break;

        case MBR_RECOVERY_TYPE:
            strcpy((char *)partition_ent->name, "recovery");
            break;

        case MBR_MISC_TYPE:
            strcpy((char *)partition_ent->name, "msic");
            break;

        case MBR_SSD_TYPE:
            strcpy((char *)partition_ent->name, "ssd");
            break;
    };
}

/*
 * Find index of parition in array of partition entries
 */
unsigned int ptdev_get_index(partition_device_t *part_dev,
                             const char *name)
{
    uint32_t input_string_length = strlen(name);
    unsigned n;
    int curr_slot = INVALID;
    const char *suffix_curr_actv_slot = NULL;
    char *curr_suffix = NULL;
    unsigned partition_count;
    struct partition_entry *partition_entries;

    if ((!part_dev) || (!part_dev->partition_entries) || (!name)) {
        return INVALID_PTN;
    }

    partition_entries = part_dev->partition_entries;
    partition_count = part_dev->count;

    if (partition_count > NUM_PARTITIONS) {
        return INVALID_PTN;
    }

    /*  We iterate through the parition entries list,
        to find the partition with active slot suffix.
    */
    for (n = 0; n < partition_count; n++) {
        if (!strncmp((const char *)name, (const char *)partition_entries[n].name,
                     input_string_length)) {
            curr_suffix = (char *)(partition_entries[n].name + input_string_length);

            /* if partition_entries.name is NULL terminated return the index */
            if (*curr_suffix == '\0')
                return n;

            if (ptdev_multislot_is_supported(part_dev)) {
                curr_slot = ptdev_find_active_slot(part_dev);

                /* If suffix string matches with current active slot suffix return index */
                if (curr_slot != INVALID) {
                    suffix_curr_actv_slot = SUFFIX_SLOT(curr_slot);

                    if (!strcmp((const char *)curr_suffix, suffix_curr_actv_slot))
                        return n;
                    else
                        continue;
                }
                else {
                    /* No valid active slot */
                    return INVALID_PTN;
                }
            }
        }
    }

    return INVALID_PTN;
}

/* Get size of the partition */
unsigned long long ptdev_get_size(partition_device_t *part_dev,
                                  const char *name)
{
    uint32_t block_size;
    uint32_t index;
    struct partition_entry *partition_entries;
    storage_device_t *storage;

    if ((!part_dev) || (!part_dev->partition_entries) || (!name)
            || (!part_dev->storage) ) {
        return 0;
    }

    index = ptdev_get_index(part_dev, name);
    storage = part_dev->storage;
    block_size = storage->block_size;
    partition_entries = part_dev->partition_entries;

    if (index == (unsigned)INVALID_PTN)
        return 0;
    else {
        return partition_entries[index].size * block_size;
    }
}

/* Get offset of the partition */
unsigned long long ptdev_get_offset(partition_device_t *part_dev,
                                    const char *name)
{
    uint32_t block_size;
    uint32_t index;
    storage_device_t *storage;
    struct partition_entry *partition_entries;

    if ((!part_dev) || (!part_dev->partition_entries) || (!name)
            || (!part_dev->storage)) {
        return 0;
    }

    index = ptdev_get_index(part_dev, name);
    storage = part_dev->storage;
    block_size = storage->block_size;
    partition_entries = part_dev->partition_entries;

    if (index == (unsigned)INVALID_PTN)
        return 0;
    else {
        return partition_entries[index].first_lba * block_size +
               part_dev->gpt_offset;
    }
}

struct partition_info ptdev_get_info(partition_device_t *part_dev,
                                     const char *name)
{
    struct partition_info info = {0};

    if (!name) {
        PT_WARN("Invalid partition name passed\n");
        return info;
    }

    if (!part_dev) {
        PT_WARN("Invalid partition dev\n");
        return info;
    }

    info.offset = ptdev_get_offset(part_dev, name);
    info.size   = ptdev_get_size(part_dev, name);

    if (!info.offset || !info.size)
        PT_WARN("Error unable to find partition : [%s]\n", name);

    return info;
}

/* Debug: Print all parsed partitions */
void ptdev_dump_local(partition_device_t *part_dev)
{
    unsigned i = 0;
    unsigned partition_count;
    struct partition_entry *partition_entries;

    if ((!part_dev) || (!part_dev->partition_entries)) {
        PT_WARN("Invalid partition dev\n");
        return;
    }

    partition_count = part_dev->count;
    partition_entries = part_dev->partition_entries;

    for (i = 0; i < partition_count; i++) {
        PT_INFO("ptn[%d]:Name[%s] Size[%llu] Type[%u] First[%llu] Last[%llu]\n",
                i, partition_entries[i].name, partition_entries[i].size,
                partition_entries[i].dtype,
                partition_entries[i].first_lba,
                partition_entries[i].last_lba);
    }
}

void ptdev_attr_dump_local(partition_device_t *ptdev)
{
    const char *a, *b, *s;
    unsigned long long retry = 0;
    unsigned long long priority = 0;
    unsigned partition_count;
    struct partition_entry *partition_entries;

    if ((!ptdev) || (!ptdev->partition_entries)) {
        PT_WARN("Invalid partition dev\n");
        return;
    }

    partition_count = ptdev->count;
    partition_entries = ptdev->partition_entries;

    PT_INFO("active  bootable  success  retry   priority    name\n");

    for (unsigned i = 0; i < partition_count; i++) {
        a = (!!(partition_entries[i].attribute_flag & PART_ATT_ACTIVE_VAL)) ? "Y" : "N";
        b = (!!(partition_entries[i].attribute_flag & PART_ATT_UNBOOTABLE_VAL)) ? "N" :
            "Y";
        s = (!!(partition_entries[i].attribute_flag & PART_ATT_SUCCESSFUL_VAL)) ? "Y" :
            "N";
        retry = (partition_entries[i].attribute_flag & PART_ATT_MAX_RETRY_COUNT_VAL) >>
                PART_ATT_MAX_RETRY_CNT_BIT;
        priority = (partition_entries[i].attribute_flag & PART_ATT_PRIORITY_VAL) >>
                   PART_ATT_PRIORITY_BIT;
        PT_INFO("  %s       %s         %s        %llx      %llx     %s\n",
                a, b, s, retry, priority, partition_entries[i].name);
    }
}

static uint32_t
ptdev_verify_mbr_signature(uint32_t size, uint8_t *buffer)
{
    /* Avoid checking past end of buffer */
    if ((TABLE_SIGNATURE + 1) > size) {
        return 1;
    }

    /* Check to see if signature exists */
    if ((buffer[TABLE_SIGNATURE] != MMC_MBR_SIGNATURE_BYTE_0) ||
            (buffer[TABLE_SIGNATURE + 1] != MMC_MBR_SIGNATURE_BYTE_1)) {
        PT_WARN("MBR signature does not match.\n");
        return 1;
    }

    if ((buffer[0] != 0xfa) || (buffer[1] != 0xeb) || (buffer[2] != 0xfe)) {
        PT_WARN("MBR start byte no match\n");
        return 1;
    }

    return 0;
}

/* master boot record partition types should be in a byte */
static uint32_t
mbr_partition_get_type(uint32_t size, unsigned char *partition,
                       unsigned char *partition_type)
{
    uint32_t type_offset = TABLE_ENTRY_0 + OFFSET_TYPE;

    if (size < (type_offset + sizeof (*partition_type))) {
        return 1;
    }

    *partition_type = partition[type_offset];
    return 0;
}

uint32_t
ptdev_get_type(uint32_t size, unsigned char *partition,
               uint32_t *partition_type)
{
    uint32_t ret = 0;
    /*
     * If the block contains the MBR signature, then it's likely either
     * MBR or MBR with protective type (GPT).  If the MBR signature is
     * not there, then it could be the GPT backup.
     */

    /* First check the MBR signature */
    ret = ptdev_verify_mbr_signature(size, partition);

    if (!ret) {
        unsigned char mbr_partition_type = PARTITION_TYPE_MBR;

        /* MBR signature verified.  This could be MBR, MBR + EBR, or GPT */
        ret =
            mbr_partition_get_type(size, partition,
                                   &mbr_partition_type);

        if (ret) {
            PT_WARN("Cannot get TYPE of partition");
        }
        else if (MBR_PROTECTED_TYPE == mbr_partition_type) {
            *partition_type = PARTITION_TYPE_GPT;
        }
        else {
            *partition_type = PARTITION_TYPE_MBR;
        }
    }
    else {
        /*
         * This could be the GPT backup.  Make that assumption for now.
         * Anybody who treats the block as GPT backup should check the
         * signature.
         */
        *partition_type = PARTITION_TYPE_GPT_BACKUP;
    }

    return ret;
}

/*
 * Parse the gpt header and get the required header fields
 * Return 0 on valid signature
 */
static uint32_t
ptdev_parse_gpt_header(partition_device_t *part_dev, unsigned char *buffer,
                       uint64_t *first_usable_lba,
                       uint32_t *partition_entry_size,
                       uint32_t *header_size,
                       uint32_t *max_partition_count,
                       struct partition_entry *parent_entry,
                       bool secondary_gpt,
                       uint64_t *partition_entries_offset,
                       uint32_t *crc_entries_array,
                       bool check_lba)
{
    uint32_t ret = 0;
    uint32_t crc_val = 0;
    uint32_t crc_val_org = 0;
    unsigned long long last_usable_lba = 0;
    unsigned long long partition_0 = 0;
    unsigned long long current_lba = 0;
    storage_device_t *storage = part_dev->storage;
    uint32_t block_size = storage->block_size;
    uint32_t blocks_for_entries =
        (NUM_PARTITIONS * PARTITION_ENTRY_SIZE) / block_size;
    /* Get the density of the mmc device */
    uint64_t device_capacity;

    if (!parent_entry) {
        device_capacity = storage->get_capacity(storage) - part_dev->gpt_offset;
    }
    else {
        device_capacity = (parent_entry->last_lba -
                           parent_entry->first_lba + 1) * block_size;
    }

    /* Check GPT Signature */
    if (((uint32_t *) buffer)[0] != GPT_SIGNATURE_2 ||
            ((uint32_t *) buffer)[1] != GPT_SIGNATURE_1) {
        PT_WARN("GPT: (WARNING) signature invalid\n");
        return 1;
    }

    *header_size = GET_LWORD_FROM_BYTE(&buffer[HEADER_SIZE_OFFSET]);

    /* check for header size too small */
    if (*header_size < GPT_HEADER_SIZE) {
        PT_WARN("GPT Header size is too small\n");
        return 1;
    }

    /* check for header size too large */
    if (*header_size > block_size) {
        PT_WARN("GPT Header size is too large\n");
        return 1;
    }

    crc_val_org = GET_LWORD_FROM_BYTE(&buffer[HEADER_CRC_OFFSET]);
    /* Write CRC to 0 before we calculate the crc of the GPT header */
    crc_val = 0;
    PUT_LONG(&buffer[HEADER_CRC_OFFSET], crc_val);

    crc_val  = crc32(0, buffer, *header_size);

    if (crc_val != crc_val_org) {
        PT_WARN("Header crc mismatch crc_val = 0x%08x with crc_val_org = 0x%08x\n",
                crc_val, crc_val_org);
        return 1;
    }
    else {
        PUT_LONG(&buffer[HEADER_CRC_OFFSET], crc_val);
    }

    current_lba =
        GET_LLWORD_FROM_BYTE(&buffer[PRIMARY_HEADER_OFFSET]);
    *first_usable_lba =
        GET_LLWORD_FROM_BYTE(&buffer[FIRST_USABLE_LBA_OFFSET]);
    *max_partition_count =
        GET_LWORD_FROM_BYTE(&buffer[PARTITION_COUNT_OFFSET]);
    *partition_entry_size =
        GET_LWORD_FROM_BYTE(&buffer[PENTRY_SIZE_OFFSET]);
    last_usable_lba =
        GET_LLWORD_FROM_BYTE(&buffer[LAST_USABLE_LBA_OFFSET]);

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
        if (check_lba && (current_lba != ((device_capacity / block_size) - 1))) {
            PT_WARN("Secondary GPT first usable LBA mismatch\n");
            return 1;
        }
    }

    /* check for first lba should be with in the valid range */
    if (*first_usable_lba > (device_capacity / block_size)) {
        PT_WARN("Invalid first_usable_lba\n");
        PT_WARN("block_size = %d\n",  block_size);
        PT_WARN("device_capacity = %lld\n", (unsigned long long)device_capacity);
        PT_WARN("last_usable_lba = %lld\n", (unsigned long long)last_usable_lba);
        return 1;
    }

    /* check for last lba should be with in the valid range */
    if (last_usable_lba > (device_capacity / block_size)) {
        PT_WARN("Invalid last_usable_lba\n");
        PT_WARN("block_size = %d\n",  block_size);
        PT_WARN("device_capacity = %lld\n", (unsigned long long)device_capacity);
        PT_WARN("last_usable_lba = %lld\n", (unsigned long long)last_usable_lba);
        return 1;
    }

    /* check for partition entry size */
    if (*partition_entry_size != PARTITION_ENTRY_SIZE) {
        PT_WARN("Invalid parition entry size\n");
        return 1;
    }

    if ((*max_partition_count) > (MIN_PARTITION_ARRAY_SIZE /
                                  (*partition_entry_size))) {
        PT_WARN( "Invalid maximum partition count\n");
        return 1;
    }

    if (check_lba) {
        partition_0 = GET_LLWORD_FROM_BYTE(&buffer[PARTITION_ENTRIES_OFFSET]);

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

        *partition_entries_offset = partition_0  * block_size;
        crc_val_org = GET_LWORD_FROM_BYTE(&buffer[PARTITION_CRC_OFFSET]);
        *crc_entries_array = crc_val_org;
#if 0
        entry_buffer_p = (uint8_t *)MEM_ALIGN(block_size, block_size);

        if (!entry_buffer_p) {
            PT_WARN( "Failed to Allocate memory to read partition table\n");
            return 1;
        }

        crc_val = 0x0;

        for (uint32_t i = 0; i < blocks_to_read; i++) {
            /* read the partition entries to new_buffer */
            ret = read_partition(storage,
                                *partition_entries_offset + i * block_size,
                                entry_buffer_p, block_size);

            if (ret) {
                PT_WARN( "GPT: Could not read primary gpt from mmc\n");
                ret = 1;
                goto end;
            }

            crc_val  = crc32(crc_val, entry_buffer_p, block_size);
        }


        if (crc_val != crc_val_org) {
            PT_WARN("Partition entires crc mismatch crc_val= 0x%08x with crc_val_org= 0x%08x\n",
                    crc_val, crc_val_org);

            ret = 1;
            goto end;
        }

    }

end:

    if (entry_buffer_p) {
        FREE(entry_buffer_p);
        entry_buffer_p = NULL;
#endif
    }

    return ret;
}

bool ptdev_gpt_exists(partition_device_t *part_dev)
{
    return part_dev->gpt_partitions_exist;
}

bool partition_is_readonly(partition_device_t *part_dev, const char *name)
{
    struct partition_entry *partition_entries;
    uint32_t index;

    if ((!part_dev) || (!part_dev->partition_entries)) {
        PT_WARN("Invalid partition dev\n");
        return false;
    }

    partition_entries = part_dev->partition_entries;
    index = ptdev_get_index(part_dev, name);

    if (index == (unsigned)INVALID_PTN) {
        PT_WARN("Invalide partition name\n");
        return false;
    }

    return !!(partition_entries[index].attribute_flag
              & PART_ATT_READONLY_VAL);
}

static bool ptdev_sub_part_exist(struct partition_entry *partition_entries)
{
    return !memcmp(sub_part_guid, partition_entries->type_guid,
                   PARTITION_TYPE_GUID_SIZE);
}

partition_device_t *ptdev_setup(storage_device_t *storage,
                                uint64_t gpt_offset)
{
    if (!storage) {
        return NULL;
    }

    partition_device_t *part_dev = CALLOC(1, sizeof(partition_device_t));
    part_dev->storage = storage;
    part_dev->gpt_offset = gpt_offset;
    part_dev->local = true;

    return part_dev;
}

unsigned int ptdev_destroy(partition_device_t *ptdev)
{
    if (!ptdev) {
        PT_WARN( "%s pointer is null\n", __func__);
        return -1;
    }

    if (ptdev->partition_entries) {
        FREE(ptdev->partition_entries);
    }

    FREE(ptdev);
    return 0;
}

bool part_is_active(const struct partition_entry *entry)
{
    return !!(entry->attribute_flag & PART_ATT_ACTIVE_VAL);
}

void guid2hex(char *buf, uint32_t buf_len, EFI_GUID *guid)
{
    uint8_t hex_digits[17] = "0123456789abcdef";

    if (!buf || !guid || buf_len < 37) {
        return;
    }

    buf[0] = hex_digits[(guid->data1 >> 28) & 0x0f];
    buf[1] = hex_digits[(guid->data1 >> 24) & 0x0f];
    buf[2] = hex_digits[(guid->data1 >> 20) & 0x0f];
    buf[3] = hex_digits[(guid->data1 >> 16) & 0x0f];
    buf[4] = hex_digits[(guid->data1 >> 12) & 0x0f];
    buf[5] = hex_digits[(guid->data1 >> 8) & 0x0f];
    buf[6] = hex_digits[(guid->data1 >> 4) & 0x0f];
    buf[7] = hex_digits[(guid->data1 >> 0) & 0x0f];
    buf[8] = '-';
    buf[9] = hex_digits[(guid->data2 >> 12) & 0x0f];
    buf[10] = hex_digits[(guid->data2 >> 8) & 0x0f];
    buf[11] = hex_digits[(guid->data2 >> 4) & 0x0f];
    buf[12] = hex_digits[(guid->data2 >> 0) & 0x0f];
    buf[13] = '-';
    buf[14] = hex_digits[(guid->data3 >> 12) & 0x0f];
    buf[15] = hex_digits[(guid->data3 >> 8) & 0x0f];
    buf[16] = hex_digits[(guid->data3 >> 4) & 0x0f];
    buf[17] = hex_digits[(guid->data3 >> 0) & 0x0f];
    buf[18] = '-';
    buf[19] = hex_digits[(guid->data4[0] >> 4) & 0x0f];
    buf[20] = hex_digits[(guid->data4[0] >> 0) & 0x0f];
    buf[21] = hex_digits[(guid->data4[1] >> 4) & 0x0f];
    buf[22] = hex_digits[(guid->data4[1] >> 0) & 0x0f];
    buf[23] = '-';
    buf[24] = hex_digits[(guid->data4[2] >> 4) & 0x0f];
    buf[25] = hex_digits[(guid->data4[2] >> 0) & 0x0f];
    buf[26] = hex_digits[(guid->data4[3] >> 4) & 0x0f];
    buf[27] = hex_digits[(guid->data4[3] >> 0) & 0x0f];
    buf[28] = hex_digits[(guid->data4[4] >> 4) & 0x0f];
    buf[29] = hex_digits[(guid->data4[4] >> 0) & 0x0f];
    buf[30] = hex_digits[(guid->data4[5] >> 4) & 0x0f];
    buf[31] = hex_digits[(guid->data4[5] >> 0) & 0x0f];
    buf[32] = hex_digits[(guid->data4[6] >> 4) & 0x0f];
    buf[33] = hex_digits[(guid->data4[6] >> 0) & 0x0f];
    buf[34] = hex_digits[(guid->data4[7] >> 4) & 0x0f];
    buf[35] = hex_digits[(guid->data4[7] >> 0) & 0x0f];
    buf[36] = '\0';
    return;
}
#ifdef __cplusplus
}
#endif /* __cplusplus */
