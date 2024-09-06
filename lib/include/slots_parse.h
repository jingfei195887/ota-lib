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

#ifndef SDRV_SLOTS_PARSE_H
#define SDRV_SLOTS_PARSE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "system_cfg.h"
#include "storage_device.h"
#include "storage_dev_ospi.h"
#include "ab_partition_parser.h"
#include "partition_parser.h"
#include "syscall_interface.h"
#include "update_device.h"

/*
* Automatically detect all possible storage devices of the current system and create
* a partition table for each storage device. No need to specify a certain type of
* update device.
*
* Return 0 if successfully, otherwise -1.
*/
int boot_control_init_all(void);

/*
 * Setup partition devices array, and return the specific one.
 *
 * Since the system may have several boot devices, the parameter storage_id_e
 * indicate which the user want to programe.
 * invoker will get the instance of partition device by the passed parameter,
 * with partition device, user can get part name, part offset, attribute, etc.
 * for interface of partition devices, see partition_parser.h.
 *
 * Return 0 if successfully, otherwise -1.
 **/

int switch_storage_dev(partition_device_t **ptdev, storage_id_e dev);

/*
* Setup partition devices array localy, and return the specific one.
*
* Sometimes, when you need the GPT partition table on the AP side (such as NorFLASH's
* GPT partition table), instead of using the remote GPT provided by the update monitor,
* you can use this interface. This interface does not mean that the storage is local,
* but that the partition table is read to the AP side for parsing.
*
* Return 0 if successfully, otherwise -1.
*/
int switch_storage_dev_force_local(partition_device_t **ptdev,
                                   storage_id_e dev);


/*
* Setup partition devices array localy for test, and return the specific one.

* For testing purposes, ptdev is not passed to the update device.

* Return 0 if successfully, otherwise -1.
*/
int switch_storage_dev_force_local_flexible(partition_device_t **ptdev,
        storage_id_e dev);

/*
 * Free partition devices array.
 *
 * Return 0 if successfully, otherwise -1.
 **/
int free_storage_dev(partition_device_t *ptdev);

/*
 * Free partition devices array use local method.
 *
 * Return 0 if successfully, otherwise -1.
 **/
int free_storage_dev_force_local(partition_device_t *ptdev);

/*
 * Count available slots the system support currently.
 *
 * For instance, a system with a single set of partitions would return
 * 1, a system with A/B would return 2, A/B/C -> 3...
 **/

unsigned get_number_slots(partition_device_t *ptdev);

/*
 * Count available slots the system support currently for all storage device.
 *
 * If the query results in all storage devices is consistent, return this
 * value, otherwise return 1.
 **/
unsigned get_number_slots_all(void);

/*
 * The slot num if the system boot from, the value letting the system know
 * whether the current slot is A or B. The meaning of A and B is
 * left up to the implementer. It is assumed that if the current slot
 * is A, then the block devices underlying B can be accessed directly
 * without any risk of corruption.
 *
 * Return the active and successful boot slot num.
 **/
unsigned get_current_slot(partition_device_t *ptdev);

/*
 * Get the slot num where the system boot from for all for all storage device.
 * If the query results in all storage devices is consistent, return this
 * value, otherwise return uint32 max value.
 *
 * Return the active and successful boot slot num on succes
 * Return UINT_MAX on error.
 **/
unsigned get_current_slot_all(void);

/*
 * Marks the current slot as having booted successfully.
 * this shall be invoked once the system boot up successfully.
 * if the successful attribute not get marked after several reboot try.
 * the system will try rollback to old software.
 *
 * Return 0 on success, -1 on error.
 **/
int mark_boot_successful(partition_device_t *ptdev);

/*
 * Marks the current slot as having booted successfully for all storage device.
 *
 * Returns 0 if all execution results are successful, otherwise returns -1
 **/
int mark_boot_successful_all(void);

/*
 * Marks the slot passed in parameter as the active slot.
 * this shall be invoked after all inactive parts get updated,
 * and get confirmed by user, boot from the updated part after reboot.
 *
 * Return 0 on success, -1 on error.
 **/
int set_active_boot_slot(partition_device_t *ptdev, unsigned slot);

/*
 * Marks a slot as bootable for all storage device.
 *
 * Returns 0 if all execution results are successful, otherwise returns -1
 **/
int set_active_boot_slot_all(unsigned slot);

/*
 * Marks the slot passed in parameter as an unbootable.
 * This can be used while updating the contents of the slot's partitions,
 * so that the system will not attempt to boot a known bad set up.
 *
 * Returns 0 on success, -1 on error.
 **/
int set_slot_as_unbootable(partition_device_t *ptdev, unsigned slot);

/*
 * Marks a slot is unbootable for partition tables of all storage devices
 *
 * Returns 0 if all execution results are successful, otherwise returns -1.
 **/
int set_slot_as_unbootable_all(unsigned slot);

/*
 * Returns if the slot passed in parameter is bootable.
 * Note that slots can be made unbootable by both the bootloader and
 * by the OS using setSlotAsUnbootable.
 *
 * Returns 1 if the slot is bootable, 0 if it's not, and -1 on error.
 **/
int is_slot_bootable(partition_device_t *ptdev, unsigned slot);

/*
 * Returns if the slot passed in parameter is bootable for partition tables
 * of all storage devices.
 *
 * Returns 1 if the slot is bootable, 0 if it's not
 * if the query results of all storage devices is not consistent, return -1.
 **/
int is_slot_bootable_all(unsigned slot);

/*
 * Returns the string suffix used by partitions that correspond to
 * the slot number passed in parameter. The returned string is expected
 * to be statically allocated and not need to be freed.
 *
 * Returns NULL if slot does not match an existing slot.
 **/
const char *get_suffix(partition_device_t *ptdev, unsigned slot);

/*
 * Get suffix for all storage device partitions that correspond to
 * If the query results in all storage devices is consistent, return
 * the suffix string.
 *
 * Returns NULL if slot does not match an existing slot or a device
 * partition's suffix string is not consistent with others.
 **/
const char *get_suffix_all(unsigned slot);

/*
 * Returns if the slot passed in parameter has been marked as successful
 * using markBootSuccessful.
 *
 * Returns 1 if the slot has been marked as successful, 0 if it's not the case,
 * and -1 on error.
 **/
int is_slot_marked_successful(partition_device_t *ptdev, unsigned slot);

/*
 * Returns if the slot passed in parameter has been marked as successful for
 * partition tables of all storage devices.
 *
 * Returns 1 if the slot has been marked as successful, 0 if it's not the case,
 * if the query results of all storage devices is not consistent, return -1.
 **/
int is_slot_marked_successful_all(unsigned slot);

/*
 * This interface is for no all parts update in one slot feature.
 * Since the interface set_active_boot_slot, set_slot_as_unbootable will mark all
 * parts attribute in a slot, but user may want to update several parts instead
 * of all parts. User can invoke this interface to update single part attribute.
 *
 * Get part name from partition_device_t.
 *
 * Return 0 on success, otherwise return -1.
 **/

int setAttributeByPartition(partition_device_t *ptdev, unsigned slot,
                            char *partName, part_attr_t attr);

/*
 * Same with set_part_attr, clean  single part attribute.
 *
 * Return 0 on success, otherwise return -1
 **/
int clearAttributeByPartition(partition_device_t *ptdev, unsigned slot,
                              char *partName,  part_attr_t attr);

/*
 * Get another slot corresponding to the incoming parameter for the partition table
 * of all storage devices.
 *
 * Return SLOT_A if incoming parameter is SLOT_B.
 * Return SLOT_B if incoming parameter is SLOT_A.
 * Return UINT_MAX if incoming parameter error.
*/
unsigned get_inverse_slot_all(unsigned slot);

/*
 * Pass in a storage device number to find out whether the device has established a partition
 * table data structure.
 *
 * Return 0 if partition table established, otherwise return -1.
*/
int check_ptdev_exist(storage_id_e dev);

/*
 * Print the partition table of the specified storage device.
 */
void ptdev_dump(partition_device_t *ptdev);

/*
 * Print the partition table attr of the specified storage device.
 */
void ptdev_attr_dump(partition_device_t *ptdev);

/*
 * Print the partition table for all storage devices.
 */
void ptdev_dump_all();

/**
* Returns the active slot to boot into on the next boot for one partition, must return 0 or 1.
*/
int get_active_boot_slot(partition_device_t *ptdev);

/**
* Returns the active slot to boot into on the next boot for all partitions, must return 0 or 1.
*/
int get_active_boot_slot_all();


/**
* Returns true if we are in Android userdebug mode, return false if not.
*/
bool is_in_android_userdebug();

/**
* Returns true if we are in Android recovery mode, return false if not.
*/
bool is_in_android_recovery();

/*
 * Returns if the slot passed in parameter is unsuccessful.
 *
 * Returns 1 if the slot is unsuccessful, 0 if it's not, and -1 on error.
 **/
int is_slot_unsuccessful(partition_device_t *ptdev, unsigned slot);

/*
 * Returns if the slot passed in parameter is unsuccessful for partition tables
 * of all storage devices.
 *
 * Returns 1 if the slot is unsuccessful, 0 if it's not
 * if the query results of all storage devices is not consistent, return -1.
 **/
int is_slot_unsuccessful_all(unsigned slot);

/*
 * Marks the slot passed in parameter as an unsuccessful.
 *
 * Returns 0 on success, -1 on error.
 **/
int set_slot_as_unsuccessful(partition_device_t *ptdev, unsigned slot);

/*
 * Marks a slot is unsuccessful for partition tables of all storage devices
 *
 * Returns 0 if all execution results are successful, otherwise returns -1.
 **/
int set_slot_as_unsuccessful_all(unsigned slot);

/*
 * Returns if the slot passed in parameter has been marked as successful
 * using markBootSuccessful.
 *
 * Returns 1 if the slot has been marked as successful, 0 if it's not the case,
 * and -1 on error.
 **/
int is_slot_successful(partition_device_t *ptdev, unsigned slot);

/*
 * Returns if the slot passed in parameter is successful for partition tables
 * of all storage devices.
 *
 * Returns 1 if the slot is successful, 0 if it's not
 * if the query results of all storage devices is not consistent, return -1.
 **/
int is_slot_successful_all(unsigned slot);

/*
 * Marks the current slot as having booted successfully.
 * this shall be invoked once the system boot up successfully.
 * if the successful attribute not get marked after several reboot try.
 * the system will try rollback to old software.
 *
 * Return 0 on success, -1 on error.
 **/
int set_slot_as_successful(partition_device_t *ptdev, unsigned slot);

/*
 * Marks a slot is successful for partition tables of all storage devices
 *
 * Returns 0 if all execution results are successful, otherwise returns -1.
 **/
int set_slot_as_successful_all(unsigned slot);

/*
 * check whether all device can roll back.
 *
 * Returns 1 if can, 0 if not, -1 on error.
 **/
int is_inactive_slot_successful_and_bootable_all(unsigned slot);

signed get_slot_suffix_info();
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // SDRV_SLOTS_PARSE_H
