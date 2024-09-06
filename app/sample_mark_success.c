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
#if !RUN_IN_QNX
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include "slots_parse.h"
#define MARK_SUCCESS_WAKE_LOCK_NAME "ota_mark_success"

extern bool ota_wake_lock(bool lock, const char * lock_name);

int main(int argc, char *argv[])
{
    int ret = -1;
    int slot;
    const char *suffix;
    int val = -1;
    bool mark_success_lock = false;

    /* prevent OS from autosleep */
    mark_success_lock = ota_wake_lock(true, MARK_SUCCESS_WAKE_LOCK_NAME);
    if (!mark_success_lock)
    {
        PRINTF_CRITICAL("failed to get mark success wake lock\n");
        goto out;
    }

    /* init for all update devices */
    val = boot_control_init_all();

    if (0 != val) {
        PRINTF_CRITICAL("failed to setup ptdev\n");
        goto out;
    }

    /* get slot number */
    val = get_number_slots_all();

    PRINTF_INFO("slots count %d\n", val);

    if (val != 2) {
        PRINTF_CRITICAL("slots count %d is not 2\n", val);
        goto out;
    }

    /* get active slot */
    slot = get_current_slot_all();

    /* get active_slot suffix */
    suffix = get_suffix_all(slot);

    if (!suffix || ((slot != SLOT_A) && (slot != SLOT_B))) {
        PRINTF_CRITICAL("bad slot %d, suffix = %s\n", slot, suffix);
        goto out;
    }

    PRINTF_INFO("corrent slot %d, %s\n", slot, suffix);

    /* query if active slot marked successful */
    val = is_slot_marked_successful_all(slot);

    /* try to mark successful */
    if (0 == val) {
        val = mark_boot_successful_all();

        if (0 != val) {
            PRINTF_CRITICAL("mark %s successful attr error\n", suffix);
            goto out;
        }
    }

    /* already mark successful */
    else if (1 == val) {
        PRINTF_INFO("already marked successful\n");
    }

    /* already mark successful */
    else {
        PRINTF_CRITICAL("get slot %s successful attr error\n", suffix);
        goto out;
    }

    ret = 0;
out:
    if (mark_success_lock)
        ota_wake_lock(false, MARK_SUCCESS_WAKE_LOCK_NAME);

    sync();
    return ret;
}
#endif
