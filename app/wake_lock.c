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
#include <stdbool.h>
#if !RUN_IN_QNX
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/types.h>
#include "slots_parse.h"
#define WAKE_LOCK_PATH     "/sys/power/wake_lock"
#define WAKE_UNLOCK_PATH   "/sys/power/wake_unlock"

bool ota_wake_lock(bool lock, const char * lock_name)
{
    int fd = -1, len = 0;
    const char * wake_lock_path = NULL;
    bool status = false;
    int name_len = 0;

    if (!lock_name || ((name_len = strlen(lock_name)) == 0))
    {
        PRINTF_CRITICAL("invalid lock name\n");
        goto out;
    }

    if (lock)
        wake_lock_path = WAKE_LOCK_PATH;
    else
        wake_lock_path = WAKE_UNLOCK_PATH;

    if (access(wake_lock_path, F_OK) != -1) {
        printf("Path %s exists\n", wake_lock_path);
    } else {
        printf("Path %s does not exist, skip wake lock check\n", wake_lock_path);
        status = true;
        goto out;
    }

    fd = open(wake_lock_path, O_RDWR);

    if (fd < 0){
        PRINTF_CRITICAL("Failed to open file:%s\n", wake_lock_path);
        goto out;
    }

    len = write(fd, lock_name, name_len);
    if (len != name_len)
    {
        PRINTF_CRITICAL("Failed to %s wake lock\n", lock ? "lock":"unlock");
        goto out;
    }

    status = true;
out:
    if (!(fd < 0))
        close(fd);

    return status;
}
#else
bool ota_wake_lock(bool lock, const char * lock_name)
{
    return true;
}
#endif
