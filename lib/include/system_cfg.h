#ifndef _SYSTEM_CFG_H_
#define _SYSTEM_CFG_H_

#ifdef __cplusplus
extern "C" {
#endif

#define USE_HAND_OVER      0
#define WRITE_CHECK_LENGTH 262144
#define FILE_READ_LENGTH   262144
#define OTA_LIB_VERSION   "V00.00.03"

/* Usage:   open debug level print, Set to 1 to print more debugging information
            If it is set to 2, the inter-core communication message information
            will be additionally printed */
#ifndef DEBUGMODE
#define DEBUGMODE          0
#endif

#ifndef CACHE_LINE
#define CACHE_LINE         64
#endif

/* Usage:   Indicates whether to obtain self-test information from cmdline */
#ifndef CHECK_CMDLINE_MODE
#define CHECK_CMDLINE_MODE 1
#endif

/* Usage:  Indicates that when shared memory is accessed by multiple threads for reading,
the shared memory will be divided into multiple parts, and only one part will be read at a time. */
#ifndef THREAD_READ_PIECE_NUM
#define THREAD_READ_PIECE_NUM 16
#endif


/* Usage:   Force have safety update monitor service
#ifndef FORCE_SAFETY_UM_CHECK
#define FORCE_SAFETY_UM_CHECK true
#endif
*/

/* Usage:   Force have secure update monitor service
#ifndef FORCE_SECURE_UMCHECK
#define FORCE_SECURE_UMCHECK false
#endif
 */

/* Usage:   Force enable X9U AB handshake
#ifndef FORCE_CHIPA_CHIPB_HANDSHAKE
#define FORCE_CHIPA_CHIPB_HANDSHAKE false
#endif
*/

/* Usage:   Force set X9U AB handshake side
#ifndef FORCE_SUB_CHIP
#define FORCE_SUB_CHIP SUB_CHIP_A
#endif
*/

/* Usage:   Force set OTA LIB CMD
#ifndef FORCE_OTA_CMD
#define FORCE_OTA_CMD 1
#endif
*/

/* Usage:   AB handshake timeout(s): 0 is always wait */
#ifndef CHIPA_CHIPB_HANDSHAKE_TIMEOUT
#define CHIPA_CHIPB_HANDSHAKE_TIMEOUT 0
#endif

/* Usage:   AB handshake A-SIDE tcp listening IP */
#ifndef CHIPA_HANDSHAKE_IP
#define CHIPA_HANDSHAKE_IP "172.20.2.35"
#endif

/* Usage:   AB handshake A-SIDE tcp listening port */
#ifndef CHIPA_HANDSHAKE_LISTEN_PORT
#define CHIPA_HANDSHAKE_LISTEN_PORT 8001
#endif


/* Usage:   self test mode  */
#ifndef SELF_TEST_MODE
#define SELF_TEST_MODE      0
#endif

/* Usage:   Support perperty lib or not*/
#ifndef SUPPORT_PROPERTY_LIB
#define SUPPORT_PROPERTY_LIB      1
#endif

/* Usage:   Before the mark is successful, we need to check whether
            the sub-system is started. When this switch is turned on,
            we will check the properties of AP2 MP to determine whether
            the system is started successfully. */
#define CHECK_SUB_SYSTEM_SUCCESS_BY_PROPERTY      SUPPORT_PROPERTY_LIB

/* Usage:   sub-system boot successful property value */
#ifndef SUB_SYSTEM_OK
#define SUB_SYSTEM_OK                             "1"
#endif

/* Usage:   sub-system boot successful property for mp core*/
#ifndef MP_SYSTEM_PROPERTY
#define MP_SYSTEM_PROPERTY                        "cdm.rw.ota_status_mp"
#endif

/* Usage:   sub-system boot successful property for ap2*/
#ifndef AP2_SYSTEM_PROPERTY
#define AP2_SYSTEM_PROPERTY                       "cdm.rw.ota_status_ap2"
#endif

/* Usage:   sub-system boot successful property read times */
#ifndef WAIT_STATUS_TIME
#define WAIT_STATUS_TIME                          50
#endif

/* Usage:   unsigned int max value */
#ifndef UINT_MAX
#define UINT_MAX 0xffffffffU
#endif

/* Usage:   Use ipcc or rpmsg channel to make sure mp core start successfully*/
#ifndef MP_SYSTEM_CHECK_BY_RPMSG
#define MP_SYSTEM_CHECK_BY_RPMSG      0
#endif

/* Usage:   mp core check times by ipcc or rpmsg channel */
#ifndef WAIT_STATUS_TIME_BY_RPMSG
#define WAIT_STATUS_TIME_BY_RPMSG                       10
#endif

/*  Usage:  Enalbe the assert in OTA lib. To do this, we must put #include "assert.h"
            after #include "slot_parse.h" */
#undef  NDEBUG

/*  Usage:  Make sure that the ota lib printing in Android ALOGD/E has this label  */
#ifndef LOG_TAG
#define LOG_TAG "ota-lib"
#endif

/*  Usage:  gte minor value */
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/*  Usage:  gte minor value */
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

/*  Usage:  do not restore GPT */
#ifndef SKIP_RESTORE_GPT
#define SKIP_RESTORE_GPT 0
#endif

/* Usage:   build type property for android */
#ifndef ANDROID_BUILD_TYPE_PROPERTY
#define ANDROID_BUILD_TYPE_PROPERTY                        "ro.build.type"
#endif

#ifndef ANDROID_BUILD_TYPE_USERDEBUG
#define ANDROID_BUILD_TYPE_USERDEBUG                        "userdebug"
#endif

/* Usage:   recovery property for android */
#ifndef ANDROID_NORMAL_BOOT
#define ANDROID_NORMAL_BOOT                        "ro.boot.force_normal_boot"
#endif

#ifndef ANDROID_RECOVERY_RUNNING
#define ANDROID_RECOVERY_RUNNING                        "0"
#endif

/* Usage:   Force have safety update monitor service */
#ifndef FORCE_SKIP_WDT_CHECK
#define FORCE_SKIP_WDT_CHECK 0
#endif

/* Usage: force set ota-lib for AP2 */
#ifndef RUN_IN_AP2
#define RUN_IN_AP2 0
#endif

/* Usage:   global uniform rollback property */
#ifndef GLOBAL_UNIFORM_ROLLBACK_PROPERTY
#define GLOBAL_UNIFORM_ROLLBACK_PROPERTY                            "csd.rw.persist.ota_ur_global"
#endif

/* Usage:   local uniform rollback property */
#ifndef LOCAL_UNIFORM_ROLLBACK_PROPERTY
#define LOCAL_UNIFORM_ROLLBACK_PROPERTY                             "cdm.rw.persist.ota_ur_local"
#endif

/* Usage:   ota status property for side A */
#ifndef PROPERTY_OTA_STATUS_SIDE_A
#define PROPERTY_OTA_STATUS_SIDE_A                                  "csd.rw.ota_ur_status_ssa"
#endif

/* Usage:   ota status property for side B */
#ifndef PROPERTY_OTA_STATUS_SIDE_B
#define PROPERTY_OTA_STATUS_SIDE_B                                  "csd.rw.ota_ur_status_ssb"
#endif

/* Usage:  skip uniform rollback property */
#ifndef PROPERTY_SKIP_UNIFORM_ROLLBACK
#define PROPERTY_SKIP_UNIFORM_ROLLBACK                              "cdm.rw.ota_ur_skip"
#endif


/* Usage:  don't skip uniform rollback */
#define DO_NOT_SKIP_UNIFORM_ROLLBACK                                (0)

/* Usage:  skip uniform rollback */
#define SKIP_UNIFORM_ROLLBACK                                       (1)


/* Usage:   global uniform rollback on */
#ifndef GLOBAL_UNIFORM_ROLLBACK_ON
#define GLOBAL_UNIFORM_ROLLBACK_ON                                  "1"
#endif

/* Usage:   global uniform rollback off */
#ifndef GLOBAL_UNIFORM_ROLLBACK_OFF
#define GLOBAL_UNIFORM_ROLLBACK_OFF                                 "0"
#endif

/* Usage:   uniform rollback start */
#ifndef STATUS_START
#define STATUS_START                                                "0"
#endif

/* Usage:   boot successful */
#ifndef STATUS_BOOT
#define STATUS_BOOT                                                 "1"
#endif

/* Usage:   opposite also boot successful */
#ifndef STATUS_BOTH_BOOT
#define STATUS_BOTH_BOOT                                            "2"
#endif

/* Usage:   mark successful */
#ifndef STATUS_MARK
#define STATUS_MARK                                                 "3"
#endif

/* Usage:   opposite also mark successful */
#ifndef STATUS_BOTH_MARK
#define STATUS_BOTH_MARK                                            "4"
#endif

/* Usage:   uniform rollback end */
#ifndef STATUS_END
#define STATUS_END                                                  "5"
#endif

/* Usage:   local uniform rollback off */
#ifndef LOCAL_UNIFORM_ROLLBACK_OFF
#define LOCAL_UNIFORM_ROLLBACK_OFF                                  "0"
#endif

/* Usage:   local uniform rollback on */
#ifndef LOCAL_UNIFORM_ROLLBACK_IN_PROGRESS
#define LOCAL_UNIFORM_ROLLBACK_IN_PROGRESS                          "1"
#endif

/* Usage:   local uniform rollback off, opposite uniform rollback status unconfirmed */
#ifndef LOCAL_UNIFORM_ROLLBACK_OPPOSITE_UNCONFIRMED
#define LOCAL_UNIFORM_ROLLBACK_OPPOSITE_UNCONFIRMED                 "2"
#endif

/* Usage:   wait for property block */
#ifndef WAIT_FOR_PROPERTY_ALWAYS
#define WAIT_FOR_PROPERTY_ALWAYS                                    (0xFFFFFFFF)
#endif

/* Usage:   wait for property non-block */
#ifndef WAIT_FOR_PROPERTY_NO_DELAY
#define WAIT_FOR_PROPERTY_NO_DELAY                                  (0)
#endif

/* Usage:   ota lib property max len */
#ifndef OTA_LIB_PROPERTY_MAX_LEN
#define OTA_LIB_PROPERTY_MAX_LEN                                    92
#endif

#define SLEEP_TIME_INTERVAL                                         (1000*1000)

#define WAIT_TYPE_NOT_NA                                            (0)

#define WAIT_TYPE_SOMEVALUE                                         (1)

#ifndef SHM_NAMELEN
#define SHM_NAMELEN                                                  15
#endif

#ifndef WRITE_WITH_SYNC
#define WRITE_WITH_SYNC                                             (0)
#endif

#ifndef DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V2
#define DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V2                      "mmcboot"
#endif

#ifndef DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT0
#define DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT0                 "mmcboot0"
#endif

#ifndef DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT1
#define DIL_SEC_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT1                 "mmcboot1"
#endif

#ifndef DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V2
#define DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V2                       "ospiboot"
#endif

#ifndef DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT0
#define DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT0                 "ospiboot0"
#endif

#ifndef DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT1
#define DIL_SAF_NAME_IN_ANDROID_PAYLOAD_BPT_V1_BOOT1                 "ospiboot1"
#endif

/*  Usage:  Control printing logs under different systems  */
#ifdef RUN_IN_ANDROID
#include <log/log.h>
#if SELF_TEST_MODE
#define PRINTF_CRITICAL(format, ...)  {fprintf(stderr, "[ota-lib(E):%d:%s]", __LINE__,__FUNCTION__);fprintf(stderr, format, ##__VA_ARGS__);}
#define PRINTF_INFO(format, ...)      {fprintf(stdout, "[ota-lib(I):%d:%s]", __LINE__,__FUNCTION__);fprintf(stdout, format, ##__VA_ARGS__);}
#define PRINTF_DBG(format, ...)       {if(DEBUGMODE) {printf("[ota-lib(D):%d:%s]", __LINE__,__FUNCTION__);fprintf(stdout, format, ##__VA_ARGS__);}}
#define PRINTF printf
#define KEYNODE(format, ...)          {fprintf(stdout, "KEYNODE:"); fprintf(stdout, format, ##__VA_ARGS__);}
#else
#define PRINTF_CRITICAL(format, ...)  {ALOGE("[ota-lib:%d:%s]", __LINE__,__FUNCTION__);ALOGE(format, ##__VA_ARGS__);}
#define PRINTF_INFO(format, ...)      {ALOGD("[ota-lib:%d:%s]", __LINE__,__FUNCTION__);ALOGD(format, ##__VA_ARGS__);}
#define PRINTF_DBG(format, ...)       {if(DEBUGMODE) {ALOGD("[ota-lib:%d:%s]", __LINE__,__FUNCTION__);ALOGD(format, ##__VA_ARGS__);}}

#define PRINTF ALOGD
#define KEYNODE(format, ...)          {ALOGD("KEYNODE:"); ALOGD(format, ##__VA_ARGS__);}
#endif

#define MMC_PATH(x)         "/dev/block/"#x""
#define MTD_PATH(x)         "/dev/block/"#x""

#else
#define PRINTF_CRITICAL(format, ...)      {fprintf(stderr, "[ota-lib(E):%d:%s]", __LINE__,__FUNCTION__);fprintf(stderr, format, ##__VA_ARGS__);}
#define PRINTF_INFO(format, ...)          {fprintf(stdout, "[ota-lib(I):%d:%s]", __LINE__,__FUNCTION__);fprintf(stdout, format, ##__VA_ARGS__);}
#define PRINTF_DBG(format, ...)           {if(DEBUGMODE) {fprintf(stdout, "[ota-lib(D):%d:%s]", __LINE__,__FUNCTION__);fprintf(stdout, format, ##__VA_ARGS__);}}
#define PRINTF printf
#define KEYNODE(format, ...)              {fprintf(stdout, "KEYNODE:"); fprintf(stdout, format, ##__VA_ARGS__);}
#define MMC_PATH(x)         "/dev/"#x""
#define MTD_PATH(x)         "/dev/"#x""


#endif //RUN_IN_ANDROID

#define ASSERT(condition) \
    if (!(condition)) { \
       abort(); \
    }


/*  Usage:  Only used by dynamic memory allocation and release tests, do not open it */
#define MEM_TEST_MODE 0
#if MEM_TEST_MODE
#define MAX_MEM_NUMBER 256
#include <malloc.h>
#include <assert.h>
extern int malloc_cnt;
extern size_t   malloc_size[MAX_MEM_NUMBER];
extern uint64_t  malloc_addr[MAX_MEM_NUMBER];
static inline void get_malloc_size()
{
    uint64_t mem_size = 0;
    int j = 0;

    while (j < MAX_MEM_NUMBER) {
        if (0 != malloc_size[j]) {
            mem_size += malloc_size[j];
        }

        j++;
    }

    PRINTF_INFO("total malloc_size = %lld\n", (unsigned long long)mem_size);
}

static inline void *MEM_ALIGN(size_t alignment, size_t size)
{
    int i = 0;
    void *addr = memalign(alignment, size);
    malloc_cnt++;
    assert(malloc_cnt < MAX_MEM_NUMBER);

    while (i < MAX_MEM_NUMBER) {
        if (0 == malloc_addr[i]) {
            //PRINTF_INFO("%d is used\n", i);
            malloc_addr[i] = (uint64_t)addr;
            malloc_size[i] = size;
            break;
        }

        i++;
    }

    PRINTF_INFO("malloc_cnt = %d\n", malloc_cnt);
    PRINTF_INFO("new size = %d\n", (uint32_t)size);
    get_malloc_size();
    return addr;
}

static inline void *CALLOC(size_t size, size_t n)
{
    int i = 0;
    void *addr = calloc(size, n);
    malloc_cnt++;
    assert(malloc_cnt < MAX_MEM_NUMBER);

    while (i < MAX_MEM_NUMBER) {
        if (0 == malloc_addr[i]) {
            //PRINTF_INFO("%d is used\n", i);
            malloc_addr[i] = (uint64_t)addr;
            malloc_size[i] = size * n;
            break;
        }

        i++;
    }

    PRINTF_INFO("malloc_cnt = %d\n", malloc_cnt);
    PRINTF_INFO("new size = %d\n", (uint32_t)(size * n));
    get_malloc_size();
    return addr;
}

static inline void FREE(void *addr)
{
    int i = 0;
    free(addr);
    malloc_cnt--;
    PRINTF_INFO("malloc_cnt = %d\n", malloc_cnt);

    while (i < MAX_MEM_NUMBER) {
        if ((uint64_t)addr == malloc_addr[i]) {
            //PRINTF_INFO("%d is free\n", i);
            malloc_addr[i] = 0;
            malloc_size[i] = 0;
            break;
        }

        i++;
    }

    get_malloc_size();
}

#else
#define MEM_ALIGN memalign
#define CALLOC calloc
#define FREE free
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif //_SYSTEM_CFG_H_
