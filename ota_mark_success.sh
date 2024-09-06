#!/bin/sh
if [ ! -d "/dev/block/by-name/" ];then
    echo "Invalid block device, don't run ota_mark_success"
    exit 1
fi

#find out vbmeta_ap2 if in ap2 domain
find /dev/block/by-name/ -type f -o -type l -name "vbmeta*" | grep -E 'vbmeta_ap2(_[a-b])?$'
if [ $? -eq 0 ];then
    echo "OTA status for ap2 device set to 1"
    setprop cdm.rw.ota_status_ap2 1
    exit 0
fi

#Here, it could be ap1 domain,to find vbmeta/vbmeta_a/vbmeta_b
find /dev/block/by-name/ -type f  -o -type l -name "vbmeta*" | grep -E 'vbmeta(_[a-b])?$'
if [ $? -ne 0 ];then
    echo "No vbmeta found,what should be wrong"
    exit 1
fi

cmdline=$(cat /proc/cmdline)
echo "$cmdline" | grep -sw "recovery_mode"
if [ $? -eq 0 ];then
    echo "Recovery mode, don't run ota_mark_success"
    exit 0
fi

echo "run ota_mark success.sh"
/usr/bin/ota_mark_success 1>/dev/null &
