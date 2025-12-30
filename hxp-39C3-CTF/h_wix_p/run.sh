#!/bin/bash
set -euo pipefail

if [ -t 0 ] ; then
    extra_args=""
    stty intr ^]
else
    extra_args="-snapshot -nographic"
fi

qemu-system-i386 \
-kernel fiwix -append 'ro root=/dev/hda2' \
-drive "file=FiwixOS-3.5-i386.raw,format=raw,index=0" \
-machine pc -m 128 --monitor /dev/null -serial stdio -no-reboot $extra_args \
-s