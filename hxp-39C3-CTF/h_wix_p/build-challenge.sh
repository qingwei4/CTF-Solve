#!/bin/bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

dir="$(pwd)"

tempdir="$(mktemp -d -t hxp-fiwix-build.XXXXXXXXXX)"
cd "$tempdir"

echo "$tempdir"

wget https://www.fiwix.org/FiwixOS-3.5-i386.raw.gz
gzip -d FiwixOS-3.5-i386.raw.gz

loop="$(losetup --show -Pf FiwixOS-3.5-i386.raw)"
echo "loop: $loop"

mkdir mnt boot
mount "$loop"p1 mnt
cp mnt/fiwix mnt/System.map boot/

umount mnt

mount "$loop"p2 mnt

cd mnt

hash=$(openssl rand -hex 64 | openssl passwd -stdin -1 -salt '')
sed -i 's@$1$$oCLuEVgI1iAqOA8pwkzAg1@'$hash'@g' etc/passwd

hash=$(echo "hxp" | openssl passwd -stdin -1 -salt '')
echo "hxp:$hash:1337:1337:hxp:/:/bin/bash" >> etc/passwd

echo 'S0:2345:respawn:/sbin/agetty -L 9600 ttyS0' >> etc/inittab

echo 'hxp{dummy-flag.................................................}' >  flag.txt
chmod 000 flag.txt
chown 0:0 flag.txt

find . -perm /6000 -type f -delete
find etc/rc.d -name '*atd*' -delete
find etc/rc.d -name '*crond*' -delete

cd ..
sync
umount mnt

losetup -d "$loop"

cp -r  "$tempdir"/boot/* FiwixOS-3.5-i386.raw "$dir"

rm -rf "$tempdir"
