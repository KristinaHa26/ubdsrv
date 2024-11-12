#!/bin/bash
set -x

dd if=/dev/zero of=blockfile bs=1M count=1024
./ublk add -t loop -f blockfile --debug_mask=0x03
./ublk list
echo -n "hello" > /dev/ublkb0
hexdump -C /dev/ublkb0 | head
hexdump -C blockfile | head
./ublk del -n 0
rm blockfile
