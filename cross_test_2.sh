# SPDX-License-Identifier: MIT or GPL-2.0-only

#!/bin/bash
#set -x

# prepare key in hexadecimal and binary form
KEY=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd
echo -n $KEY | xxd -r -p > keyfile.bin

# create file
truncate -s 16M test.img

# register file as ublk crypt device
./ublk add -t crypt -f test.img -k $KEY -c aes-xts-plain64 -x 0 -o 0 -s 512

# write via ublk-crypt
echo "hello from ublk crypt" | sudo dd of=/dev/ublkb0 bs=512 count=1 conv=notrunc

# delete the ublk crypt device (test.img stays intact)
./ublk del 0

# open file as block device with cryptsetup
sudo cryptsetup open --type plain --key-file keyfile.bin --cipher aes-xts-plain64 --key-size 512 --offset 0 test.img test_dm

# read via dm-crypt
sudo dd if=/dev/mapper/test_dm bs=512 count=1

# delete block device and test file
sudo cryptsetup close test_dm
rm test.img
