# SPDX-License-Identifier: MIT or GPL-2.0-only

#!/bin/bash
#set -x

DM_NAME=test
IMG_NAME=test.img
IMG_SIZE=16M
KEY1=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
KEY2=559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd

dev_create()
{
  # sparse file, ciphertext contains zeroes
  truncate -s $IMG_SIZE $IMG_NAME
  LO_NAME=$(losetup --show -f $IMG_NAME)

  # pseudo-randomize content, write zeroes
  echo | cryptsetup open --type plain $LO_NAME $DM_NAME --hash sha256 -c aes-xts-plain64 -s 512 --disable-keyring
  blkdiscard -z /dev/mapper/$DM_NAME
  #hexdump -C /dev/mapper/$DM_NAME | head
  cryptsetup close $DM_NAME
  #hexdump -C $IMG_NAME | head

  #dd if=/dev/zero of=blockfile bs=512 count=32768
}

dev_remove()
{
  losetup -d $LO_NAME
  rm -f $IMG_NAME
  rm -f blockfile
}

ublk_create()
{
    local dm_row=$@

    local sector_size=512
    local optional

    if [[ "$dm_row" =~ sector_size:([0-9]+) ]]; then
        sector_size="${BASH_REMATCH[1]}"
        dm_row=$(echo "$dm_row" | sed 's/sector_size:[0-9]\+//')
    fi

    if [[ "$dm_row" =~ iv_large_sectors ]]; then
        optional=--large_iv
        dm_row=$(echo "$dm_row" | sed 's/iv_large_sectors//')
    fi

    local start_sector device_size start_size size mode cipher key iv_offset device offset
    start_sector=$(echo "$dm_row" | cut -d' ' -f1)
    device_size=$(echo "$dm_row" | cut -d' ' -f2)
    #mode=$(echo "$dm_row" | cut -d' ' -f3)
    cipher=$(echo "$dm_row" | cut -d' ' -f4)
    key=$(echo "$dm_row" | cut -d' ' -f5)
    iv_offset=$(echo "$dm_row" | cut -d' ' -f6)
    #device=$(echo "$dm_row" | cut -d' ' -f7)
    offset=$(echo "$dm_row" | cut -d' ' -f8)

    ./ublk add -t crypt -f $IMG_NAME -c $cipher -k $key -x $iv_offset -s $sector_size -o $offset --debug_mask=0x03 -y $start_sector -z $device_size $optional
    echo ./ublk add -t crypt -f $IMG_NAME -c $cipher -k $key -x $iv_offset -s $sector_size -o $offset --debug_mask=0x03 -y $start_sector -z $device_size $optional



}

dm_create()
{
  local fst snd

  echo "[$@]"
  dmsetup create $DM_NAME --table "$@"
  fst=$(sha256sum /dev/mapper/$DM_NAME | cut -d' ' -f1)
  #dmsetup table $DM_NAME --showkeys
  #hexdump -C /dev/mapper/$DM_NAME | head
  dmsetup remove -f $DM_NAME

  ublk_create $@ > /dev/null
  #hexdump -C /dev/ublkb0 | head
  snd=$(sha256sum /dev/ublkb0 | cut -d' ' -f1)
  ./ublk del 0
  if [ "$fst" = "$snd" ]; then
	  echo TRUE
  fi
  echo ""
}

dev_create

# dm_create "0 32768 zero"
# dm_create "0 32768 linear $LO_NAME 0"

# Key length AES256, AES128 
dm_create "0 32768 crypt aes-xts-plain64 $KEY1$KEY2 0 $LO_NAME 0"
dm_create "0 32768 crypt aes-xts-plain64 $KEY1 0 $LO_NAME 0"

# other ciphers
dm_create "0 32768 crypt aes-cbc-essiv:sha256 $KEY1 0 $LO_NAME 0"
dm_create "0 32768 crypt serpent-xts-plain64  $KEY1 0 $LO_NAME 0"

# capi cipher format
dm_create "0 32768 crypt capi:xts(aes)-plain64      $KEY1 0 $LO_NAME 0"
dm_create "0 32768 crypt capi:cbc(aes)-essiv:sha256 $KEY1 0 $LO_NAME 0"
dm_create "0 32768 crypt capi:xts(serpent)-plain64  $KEY1 0 $LO_NAME 0"

# size, offset, iv_offset
dm_create "0 8 crypt aes-xts-plain64 $KEY1  0 $LO_NAME  0"
dm_create "0 8 crypt aes-xts-plain64 $KEY1 32 $LO_NAME  0"
dm_create "0 8 crypt aes-xts-plain64 $KEY1 32 $LO_NAME 32"
dm_create "0 8 crypt aes-xts-plain64 $KEY1  0 $LO_NAME 32"

# sector size, allow_discards, optional parameters
dm_create "0 32768 crypt aes-xts-plain64 $KEY1 0 $LO_NAME 0 0"
# check discards with lsblk -D
dm_create "0 32768 crypt aes-xts-plain64 $KEY1 0 $LO_NAME 0 1 allow_discards"
# check physical/logical sector with lsblk -t
dm_create "0 32768 crypt aes-xts-plain64 $KEY1 0 $LO_NAME 0 1 sector_size:4096"
dm_create "0 32768 crypt aes-xts-plain64 $KEY1 0 $LO_NAME 0 2 sector_size:4096 iv_large_sectors"
dm_create "0 32768 crypt aes-xts-plain64 $KEY1 0 $LO_NAME 0 3 sector_size:4096 iv_large_sectors allow_discards"

dev_remove
