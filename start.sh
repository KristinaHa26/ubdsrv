# SPDX-License-Identifier: MIT or GPL-2.0-only

#!/bin/bash

autoreconf -i
./configure --enable-debug
make

[ -d "/run/ublksrvd" ] || mkdir -p "/run/ublksrvd"

# create backing file for demo, only 10MB
dd if=/dev/zero of=blockfile bs=1M count=10

