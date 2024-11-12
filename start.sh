#!/bin/bash

autoreconf -i
./configure --enable-debug
make

