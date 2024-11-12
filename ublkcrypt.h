// SPDX-License-Identifier: MIT or GPL-2.0-only

/* Based on the loop target and null demo from the ublk project.
 * Modified and extended by Kristina Hanicova.
 */

#ifndef UBLKCRYPT_H
#define UBLKCRYPT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "ublksrv.h"

#ifdef __cplusplus
extern "C" {
#endif

struct crypt_tgt_data {
    bool user_copy;
    bool block_device;
    uint64_t dev_offset;
    uint64_t iv_offset;
    int large_iv;
    unsigned char* key_bin;
    uint8_t key_len;

    int buffered_io;
    uint64_t sector_size;
    uint64_t start_sector;
    uint64_t device_size;
    char* cipher_name;
    char* mode_iv;
    char* file;
    char* cipher;
    char* key;
};

struct ublksrv_ctrl_dev* init_ublk_crypt(int argc, char *argv[], struct ublksrv_dev_data* data, struct crypt_tgt_data* opt, bool options_present);

int ublksrv_start_daemon(struct ublksrv_ctrl_dev *ctrl_dev, struct crypt_tgt_data* opt, const struct ublksrv_dev* this_dev);

void fill_crypt_dev_data(struct ublksrv_dev_data* data);


#ifdef __cplusplus
}
#endif

#endif // UBLKCRYPT_H
