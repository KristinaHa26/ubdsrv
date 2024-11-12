// SPDX-License-Identifier: MIT or GPL-2.0-only

/* Based on the loop target and null demo from the ublk project.
 * Modified and extended by Kristina Hanicova.
 */

#include "ublkcrypt.h"

#include <string.h>
#include <error.h>
#include <stdio.h>


static struct ublksrv_ctrl_dev *this_ctrl_dev;
static const struct ublksrv_dev *this_dev;

static void fill_options(struct crypt_tgt_data* options)
{
    options->buffered_io = false;
    options->large_iv = false;
    options->iv_offset = 0;
    options->dev_offset = 1; // in 512 byte units
    options->sector_size = 512; // in bytes
    options->start_sector = 0;
    options->device_size = 19968;
    options->cipher_name = strdup("aes");
    options->mode_iv = strdup("xts-plain64");
    options->file = strdup("blockfile");
    options->key = strdup("e8cfa3dbfe373b536be43c5637387786c01be00ba5f730aacb039e86f3eb72f3");
}

static void sig_handler(int sig)
{
    ublksrv_ctrl_stop_dev(this_ctrl_dev);
}


int main(int argc, char *argv[])
{
    int ret = -1;
    struct crypt_tgt_data options = { 0 };
    struct ublksrv_ctrl_dev *dev = NULL;
    bool options_present = false;
    struct ublksrv_dev_data data = { 0 };

    fill_crypt_dev_data(&data);

    // we use hard-coded values if they were not given on the command line
    if (argc < 6) {
        fill_options(&options);
        options_present = true;
    }

    if (signal(SIGTERM, sig_handler) == SIG_ERR)
        error(EXIT_FAILURE, errno, "signal");
    if (signal(SIGINT, sig_handler) == SIG_ERR)
        error(EXIT_FAILURE, errno, "signal");

    dev = init_ublk_crypt(argc, argv, &data, &options, options_present);
    if (!dev) {
        error(EXIT_FAILURE, ENODEV, "ublksrv_ctrl_init");
        goto error;
    }
    this_ctrl_dev = dev;

    ret = ublksrv_ctrl_add_dev(dev);
    if (ret < 0) {
        error(0, -ret, "can't add dev %d", data.dev_id);
        goto fail;
    }

    ret = ublksrv_start_daemon(dev, &options, this_dev);
    if (ret < 0) {
        error(0, -ret, "can't start daemon");
        goto fail_del_dev;
    }

    ublksrv_ctrl_del_dev(dev);
    return 0;

  fail_del_dev:
    ublksrv_ctrl_del_dev(dev);
  fail:
    ublksrv_ctrl_deinit(dev);
  error:
    return -1;
}
