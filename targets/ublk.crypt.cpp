// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include <poll.h>
#include <sys/epoll.h>
#include "ublksrv_tgt.h"

#include <crypto_backend.h>

#define MAX_CAPI_ONE_LEN 64  /*value taken from cryptsetup */

struct crypt_storage *storage = NULL;

struct crypt_tgt_data {
    bool user_copy;
    bool block_device;
    uint64_t dev_offset;
    uint64_t iv_offset;
    bool large_iv;
    unsigned char* key_bin;
    uint8_t key_len;
};

static struct crypt_tgt_data* get_private_tgt_data(const struct ublksrv_dev *dev) {
    return (struct crypt_tgt_data*) dev->tgt.tgt_data;
}

static bool backing_supports_discard(char *name)
{
	int fd;
	char buf[512];
	int len;

	len = snprintf(buf, 512, "/sys/block/%s/queue/discard_max_hw_bytes",
			basename(name));
	buf[len] = 0;
	fd = open(buf, O_RDONLY);
	if (fd > 0) {
		char val[128];
		int ret = pread(fd, val, 128, 0);
		unsigned long long bytes = 0;

		close(fd);
		if (ret > 0)
			bytes = strtol(val, NULL, 10);

		if (bytes > 0)
			return true;
	}
	return false;
}

static int crypt_setup_tgt(struct ublksrv_dev *dev, int type, bool recovery,
		const char *jbuf)
{
    struct ublksrv_tgt_info *tgt = &dev->tgt;
    const struct ublksrv_ctrl_dev_info *info =
        ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
    int fd, ret;
    unsigned long direct_io = 0;
    struct ublk_params p;
    char file[PATH_MAX];
    struct crypt_tgt_data *tgt_data = get_private_tgt_data(dev);
    struct stat sb;

    ublk_assert(jbuf);

    ret = ublksrv_json_read_target_str_info(jbuf, PATH_MAX, "backing_file", file);
    if (ret < 0) {
        ublk_err( "%s: backing file can't be retrieved from jbuf %d\n",
                __func__, ret);
        return ret;
    }

    ret = ublksrv_json_read_target_ulong_info(jbuf, "direct_io",
            &direct_io);
    if (ret) {
        ublk_err( "%s: read target direct_io failed %d\n",
                __func__, ret);
        return ret;
    }

    ret = ublksrv_json_read_target_ulong_info(jbuf, "device_offset",
            &tgt_data->dev_offset);
    if (ret) {
        ublk_err( "%s: read target offset failed %d\n",
                __func__, ret);
        return ret;
    }

    ret = ublksrv_json_read_params(&p, jbuf);
    if (ret) {
        ublk_err( "%s: read ublk params failed %d\n",
                __func__, ret);
        return ret;
    }

    fd = open(file, O_RDWR);
    if (fd < 0) {
        ublk_err( "%s: backing file %s can't be opened\n",
                __func__, file);
        return fd;
    }

    if (fstat(fd, &sb) < 0) {
        ublk_err( "%s: unable to stat %s\n",
                  __func__, file);
        return -1;
    }

    tgt_data->block_device = S_ISBLK(sb.st_mode);

    if (direct_io)
        fcntl(fd, F_SETFL, O_DIRECT);

    ublksrv_tgt_set_io_data_size(tgt);
    tgt->dev_size = p.basic.dev_sectors << 9;
    tgt->tgt_ring_depth = info->queue_depth;
    tgt->nr_fds = 1;
    tgt->fds[1] = fd;
    tgt_data->user_copy = info->flags & UBLK_F_USER_COPY;
    if (tgt_data->user_copy)
        tgt->tgt_ring_depth *= 2;

	return 0;
}

static int crypt_recover_tgt(struct ublksrv_dev *dev, int type)
{
    const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
    struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);

    if (!j)
        return -EINVAL;

    dev->tgt.tgt_data = calloc(sizeof(struct crypt_tgt_data), 1);

    return crypt_setup_tgt(dev, type, true, j->jbuf);
}

static bool is_power_of_two(uint64_t num)
{
    return (num & (num - 1)) == 0;
}

// logic from https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/lib/utils_crypt.c?ref_type=heads
static int hex_to_bin(unsigned char ch)
{
	unsigned char cu = ch & 0xdf;
	return -1 +
		((ch - '0' +  1) & (unsigned)((ch - '9' - 1) & ('0' - 1 - ch)) >> 8) +
		((cu - 'A' + 11) & (unsigned)((cu - 'F' - 1) & ('A' - 1 - cu)) >> 8);
}

static void hex_to_bytes(ssize_t len, const char* hex, unsigned char* result) {
    size_t i = 0;
    int bl, bh;

    for (i = 0; i < len; i++) {
		bh = hex_to_bin(hex[i * 2]);
		bl = hex_to_bin(hex[i * 2 + 1]);

        result[i] = (bh << 4) | bl;
    }
}

//logic inspired by: https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/lib/utils_crypt.c?ref_type=heads
static int parse_cipher(char* cipher, char** cipher_name, char** mode_iv)
{
    if (strstr(cipher, "capi") == NULL) {
        *cipher_name = strtok(cipher, "-");
        *mode_iv = strtok(NULL, " ");
        return 0;
    }

    char c[MAX_CAPI_ONE_LEN];
    char part1[MAX_CAPI_ONE_LEN];
    char part2[MAX_CAPI_ONE_LEN];

    int i = sscanf(cipher, "capi:%[^ (](%[^)])-%s", part1, c, part2);
    if (i != 3)
        return -EINVAL;

    strcat(part1, "-");
    strcat(part1, part2);

    *mode_iv = strdup(part1);
    *cipher_name = strdup(c);

    return 0;
}

static int crypt_init_tgt(struct ublksrv_dev *dev, int type, int argc, char
		*argv[])
{
    const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
    struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
    const struct ublksrv_ctrl_dev_info *info =
        ublksrv_ctrl_get_dev_info(cdev);

	int buffered_io = 0;
    int large_iv = 0;
	static const struct option lo_longopts[] = {
		{ "file",		1,	NULL, 'f' },
		{ "buffered_io",	no_argument, &buffered_io, 1},
        { "cipher", required_argument, NULL, 'c'},
        { "key", required_argument, NULL, 'k'},
        { "iv_offset", required_argument, NULL, 'x'},
        { "device_offset", required_argument, NULL, 'o'},
        { "sector_size", required_argument, NULL, 's'},
        { "large_iv", no_argument, &large_iv, 1},
        { "start_sector", required_argument, NULL, 'y'},
        { "device_size", required_argument, NULL, 'z'},
		{ NULL }
	};
	unsigned long long bytes;
	struct stat st;
	int fd, opt;
	char *file = NULL;
    char* cipher = NULL;
    char* key = NULL;
    uint64_t iv_offset = 0;
    uint64_t device_offset = 0;
    uint64_t sector_size = 0;
    uint64_t start_sector = 0;
    uint64_t device_size = 0;
    char* cipher_name = NULL;
    char* mode_iv = NULL;
    struct ublksrv_tgt_base_json tgt_json = { 0 };
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD,
		.basic = {
			.logical_bs_shift	= 9,  // sector size??
			.physical_bs_shift	= 12, //
			.io_opt_shift	= 12,
			.io_min_shift	= 9,  // sector size ??
			.max_sectors		= info->max_io_buf_bytes >> 9,
		},

		.discard = {
			.max_discard_sectors	= UINT_MAX >> 9,
			.max_discard_segments	= 1,
		},
	};
	bool can_discard = false;

    if (ublksrv_tgt_is_recovering(cdev))
        return crypt_recover_tgt(dev, 0);

	strcpy(tgt_json.name, "crypt");

	while ((opt = getopt_long(argc, argv, "-:f:c:k:o:x:s:y:z:",
				  lo_longopts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			file = strdup(optarg);
			break;
		case 'c':
			cipher = strdup(optarg);
			break;
		case 'k':
			key = strdup(optarg);
			break;
		case 'x':
			iv_offset = strtoul(optarg, NULL, 10);
			break;
		case 'o':
			device_offset = strtoul(optarg, NULL, 10);
			break;
		case 's':
			sector_size = strtoul(optarg, NULL, 10);
			break;
		case 'y':
			start_sector = strtoul(optarg, NULL, 10);
			break;
		case 'z':
			device_size = strtoul(optarg, NULL, 10);
			break;
		}
	}

	if (!file)
		return -1;

	fd = open(file, O_RDWR);
	if (fd < 0) {
		ublk_err( "%s: backing file %s can't be opened\n",
				__func__, file);
		return -2;
	}

	if (fstat(fd, &st) < 0)
		return -2;

    if (S_ISBLK(st.st_mode)) {
        unsigned int bs, pbs;

        if (ioctl(fd, BLKGETSIZE64, &bytes) != 0)
            return -1;
        if (ioctl(fd, BLKSSZGET, &bs) != 0)
            return -1;
        if (ioctl(fd, BLKPBSZGET, &pbs) != 0)
            return -1;
        p.basic.logical_bs_shift = ilog2(bs);
        p.basic.physical_bs_shift = ilog2(pbs);
        can_discard = backing_supports_discard(file);
    } else if (S_ISREG(st.st_mode)) {
        bytes = st.st_size;
        can_discard = true;
        p.basic.logical_bs_shift = ilog2(st.st_blksize);
        p.basic.physical_bs_shift = ilog2(st.st_blksize);
    } else {
        bytes = 0;
    }

	/*
	 * in case of buffered io, use common bs/pbs so that all FS
	 * image can be supported
	 */
	if (buffered_io || !ublk_param_is_valid(&p) ||
			fcntl(fd, F_SETFL, O_DIRECT)) {
		p.basic.logical_bs_shift = 9;
		p.basic.physical_bs_shift = 12;
		buffered_io = 1;
	}

    if (bytes > 0) {
        unsigned long long offset_bytes = device_offset << 9;

        if (offset_bytes >= bytes) {
            ublk_err( "%s: offset %lu greater than device size %llu",
                      __func__, device_offset, bytes);
            return -2;
        }
        bytes -= offset_bytes;
    }

    if (device_size > 0) {
        if ((device_size << 9) > bytes) {
            ublk_err( "%s: given device size %lu is greater than actual device size %llu",
                      __func__, device_size, bytes);
            return -2;
        }
        bytes = (device_size << 9);
    }

	tgt_json.dev_size = bytes;
	p.basic.dev_sectors = bytes >> 9;

	if (st.st_blksize && can_discard)
		p.discard.discard_granularity = st.st_blksize;
	else
		p.types &= ~UBLK_PARAM_TYPE_DISCARD;

    if (parse_cipher(cipher, &cipher_name, &mode_iv) != 0) {
        return -EINVAL;
    }

    if (sector_size < 512 || sector_size > 4096
            || !is_power_of_two(sector_size)) {
        ublk_err( "%s: sector size %lu is not in range 512-4096\n",
                  __func__, sector_size);
        return -EINVAL;
    }

    size_t key_len = strlen(key);
    if (key_len % 2)
        return -EINVAL;
    key_len /= 2;

    unsigned char* key_bin = (unsigned char*) malloc(key_len);
    if (!key_bin)
        return -ENOMEM;

    hex_to_bytes(key_len, key, key_bin);

    int rv = crypt_storage_init(&storage, sector_size, cipher_name, mode_iv, key_bin, key_len, large_iv);

    if (rv == -ENOENT || rv == -ENOTSUP) {
        ublk_err( "%s: crypt storage init failed, bad arguments\n",
                  __func__);
        return -1;
    }

    if (rv) {
        ublk_err( "%s: crypt storage init failed, rv is: %d\n",
                  __func__, rv);
        return -1;
    }

    struct crypt_tgt_data* tgt_data = (struct crypt_tgt_data *)calloc(1, sizeof(*tgt_data));
    if (!tgt_data) {
        return -1;
    }
    tgt_data->dev_offset = device_offset;
    tgt_data->iv_offset = iv_offset;
    tgt_data->key_bin = key_bin;
    tgt_data->key_len = key_len;

    dev->tgt.tgt_data = tgt_data;

    ublk_json_write_dev_info(cdev);
    ublk_json_write_target_base(cdev, &tgt_json);
    ublk_json_write_tgt_str(cdev, "backing_file", file);
    ublk_json_write_tgt_long(cdev, "direct_io", !buffered_io);
	ublk_json_write_tgt_str(cdev, "cipher_name", cipher_name);
	ublk_json_write_tgt_str(cdev, "mode_iv", mode_iv);
	ublk_json_write_tgt_long(cdev, "iv_offset", iv_offset);
	ublk_json_write_tgt_long(cdev, "device_offset", device_offset);
	ublk_json_write_tgt_long(cdev, "sector_size", sector_size);
	ublk_json_write_tgt_long(cdev, "large_iv", large_iv);
	ublk_json_write_tgt_long(cdev, "start_sector", start_sector);
	ublk_json_write_tgt_long(cdev, "device_size", device_size);
    ublk_json_write_params(cdev, &p);

    close(fd);

    return crypt_setup_tgt(dev, type, false, j->jbuf);
}

static void crypt_usage_for_add(void)
{
	printf("           crypt: -f backing_file -c cipher -k key\n");
	printf("                -x iv_offset -s sector_size -o device_offset\n");
	printf("                [-y start_sector -z device_size]\n");
	printf("                [--buffered_io --large_iv]\n");
	printf("	        default is direct IO to backing file\n");
	printf("	        cipher is expected in format cipher-mode-iv_mode\n");
	printf("	        sector size must be in range 512-4096 and a power of two\n");
}

static inline int crypt_fallocate_mode(const struct ublksrv_io_desc *iod)
{
       __u16 ublk_op = ublksrv_get_op(iod);
       __u32 flags = ublksrv_get_flags(iod);
       int mode = FALLOC_FL_KEEP_SIZE;

       /* follow logic of linux kernel crypt */
       if (ublk_op == UBLK_IO_OP_DISCARD) {
               mode |= FALLOC_FL_PUNCH_HOLE;
       } else if (ublk_op == UBLK_IO_OP_WRITE_ZEROES) {
               if (flags & UBLK_IO_F_NOUNMAP)
                       mode |= FALLOC_FL_ZERO_RANGE;
               else
                       mode |= FALLOC_FL_PUNCH_HOLE;
       } else {
               mode |= FALLOC_FL_ZERO_RANGE;
       }

       return mode;
}

static void crypt_queue_tgt_read(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag)
{
	unsigned ublk_op = ublksrv_get_op(iod);
    const struct crypt_tgt_data* tgt_data = get_private_tgt_data(q->dev);

	if (tgt_data->user_copy) {
		struct io_uring_sqe *sqe, *sqe2;
		__u64 pos = ublk_pos(q->q_id, tag, 0);
		void *buf = ublksrv_queue_get_io_buf(q, tag);

		ublk_get_sqe_pair(q->ring_ptr, &sqe, &sqe2);
		io_uring_prep_read(sqe, 1 /*fds[1]*/,
				buf,
				iod->nr_sectors << 9,
                (iod->start_sector + tgt_data->dev_offset) << 9);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_IO_LINK);
		sqe->user_data = build_user_data(tag, ublk_op, 1, 1);

		io_uring_prep_write(sqe2, 0 /*fds[0]*/,
				buf, iod->nr_sectors << 9, pos);
		io_uring_sqe_set_flags(sqe2, IOSQE_FIXED_FILE);
		/* bit63 marks us as tgt io */
		sqe2->user_data = build_user_data(tag, ublk_op, 0, 1);
	} else {
		struct io_uring_sqe *sqe;
		void *buf = (void *)iod->addr;

        ublk_dbg(UBLK_DBG_QUEUE, "device offset: %d\n", tgt_data->dev_offset);

		ublk_get_sqe_pair(q->ring_ptr, &sqe, NULL);
		io_uring_prep_read(sqe, 1 /*fds[1]*/,
			buf,
			(iod->nr_sectors << 9),
			(iod->start_sector + tgt_data->dev_offset) << 9);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		sqe->user_data = build_user_data(tag, ublk_op, 0, 1);
	}
}

static void crypt_queue_tgt_write(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag)
{
	unsigned ublk_op = ublksrv_get_op(iod);
    const struct crypt_tgt_data* tgt_data = get_private_tgt_data(q->dev);

	if (tgt_data->user_copy) {
		struct io_uring_sqe *sqe, *sqe2;
		__u64 pos = ublk_pos(q->q_id, tag, 0);
		void *buf = ublksrv_queue_get_io_buf(q, tag);

		ublk_get_sqe_pair(q->ring_ptr, &sqe, &sqe2);
		io_uring_prep_read(sqe, 0 /*fds[0]*/,
			buf, iod->nr_sectors << 9, pos);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_IO_LINK);
		sqe->user_data = build_user_data(tag, ublk_op, 1, 1);

		io_uring_prep_write(sqe2, 1 /*fds[1]*/,
			buf, iod->nr_sectors << 9,
			(iod->start_sector + tgt_data->dev_offset) << 9);
		io_uring_sqe_set_flags(sqe2, IOSQE_FIXED_FILE);
		/* bit63 marks us as tgt io */
		sqe2->user_data = build_user_data(tag, ublk_op, 0, 1);
	} else {
		struct io_uring_sqe *sqe;
		void *buf = (void *)iod->addr;
        char* b = (char*) buf;

        if (storage) {
            crypt_storage_encrypt(storage, (iod->start_sector) + tgt_data->iv_offset,
                                  iod->nr_sectors << 9, b);
        }

		ublk_get_sqe_pair(q->ring_ptr, &sqe, NULL);
		io_uring_prep_write(sqe, 1 /*fds[1]*/,
			buf,
			iod->nr_sectors << 9,
			(iod->start_sector + tgt_data->dev_offset) << 9);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		/* bit63 marks us as tgt io */
		sqe->user_data = build_user_data(tag, ublk_op, 0, 1);
	}
}

static int crypt_queue_tgt_io(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	const struct ublksrv_io_desc *iod = data->iod;
	struct io_uring_sqe *sqe;
	unsigned ublk_op = ublksrv_get_op(iod);
    const struct crypt_tgt_data* tgt_data = get_private_tgt_data(q->dev);

	switch (ublk_op) {
	case UBLK_IO_OP_FLUSH:
		ublk_get_sqe_pair(q->ring_ptr, &sqe, NULL);
		io_uring_prep_sync_file_range(sqe, 1 /*fds[1]*/,
				iod->nr_sectors << 9,
                (iod->start_sector + tgt_data->dev_offset) << 9,
				IORING_FSYNC_DATASYNC);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		/* bit63 marks us as tgt io */
		sqe->user_data = build_user_data(tag, ublk_op, 0, 1);
		break;
	case UBLK_IO_OP_WRITE_ZEROES:
	case UBLK_IO_OP_DISCARD:
		ublk_get_sqe_pair(q->ring_ptr, &sqe, NULL);
		io_uring_prep_fallocate(sqe, 1 /*fds[1]*/,
				crypt_fallocate_mode(iod),
                (iod->start_sector + tgt_data->dev_offset) << 9,
				iod->nr_sectors << 9);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		/* bit63 marks us as tgt io */
		sqe->user_data = build_user_data(tag, ublk_op, 0, 1);
		break;
	case UBLK_IO_OP_READ:
		crypt_queue_tgt_read(q, iod, tag);
		break;
	case UBLK_IO_OP_WRITE:
		crypt_queue_tgt_write(q, iod, tag);
		break;
	default:
		return -EINVAL;
	}

	ublk_dbg(UBLK_DBG_IO, "%s: tag %d ublk io %x %llx %u\n", __func__, tag,
			iod->op_flags, iod->start_sector, iod->nr_sectors << 9);

	return 1;
}

static co_io_job __crypt_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	int ret;
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

	io->queued_tgt_io = 0;
 again:
	ret = crypt_queue_tgt_io(q, data, tag);
	if (ret > 0) {
		if (io->queued_tgt_io)
			ublk_err("bad queued_tgt_io %d\n", io->queued_tgt_io);
		io->queued_tgt_io += 1;

		co_await__suspend_always(tag);
		io->queued_tgt_io -= 1;

		if (io->tgt_io_cqe->res == -EAGAIN)
			goto again;

		ublksrv_complete_io(q, tag, io->tgt_io_cqe->res);
	} else if (ret < 0) {
		ublk_err( "fail to queue io %d, ret %d\n", tag, tag);
	} else {
		ublk_err( "no sqe %d\n", tag);
	}
}

static int crypt_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
    const struct crypt_tgt_data* tgt_data = get_private_tgt_data(q->dev);

	if (tgt_data->block_device && ublksrv_get_op(data->iod) == UBLK_IO_OP_DISCARD) {
		__u64 r[2];
		int res;

		io_uring_submit(q->ring_ptr);

		r[0] = (data->iod->start_sector + tgt_data->dev_offset) << 9;
		r[1] = data->iod->nr_sectors << 9;
		res = ioctl(q->dev->tgt.fds[1], BLKDISCARD, &r);
		ublksrv_complete_io(q, data->tag, res);
	} else {
		io->co = __crypt_handle_io_async(q, data, data->tag);
	}
	return 0;
}

static void crypt_tgt_io_done(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct io_uring_cqe *cqe)
{
	int tag = user_data_to_tag(cqe->user_data);
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

    const struct ublksrv_io_desc *iod = data->iod;
    unsigned ublk_op = ublksrv_get_op(iod);

	if (user_data_to_tgt_data(cqe->user_data))
		return;

	ublk_assert(tag == data->tag);
	if (!io->queued_tgt_io)
		ublk_err("%s: wrong queued_tgt_io: res %d qid %u tag %u, cmd_op %u\n",
			__func__, cqe->res, q->q_id,
			user_data_to_tag(cqe->user_data),
			user_data_to_op(cqe->user_data));


    if (ublk_op == UBLK_IO_OP_READ) {
        char* b = (char*) iod->addr;
        const struct crypt_tgt_data* tgt_data = get_private_tgt_data(q->dev);

        if (storage) {
            crypt_storage_decrypt(storage, (iod->start_sector) + tgt_data->iv_offset,
                                  iod->nr_sectors << 9, b);
        }
    }

	io->tgt_io_cqe = cqe;
	io->co.resume();
}

static void crypt_deinit_tgt(const struct ublksrv_dev *dev)
{
    struct crypt_tgt_data* tgt_data = get_private_tgt_data(dev);

	fsync(dev->tgt.fds[1]);
	close(dev->tgt.fds[1]);
    free(tgt_data->key_bin);
    free(tgt_data);

    crypt_storage_destroy(storage);
}

struct ublksrv_tgt_type  crypt_tgt_type = {
	.handle_io_async = crypt_handle_io_async,
	.tgt_io_done = crypt_tgt_io_done,
	.usage_for_add	=  crypt_usage_for_add,
	.init_tgt = crypt_init_tgt,
	.deinit_tgt	=  crypt_deinit_tgt,
	.name	=  "crypt",
};

int main(int argc, char *argv[])
{
    return ublksrv_tgt_cmd_main(&crypt_tgt_type, argc, argv);
}

