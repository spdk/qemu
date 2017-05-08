/*
 * vhost-user-blk host device
 * Copyright IBM, Corp. 2011
 * Copyright(C) 2017 Intel Corporation.
 *
 * Authors:
 *  Stefan Hajnoczi <stefanha@linux.vnet.ibm.com>
 *  Changpeng Liu <changpeng.liu@intel.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#ifndef VHOST_USER_BLK_H
#define VHOST_USER_BLK_H

#include "standard-headers/linux/virtio_blk.h"
#include "qemu-common.h"
#include "hw/qdev.h"
#include "hw/block/block.h"
#include "sysemu/char.h"
#include "hw/virtio/vhost.h"

#define TYPE_VHOST_USER_BLK "vhost-user-blk"
#define VHOST_USER_BLK(obj) \
        OBJECT_CHECK(VHostUserBLK, (obj), TYPE_VHOST_USER_BLK)

typedef struct VHostUserBLK {
    VirtIODevice parent_obj;
    CharBackend chardev;
    Error *migration_blocker;
    int32_t bootindex;
    struct virtio_blk_config blkcfg;
    struct vhost_dev dev;
} VHostUserBLK;

#endif
