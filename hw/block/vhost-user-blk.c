/*
 * vhost-user-blk host device
 *
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

#include "qemu/osdep.h"
#include "migration/vmstate.h"
#include "migration/migration.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/typedefs.h"
#include "qom/object.h"
#include "hw/qdev-core.h"
#include "hw/virtio/vhost.h"
#include "hw/virtio/vhost-user-blk.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-access.h"
#include "sysemu/char.h"

static const int user_feature_bits[] = {
    VIRTIO_BLK_F_SIZE_MAX,
    VIRTIO_BLK_F_SEG_MAX,
    VIRTIO_BLK_F_GEOMETRY,
    VIRTIO_BLK_F_BLK_SIZE,
    VIRTIO_BLK_F_TOPOLOGY,
    VIRTIO_BLK_F_SCSI,
    VIRTIO_BLK_F_MQ,
    VIRTIO_F_VERSION_1,
    VIRTIO_RING_F_INDIRECT_DESC,
    VIRTIO_RING_F_EVENT_IDX,
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VHOST_INVALID_FEATURE_BIT
};

static void vhost_user_blk_update_config(VirtIODevice *vdev, uint8_t *config)
{
    VHostUserBLK *s = VHOST_USER_BLK(vdev);
    struct virtio_blk_config blkcfg;

    memset(&blkcfg, 0, sizeof(blkcfg));

    virtio_stq_p(vdev, &blkcfg.capacity, s->blkcfg.capacity);
    virtio_stl_p(vdev, &blkcfg.seg_max, s->blkcfg.seg_max);
    virtio_stl_p(vdev, &blkcfg.size_max, s->blkcfg.size_max);
    virtio_stl_p(vdev, &blkcfg.blk_size, s->blkcfg.blk_size);
    virtio_stw_p(vdev, &blkcfg.min_io_size, s->blkcfg.min_io_size);
    virtio_stl_p(vdev, &blkcfg.opt_io_size, s->blkcfg.opt_io_size);
    virtio_stw_p(vdev, &blkcfg.num_queues, s->blkcfg.num_queues);
    virtio_stw_p(vdev, &blkcfg.geometry.cylinders,
                 s->blkcfg.geometry.cylinders);
    blkcfg.geometry.heads = s->blkcfg.geometry.heads;
    blkcfg.geometry.sectors = s->blkcfg.geometry.sectors;
    blkcfg.physical_block_exp = 0;
    blkcfg.alignment_offset = 0;
    blkcfg.wce = s->blkcfg.wce;

    memcpy(config, &blkcfg, sizeof(struct virtio_blk_config));
}

static void vhost_user_blk_set_config(VirtIODevice *vdev, const uint8_t *config)
{
    VHostUserBLK *s = VHOST_USER_BLK(vdev);
    struct virtio_blk_config blkcfg;

    memcpy(&blkcfg, config, sizeof(blkcfg));

    if (blkcfg.wce != s->blkcfg.wce) {
        error_report("vhost-user-blk: does not support the operation");
    }
}

static void vhost_user_blk_start(VirtIODevice *vdev)
{
    VHostUserBLK *s = VHOST_USER_BLK(vdev);
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(vdev)));
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(qbus);
    int ret;

    if (!k->set_guest_notifiers) {
        error_report("binding does not support guest notifiers");
        return;
    }

    ret = vhost_dev_enable_notifiers(&s->dev, vdev);
    if (ret < 0) {
        error_report("Error enabling host notifiers: %d", -ret);
        return;
    }

    /* Suppress the masking guest notifiers on vhost user
    * because vhost user doesn't interrupt masking/unmasking
    * properly.
    */
    vdev->use_guest_notifier_mask = false;
    ret = k->set_guest_notifiers(qbus->parent, s->dev.nvqs, true);
    if (ret < 0) {
        error_report("Error binding guest notifier: %d", -ret);
        goto err_host_notifiers;
    }

    s->dev.acked_features = vdev->guest_features;
    ret = vhost_dev_start(&s->dev, vdev);
    if (ret < 0) {
        error_report("Error starting vhost: %d", -ret);
        goto err_guest_notifiers;
    }

    return;

err_guest_notifiers:
    k->set_guest_notifiers(qbus->parent, s->dev.nvqs, false);
err_host_notifiers:
    vhost_dev_disable_notifiers(&s->dev, vdev);
}

static void vhost_user_blk_stop(VirtIODevice *vdev)
{
    VHostUserBLK *s = VHOST_USER_BLK(vdev);
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(vdev)));
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(qbus);
    int ret;

    if (!k->set_guest_notifiers) {
        return;
    }

    vhost_dev_stop(&s->dev, vdev);

    ret = k->set_guest_notifiers(qbus->parent, s->dev.nvqs, false);
    if (ret < 0) {
        error_report("vhost guest notifier cleanup failed: %d", ret);
        return;
    }

    vhost_dev_disable_notifiers(&s->dev, vdev);
}

static void vhost_user_blk_set_status(VirtIODevice *vdev, uint8_t status)
{
    VHostUserBLK *s = VHOST_USER_BLK(vdev);
    bool should_start = status & VIRTIO_CONFIG_S_DRIVER_OK;

    if (!vdev->vm_running) {
        should_start = false;
    }

    if (s->dev.started == should_start) {
        return;
    }

    if (should_start) {
        vhost_user_blk_start(vdev);
    } else {
        vhost_user_blk_stop(vdev);
    }

}

static uint64_t vhost_user_blk_get_features(VirtIODevice *vdev,
                                            uint64_t features,
                                            Error **errp)
{
    VHostUserBLK *s = VHOST_USER_BLK(vdev);
    uint64_t get_features;

    virtio_add_feature(&features, VIRTIO_BLK_F_SIZE_MAX);
    virtio_add_feature(&features, VIRTIO_BLK_F_SEG_MAX);
    virtio_add_feature(&features, VIRTIO_BLK_F_TOPOLOGY);
    virtio_add_feature(&features, VIRTIO_BLK_F_BLK_SIZE);

    get_features = vhost_get_features(&s->dev, user_feature_bits, features);

    return get_features;
}

static void vhost_user_blk_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{

}

static void vhost_user_blk_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VHostUserBLK *s = VHOST_USER_BLK(vdev);
    int ret;

    if (!s->chardev.chr) {
        error_setg(errp, "vhost-user-blk: chardev is mandatary");
        return;
    }

    if (!s->blkcfg.num_queues) {
        error_setg(errp, "vhost-user-blk: invalid number of IO queues");
        return;
    }

    virtio_init(vdev, "virtio-blk", VIRTIO_ID_BLOCK,
                sizeof(struct virtio_blk_config));
    virtio_add_queue(vdev, 128, vhost_user_blk_handle_output);

    s->dev.nvqs = s->blkcfg.num_queues;
    s->dev.vqs = g_new(struct vhost_virtqueue, s->dev.nvqs);
    s->dev.vq_index = 0;
    s->dev.backend_features = 0;

    ret = vhost_dev_init(&s->dev, (void *)&s->chardev,
                         VHOST_BACKEND_TYPE_USER, 0);
    if (ret < 0) {
        error_setg(errp, "vhost-user-blk: vhost initialization failed: %s",
                   strerror(-ret));
        return;
    }
}

static void vhost_user_blk_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VHostUserBLK *s = VHOST_USER_BLK(dev);

    vhost_dev_cleanup(&s->dev);
    g_free(s->dev.vqs);
    virtio_cleanup(vdev);
}

static void vhost_user_blk_instance_init(Object *obj)
{
    VHostUserBLK *s = VHOST_USER_BLK(obj);

    device_add_bootindex_property(obj, &s->bootindex, "bootindex",
                                  "/disk@0,0", DEVICE(obj), NULL);
}

static const VMStateDescription vmstate_vhost_user_blk = {
    .name = "vhost-user-blk",
    .minimum_version_id = 2,
    .version_id = 2,
    .fields = (VMStateField[]) {
        VMSTATE_VIRTIO_DEVICE,
        VMSTATE_END_OF_LIST()
    },
};

static Property vhost_user_blk_properties[] = {
    DEFINE_PROP_CHR("chardev", VHostUserBLK, chardev),
    DEFINE_PROP_UINT16("num_queues", VHostUserBLK, blkcfg.num_queues, 1),
    DEFINE_PROP_UINT64("capacity", VHostUserBLK, blkcfg.capacity, 0),
    DEFINE_PROP_UINT32("block_size", VHostUserBLK, blkcfg.blk_size, 512),
    DEFINE_PROP_UINT32("max_segment_size", VHostUserBLK, blkcfg.size_max, 0),
    DEFINE_PROP_UINT32("max_segment_num", VHostUserBLK, blkcfg.seg_max, 1),
    DEFINE_PROP_UINT16("cylinders", VHostUserBLK, blkcfg.geometry.cylinders, 0),
    DEFINE_PROP_UINT8("heads",  VHostUserBLK, blkcfg.geometry.heads, 0),
    DEFINE_PROP_UINT8("sectors", VHostUserBLK, blkcfg.geometry.sectors, 0),
    DEFINE_PROP_UINT16("min_io_size",  VHostUserBLK, blkcfg.min_io_size, 0),
    DEFINE_PROP_UINT32("opt_io_size",  VHostUserBLK, blkcfg.opt_io_size, 0),
    DEFINE_PROP_UINT8("writecache",  VHostUserBLK, blkcfg.wce, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void vhost_user_blk_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    dc->props = vhost_user_blk_properties;
    dc->vmsd = &vmstate_vhost_user_blk;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    vdc->realize = vhost_user_blk_device_realize;
    vdc->unrealize = vhost_user_blk_device_unrealize;
    vdc->get_config = vhost_user_blk_update_config;
    vdc->set_config = vhost_user_blk_set_config;
    vdc->get_features = vhost_user_blk_get_features;
    vdc->set_status = vhost_user_blk_set_status;
}

static const TypeInfo vhost_user_blk_info = {
    .name = TYPE_VHOST_USER_BLK,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VHostUserBLK),
    .instance_init = vhost_user_blk_instance_init,
    .class_init = vhost_user_blk_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&vhost_user_blk_info);
}

type_init(virtio_register_types)
