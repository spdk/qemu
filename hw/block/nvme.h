#ifndef HW_NVME_H
#define HW_NVME_H
#include "qemu/cutils.h"
#include "block/nvme.h"
#include "hw/virtio/vhost.h"
#include "sysemu/hostmem.h"
#include "chardev/char-fe.h"

typedef struct NvmeAsyncEvent {
    QSIMPLEQ_ENTRY(NvmeAsyncEvent) entry;
    NvmeAerResult result;
} NvmeAsyncEvent;

typedef struct NvmeRequest {
    struct NvmeSQueue       *sq;
    BlockAIOCB              *aiocb;
    uint16_t                status;
    bool                    has_sg;
    NvmeCqe                 cqe;
    BlockAcctCookie         acct;
    QEMUSGList              qsg;
    QEMUIOVector            iov;
    QTAILQ_ENTRY(NvmeRequest)entry;
} NvmeRequest;

typedef struct NvmeSQueue {
    struct NvmeCtrl *ctrl;
    uint16_t    sqid;
    uint16_t    cqid;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    size;
    uint64_t    dma_addr;
    QEMUTimer   *timer;
    NvmeRequest *io_req;
    QTAILQ_HEAD(sq_req_list, NvmeRequest) req_list;
    QTAILQ_HEAD(out_req_list, NvmeRequest) out_req_list;
    QTAILQ_ENTRY(NvmeSQueue) entry;
} NvmeSQueue;

typedef struct NvmeStatus {
    uint16_t p:1;     /* phase tag */
    uint16_t sc:8;    /* status code */
    uint16_t sct:3;   /* status code type */
    uint16_t rsvd2:2;
    uint16_t m:1;     /* more */
    uint16_t dnr:1;   /* do not retry */
} NvmeStatus;

#define nvme_cpl_is_error(status) \
        (((status & 0x01fe) != 0) || ((status & 0x0e00) != 0))

typedef struct NvmeCQueue {
    struct NvmeCtrl *ctrl;
    uint8_t     phase;
    uint16_t    cqid;
    uint16_t    irq_enabled;
    uint32_t    head;
    uint32_t    tail;
    int32_t     virq;
    uint32_t    vector;
    uint32_t    size;
    uint64_t    dma_addr;
    EventNotifier guest_notifier;
    QEMUTimer   *timer;
    QTAILQ_HEAD(sq_list, NvmeSQueue) sq_list;
    QTAILQ_HEAD(cq_req_list, NvmeRequest) req_list;
} NvmeCQueue;

typedef struct NvmeNamespace {
    NvmeIdNs        id_ns;
} NvmeNamespace;

#define TYPE_NVME "nvme"
#define NVME(obj) \
        OBJECT_CHECK(NvmeCtrl, (obj), TYPE_NVME)

#define TYPE_VHOST_NVME "vhost-user-nvme"
#define NVME_VHOST(obj) \
        OBJECT_CHECK(NvmeCtrl, (obj), TYPE_VHOST_NVME)

typedef struct NvmeCtrl {
    PCIDevice    parent_obj;
    MemoryRegion iomem;
    MemoryRegion ctrl_mem;
    NvmeBar      bar;
    MemoryRegion *shadow_mr;
    volatile uint32_t *shadow_db;
    HostMemoryBackend *barmem;
    BlockConf    conf;

    int32_t    bootindex;
    CharBackend chardev;
    struct vhost_dev dev;
    uint32_t    num_io_queues;
    bool        dataplane_started;
    bool        vector_poll_started;

    uint32_t    page_size;
    uint16_t    page_bits;
    uint16_t    max_prp_ents;
    uint16_t    cqe_size;
    uint16_t    sqe_size;
    uint32_t    reg_size;
    uint32_t    num_namespaces;
    uint32_t    num_queues;
    uint32_t    max_q_ents;
    uint64_t    ns_size;
    uint32_t    cmb_size_mb;
    uint32_t    cmbsz;
    uint32_t    cmbloc;
    uint8_t     *cmbuf;
    uint64_t    irq_status;

    char            *serial;
    NvmeNamespace   *namespaces;
    NvmeSQueue      **sq;
    NvmeCQueue      **cq;
    NvmeSQueue      admin_sq;
    NvmeCQueue      admin_cq;
    NvmeIdCtrl      id_ctrl;
} NvmeCtrl;

#endif /* HW_NVME_H */
