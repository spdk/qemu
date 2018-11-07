#ifndef HW_NVME_H
#define HW_NVME_H
#include "block/nvme.h"
#include "qemu/cutils.h"
#include "nvme_lnvm_structs.h"

typedef struct NvmeAsyncEvent {
    QSIMPLEQ_ENTRY(NvmeAsyncEvent) entry;
    NvmeAerResult result;
} NvmeAsyncEvent;

typedef struct NvmeRequest {
    struct NvmeSQueue       *sq;
    struct NvmeNamespace    *ns;
    BlockAIOCB              *aiocb;
    uint8_t                 cmd_opcode;
    uint16_t                status;
    bool                    has_sg;
    uint64_t                slba;
    uint16_t                is_write;
    uint16_t                nlb;
    uint16_t                ctrl;
    uint64_t                meta_size;
    uint64_t                mptr;
    void                    *meta_buf;
    NvmeCqe                 cqe;
    BlockAcctCookie         acct;
    QEMUSGList              qsg;
    QEMUIOVector            iov;
    QTAILQ_ENTRY(NvmeRequest)entry;
} NvmeRequest;

typedef struct DMAOff {
    QEMUSGList *qsg;
    int ndx;
    dma_addr_t ptr;
    dma_addr_t len;
} DMAOff;

typedef struct NvmeSQueue {
    struct NvmeCtrl *ctrl;
    uint8_t     phys_contig;
    uint8_t     arb_burst;
    uint16_t    sqid;
    uint16_t    cqid;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    size;
    uint64_t    dma_addr;
    uint64_t    completed;
    uint64_t    *prp_list;
    QEMUTimer   *timer;
    NvmeRequest *io_req;
    QTAILQ_HEAD(, NvmeRequest) req_list;
    QTAILQ_HEAD(, NvmeRequest) out_req_list;
    QTAILQ_ENTRY(NvmeSQueue) entry;
    /* Mapped memory location where the tail pointer is stored by the guest
     * without triggering MMIO exits. */
    uint64_t    db_addr;
    /* virtio-like eventidx pointer, guest updates to the tail pointer that
     * do not go over this value will not result in MMIO writes (but will
     * still write the tail pointer to the "db_addr" location above). */
    uint64_t    eventidx_addr;
} NvmeSQueue;

typedef struct NvmeCQueue {
    struct NvmeCtrl *ctrl;
    uint8_t     phys_contig;
    uint8_t     phase;
    uint16_t    cqid;
    uint16_t    irq_enabled;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    vector;
    uint32_t    size;
    uint64_t    dma_addr;
    uint64_t    *prp_list;
    QEMUTimer   *timer;
    QTAILQ_HEAD(sq_list, NvmeSQueue) sq_list;
    QTAILQ_HEAD(cq_req_list, NvmeRequest) req_list;
    /* Mapped memory location where the head pointer is stored by the guest
     * without triggering MMIO exits. */
    uint64_t    db_addr;
    /* virtio-like eventidx pointer, guest updates to the head pointer that
     * do not go over this value will not result in MMIO writes (but will
     * still write the head pointer to the "db_addr" location above). */
    uint64_t    eventidx_addr;
} NvmeCQueue;

typedef struct NvmeNamespace {
    struct NvmeCtrl *ctrl;
    NvmeIdNs        id_ns;
    NvmeRangeType   lba_range[64];
    unsigned long   *util;
    unsigned long   *uncorrectable;
    uint32_t        id;
    uint64_t        ns_blks;
    uint64_t        start_block;
    uint64_t        meta_start_offset;
} NvmeNamespace;

#define TYPE_NVME "nvme"
#define NVME(obj) \
        OBJECT_CHECK(NvmeCtrl, (obj), TYPE_NVME)

typedef struct NvmeCtrl {
    PCIDevice    parent_obj;
    MemoryRegion iomem;
    MemoryRegion ctrl_mem;
    NvmeBar      bar;
    BlockConf    conf;

    uint32_t    page_size;
    time_t      start_time;
    uint16_t    temperature;
    uint16_t    page_bits;
    uint16_t    max_prp_ents;
    uint16_t    cqe_size;
    uint16_t    sqe_size;
    uint16_t    oacs;
    uint16_t    oncs;
    uint32_t    reg_size;
    uint32_t    num_namespaces;
    uint32_t    num_queues;
    uint32_t    max_q_ents;
    uint64_t    ns_size;
    uint8_t     db_stride;
    uint8_t     aerl;
    uint8_t     acl;
    uint8_t     elpe;
    uint8_t     elp_index;
    uint8_t     error_count;
    uint8_t     mdts;
    uint8_t     cqr;
    uint8_t     max_sqes;
    uint8_t     max_cqes;
    uint8_t     meta;
    uint8_t     vwc;
    uint8_t     mc;
    uint8_t     dpc;
    uint8_t     dps;
    uint8_t     extended;
    uint8_t     lba_index;
    uint8_t     mpsmin;
    uint8_t     mpsmax;
    uint8_t     intc;
    uint8_t     intc_thresh;
    uint8_t     intc_time;
    uint8_t     err_rec_dulbe;
    uint8_t     outstanding_aers;
    uint8_t     temp_warn_issued;
    uint8_t     num_errors;
    uint8_t     cqes_pending;
    uint16_t    vid;
    uint16_t    did;
    uint32_t    cmbsz;
    uint32_t    cmbloc;
    uint8_t     *cmbuf;
    uint64_t    irq_status;
    uint64_t    host_timestamp;                 /* Timestamp sent by the host */
    uint64_t    timestamp_set_qemu_clock_ms;    /* QEMU clock time */

    char            *serial;
    char            *ns_data_fname;
    NvmeErrorLog    *elpes;
    NvmeRequest     **aer_reqs;
    NvmeNamespace   *namespaces;
    NvmeSQueue      **sq;
    NvmeCQueue      **cq;
    NvmeSQueue      admin_sq;
    NvmeCQueue      admin_cq;
    NvmeFeatureVal  features;
    NvmeIdCtrl      id_ctrl;

    QSIMPLEQ_HEAD(aer_queue, NvmeAsyncEvent) aer_queue;
    QEMUTimer   *aer_timer;
    uint8_t     aer_mask;

    QemuMutex   enq_evt_mutex;

    uint64_t    db_addr;
    uint64_t    eventidx_addr;

    LnvmCtrl    lnvm_ctrl;
} NvmeCtrl;

typedef struct NvmeDifTuple {
    uint16_t guard_tag;
    uint16_t app_tag;
    uint32_t ref_tag;
} NvmeDifTuple;

static int nvme_qemu_fls(int i);
static void nvme_set_error_page(NvmeCtrl *n, uint16_t sqid, uint16_t cid,
                                uint16_t status, uint16_t location, uint64_t lba, uint32_t nsid);
static void nvme_rw_cb(void *opaque, int ret);
static void nvme_addr_write(NvmeCtrl *n, hwaddr addr, void *buf, int size);
static void nvme_addr_read(NvmeCtrl *n, hwaddr addr, void *buf, int size);
static uint16_t nvme_map_prp(QEMUSGList *qsg, QEMUIOVector *iov,
                             uint64_t prp1, uint64_t prp2, uint32_t len, NvmeCtrl *n);
static uint16_t nvme_dma_write_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
                                   uint64_t prp1, uint64_t prp2);
static uint16_t nvme_dma_read_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
                                  uint64_t prp1, uint64_t prp2);
static void nvme_enqueue_event(NvmeCtrl *n, uint8_t event_type,
                               uint8_t event_info, uint8_t log_page);
static void nvme_enqueue_req_completion(NvmeCQueue *cq, NvmeRequest *req);
#endif /* HW_NVME_H */
