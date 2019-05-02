/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef HW_NVME_LNVM_H
#define HW_NVME_LNVM_H

enum LnvmAdminCommands {
    LNVM_ADM_CMD_IDENTIFY          = 0xe2,
};

enum Lnvm2AdminCommands {
    LNVM_ADM_DEVICE_GEOMETRY    = 0xe2,
    LNVM_ADM_REPORT_CHUNK       = 0xf2,
};

enum Lnvm2IoCommands {
    LNVM_CMD_VEC_ERASE   = 0x90,
    LNVM_CMD_VEC_WRITE   = 0x91,
    LNVM_CMD_VEC_READ    = 0x92,
    LNVM_CMD_VEC_COPY    = 0x93,
};

typedef enum {
    LNVM_SEC_ERASED     = 0x45, // 'E'
    LNVM_SEC_WRITTEN    = 0x57, // 'W'
    LNVM_SEC_BAD        = 0x42, // 'B'
} LnvmMetaState;

// Per LBA-sector state of the emulated drive
typedef struct QEMU_PACKED {
    LnvmMetaState state;
} LnvmInternalMeta;

enum LnvmVersions {
    LNVM_DISABLED = 0x0,
    LNVM_2_0_VER  = 0x2,
};

typedef struct LnvmRwcCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2;
    uint64_t    metadata;
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    lbal;
    uint16_t    nlb;
    uint16_t    control;
    uint64_t    dlbal;
} LnvmRwcCmd;

typedef struct LnvmDmCmd {
    uint8_t opcode;
    uint8_t flags;
    uint16_t cid;
    uint32_t nsid;
    uint32_t rsvd1[8];
    uint64_t spba;
    uint32_t nlb;
    uint32_t rsvd2[3];
} LnvmDmCmd;

enum LnvmStatusCodes {
    LNVM_WR_SKIP_PAGE      = 0x400a,
    LNVM_RD_CRC_ERROR      = 0x4004,
    LNVM_WR_PROG_FAIL      = 0x40ff,
    LNVM_RD_ECC_ERROR      = 0x4281,
    LNVM_WR_PTR_CHECK_FAIL = 0x42f0,
    LNVM_RD_EMPTY_PAGE     = 0x42ff,
    LNVM_RD_ECC_HIGH       = 0x4700,
    LNVM_ER_OFFLINE_CHUNK  = 0x02C0,
    LNVM_ER_INVLD_RESET    = 0x02C1,
};

typedef struct QEMU_PACKED {
    uint64_t    notification_count;
    uint64_t    ppa_addr;
    uint32_t    nsid;
    uint16_t    state;
    uint8_t     mask;
    uint8_t     rsvd1[9];
    uint16_t    nlb;
    uint8_t     rsvd2[30];
} LnvmChunksNotiEntry;

enum {
    /* scope */
    LNVM_LOGPAGE_SCOPE_SECTOR       = 1,
    LNVM_LOGPAGE_SCOPE_CHUNK        = 2,
    LNVM_LOGPAGE_SCOPE_LUN          = 4,

    /* severity */
    LNVM_LOGPAGE_SEVERITY_LOW       = 1,
    LNVM_LOGPAGE_SEVERITY_MID       = 2,
    LNVM_LOGPAGE_SEVERITY_HIGH      = 4,
    LNVM_LOGPAGE_SEVERITY_UNREC     = 8,
    LNVM_LOGPAGE_SEVERITY_REFRESHED = 16,
    LNVM_LOGPAGE_SEVERITY_WLI       = (1 << 8),
};

enum LnvmLogIdentifier {
    LNVM_LOG_CHUNK_NOTIFICATION = 0xD0,
    LNVM_LOG_CHUNK_REPORT       = 0xCA
};

enum LnvmFeatureId {
    LNVM_MEDIA_FEEDBACK        = 0xCA
};

typedef struct LnvmIdLbaFormat {
    uint8_t ch_bit_len;
    uint8_t lun_bit_len;
    uint8_t chunk_bit_len;
    uint8_t sector_bit_len;
    uint8_t resv[4];
} QEMU_PACKED LnvmIdLbaFormat;

typedef struct LnvmAddrF {
    uint64_t ch_mask;
    uint64_t lun_mask;
    uint64_t pln_mask;
    uint64_t blk_mask;
    uint64_t pg_mask;
    uint64_t sec_mask;
    uint8_t ch_offset;
    uint8_t lun_offset;
    uint8_t pln_offset;
    uint8_t blk_offset;
    uint8_t pg_offset;
    uint8_t sec_offset;
    uint8_t  ch_len;
    uint8_t  lun_len;
    uint8_t  pln_len;
    uint8_t  blk_len;
    uint8_t  pg_len;
    uint8_t  sec_len;
} LnvmAddrF;

typedef struct Lnvm13Geo {
    uint16_t num_ch;
    uint16_t num_lun;
    uint32_t num_chnks;
    uint32_t clba;
    uint32_t csecs;
    uint32_t sos;
    uint8_t resv[44];
} QEMU_PACKED Lnvm13Geo;

typedef struct Lnvm13Wrt {
    uint32_t mw_min;
    uint32_t mw_opt;
    uint32_t mw_cunits;
    uint8_t resv[52];
} QEMU_PACKED Lnvm13Wrt;

typedef struct Lnvm13Perf {
    uint32_t trdt;
    uint32_t trdm;
    uint32_t tprt;
    uint32_t tprm;
    uint32_t tbet;
    uint32_t tbem;
    uint8_t resv[40];
} QEMU_PACKED Lnvm13Perf;

typedef struct LnvmIdCtrl {
    uint8_t ver_id;
    uint8_t min_id;
    uint8_t resv1[6];
    struct LnvmIdLbaFormat lbaf;
    uint32_t mccap;
    uint8_t resv2[12];
    uint8_t wit;
    uint8_t resv3[31];
    Lnvm13Geo geo;
    Lnvm13Wrt wrt;
    Lnvm13Perf perf;
} QEMU_PACKED LnvmIdCtrl;

typedef enum {
    LNVM_CHNK_FREE = 0x1,
    LNVM_CHNK_FULL = 0x2,
    LNVM_CHNK_OPEN = 0x4,
    LNVM_CHNK_BAD  = 0x8,
} LnvmChnkState ;

enum LnvmChnkReportOpt {
    LNVM_CHNK_REP_ALL  = 0x0,
    LNVM_CHNK_REP_FREE = 0x1,
    LNVM_CHNK_REP_FULL = 0x2,
    LNVM_CHNK_REP_OPEN = 0x3,
    LNVM_CHNK_REP_BAD  = 0x4,
    LNVM_CHNK_REP_SEQ  = 0xA,
    LNVM_CHNK_REP_RAND = 0xB
};

enum LnvmChnkLimit {
    LNVM_CHNK_SEQ  = 0x1,
    LNVM_CHNK_RAND = 0x2,
};

typedef struct LnvmChnkDesc {
    uint8_t    state;
    uint8_t    type;
    uint8_t    wli;
    uint8_t    rsvd[5];
    uint64_t   slba;
    uint64_t   cnlb;
    uint64_t   wplba;
} QEMU_PACKED LnvmChnkDesc;

typedef struct LnvmChnks {
    uint64_t   nlb;
    uint64_t   rsvd[7];
    struct LnvmChnkDesc chnk[0];
} QEMU_PACKED LnvmChnks;

typedef struct LnvmBbt {
    uint8_t     tblid[4];
    uint16_t    verid;
    uint16_t    revid;
    uint32_t    rvsd1;
    uint32_t    tblks;
    uint32_t    tfact;
    uint32_t    tgrown;
    uint32_t    tdresv;
    uint32_t    thresv;
    uint32_t    rsvd2[8];
    uint8_t     blk[0];
} QEMU_PACKED LnvmBbt;

/* Parameters passed on to QEMU to configure the characteristics of the drive */
typedef struct LnvmParams {
    uint32_t    aer_thread_sleep;
    /* configurable device characteristics */
    uint16_t    pgs_per_blk;
    uint16_t    sec_size;
    uint8_t     sec_per_pg;
    uint8_t     max_sec_per_rq;
    uint16_t    blks_per_pln;
    uint8_t     num_ch;
    uint8_t     num_pln;
    uint8_t     num_lun;
    uint32_t    ws_factor;
    uint32_t    cu_factor;
    /* calculated values */
    uint32_t    ppa_secs_per_pl;
    uint32_t    ppa_secs_per_pg;
    uint32_t    ppa_secs_per_blk;
    uint32_t    ppa_secs_per_lun;
    uint32_t    ppa_secs_total; /* Sectors as defined in PPA addressing */
    uint32_t    chunks_no; /* Number of chunks on whole device */
} QEMU_PACKED LnvmParams;

enum LnvmResponsibility {
    LNVM_RSP_L2P       = 1 << 0,
    LNVM_RSP_ECC       = 1 << 1,
};

#define LNVM_MAX_CHNK_NOTI (1024)
typedef struct LnvmChunksNoti {
    QemuMutex events_mutex;     /* Guards access to the events array and events* variables */

    LnvmChunksNotiEntry events[LNVM_MAX_CHNK_NOTI];
    uint64_t events_cnt;        /* How many events were issued already */
    uint32_t n;
    uint32_t j;
    QemuThread aer_thread;       /* AER thread */
    QemuSemaphore aer_qsem;      /* Signalled when aer_thread should end */
} LnvmChunksNoti;

typedef struct LnvmFeature {
    uint32_t    hecc:1;
    uint32_t    vhecc:1;
    uint32_t    resv:30;
} LnvmFeature;

typedef struct LnvmErrInjection {
    uint32_t    err_freq;
    uint32_t    err_cnt;
    uint32_t    n_err;
} LnvmErrInjection;

typedef struct LnvmCtrl {
    LnvmParams          params;
    LnvmIdCtrl          id_ctrl;
    LnvmAddrF           ppaf;
    LnvmFeature         features;
    LnvmErrInjection    err_write;
    LnvmErrInjection    err_erase;
    LnvmErrInjection    err_read;
    LnvmChnkDesc        *chunk_state;
    LnvmChunksNoti      te_data;
    char                *meta_fname;
    FILE                *metadata_fp;
} LnvmCtrl;

#define LNVM_ER_DULBE(err_rec)  ((err_rec >> 8) & 0x1)

#endif /* HW_NVME_LNVM_H */
