/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef HW_NVME_LNVM_HELPERS_H
#define HW_NVME_LNVM_HELPERS_H

#define LNVM_MAX_GRPS_PR_IDENT (20)
#define LNVM_FEAT_EXT_START 64
#define LNVM_FEAT_EXT_END 127
#define LNVM_PBA_UNMAPPED UINT64_MAX
#define LNVM_LBA_UNMAPPED UINT64_MAX

static uint8_t lnvm_dev(NvmeCtrl *n)
{
    return (n->lnvm_ctrl.id_ctrl.ver_id != LNVM_DISABLED);
}

static uint16_t
lnvm_inject_err_status(NvmeRequest *req)
{
    switch (req->cmd_opcode) {
    case NVME_CMD_WRITE:
    case LNVM_CMD_VEC_WRITE:
        return NVME_WRITE_FAULT;
    case NVME_CMD_DSM:
    case LNVM_CMD_VEC_ERASE:
        return LNVM_ER_OFFLINE_CHUNK;
    case NVME_CMD_READ:
    case LNVM_CMD_VEC_READ:
        return NVME_UNRECOVERED_READ;
    default:
        assert(0 && "Invalid opcode");
    }
}

static bool
lnvm_cmd_is_vector(uint8_t opcode)
{
     switch (opcode) {
        case LNVM_CMD_VEC_WRITE:
        case LNVM_CMD_VEC_READ:
        case LNVM_CMD_VEC_ERASE:
        case LNVM_CMD_VEC_COPY:
            return true;
        default:
            return false;
    }
}

static void lnvm_inject_err(LnvmCtrl *ln, LnvmErrInjection *inj,
                            NvmeRequest *req, NvmeCqe *cqe)
{
    if (!inj->err_freq) {
        return;
    }

    if ((inj->err_cnt + req->nlb) > inj->err_freq) {
        if (lnvm_cmd_is_vector(req->cmd_opcode)) {
            uint32_t i, n_err;

            /* kill n_err sectors in ppa list */
            for (i = 0; i < req->nlb; i++) {
                if (inj->err_cnt + i < inj->err_freq) {
                    continue;
                }

                n_err = inj->n_err < req->nlb - i ? inj->n_err : req->nlb - i;
                bitmap_set((uint64_t *)&cqe->result, i, n_err);
                break;
            }
        }

        req->status = lnvm_inject_err_status(req);
        inj->err_cnt = 0;
    }

    inj->err_cnt += req->nlb;
}

static void lnvm_post_cqe(NvmeCtrl *n, NvmeRequest *req)
{
    LnvmCtrl *ln = &n->lnvm_ctrl;
    NvmeCqe *cqe = &req->cqe;

    /* Do post-completion processing depending on the type of command. This is
      * used primarily to inject different types of errors.
      */
    switch (req->cmd_opcode) {
    case LNVM_CMD_VEC_WRITE:
    case NVME_CMD_WRITE:
        lnvm_inject_err(ln, &ln->err_write, req, cqe);
        break;
    case LNVM_CMD_VEC_READ:
    case NVME_CMD_READ:
        lnvm_inject_err(ln, &ln->err_read, req, cqe);
        break;
    case LNVM_CMD_VEC_ERASE:
    case NVME_CMD_DSM:
        lnvm_inject_err(ln, &ln->err_erase, req, cqe);
        break;
    }
}

static void lnvm_print_ppa(LnvmCtrl *ln, uint64_t ppa)
{
    uint64_t ch = (ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
    uint64_t lun = (ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
    uint64_t blk = (ppa & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
    uint64_t pg = (ppa & ln->ppaf.pg_mask) >> ln->ppaf.pg_offset;
    uint64_t pln = (ppa & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset;
    uint64_t sec = (ppa & ln->ppaf.sec_mask) >> ln->ppaf.sec_offset;

    printf("ppa: ch(%lu), lun(%lu), blk(%lu), pg(%lu), pl(%lu), sec(%lu)\n",
           ch, lun, blk, pg, pln, sec);
}

/* The whole PPA addres range may contain sections not backed up physically.
 * The function returns block's number as if they were packed tightly. */
static inline int64_t lnvm_ppa_to_sec_no(LnvmCtrl *ln, uint64_t ppa)
{
    //uint64_t ch = (ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
    uint64_t lun = (ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
    uint64_t pln = (ppa & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset;
    uint64_t blk = (ppa & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
    uint64_t pg = (ppa & ln->ppaf.pg_mask) >> ln->ppaf.pg_offset;
    uint64_t sec = (ppa & ln->ppaf.sec_mask) >> ln->ppaf.sec_offset;

    uint64_t off = sec;
    off += pln * ln->params.ppa_secs_per_pl;
    off += pg * ln->params.ppa_secs_per_pg;
    off += blk * ln->params.ppa_secs_per_blk;
    off += lun * ln->params.ppa_secs_per_lun;

    return off;
}

static uint32_t lnvm_ns_get_data_size_shift(NvmeNamespace *ns)
{
    uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    return ns->id_ns.lbaf[lba_index].ds;
}

static uint32_t lnvm_ns_get_meta_size(NvmeNamespace *ns)
{
    uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    return ns->id_ns.lbaf[lba_index].ms;
}

static int lnvm_meta_state_get(NvmeNamespace *ns, uint64_t ppa,
                               LnvmMetaState *state, void *user_meta)
{
    LnvmCtrl *ln = &ns->ctrl->lnvm_ctrl;
    FILE *meta_fp = ns->ctrl->metadata_fp;
    size_t tgt_oob_len = lnvm_ns_get_meta_size(ns);
    size_t int_oob_len = sizeof(LnvmInternalMeta);
    size_t meta_len = tgt_oob_len + int_oob_len;
    uint64_t seek = lnvm_ppa_to_sec_no(&ns->ctrl->lnvm_ctrl, ppa) * meta_len;
    LnvmInternalMeta int_meta;

    // Validate if the LBA is within a valid range
    //uint64_t ch = (ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
    uint64_t lun = (ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
    uint64_t chk = (ppa & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
    uint64_t sec = ppa & (ln->ppaf.pg_mask | ln->ppaf.pln_mask | ln->ppaf.sec_mask);
    if ((lun >= ln->params.num_lun) ||
            (chk >= ln->params.blks_per_pln) ||
            (sec >= ln->params.ppa_secs_per_blk)) {
        return -1;
    }

    if (fseek(meta_fp, seek, SEEK_SET)) {
        perror("lnvm_meta_state_get: fseek");
        return -1;
    }

    if (fread(&int_meta, int_oob_len, 1, meta_fp) != 1) {
        printf("lnvm_meta_state_get: fread - state: ppa(0x%016lx)\n", ppa);
        return -1;
    }

    *state = int_meta.state;

    if (user_meta) {
        if (fread(user_meta, tgt_oob_len, 1, meta_fp) != 1) {
            printf("lnvm_meta_state_get: fread - meta: ppa(0x%016lx)\n", ppa);
            return -1;
        }
    }

    return 0;
}

static int lnvm_meta_state_set(NvmeNamespace *ns, uint64_t ppa,
                               LnvmMetaState state, void *user_meta)
{
    FILE *meta_fp = ns->ctrl->metadata_fp;
    size_t tgt_oob_len = lnvm_ns_get_meta_size(ns);
    size_t int_oob_len = sizeof(LnvmInternalMeta);
    size_t meta_len = tgt_oob_len + int_oob_len;
    uint64_t seek = lnvm_ppa_to_sec_no(&ns->ctrl->lnvm_ctrl, ppa) * meta_len;
    LnvmInternalMeta int_meta;

    if (lnvm_meta_state_get(ns, ppa, &int_meta.state, NULL)) {
        printf("lnvm_meta_state_set: lnvm_meta_state_get failed for ppa(0x%016lx)\n",
               ppa);
        return LNVM_WR_PTR_CHECK_FAIL;
    }

    if (int_meta.state == state) {
        if (state == LNVM_SEC_ERASED || state == LNVM_SEC_BAD) {
            return 0; // EDTC erase or set bad block - an OK situation.
        } else {
            printf("lnvm_meta_state_set: Invalid transistion %c->%c for ppa(0x%016lx)\n",
                   int_meta.state, state, ppa);
            return LNVM_WR_PTR_CHECK_FAIL;
        }
    }

    // Additional sanity check to catch non-sequential writes: for every
    // sector scheck if the predecessing one is marked as written.
    if (state == LNVM_SEC_WRITTEN) {
        LnvmCtrl *ln = &ns->ctrl->lnvm_ctrl;
        uint64_t sec_mask = ln->ppaf.sec_mask | ln->ppaf.pg_mask | ln->ppaf.pln_mask;
        uint64_t sec_no = (ppa & sec_mask);

        // Only groups of X=<sec per plane> sectors are valid for a write.
        // An optimization can be applied and the code below tests only the 1st PPA.
        // It's assumed the PPAs are already tested for continuousness, alignment, etc.

        // Do not test the 1st X sectors in Erase Block (no other sectors are preceeding them).
        if (sec_no >= ln->params.sec_per_pg) {
            // If the 1st PPA from the group of X passes, all will pass. So check only the 1st one.
            if (!((ppa & ln->ppaf.sec_mask) % ln->params.sec_per_pg)) {
                uint64_t prev_ppa = ppa - 1;
                if (lnvm_meta_state_get(ns, prev_ppa, &int_meta.state, NULL)) {
                    printf("lnvm_meta_state_set: lnvm_meta_state_get_2 failed for ppa(0x%016lx)",
                           prev_ppa);
                    return LNVM_WR_PTR_CHECK_FAIL;
                }

                if (int_meta.state != LNVM_SEC_WRITTEN) {
                    printf("nand_rule: previous page state(%c) is not (W) for ppa(0x%016lx)\n",
                           state, prev_ppa);
                    return LNVM_WR_SKIP_PAGE;
                }
            }
        }
    }

    if (fseek(meta_fp, seek, SEEK_SET)) {
        perror("lnvm_meta_state_set: fseek");
        return LNVM_WR_PROG_FAIL;
    }

    int_meta.state = state;
    if (fwrite(&int_meta, int_oob_len, 1, meta_fp) != 1) {
        printf("lnvm_meta_state_get: fwrite - state: ppa(%lu)\n", ppa);
        return LNVM_WR_PROG_FAIL;
    }

    if (user_meta) {
        if (fwrite(user_meta, tgt_oob_len, 1, meta_fp) != 1) {
            printf("lnvm_meta_state_get: fwrite - meta: ppa(%lu)\n", ppa);
            return LNVM_WR_PROG_FAIL;
        }
    }

    if (fflush(meta_fp)) {
        perror("lnvm_meta_state_set: fflush");
        return LNVM_WR_PROG_FAIL;
    }

    return 0;
}

static inline int64_t lnvm_lba_to_chnk_no(LnvmCtrl *ln, uint64_t lba)
{
    //uint64_t ch = (lba & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
    uint64_t lun = (lba & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
    uint64_t blk = (lba & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;

    return blk + lun * ln->params.blks_per_pln;
}

static void lnvm_set_chunk_state(LnvmCtrl *ln, uint64_t lba,
                                 LnvmMetaState state)
{
    uint64_t sec_mask = ln->ppaf.sec_mask | ln->ppaf.pg_mask | ln->ppaf.pln_mask;
    uint64_t chunk_no = lnvm_lba_to_chnk_no(ln, lba);
    uint64_t end_sec = (lba & sec_mask) + 1;
    size_t sec_per_chunk = ln->params.sec_per_pg * ln->params.num_pln *
                           ln->params.pgs_per_blk;

    if (state == LNVM_SEC_BAD) {
        ln->chunk_state[chunk_no].state = LNVM_CHNK_BAD;
        ln->chunk_state[chunk_no].wplba = 0;
        ln->chunk_state[chunk_no].cnlb = 0;
    } else if (state == LNVM_SEC_ERASED) {
        ln->chunk_state[chunk_no].state = LNVM_CHNK_FREE;
        ln->chunk_state[chunk_no].wplba = 0;
    } else {
        if (end_sec == sec_per_chunk) {
            ln->chunk_state[chunk_no].state = LNVM_CHNK_FULL;
            ln->chunk_state[chunk_no].wplba = ln->chunk_state[chunk_no].cnlb + sec_per_chunk;
        } else {
            ln->chunk_state[chunk_no].state = LNVM_CHNK_OPEN;
            ln->chunk_state[chunk_no].wplba = end_sec;
        }
    }
}

static LnvmChnkState lnvm_get_chunk_state(LnvmCtrl *ln, uint64_t lba)
{
    uint64_t chunk_no = lnvm_lba_to_chnk_no(ln, lba);

    return ln->chunk_state[chunk_no].state;
}

static inline uint64_t lnvm_get_next_chunk(uint64_t curr_chunk, LnvmCtrl *ln)
{
    uint64_t mask = ln->ppaf.ch_mask | ln->ppaf.lun_mask;
    uint64_t next_chunk = (curr_chunk & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;

    next_chunk++;

    return ((curr_chunk & mask) | (next_chunk << ln->ppaf.blk_offset));
}
/*
 * If variable range is set to true, function will iterate over chunks
 * sequentially from first chunk stored under lba_list. In other cases function
 * using will iterate over addresses in lba_list.
 */
static int lnvm_set_chunk_state_persistent(NvmeNamespace *ns, LnvmCtrl *ln,
                                           uint64_t *lba_list,
                                           int lba_count, uint64_t *result, LnvmMetaState state,
                                           bool range)
{
    uint64_t mask = ln->ppaf.ch_mask | ln->ppaf.lun_mask | ln->ppaf.blk_mask;
    uint64_t res = 0;
    uint64_t pl, pg, sec;
    int i;

    for (i = 0; i < lba_count; i++) {
        uint64_t lba = 0;

        if (!range || (i == 0)) {
            lba = lba_list[i];
        } else {
            lba = lnvm_get_next_chunk(lba, ln);
        }

        for (pl = 0; pl < ln->params.num_pln; pl++) {
            uint64_t lba_pl = (lba & mask) | (pl << ln->ppaf.pln_offset);

            // Check bad-block-table to error on bad blocks
            if (state != LNVM_SEC_BAD
                    && lnvm_get_chunk_state(ln, lba_pl) == LNVM_CHNK_BAD) {
                printf("nand_rule: _erase_meta: failed -- block is bad\n");
                lnvm_print_ppa(ln, lba_pl);
                res |= 1 << i;
                break;
            }

            for (pg = 0; pg < ln->params.pgs_per_blk; pg++) {
                for (sec = 0; sec < ln->params.sec_per_pg; sec++) {
                    uint64_t lba_sec = lba_pl;
                    lba_sec |= pg << ln->ppaf.pg_offset;
                    lba_sec |= sec << ln->ppaf.sec_offset;

                    if (lnvm_meta_state_set(ns, lba_sec, state, NULL)) {
                        res |= 1 << i;
                    }
                }
            }
        }
        lnvm_set_chunk_state(ln, lba, state);
    }

    if (result) {
        *result = res;
    }

    return 0;
}

static inline void *lnvm_meta_index(NvmeNamespace *ns, void *meta,
                                    uint32_t index)
{
    return meta + (index * lnvm_ns_get_meta_size(ns));
}

static void lnvm_te_new_event(NvmeCtrl *n, uint64_t ppa_addr, uint32_t nsid,
                              uint16_t state,
                              uint16_t mask, uint16_t nlb)
{
    LnvmChunksNoti *td = &n->lnvm_ctrl.te_data;
    uint32_t j = 0;

    if (!n->aer_timer) {
        //controller is stopped - cannot issue AER
        return;
    }

    qemu_mutex_lock(&td->events_mutex);
    if (td->n + 1 > LNVM_MAX_CHNK_NOTI) {
	//overflow - remove oldest element
        td->j = (td->j + 1) % LNVM_MAX_CHNK_NOTI;
	td->n--;
    }
    j = ((td->j + td->n) % LNVM_MAX_CHNK_NOTI);
    td->n++;
    td->events_cnt++;
    td->events[j].notification_count = td->events_cnt;
    td->events[j].ppa_addr = ppa_addr;
    td->events[j].nsid = nsid;
    td->events[j].state = state;
    td->events[j].mask = mask;
    td->events[j].nlb = nlb - 1; //zero based
    qemu_mutex_unlock(&td->events_mutex);

    nvme_enqueue_event(n, NVME_AER_TYPE_VENDOR_SPECIFIC, 0,
                       LNVM_LOG_CHUNK_NOTIFICATION);
}

static void *lnvm_te_thread(void *arg)
{
    NvmeCtrl *n = (NvmeCtrl *)arg;
    LnvmCtrl *ln = &n->lnvm_ctrl;
    struct timespec ts = {0};
    uint8_t chunk_state;
    int ret;
    uint64_t ppa;
    uint64_t cnt = 0;
    uint64_t total_chunks = ln->params.chunks_no;
    int nsid = 1;
    srand((unsigned)time(NULL));

    // Timeout is given in miliseconds
    ts.tv_sec = ln->params.aer_thread_sleep / 1000;
    ts.tv_nsec = (ln->params.aer_thread_sleep - ts.tv_sec * 1000) * 100000;

    for (;;) {
        nanosleep(&ts, NULL);

        ret = qemu_sem_timedwait(&ln->te_data.aer_qsem, 0);
        if (ret != -1) {
            break;
        }

        while (true) {
            cnt = rand() % total_chunks;
            chunk_state = ln->chunk_state[cnt].state;
            ppa = cnt << ln->ppaf.blk_offset;
            if (chunk_state == LNVM_CHNK_FULL || chunk_state == LNVM_CHNK_OPEN) {
                int scope = rand() % 3 ? LNVM_LOGPAGE_SCOPE_CHUNK :
                            LNVM_LOGPAGE_SCOPE_SECTOR;
                int nlb = 1;
                if (scope == LNVM_LOGPAGE_SCOPE_SECTOR) {
                    int sec = rand() % (ln->params.ppa_secs_per_blk);
                    if (ln->params.ppa_secs_per_blk > sec + 1) {
		        nlb = 1 + (rand() % (ln->params.ppa_secs_per_blk - sec - 1));
		    }
                    ppa += sec;
                }
                lnvm_te_new_event(n, ppa, nsid, LNVM_LOGPAGE_SEVERITY_MID, scope, nlb);
                break;
            }
        }
    }

    return 0;
}

static void lnvm_te_init(NvmeCtrl *n)
{
    LnvmCtrl *ln = &n->lnvm_ctrl;

    memset(&ln->te_data, 0x0, sizeof(ln->te_data));
    qemu_mutex_init(&ln->te_data.events_mutex);

    if (ln->params.aer_thread_sleep) {
        qemu_sem_init(&ln->te_data.aer_qsem, 0);
        qemu_thread_create(&ln->te_data.aer_thread, "AER", lnvm_te_thread, n,
                           QEMU_THREAD_JOINABLE);
    }
}

static void lnvm_te_exit(NvmeCtrl *n)
{
    LnvmCtrl *ln = &n->lnvm_ctrl;

    if (ln->params.aer_thread_sleep) {
        /* send a quit signal and wait for the thread to end */
        qemu_sem_post(&ln->te_data.aer_qsem);
        qemu_thread_join(&ln->te_data.aer_thread);
        qemu_sem_destroy(&ln->te_data.aer_qsem);
    }

    qemu_mutex_destroy(&ln->te_data.events_mutex);
}

static uint16_t lnvm_rwc(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                         NvmeRequest *req, bool vector)
{
    /* In the case of a LightNVM device. The slba is the logical address, while
     * the actual physical block address is stored in Command Dword 11-10.
     * This function is made based on 1.2 spec, but it support 2.0 spec also,
     * since all the important fields are the same. */
    LnvmCtrl *ln = &n->lnvm_ctrl;
    LnvmRwcCmd *lrw = (LnvmRwcCmd *)cmd;
    NvmeCqe *cqe = &req->cqe;
    uint64_t lba_list[ln->params.max_sec_per_rq]; /* source or destination in r/w mode */
    uint64_t dlba_list[ln->params.max_sec_per_rq]; /* destination in copy mode */
    uint8_t *meta_buf = NULL;
    uint8_t *copy_buf = NULL;
    uint64_t *aio_offset_list;
    uint32_t lba_count = le16_to_cpu(lrw->nlb) + 1;
    uint64_t prp1 = le64_to_cpu(lrw->prp1);
    uint64_t prp2 = le64_to_cpu(lrw->prp2);
    uint64_t lbal = le64_to_cpu(lrw->lbal);
    uint64_t dlbal = le64_to_cpu(lrw->dlbal);
    uint64_t meta = le64_to_cpu(lrw->metadata);
    uint64_t data_size = lba_count << lnvm_ns_get_data_size_shift(ns);
    uint32_t meta_size = lba_count * lnvm_ns_get_meta_size(ns);
    uint16_t is_write = (lrw->opcode == LNVM_CMD_VEC_WRITE)
                        || (lrw->opcode == NVME_CMD_WRITE);
    uint16_t is_read = (lrw->opcode == LNVM_CMD_VEC_READ)
                       || (lrw->opcode == NVME_CMD_READ);
    uint16_t is_copy = !is_write && !is_read;
    uint16_t err = 0;
    uint64_t i, j;
    uint32_t state = LNVM_SEC_ERASED;
    int ret;

    if (is_copy) {
        copy_buf = g_malloc0(1 << lnvm_ns_get_data_size_shift(ns));
        if (!copy_buf) {
            printf("lnvm_rwc: ENOMEM\n");
            return -ENOMEM;
        }
    }

    aio_offset_list = g_malloc0(sizeof(uint64_t) * ln->params.max_sec_per_rq);
    if (!aio_offset_list) {
        printf("lnvm_rwc: ENOMEM\n");
        err = -ENOMEM;
        goto fail_free_copy_buf;
    }

    if (meta_size) {
        meta_buf = g_malloc0(meta_size * ln->params.max_sec_per_rq);
        if (!meta_buf) {
            printf("lnvm_rwc: ENOMEM\n");
            err = -ENOMEM;
            goto fail_free_aio_offset_list;
        }
    }

    if (lba_count > ln->params.max_sec_per_rq) {
        printf("nand_rule: lnvm_rwc: npages too large (%u). Max:%u supported\n",
               lba_count, ln->params.max_sec_per_rq);
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                            offsetof(LnvmRwcCmd, nlb), lbal, ns->id);
        bitmap_set((uint64_t *)&cqe->result, 0, ln->params.max_sec_per_rq);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_meta_buf;
    }

    if ((is_write || is_copy) && (lba_count < ln->params.sec_per_pg)) {
        printf("nand_rule: lnvm_rwc: I/O does not respect device write constrains."
               "Sectors send: (%u). Min:%u sectors required\n",
               lba_count, ln->params.sec_per_pg);
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                            offsetof(LnvmRwcCmd, nlb), lbal, ns->id);
        bitmap_set((uint64_t *)&cqe->result, 0, lba_count);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_meta_buf;
    }

    if (vector) {
        if (lba_count > 1 || is_copy) {
            nvme_addr_read(n, lbal, lba_list, lba_count * sizeof(uint64_t));
            if (is_copy) {
                nvme_addr_read(n, dlbal, dlba_list, lba_count * sizeof(uint64_t));
            }
        } else {
            lba_list[0] = lbal;
        }
    } else {
        for (i = 0; i < lba_count; i++) {
            lba_list[i] = lbal + i;
        }
    }

    if (meta && is_write) {
        nvme_addr_read(n, meta, meta_buf, meta_size);
    }

    for (i = 0; i < lba_count; i++) {
        uint64_t *lbas_to_read = lba_list;
        uint64_t *lbas_to_write = is_copy ? dlba_list : lba_list;

        if (is_write || is_copy) {
            // All (i.e. X=4) sectors within a plane must be written at once
            // thus a group of X sector must be properly aligned and have
            // consecutive addresses. Perform the check for the whole group upfront.
            if (i % ln->params.sec_per_pg == 0) {
                // First ensure there are still X LBAs on the list
                if (lba_count - i < ln->params.sec_per_pg) {
                    printf("nand_rule: lnvm_rwc: I/O does not respect device write constrains. "
                           "Sectors send: (%u) when multiple of %d is required.\n",
                           lba_count, ln->params.sec_per_pg);

                    bitmap_set((uint64_t *)&cqe->result, i, lba_count - i);
                    err = NVME_INVALID_FIELD | NVME_DNR;
                    goto fail_free_meta_buf;
                }

                // Check if the 1st LBA is aligned to sector boundary
                if ((lbas_to_write[i] & ln->ppaf.sec_mask) != 0) {
                    printf("nand_rule: lnvm_rwc: I/O set does not respect device write constrains. "
                           "LBA not aligned to to sector boundary: ");
                    lnvm_print_ppa(ln, lbas_to_read[i]);

                    bitmap_set((uint64_t *)&cqe->result, i, lba_count - i);
                    err = NVME_INVALID_FIELD | NVME_DNR;
                    goto fail_free_meta_buf;
                }

                // Finally check the continuousness
                for (j = 1; j < ln->params.sec_per_pg; j++) {
                    if (lbas_to_read[i] + j != lbas_to_read[i + j]) {
                        printf("nand_rule: lnvm_rwc: I/O set does not respect device write constrains. "
                               "Non-continuous group of LBAs detected at: ");
                        lnvm_print_ppa(ln, lbas_to_read[i + j]);

                        bitmap_set((uint64_t *)&cqe->result, i, lba_count - i);
                        err = NVME_INVALID_FIELD | NVME_DNR;
                        goto fail_free_meta_buf;
                    }
                }
            }
        }

        uint64_t lba_to_read = lbas_to_read[i];
        uint64_t lba_to_write = lbas_to_write[i];

        if (is_read || is_copy) {
            state = LNVM_SEC_ERASED;
            ret = lnvm_meta_state_get(ns, lba_to_read, &state, lnvm_meta_index(ns, meta_buf,
                                      i));

            if (LNVM_ER_DULBE(n->features.err_rec) && (ret || state != LNVM_SEC_WRITTEN)) {
                printf("lnvm_rwc: opcode %x failed: block is not written, ret(%d), state(%c) for ",
                       lrw->opcode, ret, state);
                lnvm_print_ppa(ln, lba_to_read);

                /* Copy what has been read from the OOB area */
                if (meta && is_read) {
                    nvme_addr_write(n, meta, meta_buf, meta_size);
                }

                bitmap_set((uint64_t *)&cqe->result, i, lba_count - i);
                err = NVME_DULB_ERROR;
                goto fail_free_meta_buf;
            }
        }

        if (is_write || is_copy) {
            ret = lnvm_meta_state_set(ns, lba_to_write, LNVM_SEC_WRITTEN,
                                      lnvm_meta_index(ns, meta_buf, i));
            if (ret) {
                printf("lnvm_rwc: set written + meta status failed with psl[%ld] = ", i);
                lnvm_print_ppa(ln, lba_to_write);

                bitmap_set((uint64_t *)&cqe->result, i, lba_count - i);
                err = ret;
                goto fail_free_meta_buf;
            }
            lnvm_set_chunk_state(ln, lba_to_write, LNVM_SEC_WRITTEN);
        }

        if (is_copy) {
            uint64_t sec_shift = lnvm_ns_get_data_size_shift(ns);
            uint64_t sec_len = 1 << sec_shift;
            uint64_t src_off = ns->start_block + (lnvm_ppa_to_sec_no(ln,
                                                                     lba_to_read) << sec_shift);
            uint64_t dst_off = ns->start_block + (lnvm_ppa_to_sec_no(ln,
                                                                     lba_to_write) << sec_shift);

            if ((blk_pread(n->conf.blk, src_off, copy_buf, sec_len) != sec_len) ||
                    (blk_pwrite(n->conf.blk, dst_off, copy_buf, sec_len, 0) != sec_len)) {
                printf("lnvm_rwc: data copy failed for psl[%ld] = ", i);
                lnvm_print_ppa(ln, lba_to_write);

                bitmap_set((uint64_t *)&cqe->result, i, lba_count - i);
                err = NVME_INVALID_FIELD | NVME_DNR;
                goto fail_free_meta_buf;
            }
        }
    }

    if (meta && is_read) {
        nvme_addr_write(n, meta, meta_buf, meta_size);
    }

    if (copy_buf) {
        g_free(copy_buf);
        copy_buf = NULL;
    }

    if (meta_buf) {
        g_free(meta_buf);
        meta_buf = NULL;
    }

    if (is_read || is_write) {
        if (nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, data_size, n)) {
            printf("lnvm_rwc: malformed prp (size:%lu), w:%d\n", data_size, is_write);
            for (i = 0; i < lba_count; i++) {
                lnvm_print_ppa(ln, lba_list[i]);
            }

            nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                                offsetof(NvmeRwCmd, prp1), 0, ns->id);
            err = NVME_INVALID_FIELD | NVME_DNR;
            goto fail_free_meta_buf;
        }
        req->has_sg = true;
    }

    req->slba = lba_list[0];
    req->meta_size = 0;
    req->status = NVME_SUCCESS;
    req->nlb = lba_count;
    req->ns = ns;
    req->is_write = is_write;

    if (is_read || is_write) {
        /* If several LUNs are set up, the ppa list sent by the host will not be
         * sequential. In this case, we need to pass on the list of ppas to the dma
         * handlers to write/read data to/from the right physical sector
         */
        for (i = 0; i < lba_count; i++) {
            aio_offset_list[i] = ns->start_block + (lnvm_ppa_to_sec_no(ln,
                                                                       lba_list[i]) << lnvm_ns_get_data_size_shift(ns));
        }

        dma_acct_start(n->conf.blk, &req->acct, &req->qsg, req->is_write ?
                       BLOCK_ACCT_WRITE : BLOCK_ACCT_READ);
        if (req->qsg.nsg > 0) {
            req->aiocb = req->is_write ?
                         dma_blk_write_list(n->conf.blk, &req->qsg, aio_offset_list,
                                            1 << lnvm_ns_get_data_size_shift(ns), BDRV_SECTOR_SIZE,
                                            nvme_rw_cb, req) :
                         dma_blk_read_list(n->conf.blk, &req->qsg, aio_offset_list,
                                           1 << lnvm_ns_get_data_size_shift(ns), BDRV_SECTOR_SIZE,
                                           nvme_rw_cb, req);
        } else {
            uint64_t aio_offset = aio_offset_list[0];

            req->aiocb = req->is_write ?
                         blk_aio_pwritev(n->conf.blk, aio_offset, &req->iov, 0, nvme_rw_cb, req) :
                         blk_aio_preadv(n->conf.blk, aio_offset, &req->iov, 0, nvme_rw_cb, req);

            g_free(aio_offset_list);
        }
    } else {
        /* In case of the copy command everything is already finished.
         * Call the ending callback manually. */
        g_free(aio_offset_list);
        nvme_rw_cb(req, 0);
    }

    return NVME_NO_COMPLETE;

fail_free_meta_buf:
    if (meta_buf) {
        g_free(meta_buf);
    }
fail_free_aio_offset_list:
    g_free(aio_offset_list);
fail_free_copy_buf:
    if (copy_buf) {
        g_free(copy_buf);
    }
    return err;
}

static uint16_t lnvm_identify(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeIdentify *c = (NvmeIdentify *)cmd;
    uint32_t nsid = le32_to_cpu(c->nsid);
    uint64_t prp1 = le64_to_cpu(c->prp1);
    uint64_t prp2 = le64_to_cpu(c->prp2);

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    return nvme_dma_read_prp(n, (uint8_t *)&n->lnvm_ctrl.id_ctrl,
                             sizeof(LnvmIdCtrl), prp1, prp2);
}

static uint16_t lnvm_chnks_report(NvmeCtrl *n, NvmeCmd *cmd)
{
    LnvmCtrl *ln;
    NvmeGetLogPage *get_log_page_cmd = (NvmeGetLogPage *)cmd;

    uint32_t nsid = le32_to_cpu(get_log_page_cmd->nsid);
    uint64_t prp1 = le64_to_cpu(get_log_page_cmd->prp1);
    uint64_t prp2 = le64_to_cpu(get_log_page_cmd->prp2);
    uint32_t transfer_size = le32_to_cpu(get_log_page_cmd->numdu << 16 |
                                         get_log_page_cmd->numdl);
    uint64_t offset = le64_to_cpu((uint64_t)get_log_page_cmd->lpou << 32 |
                                  get_log_page_cmd->lpol);
    uint64_t schunk;
    uint64_t chunks_no;

    // convert 0-based number of dwords to transfer
    transfer_size = (transfer_size + 1) << 2;

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ln = &n->lnvm_ctrl;

    schunk = offset / sizeof(LnvmChnkDesc);
    chunks_no = transfer_size / sizeof(LnvmChnkDesc);

    if (schunk + chunks_no > ln->params.chunks_no) {
        return NVME_LBA_RANGE;
    }

    if (nvme_dma_read_prp(n, (uint8_t *)ln->chunk_state + offset,
                          transfer_size, prp1, prp2)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static void lnvm_erase_io_complete_cb(void *opaque, int ret)
{
    NvmeRequest *req = opaque;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    block_acct_done(blk_get_stats(n->conf.blk), &req->acct);
    if (!ret) {
        req->status = NVME_SUCCESS;
    } else {
        req->status = LNVM_WR_PROG_FAIL;
    }

    nvme_enqueue_req_completion(cq, req);
}

static uint16_t lnvm_dsm(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                         NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint64_t prp1 = le64_to_cpu(cmd->prp1);
    uint64_t prp2 = le64_to_cpu(cmd->prp2);
    LnvmCtrl *ln = &n->lnvm_ctrl;

    if (dw11 & NVME_DSMGMT_AD) {
        uint16_t nr = (dw10 & 0xff) + 1;

        int i;
        uint64_t slba;
        uint32_t nlb;
        NvmeDsmRange range[nr];

        if (nvme_dma_write_prp(n, (uint8_t *)range, sizeof(range), prp1, prp2)) {
            nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                                offsetof(NvmeCmd, prp1), 0, ns->id);
            return NVME_INVALID_FIELD | NVME_DNR;
        }

        req->status = NVME_SUCCESS;
        for (i = 0; i < nr; i++) {
            uint64_t start_chunk;
            slba = le64_to_cpu(range[i].slba);
            nlb = le32_to_cpu(range[i].nlb);
            start_chunk = (slba & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;

            if (start_chunk + nlb > ln->params.blks_per_pln) {
                nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                                    offsetof(NvmeCmd, cdw10), slba + nlb, ns->id);
                return NVME_LBA_RANGE | NVME_DNR;
            }

            if (lnvm_set_chunk_state_persistent(ns, ln, &slba, nlb,
                                                (uint64_t *)&req->cqe.result, LNVM_SEC_ERASED, true)) {
                printf("lnvm_vector_erase: failed: ");
                lnvm_print_ppa(ln, slba);
                req->status = LNVM_WR_PROG_FAIL;
                return NVME_INVALID_FIELD | NVME_DNR;
            }

            if (req->status != NVME_SUCCESS) {
                return req->status;
            }
        }
        return NVME_SUCCESS;
    } else {
        return NVME_INVALID_FIELD;
    }
}

static uint16_t lnvm_vector_erase(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                                  NvmeRequest *req)
{
    LnvmCtrl *ln = &n->lnvm_ctrl;
    LnvmRwcCmd *dm = (LnvmRwcCmd *)cmd;
    uint64_t lbal = le64_to_cpu(dm->lbal);
    uint64_t psl[ln->params.max_sec_per_rq];
    uint32_t nlb = le16_to_cpu(dm->nlb) + 1;

    if (nlb > 1) {
        nvme_addr_read(n, lbal, (void *)psl, nlb * sizeof(uint64_t));
    } else {
        psl[0] = lbal;
    }

    req->slba = lbal;
    req->meta_size = 0;
    req->status = NVME_SUCCESS;
    req->nlb = nlb;
    req->ns = ns;

    if (lnvm_set_chunk_state_persistent(ns, ln, psl, nlb, (uint64_t *)&req->cqe.result,
                                        LNVM_SEC_ERASED, false)) {
        printf("lnvm_vector_erase: failed: ");
        lnvm_print_ppa(ln, psl[0]);
        req->status = LNVM_WR_PROG_FAIL;

        return NVME_INVALID_FIELD | NVME_DNR;
    }

    lnvm_erase_io_complete_cb(req, 0);
    return NVME_NO_COMPLETE;
}

static uint16_t lnvm_chnks_notification(NvmeCtrl *n, NvmeCmd *cmd,
                                               uint32_t buf_len)
{
    uint32_t cnt = buf_len / sizeof(LnvmChunksNotiEntry);
    uint64_t prp1 = le64_to_cpu(cmd->prp1);
    uint64_t prp2 = le64_to_cpu(cmd->prp2);
    LnvmChunksNoti *td = &n->lnvm_ctrl.te_data;
    uint32_t i, j;
    uint16_t status;
    LnvmChunksNotiEntry *log = NULL;

    if (!cnt) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    log = calloc(cnt, sizeof(LnvmChunksNotiEntry));
    if (!log) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    qemu_mutex_lock(&td->events_mutex);
    for (i = 0; i < cnt; i++) {
	j = td->j;
	if (td->n == 0) {
            break;
	}
	td->j = (td->j + 1) % LNVM_MAX_CHNK_NOTI;
	td->n--;
        if (td->events[j].notification_count == 0) {
            continue;
	}
        log[i].notification_count = cpu_to_le64(td->events[j].notification_count);
        log[i].ppa_addr = cpu_to_le64(td->events[j].ppa_addr);
        log[i].nsid     = cpu_to_le32(td->events[j].nsid);
        log[i].state = cpu_to_le16(td->events[j].state);
        log[i].mask    = td->events[j].mask;
        log[i].nlb   = cpu_to_le16(td->events[j].nlb);
        memset(&td->events[j], 0, sizeof(LnvmChunksNotiEntry));
    }
    qemu_mutex_unlock(&td->events_mutex);

    n->aer_mask &= ~(1 << NVME_AER_TYPE_VENDOR_SPECIFIC);
    if (!QSIMPLEQ_EMPTY(&n->aer_queue)) {
        timer_mod(n->aer_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
    }

    status = nvme_dma_read_prp(n, (void *)log, cnt * sizeof(LnvmChunksNotiEntry), prp1, prp2);
    free(log);
    return status;
}

static void lnvm_init_id_ppaf(LnvmCtrl *ln)
{

    /* We devide the address space linearly to be able to fit into the 4KB
     * sectors that the nvme driver divides the backend file. We do the
     * division in LUNS - BLOCKS - PLANES - PAGES - SECTORS.
     *
     * For example a quad plane configuration is layed out as:
     * -----------------------------------------------------------
     * |                        QUAD PLANE                       |
     * -------------- -------------- -------------- --------------
     * |   LUN 00   | |   LUN 01   | |   LUN 02   | |   LUN 03   |
     * -------------- -------------- -------------- --------------
     * |   BLOCKS            |          ...          |   BLOCKS  |
     * ----------------------
     * |   PLANES   |              ...               |   PLANES  |
     * -------------                                 -------------
     * | PAGES |                 ...                 |   PAGES   |
     * -----------------------------------------------------------
     * |                        ALL SECTORS                      |
     * -----------------------------------------------------------
     */

    ln->ppaf.sec_offset = 0;
    ln->ppaf.sec_len = nvme_qemu_fls(cpu_to_le16(ln->params.sec_per_pg) - 1);

    ln->ppaf.pln_offset = ln->ppaf.sec_offset + ln->ppaf.sec_len;
    ln->ppaf.pln_len = nvme_qemu_fls(cpu_to_le16(ln->params.num_pln) - 1);

    ln->ppaf.pg_offset = ln->ppaf.pln_offset + ln->ppaf.pln_len;
    ln->ppaf.pg_len = nvme_qemu_fls(cpu_to_le16(ln->params.pgs_per_blk) - 1);

    ln->ppaf.blk_offset = ln->ppaf.pg_offset + ln->ppaf.pg_len;
    ln->ppaf.blk_len = nvme_qemu_fls(cpu_to_le16(ln->params.blks_per_pln) - 1);

    ln->ppaf.lun_offset = ln->ppaf.blk_offset + ln->ppaf.blk_len;
    ln->ppaf.lun_len = nvme_qemu_fls(cpu_to_le16(ln->params.num_lun) - 1);

    ln->ppaf.ch_offset = ln->ppaf.lun_offset + ln->ppaf.lun_len;
    ln->ppaf.ch_len = nvme_qemu_fls(cpu_to_le16(ln->params.num_ch) - 1);

    /* Calculated values */
    ln->params.ppa_secs_per_pl = ln->params.sec_per_pg;
    ln->params.ppa_secs_per_pg = ln->params.ppa_secs_per_pl * ln->params.num_pln;
    ln->params.ppa_secs_per_blk = ln->params.ppa_secs_per_pg *
                                  ln->params.pgs_per_blk;
    ln->params.ppa_secs_per_lun = ln->params.ppa_secs_per_blk *
                                  ln->params.blks_per_pln;
    ln->params.ppa_secs_total = ln->params.ppa_secs_per_lun * ln->params.num_lun;
    ln->params.chunks_no = ln->params.num_ch * ln->params.num_lun
                           * ln->params.blks_per_pln;

    /* Address component selection MASK */
    ln->ppaf.sec_mask = ((1 << ln->ppaf.sec_len) - 1) <<
                        ln->ppaf.sec_offset;
    ln->ppaf.pln_mask = ((1 << ln->ppaf.pln_len) - 1) <<
                        ln->ppaf.pln_offset;
    ln->ppaf.pg_mask = ((1 << ln->ppaf.pg_len) - 1) <<
                       ln->ppaf.pg_offset;
    ln->ppaf.blk_mask = ((1 << ln->ppaf.blk_len) - 1) <<
                        ln->ppaf.blk_offset;
    ln->ppaf.lun_mask = ((1 << ln->ppaf.lun_len) - 1) <<
                        ln->ppaf.lun_offset;
    ln->ppaf.ch_mask = ((1 << ln->ppaf.ch_len) - 1) <<
                       ln->ppaf.ch_offset;
}

static size_t lnvm_get_meta_per_sector(NvmeCtrl *n)
{
    return sizeof(LnvmInternalMeta) + lnvm_ns_get_meta_size(
                                       &n->namespaces[0]);
}

static size_t lnvm_get_total_meta_size(NvmeCtrl *n)
{
    return lnvm_get_meta_per_sector(n) * n->lnvm_ctrl.params.ppa_secs_total;
}

static int lnvm_init_meta(NvmeCtrl *n)
{
    // The code as is won't work with multiple namespaces. Since it's unusual
    // for OCSSDs, we should be OK for now.
    if (n->num_namespaces != 1) {
        printf("nvme: lnvm_init_meta: multiple namespaces not supported\n");
        return -1;
    }

    // Meta is stored per PPA sector and consist of two parts:
    // - internal meta (erased/written state managed by qemu)
    // - user-accesible meta (size defined by the active LBA format)
    LnvmCtrl *ln = &n->lnvm_ctrl;
    const size_t meta_per_sector = lnvm_get_meta_per_sector(n);

    // Create meta-data file when it is empty or invalid
    if (ftruncate(fileno(n->metadata_fp), 0)) {
        printf("nvme: lnvm_init_meta: ftruncate\n");
        return -1;
    }

    char *sector_meta = (char *)calloc(1, meta_per_sector);
    if (!sector_meta) {
        printf("nvme: lnvm_init_meta: malloc\n");
        return -ENOMEM;
    }

    ((LnvmInternalMeta *)sector_meta)->state = LNVM_SEC_ERASED;

    int i;
    for (i = 0; i < ln->params.ppa_secs_total; i++) {
        size_t written = fwrite(sector_meta, 1, meta_per_sector, n->metadata_fp);
        if (written != meta_per_sector) {
            printf("nvme: lnvm_init_meta: fwrite\n");
            return -EIO;
        }
    }

    free(sector_meta);

    return 0;
}

static int lnvm_init_chunk_state(NvmeCtrl *n)
{
    // The code as is won't work with multiple namespaces. Since it's unusual
    // for OCSSDs, we should be OK for now.
    if (n->num_namespaces != 1) {
        printf("nvme: lnvm_init_meta: multiple namespaces not supported\n");
        return -1;
    }
    NvmeNamespace *ns = &n->namespaces[0];
    LnvmCtrl *ln = &n->lnvm_ctrl;
    size_t total_chunks = ln->params.num_ch * ln->params.num_lun *
                          ln->params.blks_per_pln;
    size_t meta_len = sizeof(LnvmInternalMeta) + lnvm_ns_get_meta_size(
                          &n->namespaces[0]);
    size_t sec_per_chunk = ln->params.sec_per_pg * ln->params.num_pln *
                           ln->params.pgs_per_blk;
    size_t read_metas;
    bool found_erased;
    size_t written, i, j;
    uint64_t ppa;

    uint8_t *meta_buf = malloc(meta_len * sec_per_chunk);
    if (!meta_buf) {
        return -1;
    }

    ln->chunk_state = malloc(total_chunks * sizeof(LnvmChnkDesc));
    if (!ln->chunk_state) {
        free(meta_buf);
        return -1;
    }

    fseek(n->metadata_fp, 0, SEEK_SET);

    for (i = 0; i < total_chunks; i++) {
        read_metas = fread(meta_buf, meta_len, sec_per_chunk, n->metadata_fp);
        if (read_metas != sec_per_chunk) {
            printf("Invalid size of the meta file\n");

            free(meta_buf);
            free(ln->chunk_state);
            ln->chunk_state = NULL;
            return -1;
        }

        found_erased = false;
        written = 0;

        for (j = 0; j < sec_per_chunk; j++) {
            switch (*(uint32_t *)(meta_buf + j * meta_len)) {
            case LNVM_SEC_WRITTEN:
                written ++;
                break;
            case LNVM_SEC_ERASED:
                found_erased = true;
                break;
            default:
                break;
            }
        }

        ppa = i << ln->ppaf.blk_offset;
        if (written == sec_per_chunk) {
            ln->chunk_state[i].state = LNVM_CHNK_FULL;
        } else if (written != 0) {
            ln->chunk_state[i].state = LNVM_CHNK_OPEN;
        } else if (found_erased && written == 0) {
            ln->chunk_state[i].state = LNVM_CHNK_FREE;
        } else {
            /* Error case - need to update metadata file */
            lnvm_set_chunk_state_persistent(ns, ln, &ppa, 1, NULL, LNVM_SEC_BAD,
                                            false);
        }
        ln->chunk_state[i].type = LNVM_CHNK_SEQ;
        ln->chunk_state[i].wli = 0;
        ln->chunk_state[i].slba = ppa;
        ln->chunk_state[i].cnlb = sec_per_chunk;
        ln->chunk_state[i].wplba = 0;
        if (ln->chunk_state[i].state == LNVM_CHNK_OPEN) {
            ln->chunk_state[i].wplba = written;
        } else if (ln->chunk_state[i].state == LNVM_CHNK_FULL) {
            ln->chunk_state[i].wplba = ppa + sec_per_chunk;
        }
    }

    free(meta_buf);
    return 0;
}

static int lnvm_init(NvmeCtrl *n)
{
    LnvmCtrl *ln;
    NvmeNamespace *ns;
    unsigned int i;
    uint64_t chnl_blks;

    ln = &n->lnvm_ctrl;

    if (ln->params.num_ch != 1) {
        printf("nvme: Only 1 channel is supported at the moment\n");
    }
    if ((ln->params.num_pln > 4) || (ln->params.num_pln == 3)) {
        printf("nvme: Only single, dual and quad plane modes supported \n");
    }

    for (i = 0; i < n->num_namespaces; i++) {
        ns = &n->namespaces[i];

        //Count how many blks per pln we can fit into file
        chnl_blks = ns->ns_blks / (ln->params.sec_per_pg * ln->params.pgs_per_blk);
        chnl_blks = chnl_blks / (ln->params.num_lun * ln->params.num_pln);

        if (chnl_blks < ln->params.blks_per_pln) {
            printf("Too small data file\n");
            return -EINVAL;
        }

        memset(&ln->id_ctrl.resv1[0], 0, sizeof(uint8_t) * 6);
        memset(&ln->id_ctrl.resv2[0], 0, sizeof(uint8_t) * 44);
        ln->id_ctrl.mccap = 0x01;   // Vector Copy is supported
        ln->id_ctrl.min_id = 0;

        ln->id_ctrl.lbaf.ch_bit_len = nvme_qemu_fls(ln->params.num_ch - 1);
        ln->id_ctrl.lbaf.lun_bit_len = nvme_qemu_fls(ln->params.num_lun - 1);
        ln->id_ctrl.lbaf.chunk_bit_len = nvme_qemu_fls(ln->params.blks_per_pln - 1);
        ln->id_ctrl.lbaf.sector_bit_len = nvme_qemu_fls(ln->params.num_pln - 1) +
                                          nvme_qemu_fls(ln->params.pgs_per_blk - 1) + nvme_qemu_fls(
                                              ln->params.sec_per_pg - 1);
        memset(&ln->id_ctrl.lbaf.resv[0], 0, sizeof(uint8_t) * 4);

        ln->id_ctrl.geo.num_ch = ln->params.num_ch;
        ln->id_ctrl.geo.num_lun = ln->params.num_lun;
        ln->id_ctrl.geo.num_chnks = ln->params.blks_per_pln;
        ln->id_ctrl.geo.clba = ln->params.num_pln * ln->params.pgs_per_blk *
                                   ln->params.sec_per_pg;
        ln->id_ctrl.geo.csecs = ln->params.sec_size;
        ln->id_ctrl.geo.sos = lnvm_ns_get_meta_size(ns);
        memset(&ln->id_ctrl.geo.resv, 0, sizeof(uint8_t) * 44);

        ln->id_ctrl.wrt.mw_min = ln->params.sec_per_pg * ln->params.ws_factor;
        ln->id_ctrl.wrt.mw_opt = ln->id_ctrl.wrt.mw_min * ln->params.num_pln;
        ln->id_ctrl.wrt.mw_cunits = ln->id_ctrl.wrt.mw_opt * ln->params.cu_factor;
        memset(&ln->id_ctrl.wrt.resv[0], 0, sizeof(uint8_t) * 52);

        ln->id_ctrl.perf.trdt = 1000;
        ln->id_ctrl.perf.trdm = 1000;
        ln->id_ctrl.perf.tprt = 1000;
        ln->id_ctrl.perf.tprm = 1000;
        ln->id_ctrl.perf.tbet = 1000000;
        ln->id_ctrl.perf.tbem = 1000000;
        memset(&ln->id_ctrl.wrt.resv[0], 0, sizeof(uint8_t) * 40);

        lnvm_init_id_ppaf(ln);
    }

    lnvm_te_init(n);

    return 0;
}

static void lnvm_exit(NvmeCtrl *n)
{
    LnvmCtrl *ln = &n->lnvm_ctrl;

    lnvm_te_exit(n);

    free(ln->chunk_state);
}
#endif /* HW_NVME_LNVM_STRUCTS_H */

