/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006-2016 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2013-2017 Intel Corp., Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

//#include <rdma/fi_errno.h>
#include <rdma/fi_sched.h>
#include <rdma/fi_tagged.h>

/***********************************************/
/* Schedule op implementation via pt2pt tagged */
/***********************************************/

/* General Finite State Machine for a schedule */

#define CASE(label, action) \
    case label: \
        do { \
            action; \
        } while(0); \
        break

#define HANDLE_RET(handler) \
    do { \
        int ret = handler; \
        if (ret) \
            return ret; \
    } while(0)

#define SWITCH_CASE_ELEMENT(current_op, hnop, hcopy, hsend, hrecv, hsendrecv, hsend_red, hrecv_red, hsendrecv_red) \
    do { \
        switch((current_op)->u.element->code) { \
            CASE(FI_SCHED_OP_ELEMENT_CODE_NOP, hnop); \
            CASE(FI_SCHED_OP_ELEMENT_CODE_COPY, hcopy); \
            CASE(FI_SCHED_OP_ELEMENT_CODE_SEND, hsend); \
            CASE(FI_SCHED_OP_ELEMENT_CODE_RECV, hrecv); \
            CASE(FI_SCHED_OP_ELEMENT_CODE_SENDRECV, hsendrecv); \
            CASE(FI_SCHED_OP_ELEMENT_CODE_SEND_RED, hsend_red); \
            CASE(FI_SCHED_OP_ELEMENT_CODE_RECV_RED, hrecv_red); \
            CASE(FI_SCHED_OP_ELEMENT_CODE_SENDRECV_RED, hsendrecv_red); \
        } \
    } while(0)

#define SWITCH_CASE_OP(current_op, helement, harray, hlist) \
    do { \
        switch((current_op)->code) { \
            CASE(FI_SCHED_OP_CODE_ELEMENT, helement); \
            CASE(FI_SCHED_OP_CODE_ARRAY, harray); \
            CASE(FI_SCHED_OP_CODE_LIST, hlist); \
        } \
    } while(0)

#define SWITCH_CASE(current_op, nested_op, helement, nested_harray, nested_hlist, check) \
    SWITCH_CASE_OP(current_op, \
                   helement, \
                   int i; \
                   for (i = 0; i < (current_op)->u.array->nop; i++) { \
                       struct fi_sched_op * nested_op = (current_op)->u.array->op[i]; \
                       size_t ic = FI_SCHED_IC(nested_op); \
                       size_t cc = FI_SCHED_CC(nested_op); \
                       nested_harray; \
                       FI_SCHED_IC(current_op) += (FI_SCHED_IC(nested_op) - ic); \
                       FI_SCHED_CC(current_op) += (FI_SCHED_CC(nested_op) - cc); \
                   }, \
                   struct fi_sched_op_list * l; \
                   for (l = (current_op)->u.list; l; l = l->next) { \
                       struct fi_sched_op * nested_op = l->op; \
                       size_t ic = FI_SCHED_IC(nested_op); \
                       size_t cc = FI_SCHED_CC(nested_op); \
                       nested_hlist; \
                       FI_SCHED_IC(current_op) += (FI_SCHED_IC(nested_op) - ic); \
                       FI_SCHED_CC(current_op) += (FI_SCHED_CC(nested_op) - cc); \
                       if ((check) && FI_SCHED_CC(nested_op) < FI_SCHED_OC(nested_op)) break; \
                   })

/* pt2pt operation handlers */

#define CALL(call) while (-FI_EAGAIN == call)

#define BUF(hbuf, i, offset) ((hbuf) ? (char *)((hbuf)[i].u.ptr) + (offset) : NULL)
#define CNT(flags, hbuf, i, loc_size) ((flags) & FI_SCHED_FLAG_UNIQUE_COUNTS ? (loc_size) : ((hbuf) ? (hbuf)[i].size : 0))

#define COPY(header, op, kind) \
    fi_sched_op_copy(header, op, &op->u.element->u.kind->dst_buf, &op->u.element->u.kind->src_buf)

static inline int
fi_sched_op_copy(struct fi_sched_header *header, struct fi_sched_op *op,
        struct fi_sched_buf *dst_buf, struct fi_sched_buf *src_buf) {
    void *dst = BUF(header->buf, dst_buf->u.index, dst_buf->offset);
    void *src = BUF(header->buf, src_buf->u.index, src_buf->offset);
    size_t len = CNT(header->flags, header->buf, src_buf->u.index, src_buf->size);
    memcpy(dst, src, len);
    FI_SCHED_IC(op)++;
    FI_SCHED_CC(op)++;
    return 0;
}

#define UPDATE(dst, src, len, type, op) \
    do { \
        size_t _i; \
        for (_i = 0; _i < (len)/sizeof(type); _i++) \
            ((type *)(dst))[_i] op ((type *)(src))[_i]; \
    } while (0)

#define RED(header, op, kind) \
    fi_sched_op_red(header, op, &op->u.element->u.kind->dst_buf, &op->u.element->u.kind->tmp_buf)

static inline int
fi_sched_op_red(struct fi_sched_header *header, struct fi_sched_op *op,
        struct fi_sched_buf *dst_buf, struct fi_sched_buf *src_buf) {
    void *dst = BUF(header->buf, dst_buf->u.index, dst_buf->offset);
    void *src = BUF(header->buf, src_buf->u.index, src_buf->offset);
    size_t len = CNT(header->flags, header->buf, src_buf->u.index, src_buf->size);
    switch (header->op) {
        CASE(FI_SCHED_RED_CODE_SUM, 
                switch (header->type) {
                    CASE(FI_SCHED_TYPE_CODE_DOUBLE, UPDATE(dst, src, len, double, +=));
                    CASE(FI_SCHED_TYPE_CODE_FLOAT, UPDATE(dst, src, len, float, +=));
                    CASE(FI_SCHED_TYPE_CODE_INT, UPDATE(dst, src, len, int, +=));
                    CASE(FI_SCHED_TYPE_CODE_CHAR, UPDATE(dst, src, len, char, +=));
                });
    }
    return 0;
}

#define SEND(header, op, kind) \
    fi_sched_op_send(header, op, &op->u.element->u.kind->src_buf, op->u.element->u.kind->dst)

static inline int
fi_sched_op_send(struct fi_sched_header *header, struct fi_sched_op *op, struct fi_sched_buf *buf, size_t dst)
{
    CALL(fi_tsend(header->tx[0].ep,
                  BUF(header->buf, buf->u.index, buf->offset),
                  CNT(header->flags, header->buf, buf->u.index, buf->size),
                  NULL,
                  header->addr[dst],
                  header->match_bits | header->rank,
                  FI_SCHED_CTX(op)));
    FI_SCHED_IC(op)++;
    return 0;
}

#define RECV_RED(header, op, kind) \
    fi_sched_op_recv(header, op, &op->u.element->u.kind->tmp_buf, op->u.element->u.kind->src)
#define RECV(header, op, kind) \
    fi_sched_op_recv(header, op, &op->u.element->u.kind->dst_buf, op->u.element->u.kind->src)

static inline int
fi_sched_op_recv(struct fi_sched_header *header, struct fi_sched_op *op, struct fi_sched_buf *buf, size_t src)
{
    CALL(fi_trecv(header->rx[0].ep,
                  BUF(header->buf, buf->u.index, buf->offset),
                  CNT(header->flags, header->buf, buf->u.index, buf->size),
                  NULL,
                  header->addr[src],
                  header->match_bits | src,
                  0,
                  FI_SCHED_CTX(op)));
    FI_SCHED_IC(op)++;
    return 0;
}

/* Issue the schedule */
/* Return value:
 * 0 - normal return code, op is scheduled
 * <0 - error code
 */

static inline int
fi_sched_issue_internal(struct fi_sched_header *header, struct fi_sched_op *op)
{
    if (FI_SCHED_IC(op) >= FI_SCHED_OC(op))
        return 0;
    SWITCH_CASE(op, nested_op,
                SWITCH_CASE_ELEMENT(op,
                                    , /* hnop */
                                    COPY(header, op, copy), /* hcopy */
                                    SEND(header, op, send), /* hsend */
                                    RECV(header, op, recv), /* hrecv */
                                    RECV(header, op, sendrecv);
                                    SEND(header, op, sendrecv), /* hsendrecv */
                                    SEND(header, op, send_red), /* hsend_red */
                                    RECV_RED(header, op, recv_red), /* hrecv_red */
                                    RECV_RED(header, op, sendrecv_red);
                                    SEND(header, op, sendrecv_red) /* hsendrecv_red */
                                   ),
                fi_sched_issue_internal(header, nested_op), /* harray */
                fi_sched_issue_internal(header, nested_op), /* hlist */
                1 /* check */
               );
    return 0;
}

int
fi_sched_issue(struct fi_sched *sched)
{
    /* TODO: clear the op issue & completion count */
    return fi_sched_issue_internal(sched->header, sched->op);
}

/* Progress the schedule */
/* Return value:
 * >0 - number of completion events caught not related to the schedule,
 *      'buf' contains completion queue events as if read with 'fi_cq_read',
 *      '*completion_flag' indicates the schedule completion
 * 0 - normal return code,
 *      '*completion_flag' indicates the schedule completion
 * <0 - error code
 */


/* TODO multiple cq, multiple count */
#define WAIT(header, buf, count, blocking) fi_sched_op_wait(header, buf, count, blocking)

static inline int
fi_sched_op_wait(struct fi_sched_header *header, void *buf, size_t count, int blocking)
{
    while (1) {
        int ret = fi_cq_read(header->rx[0].cq, buf, 1);
        if (ret != -FI_EAGAIN || !blocking)
            return ret;
    }
    return 0;
}

/*
 * ctx is fi_cq_entry.op_context
 * check if this operation matches this completion context
 */
static inline void
fi_sched_check_completion(struct fi_sched_header *header, struct fi_sched_op *op, void *ctx)
{
    if (FI_SCHED_CC(op) >= FI_SCHED_IC(op))
        return;
    SWITCH_CASE(op, nested_op,
                if (ctx == FI_SCHED_CTX(op))
                    FI_SCHED_CC(op)++;
                if (FI_SCHED_CC(op) >= FI_SCHED_OC(op)) {
                    if (op->u.element->code == FI_SCHED_OP_ELEMENT_CODE_RECV_RED)
                        RED(header, op, recv_red);
                    else if (op->u.element->code == FI_SCHED_OP_ELEMENT_CODE_SENDRECV_RED)
                        RED(header, op, sendrecv_red);
                }, /* helement */
                fi_sched_check_completion(header, nested_op, ctx), /* harray */
                fi_sched_check_completion(header, nested_op, ctx), /* hlist */
                1 /* check */
               );
}

static inline int
fi_sched_progress_internal(struct fi_sched_header *header, struct fi_sched_op *op,
        void *buf, size_t count, int blocking)
{
    size_t cc;
    int is_list = op->code == FI_SCHED_OP_CODE_LIST;
    while ((cc = FI_SCHED_CC(op)) < FI_SCHED_OC(op)) {
        int ret = 0;
        void *ctx = NULL;
        if (!is_list) {
            if ((ret = WAIT(header, buf, count, blocking)) < 1)
                return ret; /* no schedule-related events */
            ctx = ((struct fi_cq_entry *)buf)->op_context;
        }
        SWITCH_CASE(op, nested_op,
                    fi_sched_check_completion(header, op, ctx), /* helement */
                    fi_sched_check_completion(header, nested_op, ctx), /* harray */
                    fi_sched_issue_internal(header, nested_op);
                    ret = fi_sched_progress_internal(header, nested_op, buf, count, blocking), /* hlist */
                    1 /* check */
                   );
        if (FI_SCHED_CC(op) == cc)
            return ret; /* no schedule-related completions */
    }
    return -FI_EAGAIN; /* op is completed, no other events pending */
}

int
fi_sched_wait(struct fi_sched *sched, void *buf, size_t count, int *completion_flag)
{
    int ret = fi_sched_progress_internal(sched->header, sched->op, buf, count, 1);
    *completion_flag = FI_SCHED_CC(sched->op) >= FI_SCHED_OC(sched->op);
    return ret;
}

int
fi_sched_test(struct fi_sched *sched, void *buf, size_t count, int *completion_flag)
{
    int ret = fi_sched_progress_internal(sched->header, sched->op, buf, count, 0);
    *completion_flag = FI_SCHED_CC(sched->op) >= FI_SCHED_OC(sched->op);
    return ret;
}

/*****************************/
/* Schedule helper functions */
/*****************************/

#define RESERVE_SPACE(buf, type, count, space) \
    type *buf = (type *)(space)->ptr; \
    do { \
        size_t _s = sizeof(type)*count; \
        assert(_s < (space)->left); \
        memset((space)->ptr, 0, _s); \
        (space)->left -= _s; \
        (space)->used += _s; \
        (space)->ptr += _s; \
    } while (0)

struct fi_sched_op *
fi_sched_op_create(struct fi_sched_space *space, uint64_t flags, enum fi_sched_op_code code, ...)
{
    va_list op_arg;
    va_start(op_arg, code);
    RESERVE_SPACE(op, struct fi_sched_op, 1, space);
    FI_SCHED_OC(op) = 0;
    op->code = code;
    SWITCH_CASE_OP(op,
            /* element op */
            RESERVE_SPACE(uop, struct fi_sched_op_element, 1, space);
            uop->code = va_arg(op_arg, enum fi_sched_op_element_code);
            op->u.element = uop;
            SWITCH_CASE_ELEMENT(op,
                RESERVE_SPACE(eop, struct fi_sched_op_element_nop, 1, space);
                uop->u.nop = eop,

                FI_SCHED_OC(op) = 1;
                RESERVE_SPACE(eop, struct fi_sched_op_element_copy, 1, space);
                if (flags & FI_SCHED_FLAG_MULTIPLE_BUFFERS)
                    eop->dst_buf.u.index = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->dst_buf.offset = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->dst_buf.size = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_MULTIPLE_BUFFERS)
                    eop->src_buf.u.index = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->src_buf.offset = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->src_buf.size = va_arg(op_arg, size_t);
                uop->u.copy = eop,

                FI_SCHED_OC(op) = 1;
                RESERVE_SPACE(eop, struct fi_sched_op_element_send, 1, space);
                eop->dst = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_MULTIPLE_BUFFERS)
                    eop->src_buf.u.index = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->src_buf.offset = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->src_buf.size = va_arg(op_arg, size_t);
                uop->u.send = eop,

                FI_SCHED_OC(op) = 1;
                RESERVE_SPACE(eop, struct fi_sched_op_element_recv, 1, space);
                eop->src = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_MULTIPLE_BUFFERS)
                    eop->dst_buf.u.index = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->dst_buf.offset = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->dst_buf.size = va_arg(op_arg, size_t);
                uop->u.recv = eop,

                FI_SCHED_OC(op) = 2;
                RESERVE_SPACE(eop, struct fi_sched_op_element_sendrecv, 1, space);
                eop->dst = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_MULTIPLE_BUFFERS)
                    eop->src_buf.u.index = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->src_buf.offset = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->src_buf.size = va_arg(op_arg, size_t);
                eop->src = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_MULTIPLE_BUFFERS)
                    eop->dst_buf.u.index = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->dst_buf.offset = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->dst_buf.size = va_arg(op_arg, size_t);
                uop->u.sendrecv = eop,

                FI_SCHED_OC(op) = 1;
                RESERVE_SPACE(eop, struct fi_sched_op_element_send_red, 1, space);
                eop->dst = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_MULTIPLE_BUFFERS)
                    eop->src_buf.u.index = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->src_buf.offset = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->src_buf.size = va_arg(op_arg, size_t);
                uop->u.send_red = eop,

                FI_SCHED_OC(op) = 1;
                RESERVE_SPACE(eop, struct fi_sched_op_element_recv_red, 1, space);
                eop->src = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_MULTIPLE_BUFFERS)
                    eop->dst_buf.u.index = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->dst_buf.offset = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->dst_buf.size = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_MULTIPLE_BUFFERS)
                    eop->tmp_buf.u.index = va_arg(op_arg, size_t);
                uop->u.recv_red = eop,

                FI_SCHED_OC(op) = 2;
                RESERVE_SPACE(eop, struct fi_sched_op_element_sendrecv_red, 1, space);
                eop->dst = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_MULTIPLE_BUFFERS)
                    eop->src_buf.u.index = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->src_buf.offset = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->src_buf.size = va_arg(op_arg, size_t);
                eop->src = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_MULTIPLE_BUFFERS)
                    eop->dst_buf.u.index = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->dst_buf.offset = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_UNIQUE_COUNTS)
                    eop->dst_buf.size = va_arg(op_arg, size_t);
                if (flags & FI_SCHED_FLAG_MULTIPLE_BUFFERS)
                    eop->tmp_buf.u.index = va_arg(op_arg, size_t);
                uop->u.sendrecv_red = eop
            ),

            /* array op */
            RESERVE_SPACE(uop, struct fi_sched_op_array, 1, space);
            uop->nop = va_arg(op_arg, int);
            RESERVE_SPACE(aop, struct fi_sched_op *, uop->nop, space);
            (void)aop;
            op->u.array = uop,

            /* list op */
            struct fi_sched_op *next_op;
            struct fi_sched_op_list **tailp = &op->u.list;
            while ((next_op = va_arg(op_arg, struct fi_sched_op *))) {
                FI_SCHED_OC(op) += FI_SCHED_OC(next_op);
                RESERVE_SPACE(uop, struct fi_sched_op_list, 1, space);
                uop->op = next_op;
                *tailp = uop;
                tailp = &uop->next;
            }
            *tailp = NULL);
    return op;
}

void
fi_sched_op_array_populate(struct fi_sched_op *array, int index, struct fi_sched_op *op)
{
    FI_SCHED_OC(array) += FI_SCHED_OC(op);
    array->u.array->op[index] = op;
}

struct fi_sched_op_list **
fi_sched_op_list_populate(struct fi_sched_space *space, struct fi_sched_op *list,
        struct fi_sched_op_list **tailp, struct fi_sched_op *op)
{
    FI_SCHED_OC(list) += FI_SCHED_OC(op);
    RESERVE_SPACE(lop, struct fi_sched_op_list, 1, space);
    *tailp = lop;
    lop->op = op;
    lop->next = NULL;
    return &lop->next;
}

/* Debugging functions */

#define PRINT_OP(level, name, format, ...) \
    fprintf(stderr, "%*sop(%lu/%lu), ctx %p: " #name format "\n", (level)*3, "", \
            FI_SCHED_CC(op), FI_SCHED_OC(op), FI_SCHED_CTX(op), ##__VA_ARGS__)
void
fi_sched_op_print(struct fi_sched_op *op, int level)
{
    SWITCH_CASE(op, nested_op,
            SWITCH_CASE_ELEMENT(op,
                PRINT_OP(level, NOP, ""),
                PRINT_OP(level, COPY, ": local copy"),
                PRINT_OP(level, SEND, ": to %lu",
                    op->u.element->u.send->dst),
                PRINT_OP(level, RECV, ": from %lu",
                    op->u.element->u.recv->src),
                PRINT_OP(level, SENDRECV, ": to %lu from %lu",
                    op->u.element->u.sendrecv->dst, op->u.element->u.sendrecv->src),
                PRINT_OP(level, SEND_RED, ": to %lu",
                    op->u.element->u.send->dst),
                PRINT_OP(level, RECV_RED, ": from %lu into buf #%lu, using tmpbuf #%lu",
                    op->u.element->u.recv_red->src, op->u.element->u.recv_red->dst_buf.u.index, op->u.element->u.recv_red->tmp_buf.u.index),
                PRINT_OP(level, SENDRECV_RED, ": to %lu from %lu",
                    op->u.element->u.sendrecv_red->dst, op->u.element->u.sendrecv_red->src)),
            PRINT_OP(level, ARRAY, "(%lu):", op->u.array->nop); fi_sched_op_print(nested_op, level+1),
            PRINT_OP(level, LIST, ":"); fi_sched_op_print(nested_op, level+1),
            0);
}
