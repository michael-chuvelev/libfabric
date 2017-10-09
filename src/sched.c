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

#define SWITCH_CASE_ELEMENT(current_op, hnop, hsend, hrecv, hsendrecv) \
    do { \
        switch((current_op)->u.element->code) { \
            CASE(FI_SCHED_OP_ELEMENT_CODE_NOP, hnop); \
            CASE(FI_SCHED_OP_ELEMENT_CODE_SEND, hsend); \
            CASE(FI_SCHED_OP_ELEMENT_CODE_RECV, hrecv); \
            CASE(FI_SCHED_OP_ELEMENT_CODE_SENDRECV, hsendrecv); \
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

#define SWITCH_CASE(current_op, nested_op, helement, nested_harray, nested_hlist) \
    SWITCH_CASE_OP(current_op, \
                   helement, \
                   struct fi_sched_op * nested_op; \
                   int i; \
                   for (i = 0; i < (current_op)->u.array->nop; i++) { \
                       nested_op = (current_op)->u.array->op[i]; \
                       nested_harray; \
                   }, \
                   struct fi_sched_op * nested_op; \
                   struct fi_sched_op_list * l; \
                   for (l = (current_op)->u.list; l; l = l->next) { \
                       nested_op = l->op; \
                       nested_hlist; \
                   })
#if 0
#define SWITCH_CASE(current_op, nested_op, helement, harray, hlist) \
    do { \
        switch((current_op)->code) { \
            CASE(FI_SCHED_OP_CODE_ELEMENT, helement); \
            CASE(FI_SCHED_OP_CODE_ARRAY, \
                    struct fi_sched_op * nested_op; \
                    int i; \
                    for (i = 0; i < (current_op)->u.array->nop; i++) { \
                        nested_op = (current_op)->u.array->op[i]; \
                        harray; \
                    }); \
            CASE(FI_SCHED_OP_CODE_LIST, \
                    struct fi_sched_op * nested_op; \
                    struct fi_sched_op_list * l; \
                    for (l = (current_op)->u.list; l; l = l->next) { \
                        nested_op = l->op; \
                        hlist; \
                    }); \
        } \
    } while(0)
#endif

/* pt2pt operation handlers */

#define CALL(call) call

#define SEND(header, op, kind) \
    fi_sched_op_send(header, op, &op->u.element->u.kind->src_buf, op->u.element->u.kind->dst)

static inline int
fi_sched_op_send(struct fi_sched_header *header, struct fi_sched_op *op, struct fi_sched_buf *buf, size_t dst)
{
    CALL(fi_tsend(header->tx[0].ctx,
                  (char *)header->buf[buf->u.index].u.ptr + buf->offset,
                  header->buf[buf->u.index].size,
                  NULL,
                  header->group[dst],
                  header->match_bits & header->rank,
                  op->ctx));
    return 0;
}

#define RECV(header, op, kind) \
    fi_sched_op_recv(header, op, &op->u.element->u.kind->dst_buf, op->u.element->u.kind->src)

static inline int
fi_sched_op_recv(struct fi_sched_header *header, struct fi_sched_op *op, struct fi_sched_buf *buf, size_t src)
{
    CALL(fi_trecv(header->rx[0].ctx,
                  (char *)header->buf[buf->u.index].u.ptr + buf->offset,
                  header->buf[buf->u.index].size,
                  NULL,
                  header->group[src],
                  header->match_bits & src,
                  0,
                  op->ctx));
    return 0;
}

/* TODO multiple op ctx on cq, multiple count */
static inline int
fi_sched_op_wait(struct fi_sched_header *header, struct fi_sched_op *op,
                 void *buf, size_t count, int *completion_count, int blocking)
{
    int ret = 0;
    while (1) {
        ret = CALL(fi_cq_read(header->rx[0].cq, buf, 1));
        if (ret >= 0)
            if (ret > 0 && ((struct fi_cq_tagged_entry *)buf)->op_context == op->ctx) {
                FI_SCHED_COMPLETION_COUNT(op)++;
                *completion_count = 1;
                return 0;
            } else {
                *completion_count = 0;
                return ret;
            }
        else if (ret == -FI_EAGAIN && !blocking)
            return 0;
        else if (ret < 0 && ret != -FI_EAGAIN)
            return ret;
    }
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
    if (FI_SCHED_ISSUE_COUNT(op))
        return 0;
    SWITCH_CASE(op, nested_op,
                SWITCH_CASE_ELEMENT(op,
                                    , /* hnop */
                                    HANDLE_RET(SEND(header, op, send)), /* hsend */
                                    HANDLE_RET(RECV(header, op, recv)), /* hrecv */
                                    HANDLE_RET(RECV(header, op, sendrecv));
                                    HANDLE_RET(SEND(header, op, sendrecv)) /* hsendrecv */
                                   ),
                HANDLE_RET(fi_sched_issue_internal(header, nested_op)), /* harray */
                HANDLE_RET(fi_sched_issue_internal(header, nested_op));
                if (FI_SCHED_COMPLETION_COUNT(nested_op) < FI_SCHED_OP_COUNT(nested_op)) return 0 /* hlist */
               );
    FI_SCHED_ISSUE_COUNT(op) = 1;
    return 0;
}

int
fi_sched_issue(struct fi_sched *sched)
{
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

static inline int
fi_sched_progress_internal(struct fi_sched_header *header, struct fi_sched_op *op,
                           void *buf, size_t count, int *completion_count, int blocking)
{
    int cc = 0;
    if (FI_SCHED_COMPLETION_COUNT(op) >= FI_SCHED_OP_COUNT(op))
        return 0;
    SWITCH_CASE(op, nested_op,
                SWITCH_CASE_ELEMENT(op,
                                    , /* hnop */
                                    HANDLE_RET(fi_sched_op_wait(header, op, buf, count, completion_count, blocking)), /* hsend */
                                    HANDLE_RET(fi_sched_op_wait(header, op, buf, count, completion_count, blocking)), /* hrecv */
                                    HANDLE_RET(fi_sched_op_wait(header, op, buf, count, completion_count, blocking));
                                    HANDLE_RET(fi_sched_op_wait(header, op, buf, count, completion_count, blocking)) /* hsendrecv */
                                   ),
                HANDLE_RET(fi_sched_progress_internal(header, nested_op, buf, count, &cc, blocking));
                FI_SCHED_COMPLETION_COUNT(op) += cc, /* harray */
                HANDLE_RET(fi_sched_issue_internal(header, nested_op));
                HANDLE_RET(fi_sched_progress_internal(header, nested_op, buf, count, &cc, blocking));
                FI_SCHED_COMPLETION_COUNT(op) += cc;
                if (FI_SCHED_COMPLETION_COUNT(nested_op) < FI_SCHED_OP_COUNT(nested_op)) return 0 /* hlist */
               );
    return 0;
}

int
fi_sched_wait(struct fi_sched *sched, void *buf, size_t count, int *completion_flag)
{
    int completion_count = 0;
    int ret = fi_sched_progress_internal(sched->header, sched->op, buf, count, &completion_count, 1);
    *completion_flag = FI_SCHED_COMPLETION_COUNT(sched->op) == FI_SCHED_OP_COUNT(sched->op);
    return ret;
}

int
fi_sched_test(struct fi_sched *sched, void *buf, size_t count, int *completion_flag)
{
    int completion_count = 0;
    int ret = fi_sched_progress_internal(sched->header, sched->op, buf, count, &completion_count, 0);
    *completion_flag = FI_SCHED_COMPLETION_COUNT(sched->op) == FI_SCHED_OP_COUNT(sched->op);
    return ret;
}

/* Schedule helper functions */

struct fi_sched_space {
    char *ptr;
    size_t left;
    size_t used;
};

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

#include <stdarg.h>
#include <assert.h>
#include <string.h>

struct fi_sched_op *
fi_sched_op_create(struct fi_sched_space *space, enum fi_sched_op_code code, ...)
{
    va_list op_arg;
    va_start(op_arg, code);
    RESERVE_SPACE(op, struct fi_sched_op, 1, space);
    op->code = code;
    SWITCH_CASE_OP(op,
            /* element op */
            RESERVE_SPACE(uop, struct fi_sched_op_element, 1, space);
            uop->code = va_arg(op_arg, enum fi_sched_op_element_code);
            op->u.element = uop;
            SWITCH_CASE_ELEMENT(op,
                RESERVE_SPACE(eop, struct fi_sched_op_element_nop, 1, space);
                uop->u.nop = eop,
                RESERVE_SPACE(eop, struct fi_sched_op_element_send, 1, space);
                eop->src_buf.u.index = va_arg(op_arg, size_t);
                eop->dst = va_arg(op_arg, size_t);
                uop->u.send = eop,
                RESERVE_SPACE(eop, struct fi_sched_op_element_recv, 1, space);
                eop->dst_buf.u.index = va_arg(op_arg, size_t);
                eop->src = va_arg(op_arg, size_t);
                uop->u.recv = eop,
                RESERVE_SPACE(eop, struct fi_sched_op_element_sendrecv, 1, space);
                eop->src_buf.u.index = va_arg(op_arg, size_t);
                eop->dst = va_arg(op_arg, size_t);
                eop->dst_buf.u.index = va_arg(op_arg, size_t);
                eop->src = va_arg(op_arg, size_t);
                uop->u.sendrecv = eop),
            /* array op */
            RESERVE_SPACE(uop, struct fi_sched_op_array, 1, space);
            uop->nop = va_arg(op_arg, int);
            RESERVE_SPACE(aop, struct fi_sched_op, uop->nop, space);
            op->u.array = uop,
            /* list op */
            struct fi_sched_op *next_op;
            struct fi_sched_op_list **tailp = &op->u.list;
            while ((next_op = va_arg(op_arg, struct fi_sched_op *))) {
                RESERVE_SPACE(uop, struct fi_sched_op_list, 1, space);
                uop->op = next_op;
                *tailp = uop;
                tailp = &uop->next;
            }
            *tailp = NULL);
    return op;
}

void
fi_sched_op_array_populate(struct fi_sched_op_array *array, int index, struct fi_sched_op *op)
{
    array->op[index] = op;
}

struct fi_sched_op_list **
fi_sched_op_list_populate(struct fi_sched_space *space, struct fi_sched_op_list **tailp, struct fi_sched_op *op)
{
    RESERVE_SPACE(lop, struct fi_sched_op_list, 1, space);
    *tailp = lop;
    lop->op = op;
    lop->next = NULL;
    return &lop->next;
}

/* Debugging functions */
#include <stdio.h>

#define PRINT_OP(level, op, format, ...) fprintf(stderr, "%*sop: " #op format "\n", (level)*3, "", ##__VA_ARGS__)
void
fi_sched_op_print(struct fi_sched_op *op, int level)
{
    SWITCH_CASE(op, nested_op,
            SWITCH_CASE_ELEMENT(op,
                PRINT_OP(level, NOP, ""),
                PRINT_OP(level, SEND, ": to %lu", op->u.element->u.send->dst),
                PRINT_OP(level, RECV, ": from %lu", op->u.element->u.recv->src),
                PRINT_OP(level, SENDRECV, ": to %lu from %lu", op->u.element->u.sendrecv->dst, op->u.element->u.sendrecv->src)),
            PRINT_OP(level, ARRAY, "(%lu):", op->u.array->nop); fi_sched_op_print(nested_op, level+1),
            PRINT_OP(level, LIST, ":"); fi_sched_op_print(nested_op, level+1));
}
