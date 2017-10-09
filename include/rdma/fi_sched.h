/*
 * Copyright (c) 2013-2014 Intel Corporation. All rights reserved.
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

#ifndef FI_SCHED_H
#define FI_SCHED_H

#include <rdma/fabric.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>


#ifdef __cplusplus
extern "C" {
#endif

struct fi_sched_ep {
    struct fid_ep *ctx;
    struct fid_cq *cq;
};

struct fi_sched_buf {
    union {
        void *ptr;
        size_t index;
    } u;
    size_t size;
    size_t offset;
    uint64_t flags;
};

struct fi_sched_header {
    /* ep info */
    int ntx;
    struct fi_sched_ep *tx;
    int nrx;
    struct fi_sched_ep *rx;
    /* buffers info */
    int nbuf;
    struct fi_sched_buf *buf;
    /* reduction info */
    int datatype;
    int op;
    /* addressing info */
    int ngroup;
    fi_addr_t *group;
    /* matching info */
    size_t rank;
    uint64_t match_bits;
    /* flags */
    uint64_t flags;
};

enum fi_sched_op_code {
    FI_SCHED_OP_CODE_ELEMENT,
    FI_SCHED_OP_CODE_ARRAY,
    FI_SCHED_OP_CODE_LIST,
};

enum fi_sched_op_element_code {
    FI_SCHED_OP_ELEMENT_CODE_NOP,
    FI_SCHED_OP_ELEMENT_CODE_SEND,
    FI_SCHED_OP_ELEMENT_CODE_RECV,
    FI_SCHED_OP_ELEMENT_CODE_SENDRECV,
};

struct fi_sched_op_element {
    enum fi_sched_op_element_code code;
    union {
        struct fi_sched_op_element_nop      *nop;
        struct fi_sched_op_element_send     *send;
        struct fi_sched_op_element_recv     *recv;
        struct fi_sched_op_element_sendrecv *sendrecv;
    } u;
};

struct fi_sched_op_element_nop {
};

struct fi_sched_op_element_send {
    struct fi_sched_buf src_buf;
    size_t dst;
};

struct fi_sched_op_element_recv {
    struct fi_sched_buf dst_buf;
    size_t src;
};

struct fi_sched_op_element_sendrecv {
    struct fi_sched_buf src_buf;
    size_t dst;
    struct fi_sched_buf dst_buf;
    size_t src;
};

struct fi_sched_op_array {
    size_t nop;
    struct fi_sched_op *op[0];
};

struct fi_sched_op_list {
    struct fi_sched_op_list *next;
    struct fi_sched_op *op;
};

struct fi_sched_op {
    enum fi_sched_op_code code;
    union {
        struct fi_sched_op_element *element;
        struct fi_sched_op_array   *array;
        struct fi_sched_op_list    *list;
    } u;
    size_t op_count;
    size_t completion_count;
    size_t issue_count;
    uint64_t unit;
    void *ctx[4];
};

struct fi_sched {
    struct fi_sched_header *header;
    struct fi_sched_op *op;
};

int fi_sched_issue(struct fi_sched *sched);
int fi_sched_wait(struct fi_sched *sched, void *buf, size_t count, int *completion_flag);
int fi_sched_test(struct fi_sched *sched, void *buf, size_t count, int *completion_flag);

#define FI_SCHED_OP_COUNT(op)         ((op)->op_count)
#define FI_SCHED_COMPLETION_COUNT(op) ((op)->completion_count)
#define FI_SCHED_ISSUE_COUNT(op)      ((op)->issue_count)
#define FI_SCHED_UNIT_NUM(op)         ((op)->unit & 0xffffffff)
#define FI_SCHED_UNIT_CNT(op)         (((op)->unit >> 32) & 0xffffffff)
#define FI_SCHED_UNIT(num, cnt)       ((((cnt) & 0xffffffff) << 32) | ((num) & 0xffffffff))

#ifdef __cplusplus
}
#endif

#endif /* FI_SCHED_H */

