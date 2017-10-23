/*
 * Copyright (c) 2013-2015 Intel Corporation.  All rights reserved.
 * Copyright (c) 2014-2016, Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2015 Los Alamos Nat. Security, LLC. All rights reserved.
 * Copyright (c) 2016 Cray Inc.  All rights reserved.
 *
 * This software is available to you under the BSD license below:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_sched.h>

/***********************/
/* Debugging & service */
/***********************/

#define VERBOSE(verbose, rank, message, ...) \
    if (verbose) fprintf(stderr, "[%d] " message "\n", rank, ##__VA_ARGS__)
#define ERROR(message, ...) \
    do { \
        fprintf(stderr, "ERROR: " message ". Aborted.\n", ##__VA_ARGS__); \
        exit(1); \
    } while(0)
#define MALLOC(ptr, type, count) \
    if (!((ptr) = (type*)malloc((count)*sizeof(type)))) \
        ERROR("failed to allocate %lu bytes", (count)*sizeof(type))
#define CALLOC(ptr, type, count) \
    if (!((ptr) = (type*)calloc(count, sizeof(type)))) \
        ERROR("failed to allocate %lu bytes", (count)*sizeof(type))

/* addr_to_str: char * return value should be freed if not used anymore */
static inline char * addr_to_str(char *addr, size_t addrlen) {
    int i;
    char *str = NULL;
    char byte[4];
    CALLOC(str, char, 4*addrlen);
    for (i = 0; i < addrlen; i++) {
        if (i) strcat(str, ":");
        sprintf(byte, "%u", (unsigned char)addr[i]);
        strcat(str, byte);
    }
    return str;
}

/* str_to_addr: char * return value should be freed if not used anymore */
static inline char * str_to_addr(char *str, size_t *addrlen) {
    int i;
    char *str_p, *addr = NULL;
    char byte[4];
    for (i = 1, str_p = str; *str_p; str_p++)
        if (*str_p == ':') {
            *str_p = '\0';
            i++;
        }
    *addrlen = i;
    CALLOC(addr, char, *addrlen);
    for (i = 0, str_p = str; i < *addrlen; i++) {
        addr[i] = atoi(str_p);
        str_p += strlen(str_p) + 1;
    }
    return addr;
}

#define IS_ENV(env, var) (strncmp(env, var "=", strlen(var "=")) == 0)

static inline int is_exec_env(char *env) {
    return IS_ENV(env, "PATH") || IS_ENV(env, "LD_LIBRARY_PATH");
}

/* exec_env: char * return value should be freed if not used anymore */
static inline char * exec_env() {
    extern char **environ;
    char **environ_p;
    char *env = NULL;
    size_t env_len = 0;
    for (environ_p = environ; *environ_p; environ_p++)
        if (is_exec_env(*environ_p)) env_len += strlen(*environ_p) + 1;
    CALLOC(env, char, env_len + 1);
    for (environ_p = environ; *environ_p; environ_p++)
        if (is_exec_env(*environ_p)) {
            strcat(env, *environ_p);
            strcat(env, " ");
        }
    return env;
}

/* exec_host: char * return value should be freed if not used anymore */
static inline char * exec_host() {
    char *hostname = NULL;
    CALLOC(hostname, char, 256);
    if (gethostname(hostname, 256) == -1) ERROR("gethostname failed");
    return hostname;
}

#define INT_TO_STR(str, len, init) char str[len]; sprintf(str, "%d", init)

/*******************************/
/* Program argument processing */
/*******************************/

#define ARG(arg, key, handler) \
    if (strcmp(arg, "-" #key) == 0) do {handler;} while(0)

static inline char * next_arg(char *argv[], int *ind) {
    if (!argv[++(*ind)]) ERROR("%s requires argument", argv[(*ind)-1]);
    return argv[*ind];
}

/* split_arg: char ** return value should be freed if not used anymore */
static inline char ** split_arg(char *arg, char delim, int *len) {
    char **arg_array = NULL, **arg_array_p, *arg_p;
    *len = 1;
    for (arg_p = arg; *arg_p; arg_p++)
        if (*arg_p == delim) (*len)++;
    MALLOC(arg_array, char *, *len);
    arg_array_p = arg_array;
    *(arg_array_p++) = arg;
    for (arg_p = arg; *arg_p; arg_p++)
        if (*arg_p == delim) {
            *arg_p = '\0';
            *(arg_array_p++) = arg_p + 1;
        }
    return arg_array;
}

static inline void arg_help()
{
    printf("Usage:\nfi_sched -hosts <hosts> [-v] | fi_sched -h\n");
    exit(0);
}

/**********************/
/* Connection control */
/**********************/

struct ctrl_proc {
    char *hostname;
    char *addr;
};

struct ctrl_conn {
    char *progname;
    int nchild;
    struct ctrl_proc *child;
    struct ctrl_proc *parent;
    struct ctrl_proc me;
};

/* ctrl_conn_hosts: conn->child should be freed if not used anymore */
static inline void ctrl_conn_hosts(char *hosts, struct ctrl_conn *conn, int *size, int *rank)
{
    int i, j, n, o, len = 0;
    char *host_p = NULL;
    char **host_array = split_arg(hosts, ',', &len);
    for (i = 0, conn->nchild = 0; i < len; i++)
        conn->nchild += (host_p = strchr(host_array[i], ':')) ? atoi(host_p + 1) : 1;
    *size = conn->nchild + 1;
    *rank = 0;
    if (!conn->child)
        CALLOC(conn->child, struct ctrl_proc, conn->nchild);
    for (i = 0, o = 0; i < len; i++, o += n) {
        n = (host_p = strchr(host_array[i], ':')) ? atoi(host_p + 1) : 1;
        if (host_p)
            *host_p = '\0';
        for (j = 0; j < n; j++)
            conn->child[o+j].hostname = strlen(host_array[i]) ? host_array[i] : conn->me.hostname;
    }
    free(host_array);
}

/* ctrl_conn_addr: conn->parent should be freed if not used anymore */
static inline void ctrl_conn_addr(char *addr, struct ctrl_conn *conn)
{
    if (!conn->parent) CALLOC(conn->parent, struct ctrl_proc, 1);
    conn->parent->addr = addr;
}

/* ctrl_conn_init: free(conn->me.hostname), free(conn->progname), free(conn->parent), free(conn->child) when done */
static inline int ctrl_conn_init(int argc, char *argv[], struct ctrl_conn *conn, int *size, int *rank, int *verbose) {
    int i;
    *size = 0;
    *rank = -1;
    *verbose = 0;
    /* get arguments */
    if (!(conn->progname = realpath(argv[0], NULL)))
        ERROR("realpath(%s, NULL) returned NULL", argv[0]);
    if (!(conn->me.hostname = exec_host()))
        ERROR("failed to gethostname");
    if (argc < 2) {
        arg_help();
        ERROR("no arguments provided");
    }
    for (i = 1; i < argc; i++) {
        ARG(argv[i], help, arg_help());
        else ARG(argv[i], h, arg_help());
        else ARG(argv[i], verbose, *verbose = 1);
        else ARG(argv[i], v, *verbose = 1);
        else ARG(argv[i], hosts, ctrl_conn_hosts(next_arg(argv, &i), conn, size, rank));
        else ARG(argv[i], rank, *rank = atoi(next_arg(argv, &i)));
        else ARG(argv[i], size, *size = atoi(next_arg(argv, &i)));
        else ARG(argv[i], addr, ctrl_conn_addr(next_arg(argv, &i), conn));
    }
    if (!(*size) || (*rank) == -1) ERROR("incorrect parameters: size %d, rank %d", *size, *rank);
    return 0;
}

static inline int ctrl_conn_start(int size, int rank, int verbose, struct ctrl_conn *conn, char *addr_str) {
    if (conn->child) {
        /* parent: start children processes */
        int i;
        pid_t pid;
        char *env_str = exec_env();
        INT_TO_STR(size_str, 10, size);
        for (i = 0; i < conn->nchild; i++) {
            INT_TO_STR(rank_str, 10, i+1);
            if ((pid = fork()) == 0)
                execlp("ssh", "ssh", conn->child[i].hostname, env_str, conn->progname,
                        "-rank", rank_str, "-size", size_str, "-addr", addr_str,
                        verbose ? "-v" : "", NULL);
            else if (pid < 0)
                ERROR("Couldn't run %s %s %s %s: fork() returned %d",
                        "ssh", conn->child[i].hostname, env_str, conn->progname, pid);
        }
        free(env_str);
    }
    return 0;
}

static inline int ctrl_conn_finalize(struct ctrl_conn *conn) {
    int i, status;
    for (i = 0; i < conn->nchild; i++)
        if (wait(&status) == -1) ERROR("wait returned -1");
    free(conn->child);
    free(conn->parent);
    free(conn->progname);
    return 0;
}

static inline void ctrl_conn_print(int verbose, int rank, struct ctrl_conn *conn) {
    int i;
    VERBOSE(verbose, rank, "progname: %s", conn->progname);
    VERBOSE(verbose, rank, "me: hostname %s, addr %s",
            conn->me.hostname, conn->me.addr);
    if (conn->parent)
        VERBOSE(verbose, rank, "parent: hostname %s, addr %s",
                conn->parent->hostname, conn->parent->addr);
    VERBOSE(verbose, rank, "nchild: %d", conn->nchild);
    if (conn->child)
        for (i = 0; i < conn->nchild; i++)
            VERBOSE(verbose, rank, "child[%d]: hostname %s, addr %s",
                    i, conn->child[i].hostname, conn->child[i].addr);
}

/******************/
/* Fabric control */
/******************/

#define CALL(call) \
    do { \
        int _ret; \
        if (_ret = (call)) ERROR(#call " failed: returned %d", _ret); \
    } while(0)

#define SEND(ep, buf, len, addr, tag, ctx) \
    CALL(fi_tsend(ep, buf, len, NULL, addr, tag, ctx))
#define RECV(ep, buf, len, addr, tag, ctx) \
    CALL(fi_trecv(ep, buf, len, NULL, addr, tag, 0, ctx))
#define WAIT(cq) \
    do { \
        struct fi_cq_tagged_entry _wc[1]; \
        int _ret = fi_cq_read(cq, (void *)_wc, 1); \
        if (_ret > 0) break; \
        else if (_ret < 0 && _ret != -FI_EAGAIN) \
            ERROR("fi_cq_read returned %d", _ret); \
    } while(1)

struct ctrl_fi {
    int size;
    int rank;
    struct fi_info *info;
    struct fid_fabric *fabric;
    struct fid_domain *domain;
    struct fid_cq *cq;
    struct fid_av *av;
    struct fid_ep *ep;
    fi_addr_t *fi_addr;
};

/* ctrl_fi_info: do fi_freeinfo(fi->info), free(ret_value) when done */
static inline char * ctrl_fi_init(int size, struct ctrl_fi *fi) {
    char addr[64];
    size_t addrlen = sizeof(addr);
    struct fi_info *hints, *info;
    struct fi_cq_attr cq_attr = {0};
    struct fi_av_attr av_attr = {0};
    hints = fi_allocinfo();
    hints->ep_attr->type = FI_EP_RDM;
    hints->caps = FI_TAGGED;
    hints->mode = FI_CONTEXT;
    CALL(fi_getinfo(FI_VERSION(1, 5), NULL, NULL, 0, hints, &fi->info));
    fi_freeinfo(hints);
    CALL(fi_fabric(fi->info->fabric_attr, &fi->fabric, NULL));
    CALL(fi_domain(fi->fabric, fi->info, &fi->domain, NULL));
    cq_attr.format = FI_CQ_FORMAT_TAGGED;
    CALL(fi_cq_open(fi->domain, &cq_attr, &fi->cq, NULL));
    av_attr.type = fi->info->domain_attr->av_type;
    CALL(fi_av_open(fi->domain, &av_attr, &fi->av, NULL));
    CALL(fi_endpoint(fi->domain, fi->info, &fi->ep, NULL));
    CALL(fi_ep_bind(fi->ep, &fi->av->fid, 0));
    CALL(fi_ep_bind(fi->ep, &fi->cq->fid, FI_SEND|FI_RECV));
    CALL(fi_enable(fi->ep));
    CALL(fi_getname(&fi->ep->fid, addr, &addrlen));
    return addr_to_str(addr, addrlen);
}

/* ctrl_fi_addr_exchange: free(fi->fi_addr) when done */
static inline int ctrl_fi_addr_exchange(int size, int rank, struct ctrl_fi *fi, char *addr_str, char *paddr_str) {
    int i;
    size_t addrlen;
    char *addr = str_to_addr(addr_str, &addrlen), *addr_table = NULL;
    MALLOC(fi->fi_addr, fi_addr_t, size);
    MALLOC(addr_table, char, addrlen*size);
    if (rank == 0) {
        memcpy(addr_table, addr, addrlen);
        for (i = 1; i < size; i++) {
            RECV(fi->ep, &addr_table[addrlen*i], addrlen, FI_ADDR_UNSPEC, i, NULL);
            WAIT(fi->cq);
        }
        CALL(size != fi_av_insert(fi->av, addr_table, size, fi->fi_addr, 0, NULL));
        for (i = 1; i < size; i++) {
            SEND(fi->ep, addr_table, addrlen*size, fi->fi_addr[i], 0, NULL);
            WAIT(fi->cq);
        }
    } else {
        char *paddr = str_to_addr(paddr_str, &addrlen);
        fi_addr_t fi_paddr;
        CALL(1 != fi_av_insert(fi->av, paddr, 1, &fi_paddr, 0, NULL));
        free(paddr);
        SEND(fi->ep, addr, addrlen, fi_paddr, rank, NULL);
        WAIT(fi->cq);
        RECV(fi->ep, addr_table, addrlen*size, fi_paddr, 0, NULL);
        WAIT(fi->cq);
        CALL(size != fi_av_insert(fi->av, addr_table, size, fi->fi_addr, 0, NULL));
    }
    free(addr);
    free(addr_table);
    return 0;
}

static inline int ctrl_fi_barrier(int size, int rank, struct ctrl_fi *fi) {
    int i;
    int tag = 0xf0f0f0f0;
    if (rank == 0)
        for (i = 1; i < size; i++) {
            SEND(fi->ep, NULL, 0, fi->fi_addr[i], tag, NULL);
            WAIT(fi->cq);
            RECV(fi->ep, NULL, 0, fi->fi_addr[i], tag, NULL);
            WAIT(fi->cq);
        }
    else {
        RECV(fi->ep, NULL, 0, fi->fi_addr[0], tag, NULL);
        WAIT(fi->cq);
        SEND(fi->ep, NULL, 0, fi->fi_addr[0], tag, NULL);
        WAIT(fi->cq);
    }
    return 0;
}

/*******************/
/* Program control */
/*******************/

/* ctrl_init: free(conn->progname), free(conn->parent), free(conn->child), free(fi->fi_addr) when done */
static inline int ctrl_init(int argc, char *argv[],
        struct ctrl_conn *conn, struct ctrl_fi *fi, int *size, int *rank, int *verbose) {
    char *addr_str = NULL;
    ctrl_conn_init(argc, argv, conn, size, rank, verbose);
    ctrl_conn_start(*size, *rank, *verbose, conn, addr_str = ctrl_fi_init(*size, fi));
    ctrl_fi_addr_exchange(*size, *rank, fi, addr_str, conn->parent ? conn->parent->addr : NULL);
    free(addr_str);
    return 0;
}

static inline int ctrl_finalize(int size, int rank, struct ctrl_conn *conn, struct ctrl_fi *fi) {
    ctrl_fi_barrier(size, rank, fi);
    fi_freeinfo(fi->info);
    free(fi->fi_addr);
    ctrl_conn_finalize(conn);
    return 0;
}

/***********************/
/* Schedule management */
/***********************/

/* barrier */
static inline struct fi_sched_op* sched_barrier_dissemination(struct fi_sched_space *space, int size, int rank) {
    /* algorithm: dissemination */
    struct fi_sched_op *op = fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_LIST, NULL);
    struct fi_sched_op_list **tail = &op->u.list;
    int mask;
    for (mask = 0x1; mask < size; mask <<= 1)
        if (rank & mask)
            tail = fi_sched_op_list_populate(space, op, tail,
                    fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_ELEMENT,
                        FI_SCHED_OP_ELEMENT_CODE_SENDRECV, rank-mask, rank-mask));
        else if (rank + mask < size)
            tail = fi_sched_op_list_populate(space, op, tail,
                    fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_ELEMENT,
                        FI_SCHED_OP_ELEMENT_CODE_SENDRECV, rank+mask, rank+mask));
    return op;
}

/* bcast */
static inline int k_tree(int size, int rank, int k, int *parent) {
    int h, pofk;
    for (h = 0, pofk = 1; rank % (pofk*k) == 0 && pofk < size; h++, pofk *= k) ;
    *parent = rank - rank % (pofk*k);
    return h;
}

static inline struct fi_sched_op* sched_bcast_knomial(struct fi_sched_space *space, int size, int rank, int root, int k) {
    /* algorithm: k-nomial */
    struct fi_sched_op *op = fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_LIST, NULL);
    struct fi_sched_op_list **tail = &op->u.list;
    int rel_rank = (rank + size - root) % size;
    int rel_parent;
    int height = k_tree(size, rel_rank, k, &rel_parent);
    if (rel_rank)
        tail = fi_sched_op_list_populate(space, op, tail,
                    fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_ELEMENT,
                        FI_SCHED_OP_ELEMENT_CODE_RECV, (size_t) (root + rel_parent) % size));
    if (height) {
        int i, j, pofk;
        struct fi_sched_op *ar = fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_ARRAY, height*(k-1));
        for (i = 0, pofk = 1; i < height; i++, pofk *= k)
            for (j = 1; j < k; j++)
                fi_sched_op_array_populate(ar, (k-1)*(height-i-1) + (j-1),
                        rel_rank + pofk*j >= size ?
                        fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_ELEMENT, FI_SCHED_OP_ELEMENT_CODE_NOP) :
                        fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_ELEMENT, FI_SCHED_OP_ELEMENT_CODE_SEND,
                            (size_t) ((rank + pofk*j) % size)));
        fi_sched_op_list_populate(space, op, tail, ar);
    }
    return op;
}

/* reduce */
static inline struct fi_sched_op* sched_reduce_knomial(struct fi_sched_space *space, int size, int rank, int root, int k) {
    /* algorithm: k-nomial */
    struct fi_sched_op *op = fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_LIST, NULL);
    struct fi_sched_op_list **tail = &op->u.list;
    int rel_rank = (rank + size - root) % size;
    int rel_parent;
    int height = k_tree(size, rel_rank, k, &rel_parent);
    if (height) {
        int i, j, pofk;
        for (i = 0, pofk = 1; i < height; i++, pofk *= k)
            for (j = 1; j < k; j++)
                tail = fi_sched_op_list_populate(space, op, tail,
                        rel_rank + pofk*j >= size ?
                        fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_ELEMENT, FI_SCHED_OP_ELEMENT_CODE_NOP) :
                        fi_sched_op_create(space, FI_SCHED_FLAG_MULTIPLE_BUFFERS,
                            FI_SCHED_OP_CODE_ELEMENT, FI_SCHED_OP_ELEMENT_CODE_RECV_RED,
                            (size_t) ((rank + pofk*j) % size), (size_t)0, (size_t)1));
    }
    if (rel_rank)
        tail = fi_sched_op_list_populate(space, op, tail,
                    fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_ELEMENT,
                        FI_SCHED_OP_ELEMENT_CODE_SEND_RED, (size_t) (root + rel_parent) % size));
    return op;
}

/* allreduce */
static inline struct fi_sched_op* sched_allreduce_rec_doubling(struct fi_sched_space *space, int size, int rank) {
    /* algorithm: recursive doubling */
    struct fi_sched_op *op = fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_LIST, NULL);
    struct fi_sched_op_list **tail = &op->u.list;
    int pof2, rem, new_rank, mask;
    for (pof2 = 0x1; pof2 <= size; pof2 <<= 1) ;
    pof2 >>= 1;
    rem = size - pof2;
    new_rank = rank - rem;

    if (rank < rem)
        tail = fi_sched_op_list_populate(space, op, tail,
                fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_ELEMENT,
                    FI_SCHED_OP_ELEMENT_CODE_SEND_RED, (size_t) (rank + rem)));
    else if (new_rank < rem)
        tail = fi_sched_op_list_populate(space, op, tail,
                fi_sched_op_create(space, FI_SCHED_FLAG_MULTIPLE_BUFFERS,
                    FI_SCHED_OP_CODE_ELEMENT, FI_SCHED_OP_ELEMENT_CODE_RECV_RED,
                    (size_t) new_rank, (size_t)0, (size_t)1));

    if (new_rank >= 0)
        for (mask = 0x1; mask < pof2; mask <<= 1)
            if (new_rank & mask)
                tail = fi_sched_op_list_populate(space, op, tail,
                        fi_sched_op_create(space, FI_SCHED_FLAG_MULTIPLE_BUFFERS,
                            FI_SCHED_OP_CODE_ELEMENT, FI_SCHED_OP_ELEMENT_CODE_SENDRECV_RED,
                            (size_t)(rank-mask), (size_t)0, (size_t)(rank-mask), (size_t)0, (size_t)1));
            else if (new_rank + mask < pof2)
                tail = fi_sched_op_list_populate(space, op, tail,
                        fi_sched_op_create(space, FI_SCHED_FLAG_MULTIPLE_BUFFERS,
                            FI_SCHED_OP_CODE_ELEMENT, FI_SCHED_OP_ELEMENT_CODE_SENDRECV_RED,
                            (size_t)(rank+mask), (size_t)0, (size_t)(rank+mask), (size_t)0, (size_t)1));

    if (rank < rem)
        tail = fi_sched_op_list_populate(space, op, tail,
                fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_ELEMENT,
                    FI_SCHED_OP_ELEMENT_CODE_RECV, (size_t) (rank + rem)));
    else if (new_rank < rem)
        tail = fi_sched_op_list_populate(space, op, tail,
                fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_ELEMENT,
                    FI_SCHED_OP_ELEMENT_CODE_SEND, (size_t) new_rank));
    return op;
}

/* alltoall */
static inline struct fi_sched_op* sched_alltoall_pairwise(struct fi_sched_space *space, int size, int rank, size_t extent) {
    /* algorithm: pairwise exchange */
#if 0 /* as a list */
    struct fi_sched_op *op = fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_LIST,
            fi_sched_op_create(space, FI_SCHED_FLAG_MULTIPLE_BUFFERS | FI_SCHED_FLAG_UNIQUE_COUNTS,
                FI_SCHED_OP_CODE_ELEMENT, FI_SCHED_OP_ELEMENT_CODE_COPY,
                (size_t)1, extent*rank, extent, (size_t)0, extent*rank, extent),
            NULL);
    struct fi_sched_op_list **tail;
    int i;
    int pof2 = !(size&(size-1));
    for (tail = &op->u.list; *tail; tail = &(*tail)->next);
    for (i = 1; i < size; i++) {
        size_t src, dst;
        if (pof2)
            src = dst = rank ^ i;
        else {
            src = (rank - i + size) % size;
            dst = (rank + i) %size;
        }
        tail = fi_sched_op_list_populate(space, op, tail,
                    fi_sched_op_create(space, FI_SCHED_FLAG_MULTIPLE_BUFFERS | FI_SCHED_FLAG_UNIQUE_COUNTS,
                        FI_SCHED_OP_CODE_ELEMENT, FI_SCHED_OP_ELEMENT_CODE_SENDRECV,
                        dst, (size_t)0, extent*dst, extent, src, (size_t)1, extent*src, extent));
    }
    return op;
#endif
#if 1 /* as an array */
    struct fi_sched_op *op = fi_sched_op_create(space, 0, FI_SCHED_OP_CODE_ARRAY, size);
    fi_sched_op_array_populate(op, 0,
            fi_sched_op_create(space, FI_SCHED_FLAG_MULTIPLE_BUFFERS | FI_SCHED_FLAG_UNIQUE_COUNTS,
                FI_SCHED_OP_CODE_ELEMENT, FI_SCHED_OP_ELEMENT_CODE_COPY,
                (size_t)1, extent*rank, extent, (size_t)0, extent*rank, extent));
    int i;
    int pof2 = !(size&(size-1));
    for (i = 1; i < size; i++) {
        size_t src, dst;
        if (pof2)
            src = dst = rank ^ i;
        else {
            src = (rank - i + size) % size;
            dst = (rank + i) %size;
        }
        fi_sched_op_array_populate(op, i,
                    fi_sched_op_create(space, FI_SCHED_FLAG_MULTIPLE_BUFFERS | FI_SCHED_FLAG_UNIQUE_COUNTS,
                        FI_SCHED_OP_CODE_ELEMENT, FI_SCHED_OP_ELEMENT_CODE_SENDRECV,
                        dst, (size_t)0, extent*dst, extent, src, (size_t)1, extent*src, extent));
    }
    return op;
#endif
}

/***********/
/* Program */
/***********/

int main(int argc, char *argv[])
{
    int size = 0;
    int rank = -1;
    int verbose = 0;
    struct ctrl_conn conn = {0};
    struct ctrl_fi fi = {0};

    ctrl_init(argc, argv, &conn, &fi, &size, &rank, &verbose);
    ctrl_conn_print(verbose, rank, &conn);
    VERBOSE(verbose, rank, "init completed: size %d, rank %d, verbose %d", size, rank, verbose);

    /* schedule examples */
    char *space;
    size_t space_len = 1024*1024;
    MALLOC(space, char, space_len);
    struct fi_sched_space sched_space = {space, space_len, (size_t)0};
    struct fi_sched_ep ep = {fi.ep, fi.cq};
    struct fi_sched_buf buf[2] = {0};
    struct fi_sched sched;
    struct fi_sched_header header = {
        fi.info,
        1, /* int ntx; */
        &ep, /* struct fi_sched_ep *tx; */
        1, /* int nrx; */
        &ep, /* struct fi_sched_ep *rx; */
        0, /* int nbuf; */
        NULL, /* struct fi_sched_buf *buf; */
        0, /* int datatype; */
        0, /* int op; */
        size, /* int naddr; */
        fi.fi_addr, /* fi_addr_t *addr; */
        (size_t) rank, /* size_t rank; */
        0xff00ff00, /* uint64_t match_bits; */
        0 /* uint64_t flags; */
    };
    struct fi_sched_op *op;
    /* we don't really expect an out-of-order event here, so won't check wc */
    struct fi_cq_tagged_entry wc[1];
    int completed;

#if 1
    /* barrier example */
    op = sched_barrier_dissemination(&sched_space, size, rank);
    if (verbose) fi_sched_op_print(op, 0);
    sched = (struct fi_sched){&header, op};
    fi_sched_issue(&sched);
    for (completed = 0; !completed; )
        CALL(-FI_EAGAIN != fi_sched_wait(&sched, (void *)wc, 1, &completed));
    VERBOSE(1, rank, "barrier done");
#endif

#if 1
    /* bcast example */
    op = sched_bcast_knomial(&sched_space, size, rank, 0, 2);
    if (verbose) fi_sched_op_print(op, 0);
    sched = (struct fi_sched){&header, op};
    int bcast_buf = rank == 0 ? 123456789 : -1;
    buf[0].u.ptr = &bcast_buf;
    buf[0].size = sizeof(bcast_buf);
    header.nbuf = 1;
    header.buf = &buf[0];
    fi_sched_issue(&sched);
    for (completed = 0; !completed; )
        CALL(-FI_EAGAIN != fi_sched_wait(&sched, (void *)wc, 1, &completed));
    VERBOSE(1, rank, "bcast done %d", bcast_buf);
#endif

#if 1
    /* reduce example */
    op = sched_reduce_knomial(&sched_space, size, rank, 0, 2);
    if (verbose) fi_sched_op_print(op, 0);
    sched = (struct fi_sched){&header, op};
    int reduce_buf = rank, reduce_tmp;
    buf[0].u.ptr = &reduce_buf;
    buf[0].size = sizeof(reduce_buf);
    buf[1].u.ptr = &reduce_tmp;
    buf[1].size = sizeof(reduce_buf);
    header.nbuf = 2;
    header.buf = buf;
    header.type = FI_SCHED_TYPE_CODE_INT;
    header.op = FI_SCHED_RED_CODE_SUM;
    fi_sched_issue(&sched);
    for (completed = 0; !completed; )
        CALL(-FI_EAGAIN != fi_sched_wait(&sched, (void *)wc, 1, &completed));
    VERBOSE(1, rank, "reduce done %d", reduce_buf);
#endif

#if 1
    /* allreduce example */
    op = sched_allreduce_rec_doubling(&sched_space, size, rank);
    if (verbose) fi_sched_op_print(op, 0);
    sched = (struct fi_sched){&header, op};
    int allreduce_buf = rank, allreduce_tmp;
    buf[0].u.ptr = &allreduce_buf;
    buf[0].size = sizeof(allreduce_buf);
    buf[1].u.ptr = &allreduce_tmp;
    buf[1].size = sizeof(allreduce_buf);
    header.nbuf = 2;
    header.buf = buf;
    header.type = FI_SCHED_TYPE_CODE_INT;
    header.op = FI_SCHED_RED_CODE_SUM;
    fi_sched_issue(&sched);
    for (completed = 0; !completed; )
        CALL(-FI_EAGAIN != fi_sched_wait(&sched, (void *)wc, 1, &completed));
    VERBOSE(1, rank, "allreduce done %d", allreduce_buf);
#endif

#if 1
    /* alltoall example */
    int *ibuf, *obuf;
    int i;
    CALLOC(ibuf, int, size);
    CALLOC(obuf, int, size);
    for (i = 0; i < size; i++)
        ibuf[i] = i;
    op = sched_alltoall_pairwise(&sched_space, size, rank, sizeof(int));
    if (verbose) fi_sched_op_print(op, 0);
    sched = (struct fi_sched){&header, op};
    buf[0].u.ptr = ibuf;
    buf[1].u.ptr = obuf;
    buf[0].size = buf[1].size = sizeof(int)*size;
    header.nbuf = 2;
    header.buf = buf;
    header.flags = FI_SCHED_FLAG_MULTIPLE_BUFFERS | FI_SCHED_FLAG_UNIQUE_COUNTS;
    fi_sched_issue(&sched);
    for (completed = 0; !completed; )
        CALL(-FI_EAGAIN != fi_sched_wait(&sched, (void *)wc, 1, &completed));
    char *out;
    CALLOC(out, char, size*10);
    for (i = 0; i < size; i++) {
        char num[10];
        sprintf(num, "%d ", obuf[i]);
        strcat(out, num);
    }
    VERBOSE(1, rank, "alltoall done: %s", out);
    free(ibuf);
    free(obuf);
#endif

    free(space);

    /* wait for children and clean-up*/
    ctrl_finalize(size, rank, &conn, &fi);
    VERBOSE(1, rank, "done");
}
