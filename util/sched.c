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
#include <sys/socket.h>
#include <netdb.h>
#include <inttypes.h>
#include <limits.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_sched.h>

/*************/
/* Debugging */
/*************/

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

/****************************/
/* The proces/schedule info */
/****************************/

struct ct_peer {
    pid_t pid;
    char *host;
    int fd;
    uint16_t port;
};

struct ct_cm {
    char *progname;
    int nchild;
    struct ct_peer *child;
    struct ct_peer *parent;
};

struct ct_fi {
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

struct ct_sched {
    struct ct_fi *fi;
};

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
    printf("Usage:\nfi_sched <args>\n");
    exit(0);
}

/* arg_hosts: cm->child should be freed if not used anymore */
static inline void arg_hosts(char *hosts, int *size, int *rank, struct ct_cm *cm)
{
    int i;
    char **host_array = split_arg(hosts, ',', &cm->nchild);
    *size = cm->nchild + 1;
    *rank = 0;
    MALLOC(cm->child, struct ct_peer, cm->nchild);
    for (i = 0; i < cm->nchild; i++) cm->child[i].host = host_array[i];
    free(host_array);
}

/*************************/
/* Connection management */
/*************************/

/* cm_addr: the return char * pointer should be freed if not used anymore */
static inline char * cm_addr() {
    size_t len = 128;
    char *buf = NULL;
    MALLOC(buf, char, len);
    while (gethostname(buf, len) == -1) {
        free(buf);
        len *= 2;
        MALLOC(buf, char, len);
    }
    return buf;
}

static inline int cm_bind(int fd, uint16_t *port) {
    struct sockaddr_in s_addr = {0};
    uint16_t free_port = *port;
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    s_addr.sin_port = htons(free_port);
    while (bind(fd, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1) {
        s_addr.sin_port = htons(++free_port);
        if (free_port == *port) goto fail;
    }
    if (free_port != *port) *port = free_port;
    return 0;
fail:
	close(fd);
    ERROR("bind socket to port: fd %d, port %u", fd, *port);
}

static inline int cm_listen(uint16_t *port) {
    int optval = 1;
    int listenfd = -1;
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) goto fail;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval, sizeof(optval)) == -1) goto fail;
    if (cm_bind(listenfd, port) == -1) goto fail;
    if (listen(listenfd, 10) == -1) goto fail;
    return listenfd;
fail:
	if (listenfd != -1) close(listenfd);
    ERROR("open listening socket: fd %d", listenfd);
}

static inline int cm_connect(char *addr, uint16_t port)
{
    int connfd = -1;
    uint16_t connport = 1024;
    struct addrinfo *results = NULL, *rp;
	char port_s[6];
	struct addrinfo hints = {
	    .ai_family = AF_INET,       /* IPv4 */
	    .ai_socktype = SOCK_STREAM, /* TCP socket */
	    .ai_protocol = IPPROTO_TCP, /* Any protocol */
	    .ai_flags = AI_NUMERICSERV /* numeric port is used */
	};
	snprintf(port_s, 6, "%" PRIu16, port);
	if (getaddrinfo(addr, port_s, &hints, &results) == -1) goto fail;
	for (rp = results; rp; rp = rp->ai_next) {
        if ((connfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1) continue;
        if (cm_bind(connfd, &connport) == -1) goto fail;
		if (connect(connfd, rp->ai_addr, rp->ai_addrlen) == -1) goto fail;
        break;
	}
    if (!rp) goto fail;
    return connfd;
fail:
	if (connfd != -1) close(connfd);
    ERROR("open connecting socket: fd %d, port %d", connfd, connport);
}

static inline int cm_accept(int listenfd) {
    int fd;
    if ((fd = accept(listenfd, NULL, NULL)) == -1) goto fail;
    close(listenfd);
    return fd;
fail:
    close(listenfd);
    ERROR("accept connection: listenfd %d", listenfd);
}

static inline ssize_t cm_write(int fd, const void *buf, size_t count) {
    size_t passed = 0, ret;
    if (count > SSIZE_MAX) goto fail;
    while (passed < count) {
        if ((ret = write(fd, buf + passed, count - passed)) == -1) goto fail;
        passed += ret;
    }
    return (ssize_t) passed;
fail:
    close(fd);
    ERROR("write: fd %d", fd);
}

static inline ssize_t cm_read(int fd, void *buf, size_t count) {
    size_t passed = 0, ret;
    if (count > SSIZE_MAX) goto fail;
    while (passed < count) {
        if ((ret = read(fd, buf + passed, count - passed)) == -1) goto fail;
        passed += ret;
    }
    return (ssize_t) passed;
fail:
    close(fd);
    ERROR("read: fd %d", fd);
}

static inline int cm_exchange(struct ct_cm *cm, int size, size_t len, char *buf, char *all_buf) {
    if (cm->child) {
        /* parent: get children fabric addresses, bcast full table */
        int i;
        memcpy(all_buf, buf, len);
        for (i = 0; i < cm->nchild; i++)
            cm_read(cm->child[i].fd, &all_buf[len*(i+1)], len);
        for (i = 0; i < cm->nchild; i++)
            cm_write(cm->child[i].fd, all_buf, len*size);
    } else {
        /* children: send the fabric address to parent and get full table back */
        cm_write(cm->parent->fd, buf, len);
        cm_read(cm->parent->fd, all_buf, len*size);
    }
    return 0;
}

#define INT2STR(str, len, init) char str[len]; sprintf(str, "%d", init)

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

/* cm_init: free(cm->program), free(cm->parent), free(cm->child) when done */
static inline int cm_init(int argc, char *argv[], int *size, int *rank, struct ct_cm *cm, int *verbose) {
    int i;
    *size = 0;
    *rank = -1;
    /* get arguments */
    if (!(cm->progname = realpath(argv[0], NULL)))
        ERROR("realpath(%s, NULL) returned NULL", argv[0]);
    if (argc < 1) {
        arg_help();
        ERROR("no arguments");
    }
    for (i = 1; i < argc; i++) {
        ARG(argv[i], help, arg_help());
        else ARG(argv[i], h, arg_help());
        else ARG(argv[i], verbose, *verbose = 1);
        else ARG(argv[i], v, *verbose = 1);
        else ARG(argv[i], hosts, arg_hosts(next_arg(argv, &i), size, rank, cm));
        else ARG(argv[i], rank, *rank = atoi(next_arg(argv, &i)));
        else ARG(argv[i], size, *size = atoi(next_arg(argv, &i)));
        else ARG(argv[i], addr, 
                if (!cm->parent) CALLOC(cm->parent, struct ct_peer, 1);
                cm->parent->host = next_arg(argv, &i));
        else ARG(argv[i], port, 
                if (!cm->parent) CALLOC(cm->parent, struct ct_peer, 1);
                cm->parent->port = (uint16_t)atoi(next_arg(argv, &i)));
    }
    if (!(*size) || (*rank) == -1) ERROR("incorrect parameters: size %d, rank %d", *size, *rank);
    VERBOSE(*verbose, *rank, "Verbose turned on");
    if (cm->child) {
        /* parent: start children processes and get connected */
        char *env_str = exec_env();
        char *addr_str = cm_addr();
        INT2STR(size_str, 10, *size);
        for (i = 0; i < cm->nchild; i++) {
            uint16_t port = 1024;
            int listenfd = cm_listen(&port);
            INT2STR(port_str, 10, (int)port);
            INT2STR(rank_str, 10, i+1);
            if ((cm->child[i].pid = fork()) == 0)
                execlp("ssh", "ssh", cm->child[i].host, env_str, cm->progname,
                        "-rank", rank_str, "-size", size_str,
                        "-addr", addr_str, "-port", port_str, (*verbose) ? "-v" : "", NULL);
            else if (cm->child[i].pid < 0)
                ERROR("Couldn't run %s %s %s %s",
                        "ssh", cm->child[i].host, env_str, cm->progname);
            cm->child[i].fd = cm_accept(listenfd);
        }
        free(addr_str);
        free(env_str);
    } else {
        /* children: connect to parent */
        cm->parent->fd = cm_connect(cm->parent->host, cm->parent->port);
    }
    return 0;
}

static inline int cm_finalize(struct ct_cm * cm) {
    int i, status;
    for (i = 0; i < cm->nchild; i++)
        if (wait(&status) == -1) ERROR("wait returned -1");
    free(cm->child);
    free(cm->parent);
    free(cm->progname);
    return 0;
}

static inline void cm_print(int verbose, int rank, struct ct_cm *cm) {
    int i;
    VERBOSE(verbose, rank, "progname: %s", cm->progname);
    if (cm->parent)
        VERBOSE(verbose, rank, "parent: host %s, fd %d, port %u",
                cm->parent->host, cm->parent->fd, cm->parent->port);
    VERBOSE(verbose, rank, "nchild: %d", cm->nchild);
    if (cm->child)
        for (i = 0; i < cm->nchild; i++)
            VERBOSE(verbose, rank, "child[%d]: host %s, fd %d, port %u",
                    i, cm->child[i].host, cm->child[i].fd, cm->child[i].port);
}

/*********************/
/* Fabric management */
/*********************/

#define FI_CALL(call) if (call) ERROR(#call " failed")

/* fm_info: do fi_freeinfo(fi->info), free(fi->fi_addr) when done */
static inline int fm_init(int size, struct ct_fi *fi, struct ct_cm *cm) {
    char addr[64], *addr_table = NULL;
    size_t addrlen = sizeof(addr);
    struct fi_info *hints, *info;
    struct fi_cq_attr cq_attr = {0};
    struct fi_av_attr av_attr = {0};
    hints = fi_allocinfo();
    hints->ep_attr->type = FI_EP_RDM;
    hints->caps = FI_TAGGED;
    hints->mode = FI_CONTEXT;
    FI_CALL(fi_getinfo(FI_VERSION(1, 5), NULL, NULL, 0, hints, &fi->info));
    fi_freeinfo(hints);
    FI_CALL(fi_fabric(fi->info->fabric_attr, &fi->fabric, NULL));
    FI_CALL(fi_domain(fi->fabric, fi->info, &fi->domain, NULL));
    cq_attr.format = FI_CQ_FORMAT_CONTEXT;
    FI_CALL(fi_cq_open(fi->domain, &cq_attr, &fi->cq, NULL));
    av_attr.type = fi->info->domain_attr->av_type;
    FI_CALL(fi_av_open(fi->domain, &av_attr, &fi->av, NULL));
    FI_CALL(fi_endpoint(fi->domain, fi->info, &fi->ep, NULL));
    FI_CALL(fi_ep_bind(fi->ep, &fi->av->fid, 0));
    FI_CALL(fi_ep_bind(fi->ep, &fi->cq->fid, FI_SEND|FI_RECV));
    FI_CALL(fi_enable(fi->ep));
    FI_CALL(fi_getname(&fi->ep->fid, addr, &addrlen));
    MALLOC(fi->fi_addr, fi_addr_t, size);
    MALLOC(addr_table, char, addrlen*size);
    cm_exchange(cm, size, addrlen, addr, addr_table);
    FI_CALL(size != fi_av_insert(fi->av, addr_table, size, fi->fi_addr, 0, NULL));
    free(addr_table);
    return 0;
}

#define SEND(ep, buf, len, addr, tag, ctx) \
    FI_CALL(fi_tsend(ep, buf, len, NULL, addr, tag, ctx))
#define RECV(ep, buf, len, addr, tag, ctx) \
    FI_CALL(fi_trecv(ep, buf, len, NULL, addr, tag, 0, ctx))
#define WAIT(cq) \
    do { \
        struct fi_cq_entry _wc[1]; \
        int _ret = fi_cq_read(cq, (void *)_wc, 1); \
        if (_ret > 0) break; \
        else if (_ret < 0 && _ret != -FI_EAGAIN) \
            ERROR("fi_cq_read returned %d", _ret); \
    } while(1)

static inline int fm_barrier(int size, int rank, struct ct_fi *fi) {
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

static inline int fm_finalize(int size, int rank, struct ct_fi *fi) {
    fm_barrier(size, rank, fi);
    fi_freeinfo(fi->info);
    free(fi->fi_addr);
    return 0;
}

/***********************/
/* Schedule management */
/***********************/

static inline struct fi_sched_op* sched_barrier(struct fi_sched_space *space, int size, int rank) {
    /* algorithm: dissemination */
    struct fi_sched_op *op = fi_sched_op_create(space, FI_SCHED_OP_CODE_LIST, NULL);
    struct fi_sched_op_list **tail = &op->u.list;
    int mask;
    for (mask = 0x1; mask < size; mask <<= 1)
        if (rank & mask)
            tail = fi_sched_op_list_populate(space, tail,
                    fi_sched_op_create(space, FI_SCHED_OP_CODE_ELEMENT,
                        FI_SCHED_OP_ELEMENT_CODE_SENDRECV, 0, rank-mask, 0, rank-mask));
        else if (rank + mask < size)
            tail = fi_sched_op_list_populate(space, tail,
                    fi_sched_op_create(space, FI_SCHED_OP_CODE_ELEMENT,
                        FI_SCHED_OP_ELEMENT_CODE_SENDRECV, 0, rank+mask, 0, rank+mask));
    return op;
}

/***********/
/* Program */
/***********/

int main(int argc, char *argv[])
{
    int size = 0;
    int rank = -1;
    int verbose = 0;
    struct ct_cm cm = {0};
    struct ct_fi fi = {0};

    /* init connection info */
    cm_init(argc, argv, &size, &rank, &cm, &verbose);

    /* init fabric */
    VERBOSE(verbose, rank, "about to init fabrics");
    fm_init(size, &fi, &cm);
    cm_print(verbose, rank, &cm);

    char *space;
    size_t space_len = 1024*1024;
    MALLOC(space, char, space_len);
    struct fi_sched_space sched_space = {space, space_len, (size_t)0};

    /* barrier example */
    struct fi_sched_op *op = sched_barrier(&sched_space, size, rank);
    if (verbose) fi_sched_op_print(op, 0);
    VERBOSE(verbose, rank, "space used: %lu bytes", sched_space.used);
    struct fi_sched_ep ep = {fi.ep, fi.cq};
    struct fi_sched_buf buf = {0};
    struct fi_sched_header header = {
        /* ep info */
        1, /* int ntx; */
        &ep, /* struct fi_sched_ep *tx; */
        1, /* int nrx; */
        &ep, /* struct fi_sched_ep *rx; */
        /* buffers info */
        1, /* int nbuf; */
        &buf, /* struct fi_sched_buf *buf; */
        /* reduction info */
        0, /* int datatype; */
        0, /* int op; */
        /* addressing info */
        size, /* int ngroup; */
        fi.fi_addr, /* fi_addr_t *group; */
        /* matching info */
        (size_t) rank, /* size_t rank; */
        0xff00ff00, /* uint64_t match_bits; */
        /* flags */
        0 /* uint64_t flags; */
    };
    struct fi_sched sched = {&header, op};
    fi_sched_issue(&sched);
    struct fi_cq_tagged_entry wc[1];
    int completed = 0;
    do {
        fi_sched_wait(&sched, (void *)wc, 1, &completed);
    } while (!completed);

    free(space);

    /* wait for children and clean-up*/
    VERBOSE(verbose, rank, "about to exit program");
    fm_finalize(size, rank, &fi);
    cm_finalize(&cm);
    VERBOSE(verbose, rank, "done");
}
