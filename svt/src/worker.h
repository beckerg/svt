/* $Id$
 */
#ifndef SVT_WORKER_H
#define SVT_WORKER_H

#ifndef ulong
typedef unsigned long ulong;
#endif

typedef enum {
    OP_NULL,
    OP_INIT,
    OP_LOOP,
    OP_DONE,
    OP_OPEN,
    OP_CLOSE,
    OP_VERIFY,
    OP_DEADLOCK,
    OP_WLOCK1,
    OP_WLOCK2,
    OP_WUNLOCK1,
    OP_WUNLOCK2,
    OP_GET1,
    OP_GET2,
    OP_PUT1,
    OP_PUT2,
} op_t;

/* Worker stats
 */
typedef struct {
    ulong           s_gets;     // Number of gets/reads done by this worker
    ulong           s_puts;     // Number of puts/writes done by this worker
    ulong           s_recs;     // Number of records swapped by this worker
} worker_stats_t;

/* Worker state
 */
typedef struct {
    __attribute__((__aligned__(4096)))
    uint            w_id;
    pid_t           w_pid;
    struct timeval  w_start;
    struct timeval  w_stop;
    uint            w_frec;    // First rec to process (inclusive)
    uint            w_lrec;    // Last rec to process (exclusive)

    worker_stats_t  w_astats;   // Active stats
    worker_stats_t  w_fstats;   // Frozen/stabilized stats
    worker_stats_t  w_ostats;   // Old/previous stats

    op_t            w_op;       // Current operation
    bool            w_exited;   // 'true' if worker exited
    int             w_status;   // wait3() status code
    struct rusage   w_rusage;
} worker_t;

typedef void worker_init_t(worker_t *, tb_ops_t *ops);
typedef void worker_fini_t(worker_t *, tb_ops_t *ops);
typedef void worker_run_t(worker_t *, tb_ops_t *ops);

extern volatile sig_atomic_t sigxxx_cnt;
extern volatile sig_atomic_t sigint_cnt;
extern volatile sig_atomic_t sigchld_cnt;

extern const char *op2txt[];

void
worker_run(worker_init_t *, worker_fini_t *, worker_run_t *, tb_ops_t *);

#endif /* SVT_WORKER_H */
