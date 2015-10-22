/* $Id$
 */

/* Extended file descriptor.
 */
typedef struct {
    int     tf_fd;
    int     tf_opencnt;
    void   *tf_base;
} tb_fd_t;


/* Record definitition.
 */
typedef struct {
    uint64_t    tr_magic;
    uint64_t    tr_version;
    uint32_t    tr_rec_max;
    uint32_t    tr_rec_sz;
    uint32_t    tr_pad;
    uint32_t    tr_uniqid;
    uint64_t    tr_sec;
    uint64_t    tr_usec;
    uint32_t    tr_id;
    uint32_t    tr_updates;
    uint64_t    tr_hash[2];
} tb_rec_t;


/* Record operations.
 */
typedef tb_fd_t  *tb_open_t(const char *path, int flags, uint32_t rec_id);
typedef void    tb_close_t(tb_fd_t *tbfd);

typedef void    tb_init_t(tb_rec_t *rec, uint32_t rec_id);

typedef int     tb_get_t(tb_rec_t *rec, uint32_t rec_id, int n, tb_fd_t *tbfd);
typedef int     tb_put_t(tb_rec_t *rec, int n, tb_fd_t *tbfd);
typedef void    tb_update_t(tb_rec_t *rec);
typedef void    tb_verify_t(tb_rec_t *rec);

typedef struct {
    tb_open_t      *tb_open;
    tb_close_t     *tb_close;
    tb_init_t      *tb_init;
    tb_get_t       *tb_get;
    tb_put_t       *tb_put;
    tb_update_t    *tb_update;
    tb_verify_t    *tb_verify;
} tb_ops_t;

extern tb_ops_t *tb_find(const char *type);
