/* $Id$
 */

/* Run-time check-file record definition.
 */
typedef struct {
    uint64_t    rtck_hash[2];
} rtck_t;

extern void     rtck_create(void);
extern void     rtck_open(void);
extern void     rtck_close(void);

extern void     rtck_get(uint64_t *hash, uint32_t rec_id);
extern void     rtck_put(const uint64_t *hash, uint32_t rec_id);
extern void     rtck_verify(const uint64_t *hash, uint32_t rec_id);

extern int      rtck_wlock(uint32_t rec_id, int range);
extern int      rtck_wunlock(uint32_t rec_id, int range);
