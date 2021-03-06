/*
 * Copyright (c) 2015,2016 Greg Becker.  All rights reserved.
 */

/* Run-time check-file record definition.
 */
typedef struct {
    uint64_t    rtck_hash;
    uint64_t    rtck_val;
} rtck_t;

extern void     rtck_create(void);
extern void     rtck_open(void);
extern void     rtck_close(void);

extern void     rtck_hash_get(uint32_t rec_id, uint64_t *hash);
extern void     rtck_hash_set(uint32_t rec_id, const uint64_t *hash);
extern void     rtck_hash_verify(uint32_t rec_id, const uint64_t *hash);

extern void     rtck_val_get(uint32_t rec_id, uint64_t *val);
extern void     rtck_val_set(uint32_t rec_id, uint64_t val);

extern int      rtck_wlock(uint32_t rec_id, int range);
extern int      rtck_wunlock(uint32_t rec_id, int range);
