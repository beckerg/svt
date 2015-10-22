/* $Id$
 */

typedef struct {
    char         *cf_dir;               // Path to config file directory
    char         *tb_path;              // Path to test bed
    u_int         tb_rec_max;           // Max number of records in test bed
    u_int         tb_rec_sz;            // On-disk record size (includes padding)
    u_int         cf_procs_max;         // Max number of worker processes
    time_t        cf_runtime_max;       // Max number of seconds to run test
    int           cf_mmap;              // Use mmap() if true
    int           cf_status_interval;   // Status dump interval in seconds
} cf_t;


extern cf_t cf;

extern void cf_load(void);
extern void cf_save(void);
