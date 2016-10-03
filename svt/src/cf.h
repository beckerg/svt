/* $Id$
 */

typedef struct {
    char         *cf_dir;               // Path to config file directory
    char         *tb_path;              // Path to test bed
    uint          tb_rec_max;           // Max number of records in test bed
    uint          tb_rec_sz;            // On-disk record size (includes padding)
    uint          cf_jobs_max;          // Max number of worker processes
    uint          cf_range_max;         // Max number of recs to swap
    uint          cf_range_min;         // Min number of recs to swap
    time_t        cf_runtime_max;       // Max number of seconds to run test
    uint          cf_swaps_pct;         // Percent of swap puts to gets
    int           cf_mmap;              // Use mmap() if true
    int           cf_status_interval;   // Status dump interval in seconds
} cf_t;


extern cf_t cf;

extern void cf_load(void);
extern void cf_save(void);
