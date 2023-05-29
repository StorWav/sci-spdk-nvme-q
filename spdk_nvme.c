/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *
 *   Copyright (c) 2019-2021 Mellanox Technologies LTD. All rights reserved.
 *   Copyright (c) 2021, 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*-
 *   This file is part of sci-spdk-nvme-q (SSNQ) library.
 * 
 *   spdk_nvme.c
 * 
 *   Backend SPDK/NVMe IO interfaces for frontend intercepted system calls
 * 
 *   Part of this file comes from spdk/examples/nvme/perf/perf.c which is the
 *   SPDK's built-in performance evaluation tool, therefore its associated
 *   BSD LICENSE and Copyright Notice is retained as required (see above).
 *
 *   For details about SPDK please visit https://spdk.io/
 *
 *   Author: Colin Zhu <czhu@nexnt.com>
 */

#pragma GCC diagnostic ignored "-Wmissing-declarations"
#pragma GCC diagnostic ignored "-Wunused-result"
#pragma GCC diagnostic ignored "-Wformat-truncation="

#include "spdk/stdinc.h"
#include "spdk/env.h"
#include "spdk/fd.h"
#include "spdk/nvme.h"
#include "spdk/queue.h"
#include "spdk/string.h"
#include "spdk/nvme_intel.h"
#include "spdk/histogram_data.h"
#include "spdk/endian.h"
#include "spdk/dif.h"
#include "spdk/util.h"
#include "spdk/likely.h"
#include "spdk/sock.h"

#include <linux/aio_abi.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sys/time.h>

#include "sci_spdk_nvme.h"
#include "ssnq_list.h"

struct ctrlr_entry {
	struct spdk_nvme_ctrlr *ctrlr;
	enum spdk_nvme_transport_type trtype;
	struct spdk_nvme_qpair **unused_qpairs;
	TAILQ_ENTRY(ctrlr_entry) link;
	char name[1024];
};

enum entry_type {
	ENTRY_TYPE_NVME_NS,
	ENTRY_TYPE_AIO_FILE,
	ENTRY_TYPE_URING_FILE,
};

struct ns_fn_table;

struct ns_entry {
	enum entry_type type;
	const struct ns_fn_table *fn_table;

	union {
		struct {
			struct spdk_nvme_ctrlr *ctrlr;
			struct spdk_nvme_ns *ns;
		} nvme;
	} u;

	TAILQ_ENTRY(ns_entry) link;
	uint32_t num_io_requests;
	uint32_t sector_size;
	uint32_t block_size;
	uint32_t md_size;
	bool md_interleave;
	unsigned int seed;
	bool pi_loc;
	enum spdk_nvme_pi_type pi_type;
	uint32_t io_flags;
	char name[1024];
	char *dev_sn;	/* device sn */
	uint32_t nsid;	/* device namespace id */
};

struct ns_worker_ctx {
	struct ns_entry *entry;
	uint64_t current_queue_depth;
	uint64_t offset_in_ios;
	bool is_draining;

	union {
		struct {
			int num_active_qpairs;
			int num_all_qpairs;
			struct spdk_nvme_qpair **qpair;
			struct spdk_nvme_poll_group *group;
			int last_qpair;
		} nvme;
	} u;

	TAILQ_ENTRY(ns_worker_ctx) link;
	
	struct sci_ns_rings *rings;
	uint64_t ctx_id;
	int cpu;
	int pool_idx;
};

struct perf_task {
	struct ns_worker_ctx *ns_ctx;
	struct iovec *iovs;		/* array of iovecs to transfer. */
	int iovcnt;				/* Number of iovecs in iovs array. */
	int iovpos; 			/* Current iovec position. */
	uint32_t iov_offset; 	/* Offset in current iovec. */
	uint64_t submit_tsc;
	bool is_read;
	struct spdk_dif_ctx dif_ctx;
	struct list_head list;

	void *user_buf;
	void *user_iocb;
	int io_size;
	uint32_t io_size_blocks;
	uint64_t disk_offset;
	void (*callback)(void *iocb, uint64_t reserved_1, uint64_t reserved_2);

	sci_comp_cb *comp_cb;	
	uint64_t reserved_1;	/* aio_context_t ctx_id */
	uint64_t reserved_2;
	
	int state;
#define SCI_TASK_FREE		0
#define SCI_TASK_REQ_IN		1
#define SCI_TASK_REQ_OUT	2
#define SCI_TASK_RSP_IN		3
#define SCI_TASK_RSP_OUT	4
};

struct worker_thread {
	TAILQ_HEAD(, ns_worker_ctx) ns_ctx;
	TAILQ_ENTRY(worker_thread) link;
	unsigned lcore;
	pthread_t thread;
};

struct ns_fn_table {
	void (*setup_payload)(struct perf_task *task, uint8_t pattern);
	int (*submit_io)(struct perf_task *task, struct ns_worker_ctx *ns_ctx,
			     struct ns_entry *entry, uint64_t offset_in_ios);
	int64_t (*check_io)(struct ns_worker_ctx *ns_ctx);
	void (*verify_io)(struct perf_task *task, struct ns_entry *entry);
	int (*init_ns_worker_ctx)(struct ns_worker_ctx *ns_ctx);
	void (*cleanup_ns_worker_ctx)(struct ns_worker_ctx *ns_ctx);
	void (*dump_transport_stats)(uint32_t lcore, struct ns_worker_ctx *ns_ctx);
};

static TAILQ_HEAD(, ctrlr_entry) g_controllers = TAILQ_HEAD_INITIALIZER(g_controllers);
static TAILQ_HEAD(, ns_entry) g_namespaces = TAILQ_HEAD_INITIALIZER(g_namespaces);
static int g_num_namespaces;
static TAILQ_HEAD(, worker_thread) g_workers = TAILQ_HEAD_INITIALIZER(g_workers);
static int g_num_workers = 0;
static uint32_t g_main_core;
static pthread_barrier_t g_worker_sync_barrier;

static uint32_t g_metacfg_pract_flag;
static uint32_t g_metacfg_prchk_flags;
static int g_nr_io_queues_per_ns = 1;
static int g_nr_unused_io_queues;
static uint32_t g_max_completions;
static uint32_t g_disable_sq_cmb;
static bool g_warn;
static bool g_header_digest;
static bool g_data_digest;
static bool g_no_shn_notification;
/* The flag is used to exit the program while keep alive fails on the transport */
static bool g_exit;
/* Default to 10 seconds for the keep alive value. This value is arbitrary. */
static uint32_t g_keep_alive_timeout_in_ms = 10000;
static uint32_t g_quiet_count = 1;

/* When user specifies -Q, some error messages are rate limited.  When rate
 * limited, we only print the error message every g_quiet_count times the
 * error occurs.
 *
 * Note: the __count is not thread safe, meaning the rate limiting will not
 * be exact when running perf with multiple thread with lots of errors.
 * Thread-local __count would mean rate-limiting per thread which doesn't
 * seem as useful.
 */
#define RATELIMIT_LOG(...) \
	{								\
		static uint64_t __count = 0;				\
		if ((__count % g_quiet_count) == 0) {			\
			if (__count > 0 && g_quiet_count > 1) {		\
				fprintf(stderr, "Message suppressed %" PRIu32 " times: ",	\
					g_quiet_count - 1);		\
			}						\
			fprintf(stderr, __VA_ARGS__);			\
		}							\
		__count++;						\
	}

static pthread_mutex_t g_stats_mutex;

#define MAX_ALLOWED_PCI_DEVICE_NUM 128
static struct spdk_pci_addr g_allowed_pci_addr[MAX_ALLOWED_PCI_DEVICE_NUM];

struct trid_entry {
	struct spdk_nvme_transport_id trid;
	uint16_t nsid;
	char hostnqn[SPDK_NVMF_NQN_MAX_LEN + 1];
	TAILQ_ENTRY(trid_entry) tailq;
	char dev_sn[SN_SIZE];
};

static TAILQ_HEAD(, trid_entry) g_trid_list = TAILQ_HEAD_INITIALIZER(g_trid_list);

static inline void
task_complete(struct perf_task *task);

/* connections with syscall intercept module */
static struct worker_thread *workers_by_cpu[MAX_CPU_CNT];

/*****
 * SCI-SPDK parameters shared by sci_spdk_q.c and spdk_nvme.c
 *****/
#define MMAP_SCRATCH_CNT_LIMIT 2048
static uint64_t MMAP_UNIT_SIZE = 104857600ULL;
static int MAX_MMAP_CNT = 128;
static uint64_t SCRATCH_UNIT_SIZE = 536870912ULL;
static int MAX_SCRATCH_CNT = 40;
uint64_t SUBMIT_CHUNK_SIZE = 104857600ULL;

static uint32_t kdb_max_io_size = DEFAULT_MAX_IO_SIZE;
static int kdb_q_depth = MAX_Q_DEPTH;
static int kdb_io_align = DEFAULT_IO_ALIGN;
static int spdk_init_flag = 0;

static struct nvme_dummy_dev_t nvme_devs[MAX_JOB_CNT];
static int disk_config_count = 0;

/**
 * Load SSNQ config
 */
static char KIO_CONF_FILE[PATH_MAX] = {'\0'};
static char KDB_MAP_FILE[PATH_MAX] = {'\0'};
static char KDB_LIC_DIR[PATH_MAX] = {'\0'};
static char SSNQ_DBG_LEVEL[PATH_MAX] = {'\0'};
static void get_token_from_path_file(const char *desc, char *dest_str)
{
	FILE* file = fopen("SSNQ.path", "r");
	char line[PATH_MAX];
	char *token = NULL;

	while (fgets(line, PATH_MAX, file)) {
		char *is_desc_line = strstr(line, desc);
		if (is_desc_line == NULL)
			continue;

		token = strstr(line, ":=");

		if (token) {
			token += 2;  // Skip past ":=".
			while (isspace((unsigned char)*token)) {
				token++;  // Skip leading whitespace.
			}
			// Remove trailing whitespace.
			size_t len = strlen(token);
			while (len > 0 && isspace((unsigned char)token[len-1])) {
				token[--len] = '\0';
			}
			break;
		}
	}

	fclose(file);

	if (token == NULL || strlen(token) <= 0) {
		printf("ERROR: missing %s in file SSNQ.path\n", desc);
		exit(1);
	}
	
	strcpy(dest_str, token);
}

static char kdb_cfg_line[BUFSIZ] = { '\0' };
void remove_spaces(char *str)
{
	int count = 0;
	for (int i = 0; str[i]; i++)
		if (!isspace(str[i])) str[count++] = str[i];
	str[count] = '\0';
}
static void spdk_nvme_dev_add_addr(int diskidx, const char *kdb_fn)
{
	struct nvme_dummy_dev_t *dev = &nvme_devs[diskidx];
	snprintf(dev->pci_name, PCI_ADDR_SIZE, "%s", kdb_fn);
}
static void spdk_nvme_dev_add_sn(int diskidx, const char *sn)
{
	struct nvme_dummy_dev_t *dev = &nvme_devs[diskidx];
	snprintf(dev->sn, SN_SIZE, "%s", sn);
}
static void spdk_nvme_dev_add_nsid(int diskidx, int nsid)
{
	struct nvme_dummy_dev_t *dev = &nvme_devs[diskidx];
	dev->nsid = nsid;
}
static void spdk_nvme_dev_add_cpu(int diskidx, int cpu)
{
	struct nvme_dummy_dev_t *dev = &nvme_devs[diskidx];
	assert(cpu >= 0 && cpu < MAX_CPU_CNT);
	dev->cpu = cpu;
}
static int spdk_get_kdb_config(void)
{
	FILE *file = NULL;
	
	file = fopen(KIO_CONF_FILE, "r");
	if (file == NULL)
		return 1;

	/* get kdb io pattern config */
	while(fgets(kdb_cfg_line, sizeof(kdb_cfg_line), file) != NULL) {
		remove_spaces(kdb_cfg_line);

		if (kdb_cfg_line[0] == '#')
			continue;
		
		char *p_end;
		
		if (strstr(kdb_cfg_line, "mmap_unit_size="))
			MMAP_UNIT_SIZE = strtol(kdb_cfg_line+15, &p_end, 10);
		if (strstr(kdb_cfg_line, "max_mmap_cnt="))
			MAX_MMAP_CNT = strtol(kdb_cfg_line+13, &p_end, 10);
		if (strstr(kdb_cfg_line, "scratch_unit_size="))
			SCRATCH_UNIT_SIZE = strtol(kdb_cfg_line+18, &p_end, 10);
		if (strstr(kdb_cfg_line, "max_scratch_cnt="))
			MAX_SCRATCH_CNT = strtol(kdb_cfg_line+16, &p_end, 10);
		if (strstr(kdb_cfg_line, "submit_chunk_size="))
			SUBMIT_CHUNK_SIZE = strtol(kdb_cfg_line+18, &p_end, 10);
	}
	fclose(file);
	file = NULL;
	
	if (MAX_MMAP_CNT > MMAP_SCRATCH_CNT_LIMIT) {
		SCI_SPDK_LOG(DBG_ERR, 1, "[SPDK] ERROR: invalid max_mmap_cnt %d, must be [1,%d]\n", MAX_MMAP_CNT, MMAP_SCRATCH_CNT_LIMIT);
		goto err;
	}

	if (MAX_SCRATCH_CNT > MMAP_SCRATCH_CNT_LIMIT) {
		SCI_SPDK_LOG(DBG_ERR, 1, "[SPDK] ERROR: invalid max_scratch_cnt %d, must be [1,%d]\n", MAX_SCRATCH_CNT, MMAP_SCRATCH_CNT_LIMIT);
		goto err;
	}
	
	if (kdb_q_depth > MAX_Q_DEPTH) {
		SCI_SPDK_LOG(DBG_ERR, 1, "[SPDK] ERROR: invalid queue_depth %d, must be [1,%d]\n", kdb_q_depth, MAX_Q_DEPTH);
		goto err;
	}
	
	if (kdb_io_align != 512 && kdb_io_align != 4096) {
		SCI_SPDK_LOG(DBG_ERR, 1, "[SPDK] ERROR: invalid io_align %d, must be either 512 or 4096\n", kdb_io_align);
		goto err;
	}
	
	SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] MMAP_UNIT_SIZE(%lu) MAX_MMAP_CNT(%d) SCRATCH_UNIT_SIZE(%lu) MAX_SCRATCH_CNT(%d) SUBMIT_CHUNK_SIZE(%lu)\n",
			MMAP_UNIT_SIZE, MAX_MMAP_CNT, SCRATCH_UNIT_SIZE, MAX_SCRATCH_CNT, SUBMIT_CHUNK_SIZE);
	
	/* get kdb job config */
	file = fopen(KIO_CONF_FILE, "r");
	if (file == NULL)
		return 1;
	
	int disk_idx = 0;
	while(fgets(kdb_cfg_line, sizeof(kdb_cfg_line), file) != NULL) {
		if (kdb_cfg_line[0] == '#')
			continue;
			
		if (!strstr(kdb_cfg_line, "disk"))
			continue;

		char sn[SN_SIZE];
		char addr[PCI_ADDR_SIZE];
		int disknum;
		int cpu;
		int nsid;

		/* TODO: use something like "%31s" to ensure kdb_cfg_line won't overflow sn and addr */
		sscanf(kdb_cfg_line, "disk%d %s %s %d %d", &disknum, sn, addr, &nsid, &cpu);

		/* TODO: verify input values */

		/* Note: ignore disknum, always use disk_idx for the order */
		spdk_nvme_dev_add_sn(disk_idx, sn);
		spdk_nvme_dev_add_addr(disk_idx, addr);
		spdk_nvme_dev_add_nsid(disk_idx, nsid);
		spdk_nvme_dev_add_cpu(disk_idx, cpu);
		disk_idx++;
	}
	fclose(file);
	file = NULL;
	
	disk_config_count = disk_idx;
	
	for (int i=0; i<MAX_JOB_CNT; i++) {
		struct nvme_dummy_dev_t *dev = &nvme_devs[i];
		if (dev->cpu < 0)
			continue;
		SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] nvme sn(%s) pci(%s) cpu(%d)\n",
			dev->sn, dev->pci_name, dev->cpu);
	}
		
	return 0;
	
err:
	if (file != NULL)
		fclose(file);
	exit(1);
}

/*****
 * Exported functions to be called by sci_spdk_q.c
 *****/
int spdk_check_init_status(void)
{
	return spdk_init_flag;
}

static uint64_t total_size = 0;
static uint64_t total_ns = 0;
static uint64_t min_ns = 0xFFFFFFFFFFFFFFFFULL;
static uint64_t max_ns = 0;
static uint64_t total_io = 0;
static pthread_mutex_t stats_lock;

/***
 * ns_ctx requset and response rings
 ***/
struct sci_ns_rings {
	pthread_mutex_t req_q_lock;
	pthread_mutex_t rsp_q_lock;
	int req_q_in;
	int req_q_next_fill;
	struct perf_task *req_q[MAX_RING_CNT];
};
static inline int submit_single_io(struct perf_task *task);
static int sci_req_q_send_task(struct ns_worker_ctx *ns_ctx, size_t io_size, 
	bool is_read, uint64_t offset, char wr_char, 
	void *user_buf, void *user_iocb, void *callback,
	uint64_t reserved_1, uint64_t reserved_2, sci_comp_cb *comp_cb)
{
	int rval = 0;
	size_t curr_size = io_size;
	uint64_t curr_off = offset;
	void *curr_buf = user_buf;
	
	while (curr_size > 0) {
		struct perf_task io_task;
		struct perf_task *task = &io_task;
		struct iovec iovs;
		memset((void *)task, 0, sizeof(struct perf_task));
		memset((void *)&iovs, 0, sizeof(struct iovec));
		
		size_t sub_io_size = min(curr_size, SUBMIT_CHUNK_SIZE);
	
		task->io_size = sub_io_size;
		task->is_read = is_read;
		task->disk_offset = curr_off;
		task->user_buf = curr_buf;
		task->user_iocb = user_iocb;
		task->state = SCI_TASK_REQ_IN;
		task->callback = callback;
		task->reserved_1 = reserved_1;
		task->reserved_2 = reserved_2;
		task->comp_cb = comp_cb;

		task->iovcnt = 1;
		task->iovs = &iovs;
		task->ns_ctx = ns_ctx;		
	
		rval = submit_single_io(task);
		
		curr_size -= sub_io_size;
		curr_off += sub_io_size;
		curr_buf += sub_io_size;
	}
	
	return rval;	
}

/**
 * mmap buffer and scratch buffer
 */

typedef struct mmap_info {
	uint64_t unit_size;
	int max_cnt;
	int *inuse_table;
	//pthread_mutex_t table_lock;
	int next_idx;
	void *ptr;
} mmap_info_t;

static mmap_info_t mmap_info;
static mmap_info_t scratch_info;
static int mmap_inuse_table[MMAP_SCRATCH_CNT_LIMIT];
static int scratch_inuse_table[MMAP_SCRATCH_CNT_LIMIT];
static void *ssnq_mmap_ptr = NULL;
static void *scratch_buf = NULL;
static pthread_mutex_t mmap_table_lock;

void alloc_mmap_info(void)
{
	mmap_info.unit_size = MMAP_UNIT_SIZE;
	mmap_info.max_cnt = MAX_MMAP_CNT;
	mmap_info.next_idx = 0;
	mmap_info.inuse_table = &mmap_inuse_table[0];
	mmap_info.ptr = ssnq_mmap_ptr;
}

void alloc_scratch_info(void)
{
	scratch_info.unit_size = SCRATCH_UNIT_SIZE;
	scratch_info.max_cnt = MAX_SCRATCH_CNT;
	scratch_info.next_idx = 0;
	scratch_info.inuse_table = &scratch_inuse_table[0];
	scratch_info.ptr = scratch_buf;
}

void *get_mmap_entry(mmap_info_t *info, uint64_t file_size, bool is_scratch)
{
	void *buf = NULL;
	int search_cnt = info->max_cnt;
	
	pthread_mutex_lock(&mmap_table_lock);
	if (file_size > info->unit_size) {
		int chunk_needed = (file_size % info->unit_size == 0 ? file_size/info->unit_size : file_size/info->unit_size+1);
		int chunk_acquired = 0;
		int64_t start_idx = -1;
		
		/* can't go round back to index 0, has to be contegious chunks from 0 to max_cnt-1 */
		while (search_cnt > 0) {
			if (chunk_acquired == chunk_needed)
				break;
	
			if (start_idx != -1 && info->inuse_table[info->next_idx]) {
				start_idx = -1;
				chunk_acquired = 0;
				goto next_round;
			}
			else if (start_idx != -1 && !info->inuse_table[info->next_idx]) {
				chunk_acquired++;
				goto next_round;
			}
			else if (info->inuse_table[info->next_idx])
				goto next_round;
			
			start_idx = info->next_idx;
			chunk_acquired++;
			
		next_round:
			info->next_idx++;
			if (info->next_idx>=info->max_cnt)
				info->next_idx=0;

			/* special case: next idx wrap round, chain broken, must start over */
			if (chunk_acquired != chunk_needed &&
				info->next_idx == 0) {
				start_idx = -1;
				chunk_acquired = 0;				
			}
			
			search_cnt--;		
		}
		if (start_idx != -1 && chunk_needed == chunk_acquired) {
			buf = info->ptr + start_idx*info->unit_size;
			for (int64_t i=start_idx; i<start_idx+chunk_acquired; i++) {
				SCI_SPDK_LOG(DBG_HDB, -1, "[SPDK] %s: file_size(%lu) addr(%p) start_addr(%p) chunk_idx(%d)\n",
					is_scratch ? "GET_SCRATCH_SIZE_SG" : "GET_MMAP_SIZE_SG", file_size, info->ptr, buf, i);
				info->inuse_table[i] = 1;
			}
		}		
	}
	else  {
		while (search_cnt) {
			if (info->inuse_table[info->next_idx])
				goto next;
				
			buf = info->ptr + info->next_idx*info->unit_size;
			info->inuse_table[info->next_idx] = 1;
			SCI_SPDK_LOG(DBG_HDB, -1, "[SPDK] %s: file_size(%lu) addr(%p) start_addr(%p) chunk_idx(%d)\n",
				is_scratch ? "GET_SCRATCH_SIZE_1" : "sGET_MMAP_SIZE_1", file_size, info->ptr, buf, info->next_idx);
			info->next_idx++;
			if (info->next_idx>=info->max_cnt)
				info->next_idx=0;
			break;
		
next:
			info->next_idx++;
			if (info->next_idx>=info->max_cnt)
				info->next_idx=0;
			search_cnt--;
		}
	}
	pthread_mutex_unlock(&mmap_table_lock);
	
	return buf;
}
void put_mmap_entry(mmap_info_t *info, void *buf, uint64_t mmap_size, bool is_scratch)
{
	int chunk_acquired = (mmap_size % info->unit_size == 0 ? mmap_size/info->unit_size : mmap_size/info->unit_size+1);
	int start_idx = (buf - info->ptr) / info->unit_size;
		
	pthread_mutex_lock(&mmap_table_lock);
	for (int i=start_idx; i<start_idx+chunk_acquired; i++) {
		SCI_SPDK_LOG(DBG_HDB, -1, "[SPDK] %s: mmap_size(%lu) addr(%p) start_addr(%p) chunk_idx(%d)\n",
				is_scratch ? "PUT_SCRATCH" : "PUT_MMAP", mmap_size, info->ptr, buf, i);
		info->inuse_table[i] = 0;
	}
	pthread_mutex_unlock(&mmap_table_lock);
}
void sci_unmmap_region(void *mmap_addr, size_t size)
{
	put_mmap_entry(&mmap_info, mmap_addr, size, false);
}
void *sci_alloc_spdk_mem(uint64_t len)
{
	return get_mmap_entry(&scratch_info, len, true);
}
void sci_free_spdk_mem(void *buf, uint64_t mmap_size)
{
	put_mmap_entry(&scratch_info, buf, mmap_size, true);
}

void *sci_submit_mmap_io(int disk_idx,
						uint64_t disk_offset, 
						uint64_t file_size)
{
	int rc;
	struct timespec timeout;
	uint64_t start_ns, end_ns;

	uint64_t file_size_4k = (file_size % 4096 == 0 ? file_size : (file_size/4096+1)*4096);
	
	SCI_SPDK_LOG(DBG_HDB, -1, "[SPDK][%02d] >> start sub io jobs ... filesz(%lu,%lu,%d)\n", disk_idx, file_size, file_size_4k, file_size_4k/(1024*1024));
	
	void *buf = get_mmap_entry(&mmap_info, file_size_4k, false);
	struct nvme_dummy_dev_t *dev = &nvme_devs[disk_idx];
	struct ns_worker_ctx *ns_ctx = (struct ns_worker_ctx *)dev->ns_ctx_ptr;
	assert(nx_ctx != NULL);
	
	clock_gettime(CLOCK_REALTIME, &timeout);
	start_ns = timeout.tv_sec*1000*1000*1000+timeout.tv_nsec;
	
	rc = sci_req_q_send_task(ns_ctx, 
							file_size_4k,
							1, 			/* is_read */
							disk_offset, 
							'A', 
							buf,
							NULL, 		/* iocb */
							NULL,		/* callback */ 
							0,			/* ctx_id */ 
							0,
							NULL);		/* sci_comp_cb */
	if (rc != 0)
		printf("[SPDK] bad bad, sci_req_q_send_task failed, TODO need handle this error and exit out\n");

	SCI_SPDK_LOG(DBG_HDB, -1, "[SPDK][%d] >> waiting come back of sub io jobs ... filesz(%lu,%lu)\n", disk_idx, file_size, file_size_4k);

	while (1) {
		/*int check_rc = */ns_ctx->entry->fn_table->check_io(ns_ctx);
		
		if (ns_ctx->current_queue_depth == 0)
			break;
	}
	
	clock_gettime(CLOCK_REALTIME, &timeout);
	end_ns = timeout.tv_sec*1000*1000*1000+timeout.tv_nsec;

	pthread_mutex_lock(&stats_lock);
	uint64_t io_rsp_ns = end_ns - start_ns;
	total_io++;
	total_size += file_size;
	total_ns += io_rsp_ns;
	if (io_rsp_ns > max_ns) max_ns = io_rsp_ns;
	if (io_rsp_ns < min_ns) min_ns = io_rsp_ns;
	pthread_mutex_unlock(&stats_lock);
	
	SCI_SPDK_LOG(DBG_HDB, -1, "[SPDK][%d] >> all sub io jobs done filesz(%lu,%lu)\n", disk_idx, file_size, file_size_4k);

	return buf;
}

static void io_complete(void *ctx, const struct spdk_nvme_cpl *cpl);

static int
nvme_submit_io(struct perf_task *task, struct ns_worker_ctx *ns_ctx,
	       struct ns_entry *entry, uint64_t offset_in_ios)
{
	uint64_t lba;
	int qp_num;

	lba = task->disk_offset / entry->sector_size;

	//pthread_mutex_lock(&ns_ctx->rings->req_q_lock);
	qp_num = ns_ctx->u.nvme.last_qpair;
	ns_ctx->u.nvme.last_qpair++;
	if (ns_ctx->u.nvme.last_qpair == ns_ctx->u.nvme.num_active_qpairs) {
		ns_ctx->u.nvme.last_qpair = 0;
	}
	//pthread_mutex_unlock(&ns_ctx->rings->req_q_lock);

	/* TODO: support just one iovcnt for now, add readv/writev later */
	assert(task->iovcnt == 1);
	task->iovs[0].iov_base = task->user_buf;
	assert(task->iovs[0].iov_base != NULL);

	if (task->is_read) {
			return spdk_nvme_ns_cmd_read(entry->u.nvme.ns, ns_ctx->u.nvme.qpair[qp_num],
					task->iovs[0].iov_base,
					lba,
					task->io_size_blocks, io_complete,
					task, 0);
	} else {
			return spdk_nvme_ns_cmd_write(entry->u.nvme.ns, ns_ctx->u.nvme.qpair[qp_num],
					task->iovs[0].iov_base,
					lba,
					task->io_size_blocks, io_complete,
					task, 0);
	}
}

static void
perf_disconnect_cb(struct spdk_nvme_qpair *qpair, void *ctx)
{

}

static int64_t
nvme_check_io(struct ns_worker_ctx *ns_ctx)
{
	int64_t rc;

	rc = spdk_nvme_poll_group_process_completions(ns_ctx->u.nvme.group, g_max_completions,
			perf_disconnect_cb);
	if (rc < 0) {
		fprintf(stderr, "NVMe io qpair process completion error\n");
		exit(1);
	}
	return rc;
}

/*
 * TODO: If a controller has multiple namespaces, they could all use the same queue.
 *  For now, give each namespace/thread combination its own queue.
 */
static int
nvme_init_ns_worker_ctx(struct ns_worker_ctx *ns_ctx)
{
	struct spdk_nvme_io_qpair_opts opts;
	struct ns_entry *entry = ns_ctx->entry;
	struct spdk_nvme_poll_group *group;
	struct spdk_nvme_qpair *qpair;
	int i;

	ns_ctx->u.nvme.num_active_qpairs = g_nr_io_queues_per_ns;
	ns_ctx->u.nvme.num_all_qpairs = g_nr_io_queues_per_ns + g_nr_unused_io_queues;
	ns_ctx->u.nvme.qpair = calloc(ns_ctx->u.nvme.num_all_qpairs, sizeof(struct spdk_nvme_qpair *));
	if (!ns_ctx->u.nvme.qpair) {
		return -1;
	}

	spdk_nvme_ctrlr_get_default_io_qpair_opts(entry->u.nvme.ctrlr, &opts, sizeof(opts));
	if (opts.io_queue_requests < entry->num_io_requests) {
		opts.io_queue_requests = entry->num_io_requests;
	}
	opts.delay_cmd_submit = true;
	opts.create_only = true;

	ns_ctx->u.nvme.group = spdk_nvme_poll_group_create(NULL, NULL);
	if (ns_ctx->u.nvme.group == NULL) {
		goto poll_group_failed;
	}

	group = ns_ctx->u.nvme.group;
	for (i = 0; i < ns_ctx->u.nvme.num_all_qpairs; i++) {
		ns_ctx->u.nvme.qpair[i] = spdk_nvme_ctrlr_alloc_io_qpair(entry->u.nvme.ctrlr, &opts,
					  sizeof(opts));
		qpair = ns_ctx->u.nvme.qpair[i];
		if (!qpair) {
			SCI_SPDK_LOG(DBG_ERR, 1, "ERROR: spdk_nvme_ctrlr_alloc_io_qpair failed\n");
			goto qpair_failed;
		}

		if (spdk_nvme_poll_group_add(group, qpair)) {
			SCI_SPDK_LOG(DBG_ERR, 1, "ERROR: unable to add I/O qpair to poll group.\n");
			spdk_nvme_ctrlr_free_io_qpair(qpair);
			goto qpair_failed;
		}

		if (spdk_nvme_ctrlr_connect_io_qpair(entry->u.nvme.ctrlr, qpair)) {
			SCI_SPDK_LOG(DBG_ERR, 1, "ERROR: unable to connect I/O qpair.\n");
			spdk_nvme_ctrlr_free_io_qpair(qpair);
			goto qpair_failed;
		}
	}

	return 0;

qpair_failed:
	for (; i > 0; --i) {
		spdk_nvme_ctrlr_free_io_qpair(ns_ctx->u.nvme.qpair[i - 1]);
	}

	spdk_nvme_poll_group_destroy(ns_ctx->u.nvme.group);
poll_group_failed:
	free(ns_ctx->u.nvme.qpair);
	return -1;
}

static void
nvme_cleanup_ns_worker_ctx(struct ns_worker_ctx *ns_ctx)
{
	int i;

	for (i = 0; i < ns_ctx->u.nvme.num_all_qpairs; i++) {
		spdk_nvme_ctrlr_free_io_qpair(ns_ctx->u.nvme.qpair[i]);
	}

	spdk_nvme_poll_group_destroy(ns_ctx->u.nvme.group);
	free(ns_ctx->u.nvme.qpair);
}

static const struct ns_fn_table nvme_fn_table = {
	.setup_payload			= NULL,
	.submit_io				= nvme_submit_io,
	.check_io				= nvme_check_io,
	.verify_io				= NULL,
	.init_ns_worker_ctx		= nvme_init_ns_worker_ctx,
	.cleanup_ns_worker_ctx	= nvme_cleanup_ns_worker_ctx,
	.dump_transport_stats	= NULL
};

static int
build_nvme_name(char *name, size_t length, struct spdk_nvme_ctrlr *ctrlr)
{
	const struct spdk_nvme_transport_id *trid;
	int res = 0;

	trid = spdk_nvme_ctrlr_get_transport_id(ctrlr);

	switch (trid->trtype) {
	case SPDK_NVME_TRANSPORT_PCIE:
		res = snprintf(name, length, "PCIE (%s)", trid->traddr);
		break;
	default:
		fprintf(stderr, "Unknown transport type %d\n", trid->trtype);
		break;
	}
	return res;
}

static void
build_nvme_ns_name(char *name, size_t length, struct spdk_nvme_ctrlr *ctrlr, uint32_t nsid)
{
	int res = 0;

	res = build_nvme_name(name, length, ctrlr);
	if (res > 0) {
		snprintf(name + res, length - res, " NSID %u", nsid);
	}

}

static void rtrim(char *str) {
	int len = strlen(str);
	while (len > 0 && isspace(str[len - 1])) {
		str[--len] = '\0';
	}
}

static void
register_ns(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_ns *ns, char *dev_sn)
{
	struct ns_entry *entry;
	const struct spdk_nvme_ctrlr_data *cdata;
	uint32_t max_xfer_size, entries, sector_size;
	uint64_t ns_size;
	struct spdk_nvme_io_qpair_opts opts;
	uint32_t nsid;
	char sn[SN_SIZE] = {'\0'};

	cdata = spdk_nvme_ctrlr_get_data(ctrlr);

	if (!spdk_nvme_ns_is_active(ns)) {
		SCI_SPDK_LOG(DBG_INIT, -1, "Controller %-20.20s (%-20.20s): Skipping inactive NS %u\n",
		       cdata->mn, cdata->sn,
		       spdk_nvme_ns_get_id(ns));
		g_warn = true;
		return;
	}

	memcpy(sn, cdata->sn, sizeof(cdata->sn));
	rtrim(sn);
	SCI_SPDK_LOG(DBG_INIT, -1, "dev_sn(%s), sn(%s)\n", dev_sn, sn);

	ns_size = spdk_nvme_ns_get_size(ns);
	sector_size = spdk_nvme_ns_get_sector_size(ns);
	nsid = spdk_nvme_ns_get_id(ns);

	if (strcmp(dev_sn, sn) != 0)
	{
		SCI_SPDK_LOG(DBG_ERR, -1, "NVMe device serial mismatch (%s)(%s)\n",
			dev_sn, sn);
		g_warn = true;
		return;
	}
	
	int find_one = 0;
	for (int j=0; j<MAX_JOB_CNT; j++)
	{
		struct nvme_dummy_dev_t *dev = &nvme_devs[j];
		if (strcmp(dev->sn, dev_sn) != 0)
			continue;
		if (dev->nsid != nsid)
			continue;
		dev->ns_size = ns_size;
		dev->sector_size = sector_size;
		find_one = 1;
		break;
	}
	if (!find_one)
	{
		SCI_SPDK_LOG(DBG_ERR, -1, "Unable to locate device sn(%s) nsid(%d)\n",
			cdata->sn, nsid);
		return;
	}
	max_xfer_size = spdk_nvme_ns_get_max_io_xfer_size(ns);
	spdk_nvme_ctrlr_get_default_io_qpair_opts(ctrlr, &opts, sizeof(opts));
	/* NVMe driver may add additional entries based on
	 * stripe size and maximum transfer size, we assume
	 * 1 more entry be used for stripe.
	 */
	entries = (kdb_max_io_size - 1) / max_xfer_size + 2;
	if ((kdb_q_depth * entries) > opts.io_queue_size) {
		SCI_SPDK_LOG(DBG_INIT, -1, "controller IO queue size %u less than required\n",
		       opts.io_queue_size);
		SCI_SPDK_LOG(DBG_INIT, -1, "Consider using lower queue depth or small IO size because "
		       "IO requests may be queued at the NVMe driver.\n");
	}
	/* For requests which have children requests, parent request itself
	 * will also occupy 1 entry.
	 */
	entries += 1;

	entry = calloc(1, sizeof(struct ns_entry));
	if (entry == NULL) {
		perror("ns_entry malloc");
		exit(1);
	}

	entry->type = ENTRY_TYPE_NVME_NS;
	entry->fn_table = &nvme_fn_table;
	entry->u.nvme.ctrlr = ctrlr;
	entry->u.nvme.ns = ns;
	entry->num_io_requests = kdb_q_depth * entries;

	//entry->size_in_ios = ns_size / kdb_io_size;
	//entry->io_size_blocks = kdb_io_size / sector_size;
	entry->sector_size = sector_size;

	entry->block_size = spdk_nvme_ns_get_extended_sector_size(ns);
	entry->md_size = spdk_nvme_ns_get_md_size(ns);
	entry->md_interleave = spdk_nvme_ns_supports_extended_lba(ns);
	entry->pi_loc = spdk_nvme_ns_get_data(ns)->dps.md_start;
	entry->pi_type = spdk_nvme_ns_get_pi_type(ns);
	
	SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] ns_size=%lu, sector_size=%d, entry->block_size=%d max_xfer_size=%d\n",
		ns_size, sector_size, entry->block_size, max_xfer_size);

	if (spdk_nvme_ns_get_flags(ns) & SPDK_NVME_NS_DPS_PI_SUPPORTED) {
		entry->io_flags = g_metacfg_pract_flag | g_metacfg_prchk_flags;
		SCI_SPDK_LOG(DBG_INIT, -1, "WARNING: PI not supported\n");
		g_warn = true;
		free(entry);
		return;
	}

	/* If metadata size = 8 bytes, PI is stripped (read) or inserted (write),
	 *  and so reduce metadata size from block size.  (If metadata size > 8 bytes,
	 *  PI is passed (read) or replaced (write).  So block size is not necessary
	 *  to change.)
	 */
	if ((entry->io_flags & SPDK_NVME_IO_FLAGS_PRACT) && (entry->md_size == 8)) {
		entry->block_size = spdk_nvme_ns_get_sector_size(ns);
	}
	entry->dev_sn = dev_sn;
	entry->nsid = nsid;
	build_nvme_ns_name(entry->name, sizeof(entry->name), ctrlr, spdk_nvme_ns_get_id(ns));
	
	SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] dev_sn(%s) entry_name(%s)\n", dev_sn, entry->name);

	g_num_namespaces++;
	TAILQ_INSERT_TAIL(&g_namespaces, entry, link);
}

static void
unregister_namespaces(void)
{
	struct ns_entry *entry, *tmp;

	TAILQ_FOREACH_SAFE(entry, &g_namespaces, link, tmp) {
		TAILQ_REMOVE(&g_namespaces, entry, link);
		free(entry);
	}
}

static void
register_ctrlr(struct spdk_nvme_ctrlr *ctrlr, struct trid_entry *trid_entry)
{
	struct spdk_nvme_ns *ns;
	struct ctrlr_entry *entry = malloc(sizeof(struct ctrlr_entry));
	uint32_t nsid;

	if (entry == NULL) {
		perror("ctrlr_entry malloc");
		exit(1);
	}

	build_nvme_name(entry->name, sizeof(entry->name), ctrlr);

	entry->ctrlr = ctrlr;
	entry->trtype = trid_entry->trid.trtype;
	TAILQ_INSERT_TAIL(&g_controllers, entry, link);

	if (trid_entry->nsid == 0) {
		for (nsid = spdk_nvme_ctrlr_get_first_active_ns(ctrlr);
		     nsid != 0; nsid = spdk_nvme_ctrlr_get_next_active_ns(ctrlr, nsid)) {
			ns = spdk_nvme_ctrlr_get_ns(ctrlr, nsid);
			if (ns == NULL) {
				continue;
			}
			//SCI_SPDK_LOG(DBG_INFO, -1, "[SPDK] WARN: multiple ns for one trid_entry(%s)\n", trid_entry->dev_fn);
			register_ns(ctrlr, ns, trid_entry->dev_sn);
		}
	} else {
		ns = spdk_nvme_ctrlr_get_ns(ctrlr, trid_entry->nsid);
		if (!ns) {
			perror("Namespace does not exist.");
			exit(1);
		}

		register_ns(ctrlr, ns, trid_entry->dev_sn);
	}
}

static inline int
submit_single_io(struct perf_task *task)
{
	uint64_t		offset_in_ios;
	int			rc;
	struct ns_worker_ctx	*ns_ctx = task->ns_ctx;
	struct ns_entry		*entry = ns_ctx->entry;
	
	if (task->io_size % entry->block_size != 0) {
		SCI_SPDK_LOG(DBG_HDB, -1, "WARNING: IO size %u (-o) is not a multiple of sector size %u.\n",
			task->io_size, entry->block_size);
		rc = -1;
		goto ret;
	}

	offset_in_ios = task->disk_offset / task->io_size;/* won't be used */
	task->io_size_blocks = task->io_size / entry->sector_size;

	//task->submit_tsc = spdk_get_ticks();

	/* task->is_read already set, no need randomness settings */

	SCI_SPDK_LOG(DBG_HDB, -1, "[SPDK] to call fn_table->submit_io #2\n");
	rc = entry->fn_table->submit_io(task, ns_ctx, entry, offset_in_ios);
	
ret:
	if (spdk_unlikely(rc != 0)) {
		RATELIMIT_LOG("starting I/O failed\n");
	} else {
		//pthread_mutex_lock(&ns_ctx->rings->req_q_lock);
		ns_ctx->current_queue_depth++;
		//pthread_mutex_unlock(&ns_ctx->rings->req_q_lock);
	}
	
	return rc;
}

static inline void
task_complete(struct perf_task *task)
{
	struct ns_worker_ctx	*ns_ctx;

	ns_ctx = task->ns_ctx;
	//pthread_mutex_lock(&ns_ctx->rings->req_q_lock);
	ns_ctx->current_queue_depth--;
	//pthread_mutex_unlock(&ns_ctx->rings->req_q_lock);

	/*
	 * is_draining indicates when time has expired for the test run
	 * and we are just waiting for the previously submitted I/O
	 * to complete.  In this case, do not submit a new I/O to replace
	 * the one just completed.
	 */
	if (spdk_unlikely(ns_ctx->is_draining)) {
		SCI_SPDK_LOG(DBG_IO, -1, "task_complete: draining\n");
	} else {
		if (task->user_iocb != NULL && task->callback != NULL)
			task->callback(task->user_iocb, task->reserved_1, task->reserved_2);
	}
}

static void
io_complete(void *ctx, const struct spdk_nvme_cpl *cpl)
{
	struct perf_task *task = ctx;
	
	if (spdk_unlikely(spdk_nvme_cpl_is_error(cpl))) {
		if (task->is_read) {
			RATELIMIT_LOG("Read completed with error (sct=%d, sc=%d)\n",
				      cpl->status.sct, cpl->status.sc);
		} else {
			RATELIMIT_LOG("Write completed with error (sct=%d, sc=%d)\n",
				      cpl->status.sct, cpl->status.sc);
		}
		if (cpl->status.sct == SPDK_NVME_SCT_GENERIC &&
		    cpl->status.sc == SPDK_NVME_SC_INVALID_NAMESPACE_OR_FORMAT) {
			/* The namespace was hotplugged.  Stop trying to send I/O to it. */
			task->ns_ctx->is_draining = true;
		}
	}

	task_complete(task);
}

static int
init_ns_worker_ctx(struct ns_worker_ctx *ns_ctx)
{
	return ns_ctx->entry->fn_table->init_ns_worker_ctx(ns_ctx);
}

static void
cleanup_ns_worker_ctx(struct ns_worker_ctx *ns_ctx)
{
	ns_ctx->entry->fn_table->cleanup_ns_worker_ctx(ns_ctx);
}

static void usage(char *param)
{
	SCI_SPDK_LOG(DBG_ERR, 1, "ERROR: invalid parameter for %s", param);
}

static void
unregister_trids(void)
{
	struct trid_entry *trid_entry, *tmp;

	TAILQ_FOREACH_SAFE(trid_entry, &g_trid_list, tailq, tmp) {
		TAILQ_REMOVE(&g_trid_list, trid_entry, tailq);
		free(trid_entry);
	}
}

static int
add_trid(const char *trid_str, char *dev_sn)
{
	struct trid_entry *trid_entry;
	struct spdk_nvme_transport_id *trid;

	trid_entry = calloc(1, sizeof(*trid_entry));
	if (trid_entry == NULL) {
		return -1;
	}

	trid = &trid_entry->trid;
	trid->trtype = SPDK_NVME_TRANSPORT_PCIE;
	snprintf(trid->subnqn, sizeof(trid->subnqn), "%s", SPDK_NVMF_DISCOVERY_NQN);
	memcpy(trid_entry->dev_sn, dev_sn, SN_SIZE);

	if (spdk_nvme_transport_id_parse(trid, trid_str) != 0) {
		fprintf(stderr, "Invalid transport ID format '%s'\n", trid_str);
		free(trid_entry);
		return 1;
	}

	TAILQ_INSERT_TAIL(&g_trid_list, trid_entry, tailq);
	return 0;
}

static char core_mask_str[24];
static int
parse_args(struct spdk_env_opts *env_opts)
{
	env_opts->mem_size = -1;
	
	/* check active cores and construct core_mask */
	int core_cnt = get_nprocs();
	unsigned long long core_mask = (1ULL<<core_cnt) - 1;
	snprintf(core_mask_str, 24, "%llx", core_mask);
	env_opts->core_mask = core_mask_str;
	
	env_opts->mem_channel = 4;
	
	SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] core_mask=%s\n", env_opts->core_mask);
	
	for (int i=0; i<MAX_JOB_CNT; i++) {
		struct nvme_dummy_dev_t *dev = &nvme_devs[i];
		if (dev->cpu < 0)
			continue;
		
		/* device name and cpu assigned from kdb conf early on */
		char trtype_str[64];
		snprintf(trtype_str, 64, "trtype:PCIe traddr:%s", dev->pci_name);
		
		if (add_trid(trtype_str, dev->sn)) {
			printf("ERROR add_trid(%s)\n", trtype_str);
			return 1;
		}
		
		SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] add_trid(%s)\n", trtype_str);		
	}

	if (!g_nr_io_queues_per_ns) {
		usage("g_nr_io_queues_per_ns\n");
		return 1;
	}

	if (!g_quiet_count) {
		usage("-Q (--skip-errors) value must be greater than 0\n");
		return 1;
	}
	
	env_opts->no_pci = false;

	return 0;
}

static int
register_workers(void)
{
	uint32_t i;
	struct worker_thread *worker;

	SPDK_ENV_FOREACH_CORE(i) {
		worker = calloc(1, sizeof(*worker));
		if (worker == NULL) {
			fprintf(stderr, "Unable to allocate worker\n");
			return -1;
		}

		TAILQ_INIT(&worker->ns_ctx);
		worker->lcore = i;
		workers_by_cpu[i] = worker;
		TAILQ_INSERT_TAIL(&g_workers, worker, link);
		g_num_workers++;
	}

	return 0;
}

static void
unregister_workers(void)
{
	struct worker_thread *worker, *tmp_worker;
	struct ns_worker_ctx *ns_ctx, *tmp_ns_ctx;

	/* Free namespace context and worker thread */
	TAILQ_FOREACH_SAFE(worker, &g_workers, link, tmp_worker) {
		TAILQ_REMOVE(&g_workers, worker, link);

		TAILQ_FOREACH_SAFE(ns_ctx, &worker->ns_ctx, link, tmp_ns_ctx) {
			TAILQ_REMOVE(&worker->ns_ctx, ns_ctx, link);
			
			pthread_mutex_destroy(&ns_ctx->rings->req_q_lock);
			pthread_mutex_destroy(&ns_ctx->rings->rsp_q_lock);
			
			for (int i=0; i<MAX_RING_CNT; i++) {
				struct perf_task *task = ns_ctx->rings->req_q[i];
				if (task == NULL)
					continue;
				//if (task->iovs[0].iov_base != NULL)
				//	spdk_dma_free(task->iovs[0].iov_base);
				//free(task->iovs);
				//free(task);
				ns_ctx->rings->req_q[i] = NULL;
			}
			
			free(ns_ctx->rings);
			free(ns_ctx);
		}

		workers_by_cpu[worker->lcore] = NULL;
		
		free(worker);
	}
}

static bool
probe_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid,
	 struct spdk_nvme_ctrlr_opts *opts)
{
	struct trid_entry *trid_entry = cb_ctx;

	if (trid->trtype == SPDK_NVME_TRANSPORT_PCIE) {
		if (g_disable_sq_cmb) {
			opts->use_cmb_sqs = false;
		}
		if (g_no_shn_notification) {
			opts->no_shn_notification = true;
		}
	}

	if (trid->trtype != trid_entry->trid.trtype &&
	    strcasecmp(trid->trstring, trid_entry->trid.trstring)) {
		return false;
	}

	/* Set io_queue_size to UINT16_MAX, NVMe driver
	 * will then reduce this to MQES to maximize
	 * the io_queue_size as much as possible.
	 */
	opts->io_queue_size = UINT16_MAX;

	/* Set the header and data_digest */
	opts->header_digest = g_header_digest;
	opts->data_digest = g_data_digest;
	opts->keep_alive_timeout_ms = g_keep_alive_timeout_in_ms;
	memcpy(opts->hostnqn, trid_entry->hostnqn, sizeof(opts->hostnqn));

	return true;
}

static void
attach_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid,
	  struct spdk_nvme_ctrlr *ctrlr, const struct spdk_nvme_ctrlr_opts *opts)
{
	struct trid_entry	*trid_entry = cb_ctx;
	struct spdk_pci_addr	pci_addr;
	struct spdk_pci_device	*pci_dev;
	struct spdk_pci_id	pci_id;

	if (trid->trtype != SPDK_NVME_TRANSPORT_PCIE) {
		SCI_SPDK_LOG(DBG_INIT, -1, "Attached to NVMe over Fabrics controller at %s:%s: %s\n",
		       trid->traddr, trid->trsvcid,
		       trid->subnqn);
	} else {
		if (spdk_pci_addr_parse(&pci_addr, trid->traddr)) {
			return;
		}

		pci_dev = spdk_nvme_ctrlr_get_pci_device(ctrlr);
		if (!pci_dev) {
			return;
		}

		pci_id = spdk_pci_device_get_id(pci_dev);

		SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] Attached to NVMe Controller at %s [%04x:%04x]\n",
		       trid->traddr,
		       pci_id.vendor_id, pci_id.device_id);
	}

	register_ctrlr(ctrlr, trid_entry);
}

static int
register_controllers(void)
{
	struct trid_entry *trid_entry;

	TAILQ_FOREACH(trid_entry, &g_trid_list, tailq) {
		if (spdk_nvme_probe(&trid_entry->trid, trid_entry, probe_cb, attach_cb, NULL) != 0) {
			fprintf(stderr, "spdk_nvme_probe() failed for transport address '%s'\n",
				trid_entry->trid.traddr);
			return -1;
		}
	}

	return 0;
}

static void
unregister_controllers(void)
{
	struct ctrlr_entry *entry, *tmp;
	struct spdk_nvme_detach_ctx *detach_ctx = NULL;

	TAILQ_FOREACH_SAFE(entry, &g_controllers, link, tmp) {
		TAILQ_REMOVE(&g_controllers, entry, link);

		if (g_nr_unused_io_queues) {
			int i;

			for (i = 0; i < g_nr_unused_io_queues; i++) {
				spdk_nvme_ctrlr_free_io_qpair(entry->unused_qpairs[i]);
			}

			free(entry->unused_qpairs);
		}

		spdk_nvme_detach_async(entry->ctrlr, &detach_ctx);
		free(entry);
	}

	if (detach_ctx) {
		spdk_nvme_detach_poll(detach_ctx);
	}
}

static int
associate_workers_with_ns(void)
{
	struct ns_entry		*entry = TAILQ_FIRST(&g_namespaces);
	//struct worker_thread	*worker = TAILQ_FIRST(&g_workers);
	struct worker_thread	*worker = NULL;
	struct ns_worker_ctx	*ns_ctx;
	int			i, count;

	/* one namespace on one core only */
	//count = g_num_namespaces > g_num_workers ? g_num_namespaces : g_num_workers;
	count = g_num_namespaces;
		
	SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] g_num_namespaces=%d, disk_config_count=%d\n",
		g_num_namespaces, disk_config_count);
	if (g_num_namespaces != disk_config_count)
		return -1;

	for (i = 0; i < count; i++) {
		if (entry == NULL) {
			break;
		}
		
		/* locate cpu assignment from nvme device file array */
		char *dev_sn = entry->dev_sn;
		struct nvme_dummy_dev_t *curr_dev = NULL;
		for (int j=0; j<MAX_JOB_CNT; j++)
		{
			struct nvme_dummy_dev_t *dev = &nvme_devs[j];
			if (strcmp(dev->sn, dev_sn) != 0)
				continue;
			if (dev->nsid != entry->nsid)
				continue;
			assert(dev->cpu >= 0 && dev->cpu < MAX_CPU_CNT);
			worker = workers_by_cpu[dev->cpu];
			curr_dev = dev;
			break;
		}

		assert(worker != NULL);

		ns_ctx = calloc(1, sizeof(struct ns_worker_ctx));
		if (!ns_ctx) {
			return -1;
		}
		
		curr_dev->ns_ctx_ptr = ns_ctx;

		SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] Associating %s with lcore %d\n", entry->name, worker->lcore);
		ns_ctx->entry = entry;

		ns_ctx->rings = calloc(1, sizeof(struct sci_ns_rings));
		if (!ns_ctx->rings)
			return -1;
		ns_ctx->rings->req_q_in = 0;
		ns_ctx->rings->req_q_next_fill = 0;
		pthread_mutex_init(&ns_ctx->rings->req_q_lock, NULL);
		pthread_mutex_init(&ns_ctx->rings->rsp_q_lock, NULL);
		ns_ctx->cpu = worker->lcore;
		ns_ctx->pool_idx = i;
		SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] pool_idx(%d) assigned to ns_ctx(%p)\n", ns_ctx->pool_idx, ns_ctx);

		TAILQ_INSERT_TAIL(&worker->ns_ctx, ns_ctx, link);

		entry = TAILQ_NEXT(entry, link);
		if (entry == NULL) {
			entry = TAILQ_FIRST(&g_namespaces);
		}
	}
	
	/* final verification to ensure all disk_config_count devices have assigned ns_ctx_ptr */
	int no_config_count = 0;
	for (i=0; i<disk_config_count; i++)
	{
		struct nvme_dummy_dev_t *dev = &nvme_devs[i];
		if (dev->ns_ctx_ptr == NULL)
			no_config_count++;
	}
	if (no_config_count > 0)
	{
		SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] %d devices not attached with ns_ctx\n", no_config_count);
		return -1;
	}

	return 0;
}
/*
   For Ubuntu 22.04 sleep() can't be called in init() constructor so I have to
   do that in SYS_clone() in sci_spdk.c's hook function. Problem is SYS_clone()
   wait until spdk_init_flag is set but thread nvme_poll_ctrlrs will get 
   intercepted too, cauing SYS_clone() stuck forever. For now disabling this
   part but need to retore it if non-PCIE is supported such as DMA
*/
#ifdef NON_PCIE
static void *
nvme_poll_ctrlrs(void *arg)
{
	struct ctrlr_entry *entry;
	int oldstate;
	int rc;

	spdk_unaffinitize_thread();

	while (true) {
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);

		TAILQ_FOREACH(entry, &g_controllers, link) {
			if (entry->trtype != SPDK_NVME_TRANSPORT_PCIE) {
				rc = spdk_nvme_ctrlr_process_admin_completions(entry->ctrlr);
				if (spdk_unlikely(rc < 0 && !g_exit)) {
					g_exit = true;
				}
			}
		}

		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);

		/* This is a pthread cancellation point and cannot be removed. */
		sleep(1);
	}

	return NULL;
}
#endif
static void
sig_handler(int signo)
{
	SCI_SPDK_LOG(DBG_ERR, 1, "[SPDK] WARN: (%d) received\n", signo);
	g_exit = true;
}

static int
setup_sig_handlers(void)
{
	struct sigaction sigact = {};
	int rc;

	sigemptyset(&sigact.sa_mask);
	sigact.sa_handler = sig_handler;
	rc = sigaction(SIGINT, &sigact, NULL);
	if (rc < 0) {
		fprintf(stderr, "sigaction(SIGINT) failed, errno %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	rc = sigaction(SIGTERM, &sigact, NULL);
	if (rc < 0) {
		fprintf(stderr, "sigaction(SIGTERM) failed, errno %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

int spdk_init(void)
{
	int rc;
	struct worker_thread *worker;
	struct spdk_env_opts opts;
	
	/* ATTN: If crash occurs at rte_pci_scan then add a few seconds sleep.
	   Not sure why but probably it needs sci_spdk_q's instructor to be 
	   started, or maybe spdk-nvme.so library still not ready yet for device
	   scan even though spdk_nvme's constructor is already exited */
	//sleep(3);

	printf("[SPDK] Initializing SPDK resources ... (%s)(%s)\n", KIO_CONF_FILE, KDB_MAP_FILE);
	
	while (sci_get_log_fd() < 0) {
		sleep(1);
	}
	
	int cpu = -1;
	getcpu(&cpu, NULL);
	SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] spdk_init entered with cpu(%d)\n", cpu);
	
	rc = spdk_get_kdb_config();
	if (rc != 0)
		return -1;
	spdk_env_opts_init(&opts);
	opts.name = "perf";
	opts.pci_allowed = g_allowed_pci_addr;
	rc = parse_args(&opts);
	if (rc != 0) {
		return rc;
	}
	/* Transport statistics are printed from each thread.
	 * To avoid mess in terminal, init and use mutex */
	rc = pthread_mutex_init(&g_stats_mutex, NULL);
	if (rc != 0) {
		fprintf(stderr, "Failed to init mutex\n");
		return -1;
	}
	if (spdk_env_init(&opts) < 0) {
		fprintf(stderr, "Unable to initialize SPDK env\n");
		unregister_trids();
		pthread_mutex_destroy(&g_stats_mutex);
		return -1;
	}

	rc = setup_sig_handlers();
	if (rc != 0) {
		rc = -1;
		goto cleanup;
	}

	SCI_SPDK_LOG(DBG_INIT, -1, "Initializing SPDK memory pool\n");
	for (int i=0; i<MAX_JOB_CNT; i++) {
		struct nvme_dummy_dev_t *dev = &nvme_devs[i];
		if (dev->cpu < 0)
			continue;
	}
	
	pthread_mutex_init(&mmap_table_lock, NULL);

	uint64_t mmap_size = MMAP_UNIT_SIZE*MAX_MMAP_CNT;
	ssnq_mmap_ptr = spdk_dma_zmalloc(mmap_size, kdb_io_align, NULL);
	if (ssnq_mmap_ptr != NULL)
		SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] Success allocate %lu\n", mmap_size);
	else {
		SCI_SPDK_LOG(DBG_ERR, -1, "[SPDK] ERROR allocte %lu fail\n", mmap_size);
		goto cleanup;
	}
	for (int i=0; i<MAX_MMAP_CNT; i++)
		mmap_inuse_table[i] = 0;
	alloc_mmap_info();

	mmap_size = SCRATCH_UNIT_SIZE*MAX_SCRATCH_CNT;
	scratch_buf = spdk_dma_zmalloc(mmap_size, kdb_io_align, NULL);
	if (scratch_buf != NULL)
		SCI_SPDK_LOG(DBG_INIT, -1, "[SPDK] scratch_buf pages got allocated with %lu\n", mmap_size);
	else {
		SCI_SPDK_LOG(DBG_ERR, -1, "ERROR: scratch_buf pages allocation failed with %lu\n", mmap_size);
	}
	for (int i=0; i<MAX_SCRATCH_CNT; i++)
		scratch_inuse_table[i] = 0;
	alloc_scratch_info();

	if (register_workers() != 0) {
		rc = -1;
		goto cleanup;
	}

	if (register_controllers() != 0) {
		rc = -1;
		goto cleanup;
	}

	if (g_warn) {
		SCI_SPDK_LOG(DBG_ERR, -1, "WARNING: Some requested NVMe devices were skipped\n");
	}

	if (g_num_namespaces == 0) {
		fprintf(stderr, "No valid NVMe controllers or AIO or URING devices found\n");
		goto cleanup;
	}

	if (g_num_workers > 1 && g_quiet_count > 1) {
		fprintf(stderr, "Error message rate-limiting enabled across multiple threads.\n");
		fprintf(stderr, "Error suppression count may not be exact.\n");
	}
#ifdef NON_PCIE
	rc = pthread_create(&thread_id, NULL, &nvme_poll_ctrlrs, NULL);
	if (rc != 0) {
		fprintf(stderr, "Unable to spawn a thread to poll admin queues.\n");
		goto cleanup;
	}
#endif

	if (associate_workers_with_ns() != 0) {
		rc = -1;
		goto cleanup;
	}

	rc = pthread_barrier_init(&g_worker_sync_barrier, NULL, g_num_workers);
	if (rc != 0) {
		fprintf(stderr, "Unable to initialize thread sync barrier\n");
		goto cleanup;
	}
	
	/* Launch all of the secondary workers */
	g_main_core = spdk_env_get_current_core();
	TAILQ_FOREACH(worker, &g_workers, link) {
		struct ns_worker_ctx	*ns_ctx;
		TAILQ_FOREACH(ns_ctx, &worker->ns_ctx, link) {
			if (init_ns_worker_ctx(ns_ctx) != 0) {
				SCI_SPDK_LOG(DBG_ERR, 1, "ERROR: init_ns_worker_ctx() failed\n");
			}
		}
	}

	/* MUST set this flag before main_worker launched */
	spdk_init_flag = 1;
	
	printf("[SPDK] Successfully initialized SPDK resources.\n");

	while(1) {
		if (g_exit)
			break;
		sleep(2);
	}
	
	TAILQ_FOREACH(worker, &g_workers, link) {
		struct ns_worker_ctx	*ns_ctx;
		TAILQ_FOREACH(ns_ctx, &worker->ns_ctx, link) {
			cleanup_ns_worker_ctx(ns_ctx);
		}
	}

	spdk_env_thread_wait_all();
	
	pthread_barrier_destroy(&g_worker_sync_barrier);

cleanup:
	g_exit = 1;
	unregister_trids();
	unregister_namespaces();
	unregister_controllers();
	unregister_workers();

	if (ssnq_mmap_ptr != NULL) {
		spdk_dma_free(ssnq_mmap_ptr);
		ssnq_mmap_ptr = NULL;
	}
	if (scratch_buf != NULL) {
		spdk_dma_free(scratch_buf);
		scratch_buf = NULL;
	}
	pthread_mutex_destroy(&mmap_table_lock);
	
	spdk_env_fini();

	pthread_mutex_destroy(&g_stats_mutex);

	if (rc != 0) {
		fprintf(stderr, "errors occurred\n");
	}
	
	spdk_init_flag = 0;

	return rc;
}
void spdk_exit(void)
{
	g_exit = true;
}

static void *spdk_init_thread(void *arg)
{
	int oldstate;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
	spdk_init();
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	return NULL;
}

static pthread_t spdk_init_thread_id = 0;

static bool is_l64_q = false;
static bool is_pps_q = false;

static char* get_process_name_by_pid(const int pid)
{
	char* name = (char*)calloc(PATH_MAX,sizeof(char));
	if(name){
		sprintf(name, "/proc/%d/cmdline",pid);
		FILE* f = fopen(name,"r");
		if(f){
			size_t size;
			size = fread(name, sizeof(char), PATH_MAX, f);
			if(size>0){
				if('\n'==name[size-1])
					name[size-1]='\0';
			}
			fclose(f);
		}
	}
	return name;
}
static int replace_char(char *str, char orig, char rep) {
	char *ix = str;
	int n = 0;
	while((ix = strchr(ix, orig)) != NULL) {
		*ix++ = rep;
		n++;
	}
	return n;
}
static char *ps_name = NULL;
static char *pps_name = NULL;
static long my_pid = -1;
static long my_ppid = -1;
static void check_l64_q(void)
{
	my_pid = getpid();
	ps_name = get_process_name_by_pid(my_pid);
	assert(ps_name != NULL);
	
	replace_char(ps_name, '/', '-');

	if (strstr(ps_name, "q") != NULL ||
		strstr(ps_name, "l64-q") != NULL)
		is_l64_q = true;
}
static void check_pps_q(void)
{
	my_ppid = getppid();
	pps_name = get_process_name_by_pid(my_ppid);
	assert(pps_name != NULL);
	
	replace_char(pps_name, '/', '-');

	if (strstr(pps_name, "q") != NULL ||
		strstr(pps_name, "l64-q") != NULL)
		is_pps_q = true;
}

char *sci_get_ps_name(void)
{
	return ps_name;
}
char *sci_get_pps_name(void)
{
	return pps_name;
}
bool sci_is_l64_q(void)
{
	return is_l64_q;
}
bool sci_is_pps_q(void)
{
	return is_pps_q;
}

static __attribute__((constructor)) void
init(void)
{
	get_token_from_path_file("SSNQ_CONF", KIO_CONF_FILE);
	get_token_from_path_file("SSNQ_HDB_MAPS", KDB_MAP_FILE);
	get_token_from_path_file("Q_LICENSE", KDB_LIC_DIR);
	get_token_from_path_file("SSNQ_DBG_LEVEL", SSNQ_DBG_LEVEL);

	/*
	   ATTN: spdk-nvme.so loaded first so all resources exported to sci-spdk.c
	   must setup here
	*/
	int rval;
	int cpu = -1;
	
	getcpu(&cpu, NULL);
	check_l64_q();
	check_pps_q();
	
	if (!is_l64_q || is_pps_q)
		return;

#ifndef NO_SPDK	
	/* initialize dummy nvme devices */
	memset(nvme_devs, 0, sizeof(nvme_devs));
	for (int i=0; i<MAX_JOB_CNT; i++)
	{
		nvme_devs[i].fd = -1;
		nvme_devs[i].cpu = -1;
	}
	
	pthread_mutex_init(&stats_lock, NULL);
	
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rval = pthread_create(&spdk_init_thread_id, &attr, &spdk_init_thread, NULL);
	if (rval != 0)
		fprintf(stderr, "[SPDK] ERROR: failed to launch spdk_init_thread\n");
	pthread_attr_destroy(&attr);
#endif
}
char *sci_get_kdb_map_file(void)
{
	return KDB_MAP_FILE;
}
char *sci_get_q_lic_dir(void)
{
	if (strlen(KDB_LIC_DIR) <= 0)
		return NULL;
	return KDB_LIC_DIR;
}
int sci_get_debug_level(void)
{
	return atoi(SSNQ_DBG_LEVEL);
}

static __attribute__((destructor)) void
deinit(void)
{
	printf("[SPDK] (%s) is_pps_q(%d) exiting ... \n", ps_name, is_pps_q);
	
	if (!is_l64_q || is_pps_q)
		goto ret;

#ifndef NO_SPDK	
	g_exit = true;
		
	int cnt = 3;
	while (cnt--)
	{
		sleep(1);
	}
	
	if (ssnq_mmap_ptr != NULL) {
		spdk_dma_free(ssnq_mmap_ptr);
		ssnq_mmap_ptr = NULL;	
	}
	if (scratch_buf != NULL) {
		spdk_dma_free(scratch_buf);
		scratch_buf = NULL;
	}
	pthread_mutex_destroy(&mmap_table_lock);
	pthread_mutex_destroy(&stats_lock);
	
	if (total_io > 0)
		printf("[SPDK] IO results: total_size=%lu MB, total_time=%lu ms, avg_rsp_us=%lu us, min_rsp_us=%lu us, max_rsp_us=%lu us, total_io=%lu\n", 
			total_size/(1000*1000), 
			total_ns/(1000*1000),
			total_ns/(1000*total_io),
			min_ns/1000,
			max_ns/1000, total_io);
#endif
	
ret:
	printf("[SPDK] (%s) exited successfully.\n", ps_name);
	if (ps_name != NULL)
		free(ps_name);
	if (pps_name != NULL)
		free(pps_name);
}
