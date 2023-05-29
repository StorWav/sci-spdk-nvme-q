/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2022-2023 Colin Zhu. All rights reserved.
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
 *   This file is part of sci-spdk-nvme-q library.
 * 
 *   sci_spdk_nvme.h
 *
 *   Author: Colin Zhu <czhu@nexnt.com>
 */

#ifndef _SCI_SPDK_NVME_H
#define _SCI_SPDK_NVME_H

/* Use NO_SPDK to get back to normal q w/o SPDK stuff */
//#define NO_SPDK 1

#include "ssnq_common.h"
#include "ssnq_hdb_map.h"

#define MAX_JOB_CNT			64		/* one fio job for each nvme, max 64 nvme devices */
#define MAX_NVME_NAME_LEN	31		/* max dummy nvme file name length */
#define MAX_CPU_CNT			64		/* max number of cores, increase the value if needed */
#define MAX_UFFD_CNT		8		/* max number of uffd counts for each slave thread */

#define MAX_Q_DEPTH			512
#define MAX_RING_CNT		MAX_Q_DEPTH
#define DEFAULT_IO_ALIGN	4096	/* PAGE SIZE */
#define DEFAULT_MAX_IO_SIZE		0x100000UL	/* 1MB */

extern void spdk_collect_kdb_config(int *,			/* io_size */
									int *,			/* q_depth */
									int *,			/* io_align */
									uint64_t *);	/* pool_size */
extern int spdk_check_init_status(void);
extern void spdk_exit(void);
extern void *sci_submit_mmap_io(int disk_idx,
						uint64_t disk_offset, 
						uint64_t file_size);
extern void sci_unmmap_region(void *mmap_addr, size_t size);
extern void *sci_alloc_spdk_mem(uint64_t len);
extern void sci_free_spdk_mem(void *buf, uint64_t len);

extern char *sci_get_ps_name(void);
extern char *sci_get_pps_name(void);
extern bool sci_is_l64_q(void);
extern bool sci_is_pps_q(void);
extern int sci_get_log_fd(void);
extern char *sci_get_kdb_map_file(void);
extern char *sci_get_q_lic_dir(void);
extern int sci_get_debug_level(void);

struct nvme_dummy_dev_t {
	//char file_name[MAX_NVME_NAME_LEN+1];
	char pci_name[PCI_ADDR_SIZE];
	char sn[SN_SIZE];
	int fd;
	int cpu;
	uint64_t ctx_id;	/* assigned from sci front-end */
	uint64_t ns_size;
	uint32_t sector_size;
	uint32_t nsid;
	void *ns_ctx_ptr;	/*struct ns_worker_ctx*/
};

typedef struct sci_comp_cb_t {
	int sub_io_cnt;
	pthread_mutex_t comp_lock;
	pthread_cond_t comp_cond;
} sci_comp_cb;

#define DBG_ERR		0x00000001	/* BIT_0 */
#define DBG_INIT	0x00000002	/* BIT_1 */
#define DBG_INFO	0x00000004	/* BIT_2 */
#define DBG_HDB		0x00000008	/* BIT_3 */
#define DBG_IO		0x00000010	/* BIT_4 */
#define DBG_TRACE	0x00000020	/* BIT_5 */
#define DBG_MUTEX	0x00000040	/* BIT_6 */
extern void SCI_SPDK_LOG(uint32_t level, int fd, const char *fmt, ...);

static inline int is_power_of_2(int value)
{
    if (value == 0) return 1;
    return (value & (value - 1)) == 0;
}

#endif	/* _SCI_SPDK_NVME_H */
