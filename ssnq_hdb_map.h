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
 *   ssnq_hdb_map.h
 *
 *   Author: Colin Zhu <czhu@nexnt.com>
 */

#ifndef _SSNQ_HDB_MAP_H
#define _SSNQ_HDB_MAP_H

#include <sys/stat.h>
#include <linux/limits.h>
#include "ssnq_list.h"

typedef struct _hdb_map_entry_t {
	struct list_head list;
	int disk_idx;
	uint64_t disk_offset;		/* starting offset in the disk */
	uint64_t stripe_blk_size;	/* allocation size in the disk */
	uint64_t curr_pos;			/* current lseek position */
	off_t file_size;
	time_t last_modified_time;
	int idx;					/* entry's index */
	int flags;
#define HDB_MAP_FLAG_FREE		0	/* FREE */
#define HDB_MAP_FLAG_ACTIVE		1	/* ACTI */
#define HDB_MAP_FLAG_INACTIVE	2	/* IACT */
#define HDB_MAP_FLAG_OUTOFSYNC	3	/* OSYN */
#define HDB_MAP_FLAG_COPYFAIL	4	/* FAIL */
	int hash_idx;
	int sub_idx;
	char full_path[PATH_MAX];
	void *slave_ptr;
} hdb_map_entry;

typedef struct _hdb_file_entry_t {
	struct list_head file_queue;
	int file_count;
} hdb_file_entry;

#endif	/* _SSNQ_HDB_MAP_H */
