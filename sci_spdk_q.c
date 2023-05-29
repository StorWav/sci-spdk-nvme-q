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
 *   sci_spdk_q.c
 * 
 *   Frontend interceptor of system calls and memory allocation calls. The
 *   interception mechanism, which takes use of syscall_intercept libraries,
 *   is to redirect those calls to the backend high performance SPDK/NVMe
 *   IO interfaces, foster significant IO performance boost without any
 *   modification to existing applications.
 *
 *   For details about syscall_intercept please visit
 *   https://github.com/pmem/syscall_intercept
 *
 *   Author: Colin Zhu <czhu@nexnt.com>
 */

#include "libsyscall_intercept_hook_point.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/aio_abi.h>
#include <poll.h>
#include <sched.h>
#include <linux/userfaultfd.h>

#include "sci_spdk_nvme.h"
#include <xxhash.h>

#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)

static long flags = -1;
static long my_pid = -1;
static long my_ppid = -1;
static char *q_lic_dir = NULL;	/* q license directory, usually just folder q */

/**
 * Logging mechanism
 */
#ifndef NO_SPDK
static uint32_t sci_debug_level = DBG_ERR|DBG_INIT;//|DBG_INFO|DBG_HDB|DBG_IO|DBG_TRACE;
#else	/* for non-SPDK, we want to log everything to observe details */
static uint32_t sci_debug_level = DBG_ERR|DBG_INIT|DBG_INFO|DBG_HDB|DBG_IO|DBG_TRACE;
#endif
static int log_fd = -1;
static const char *log_dir = ".";
static char log_path[PATH_MAX] = { '\0' };
static char my_ps_full_path[PATH_MAX] = { '\0' };
static char my_pps_full_path[PATH_MAX] = { '\0' };
static inline int
sci_mask_match(uint32_t level)
{
	return (level > 0) && (level & sci_debug_level) == level;
}
void SCI_SPDK_LOG(uint32_t level, int fd, const char *fmt, ...)
{
	int len;
	va_list ap;

	if (!sci_mask_match(level))
		return;

	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	if (len <= 0)
		return;

	char buf[len + 1];

	va_start(ap, fmt);
	len = vsprintf(buf, fmt, ap);
	va_end(ap);
	
	struct timeval tv;
	syscall_no_intercept(SYS_gettimeofday, &tv, NULL);
	struct tm newtime;
	time_t ltime = tv.tv_sec;
	localtime_r(&ltime, &newtime);
	
	char log_buf[len + 64];
	sprintf(log_buf, "%04d.%02d.%02d_%02d:%02d:%02d_%06luus ",
		newtime.tm_year+1900, newtime.tm_mon+1, newtime.tm_mday,
		newtime.tm_hour, newtime.tm_min, newtime.tm_sec, tv.tv_usec);
	strcat(log_buf, buf);

	if (fd < 0 && log_fd >= 0)
		syscall_no_intercept(SYS_write, log_fd, log_buf, strlen(log_buf));
	else 
		syscall_no_intercept(SYS_write, fd, log_buf, strlen(log_buf));
}
static void get_path_by_pid(long pid, char *link_name)
{
	char proc_exe[32];
	sprintf(proc_exe, "/proc/%ld/exe", pid);
	syscall_no_intercept(SYS_readlink, proc_exe, link_name, PATH_MAX);
}

unsigned int max_slot = 67108863U;/* 26 bit */
uint32_t get_hash26(const char *filename)
{
	unsigned int hash = XXH32(filename, strlen(filename), 0);

	if (hash >= max_slot)
		hash = (hash >> 6) & 0x03FFFFFF;
	
	return hash;
}

struct slave_table_t {
	pthread_t pft_thr;
	int core_id;
	int slv_tid;	/* slave thread id */
};
struct cpu_table_t {
	int presented;	/* if presented in system */
	int slaves_assigned;
	struct slave_table_t *slaves[MAX_JOB_CNT];
};
static struct cpu_table_t cpu_tables[MAX_CPU_CNT];
struct slave_table_t slave_threads[MAX_JOB_CNT];
static int slave_cnt = 0;
static pthread_mutex_t pin_slave_lock;	/* this is only needed when stats system call
										   needs to assign the same cpu to page fault
										   thread, no need for actaul page fault handling */
static int disk_count = 0;

void pin_slave_thread_to_core(int core)
{
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(core, &cpuset);

	pthread_t current_thread = pthread_self();
	int err = pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
	if (err != 0) {
		perror("pthread_setaffinity_np");
		exit(EXIT_FAILURE);
	}
}
static struct slave_table_t *sci_connect_thread(const char *abs_path, int cpu)
{
	/* FIXME: this shall be called by SYS_stat or SYS_openat??? */
	struct slave_table_t *ret_slave = NULL;
	assert(cpu >= 0 && cpu < MAX_CPU_CNT);
	struct cpu_table_t *this_cpu_tbl = &cpu_tables[cpu];
	int tid = syscall_no_intercept(SYS_gettid);
	
	/* Checking if slave is connected doesn't need lock because
	   we are currenlty in the same cpu core */
	for (int i=0; i<this_cpu_tbl->slaves_assigned; i++) {
		struct slave_table_t *slave = this_cpu_tbl->slaves[i];
		if (slave == NULL)
			continue;
		
		if (slave->slv_tid == tid) {
			assert(slave->core_id == cpu);
			ret_slave = slave;
			break;
		}
	}
	
	/* If slave no connected, lock is needed to avoid a different
	   cpu core is attempting to occupy and connect to the same slave */
	if (ret_slave == NULL) {
		struct timespec timeout;
		clock_gettime(CLOCK_REALTIME, &timeout);
		uint64_t start_ns = timeout.tv_sec*1000*1000*1000+timeout.tv_nsec;

		pthread_mutex_lock(&pin_slave_lock);
		
		struct slave_table_t *slave = NULL;
		int cpu_to_pin = cpu;
		
		/* already has other assigned, find a new cpu table */
		if (this_cpu_tbl->slaves_assigned) {
			int i = 0;
			for (i=0; i<MAX_CPU_CNT; i++) {
				struct cpu_table_t *this_tbl = &cpu_tables[i];
				
				if (!this_tbl->presented)
					continue;
				
				if (this_tbl->slaves_assigned > 0)
					continue;
				
				this_cpu_tbl = this_tbl;
				cpu_to_pin = i;
				break;
			}

			/* all cpu table entry exhaused, use the one with least slaves_assigned */
			if (i>=MAX_CPU_CNT) {
				struct cpu_table_t *least_ass = NULL;
				int min_idx = -1;
				int min_ass = MAX_JOB_CNT;
			
				for (i=0; i<MAX_CPU_CNT; i++) {
					struct cpu_table_t *this_tbl = &cpu_tables[i];
				
					if (!this_tbl->presented)
						continue;
				
					if (this_tbl->slaves_assigned > 0 &&
						this_tbl->slaves_assigned < min_ass) {
						min_ass = this_tbl->slaves_assigned;
						least_ass = this_tbl;
						min_idx = i;
					}
				}
			
				assert(least_ass != NULL);
				this_cpu_tbl = least_ass;
				cpu_to_pin = min_idx;
			}
		}
		
		/* find a slave thread not connected yet */
		for (int i=0; i<slave_cnt; i++) {
			if (slave_threads[i].core_id != -1)
				continue;
			
			if (slave_threads[i].slv_tid != 0)
				continue;
			
			slave = &slave_threads[i];
			
			slave->core_id = cpu_to_pin;
			pin_slave_thread_to_core(cpu_to_pin);
			break;
		}
		
		/* FIXME: this should not happen??? */
		assert(slave != NULL);

		int slave_idx = this_cpu_tbl->slaves_assigned;
		assert(slave_idx >= 0 && slave_idx < MAX_JOB_CNT);
		
		slave->slv_tid = tid;
		this_cpu_tbl->slaves[slave_idx] = slave;
		this_cpu_tbl->slaves_assigned++;
		ret_slave = slave;
		
		pthread_mutex_unlock(&pin_slave_lock);

		clock_gettime(CLOCK_REALTIME, &timeout);
		uint64_t end_ns = timeout.tv_sec*1000*1000*1000+timeout.tv_nsec;
				
		SCI_SPDK_LOG(DBG_INIT, log_fd, "Pinning cpu(%d) to slave thread(%d), current running cpu(%d), elaps(%lu ns)\n", 
			slave->core_id, tid, cpu, (end_ns-start_ns));
	}
	
	return ret_slave;
}

static int sci_get_cpu(int *tid)
{
	int cpu = -1;
	*tid = syscall_no_intercept(SYS_gettid);
	int status = syscall_no_intercept(SYS_getcpu, &cpu, NULL, NULL);
	return cpu;
}

typedef struct hdb_open_file_t {
	hdb_map_entry *map_entry;
	int close_wait_needed;
} hdb_open_file;
static hdb_file_entry **hdb_files = NULL;
static hdb_open_file *hdb_open_files = NULL;
typedef struct hdb_mmap_meta_t {
	void *mmap_addr;
	uint64_t aligned_len;
} hdb_mmap_meta;
static hdb_mmap_meta hdb_mmap_regions[MAX_OPEN_FILES];
static pthread_mutex_t hdb_mmap_regions_lock;

static void get_hdb_map_entries(void)
{
	FILE *file;
	char line[1024];
	char map_str[5];
	int disk_idx = -1;
	uint64_t disk_offset, stripe_blk_size, file_size, last_modified_time;
	uint32_t hash;
	char flag_str[5], full_path[PATH_MAX];
	int file_cnt = 0;
	
	char *KDB_MAP_FILE = sci_get_kdb_map_file();

	file = fopen(KDB_MAP_FILE, "r");

	if (file == NULL) {
		SCI_SPDK_LOG(DBG_ERR, log_fd, "ERROR: Could not open hdb map file(%s)\n", KDB_MAP_FILE);
		return;
	}

	while (fgets(line, sizeof(line), file)) {
		if (sscanf(line, "%4s %3d %lu %lu %lu %lu %4s %8x %255s", 
				map_str, 
				&disk_idx,
				&disk_offset, 
				&stripe_blk_size, 
				&file_size, 
				&last_modified_time, 
				flag_str, 
				&hash, 
				full_path) == 9)
		{
			/* ignore .d file, which can be loaded from cpu not from slave thread */
			char *last_slash = strrchr(full_path, '/');
			if (last_slash != NULL && strcmp(last_slash + 1, ".d") == 0)
				continue;
			
			assert(hash >= 0 && hash < MAX_HDB_FILES);
			hdb_file_entry *hash_entry = hdb_files[hash];
			if (hash_entry == NULL) {
				hash_entry = calloc(1, sizeof(hdb_file_entry));
				if (hash_entry == NULL) {
					SCI_SPDK_LOG(DBG_ERR, log_fd, "ERROR: failed to allocate hdb_file_entry\n");
					continue;
				}
				hdb_files[hash] = hash_entry;
			}
			if (hash_entry->file_count == 0)
				SSNQ_INIT_LIST_HEAD(&hash_entry->file_queue);
			
			/* do not add new entry for duplicate file */
			struct list_head *rq, *rq_temp;
			int is_dup_file = 0;
			list_for_each_safe(rq, rq_temp, &hash_entry->file_queue) {
				hdb_map_entry *this_map_entry = list_entry(rq, hdb_map_entry, list);
				if (strcmp(this_map_entry->full_path, full_path)==0) {
					is_dup_file = 1;
					break;
				}
			}
			if (is_dup_file) {
				SCI_SPDK_LOG(DBG_ERR, log_fd, "ERROR: found duplicate file(%s)\n", full_path);
				continue;
			}
			if (strcmp(flag_str, "ACTI") != 0 ) {
				SCI_SPDK_LOG(DBG_ERR, log_fd, "ERROR: file(%s) not active\n", full_path);
				continue;
			}
			
			if (hash_entry->file_count > 0)
				SCI_SPDK_LOG(DBG_INIT, log_fd, "file(%s) has the same hash(%x)\n", full_path, hash);
			
			hdb_map_entry *map_entry = calloc(1, sizeof(hdb_map_entry));
			if (map_entry == NULL) {
				SCI_SPDK_LOG(DBG_ERR, log_fd, "ERROR: failed to allocate hdb_map_entry\n");
				continue;
			}
						
			SSNQ_INIT_LIST_HEAD(&map_entry->list);
			memcpy(map_entry->full_path, full_path, PATH_MAX);
			map_entry->disk_idx = disk_idx;
			map_entry->disk_offset = disk_offset;
			map_entry->stripe_blk_size = stripe_blk_size;
			map_entry->file_size = file_size;
			map_entry->last_modified_time = last_modified_time;
			map_entry->flags = HDB_MAP_FLAG_ACTIVE;
			map_entry->hash_idx = hash;
			map_entry->sub_idx = hash_entry->file_count;
			
			disk_count = max(disk_count, disk_idx);
			
			//SCI_SPDK_LOG(DBG_INIT, log_fd, "file[%05d] >> disk(%03d) diskoff(%20lu) fzalign(%16lu) sub(%02d) path(%s)\n",
			//	file_cnt++, map_entry->disk_idx, map_entry->disk_offset, map_entry->stripe_blk_size, map_entry->sub_idx, map_entry->full_path);
			
			list_add_tail(&map_entry->list, &hash_entry->file_queue);
			hash_entry->file_count++;
		}
	}
	
	disk_count++;
	SCI_SPDK_LOG(DBG_INIT, log_fd, "total %d disks are configured\n", disk_count);

	fclose(file);
}
static hdb_map_entry *sci_locate_hdb_file(const char *syscall, const char *pathname, int fd)
{
	uint32_t hash = get_hash26(pathname);
	hdb_file_entry *hash_entry = hdb_files[hash];
	if (hash_entry == NULL) {
		return NULL;
	}
	
	hdb_map_entry *map_entry = NULL;
	struct list_head *rq, *rq_temp;
	int sub_idx = -1;
	list_for_each_safe(rq, rq_temp, &hash_entry->file_queue) {
		hdb_map_entry *this_map_entry = list_entry(rq, hdb_map_entry, list);
		if (strcmp(this_map_entry->full_path, pathname) == 0) {
			sub_idx = this_map_entry->sub_idx;
			
			assert(fd >= 0 && fd < MAX_OPEN_FILES);
			//pthread_mutex_lock(&hdb_mmap_regions_lock);
			hdb_open_file *this_open_file = &hdb_open_files[fd];
			this_open_file->map_entry = this_map_entry;
			this_map_entry->curr_pos = 0;
			//pthread_mutex_unlock(&hdb_mmap_regions_lock);
			
			SCI_SPDK_LOG(DBG_HDB, log_fd, "     Intercepted [%s] for hdb file(%s), fd(%d), map_entry(%p), disk(%d)\n", 
				syscall, pathname, fd, this_open_file->map_entry, this_open_file->map_entry->disk_idx);
			map_entry = this_map_entry;
			break;
		}
	}
	
	if (map_entry == NULL)
		SCI_SPDK_LOG(DBG_HDB, log_fd, "     Intercepted [%s] for hdb file(%s), can't find map_entry for fd(%d)\n", syscall, pathname, fd);
	
	return map_entry;
}
static void sci_fcntl_dupfd(const char *syscall, int old_fd, int fd)
{
	//pthread_mutex_lock(&hdb_mmap_regions_lock);
	hdb_open_file *old_open_file = &hdb_open_files[old_fd];
	hdb_open_file *new_open_file = &hdb_open_files[fd];
	if (old_open_file->map_entry != NULL) {
		new_open_file->map_entry = old_open_file->map_entry;
		old_open_file->close_wait_needed = 0;
		SCI_SPDK_LOG(DBG_HDB, log_fd, "     Intercepted [%s] to replace fd(%d) with new_fd(%d), map_entry(%p)\n", syscall, old_fd, fd, old_open_file->map_entry);
	}
	else {
		/* do not care dupfd for other files not registered with us */
		SCI_SPDK_LOG(DBG_HDB, log_fd, "     ERROR: Intercepted [%s] to can't find map_entry for old_fd(%d)/new_fd(%d)\n", syscall, old_fd, fd);
	}
	//pthread_mutex_unlock(&hdb_mmap_regions_lock);
}

static hdb_map_entry *get_map_by_fd(int fd, const char *syscall)
{
	hdb_map_entry *map_entry = NULL;
	
	if (fd >= 0 && fd < MAX_OPEN_FILES) {
		//pthread_mutex_lock(&hdb_mmap_regions_lock);
		hdb_open_file *open_file = &hdb_open_files[fd];
		if (open_file->map_entry != NULL) {
			SCI_SPDK_LOG(DBG_HDB, log_fd, "Intercepted [%s] getting map_entry(%p) by fd(%d)\n", syscall, open_file->map_entry, fd);
			map_entry = open_file->map_entry;
		}
		//pthread_mutex_unlock(&hdb_mmap_regions_lock);
	}
	
	return map_entry;
}

static ssize_t sci_pread64(int fd, void *buf, size_t count, loff_t off)
{	
	ssize_t cnt = syscall_no_intercept(SYS_pread64, fd, buf, count, off);
	SCI_SPDK_LOG(DBG_IO, log_fd,"[SYS_pread64]: fd(%d), buf(%p), count(%d), off(%lu), rdcnt(%d)\n", 
		(u_int32_t)fd, buf, count, off, cnt);
	return cnt;
}
static int sci_open(const char *pathname, int oflags, mode_t mode, int is_64)
{
	/* ATTN: if multiple threads calling to open the same file, then differnt fd will generate
	   so we may end with multiple fd pointing to the same hdb file map entry, is this ok???
	   file position is maintained with map_entry, not fd, so it may not be ok!!! */
	
	char abs_path[PATH_MAX] = "no path";
	realpath(pathname, abs_path);
	
	int fd = syscall_no_intercept(SYS_open, pathname, oflags, mode);
	SCI_SPDK_LOG(DBG_TRACE, log_fd,"[SYS_%s]: path(%s) flags(5d) mode(%d), fd=%d\n", 
		(is_64 ? "open64" : "open"), pathname, oflags, mode, (u_int32_t)fd);

#ifndef NO_SPDK			
	if (fd != -1)
		sci_locate_hdb_file("SYS_open", abs_path, fd);
#endif
	
	return fd;	
}
static int sci_close(int fd)
{
	int tid;
	int cpu = sci_get_cpu(&tid);
	SCI_SPDK_LOG(DBG_TRACE, log_fd,"[SYS_close]CPU(%d)TID(%d) >>> starts to close fd(%d)\n", cpu, tid, (u_int32_t)fd);

#ifndef NO_SPDK
	/* ATTN: there are two race condition issues with the order of close/mmap/fcntl:
	   [1] fd can be resued anytime after close syscall is completed, so if 
	       syscall_no_intercept(SYS_close, fd) is placed at the beginning of sci_close
	       mmap() could be called anytime, for example, after we mark map_entry NULL,
	       that causing mmap() can't find a map_entry, even though fd is for new file,
	       therefore, mark map_entry NULL must go before SYS_close call to allow openat
	       to update map_entry for new file (again, same fd is resued).
	   [2] fd can be reassigned with fnctl. When we intercept fnctl, we immediately
	       issue SYS_fnctl to get a new assigned fd, and at this moment, before we have
	       a chance to truly transfer the map_entry from old fd to new fd, system could
	       issue close to old fd any time, causing fnctl unable to find map_entry if
	       intercepted fnctl is still in progress. This is why close_wait_needed flag
	       is in place. Intercepted fnctl must set this flag before issuing real syscall,
	       then if somehow close comes too fast, it must wait for this flag to get cleard,
	       which indicating fnctl is done, and then close can go ahead clearing up.
	*/
	
	/* cleanup open_file->map_entry anyway */
	if (fd >= 0 && fd < MAX_OPEN_FILES) {
		//pthread_mutex_lock(&hdb_mmap_regions_lock);
		hdb_open_file *open_file = &hdb_open_files[fd];
		if (open_file->map_entry != NULL) {
			open_file->map_entry->curr_pos = 0;
			SCI_SPDK_LOG(DBG_TRACE, log_fd, "     Intercepted [SYS_close]CPU(%d)TID(%d) checking read to close fd(%d), map_entry(%p)\n", cpu, tid, fd, open_file->map_entry);
			/* wait until we are ready to close */
			while (open_file->close_wait_needed) {
				//pthread_mutex_unlock(&hdb_mmap_regions_lock);
				struct timespec t;
				t.tv_sec = 0;
				t.tv_nsec = 10000;/* 10 */
				syscall_no_intercept(SYS_nanosleep, &t, NULL);
				//pthread_mutex_lock(&hdb_mmap_regions_lock);
			}

			SCI_SPDK_LOG(DBG_TRACE, log_fd, "     Intercepted [SYS_close]CPU(%d)TID(%d) successfully cleaned fd(%d), map_entry(%p)\n", cpu, tid, fd, open_file->map_entry);
			open_file->map_entry = NULL;
		}
		//pthread_mutex_unlock(&hdb_mmap_regions_lock);
	}
#endif

	int succ = syscall_no_intercept(SYS_close, fd);
	SCI_SPDK_LOG(DBG_TRACE, log_fd,"[SYS_close]CPU(%d)TID(%d) closed fd(%d), succ=%d\n", cpu, tid, (u_int32_t)fd, succ);
	
	return succ;	
}
static int sci_openat(int dfd, const char *pathname, int oflags, mode_t mode)
{
	int tid;
	int cpu = sci_get_cpu(&tid);
	char abs_path[PATH_MAX] = "no path";
	realpath(pathname, abs_path);
	hdb_map_entry *map_entry = NULL;
	
	SCI_SPDK_LOG(DBG_TRACE, log_fd,"[SYS_openat]CPU(%d)TID(%d) >>> starts abs(%s) flags(0x%x) mode(0x%x)\n", 
		cpu, tid, abs_path != NULL ? abs_path : "???", oflags, mode);
	int fd = syscall_no_intercept(SYS_openat, dfd, pathname, oflags, mode);

#ifndef NO_SPDK	
	if (fd != -1)
		map_entry = sci_locate_hdb_file("SYS_openat", abs_path, fd);
	/* Once a file is associated with a slave thread, no need to check again */
	if (map_entry != NULL && map_entry->slave_ptr == NULL && tid != my_pid)	/* if it is q main process itself, skip connect slave */
		map_entry->slave_ptr = (void *)sci_connect_thread(abs_path, cpu);
#endif
	
	SCI_SPDK_LOG(DBG_TRACE, log_fd,"[SYS_openat]CPU(%d)TID(%d) opened abs(%s) flags(0x%x) mode(0x%x), fd=%d\n", 
		cpu, tid, abs_path != NULL ? abs_path : "???", oflags, mode, (u_int32_t)fd);

	return fd;	
}

static bool _is_scratch_len(uint64_t len)
{
	/* skip if len smaller than 256MB */
	if (len < (256*1024*1024))
		return false;
	
	if ((len-4096) % (1024*1024) == 0)
		return true;
}

static uint64_t sci_mmap(void *addr, size_t length, int prot, int mmflags, int fd, off_t offset, int cpu, int tid)
{
	int mmap_intercepted = 0;
	uint64_t ret = 0;
	void *buf = NULL;

#ifndef NO_SPDK
	if (fd >= 0 && fd < MAX_OPEN_FILES) {
		hdb_map_entry *map_entry = get_map_by_fd(fd, "SYS_mmap");
		if (map_entry != NULL) {		
			void *buf = sci_submit_mmap_io(map_entry->disk_idx, map_entry->disk_offset, map_entry->file_size);
			if (buf == NULL) {
				printf("  >> [SCI] failed to mmap\n");
				goto out;
			}
			
			mmap_intercepted = 1;
			ret = (uint64_t)buf;
			int find_slot = 0;
			
			//pthread_mutex_lock(&hdb_mmap_regions_lock);
			for (int i=0; i<MAX_OPEN_FILES; i++) {
				if (hdb_mmap_regions[i].mmap_addr == NULL) {
					hdb_mmap_regions[i].mmap_addr = buf;
					hdb_mmap_regions[i].aligned_len = length;// aligned_len;
					find_slot = 1;
					break;
				}
			}
			//pthread_mutex_unlock(&hdb_mmap_regions_lock);
			
			/* TODO: if not find_slot, should cleanup uffd and unregister, set mmap_intercepted 0, go normal mmap */
			SCI_SPDK_LOG(DBG_HDB, log_fd, "     Intercepted [SYS_mmap] done mmap fd(%d), addr(%016llx), reg_mmap(%d), cpu(%d)\n", fd, buf, find_slot, cpu);
		}
		else {
			SCI_SPDK_LOG(DBG_HDB, log_fd, "     WARN: Intercepted [SYS_mmap] can't find map entry for fd(%d)\n", fd);
		}
	}
#endif

out:
	if (!mmap_intercepted) {
#ifndef NO_SPDK
	if (_is_scratch_len(length))
		ret = (uint64_t)sci_alloc_spdk_mem(length);
	else
#endif
		ret = syscall_no_intercept(SYS_mmap, addr, length, prot, mmflags, fd, offset);
	}

	return ret;	
}
static int sci_hdb_munmap(void *mmap_addr, int cpu, int tid)
{
	int succ = 0;
	size_t size = 0;

	//pthread_mutex_lock(&hdb_mmap_regions_lock);
	for (int i=0; i<MAX_OPEN_FILES; i++) {
		if (hdb_mmap_regions[i].mmap_addr != NULL &&
			hdb_mmap_regions[i].mmap_addr == mmap_addr) {
			void *addr = hdb_mmap_regions[i].mmap_addr;
			size = hdb_mmap_regions[i].aligned_len;
			
			hdb_mmap_regions[i].mmap_addr = NULL;
			hdb_mmap_regions[i].aligned_len = 0;
			succ = 1;
			SCI_SPDK_LOG(DBG_HDB, log_fd, "     Intercepted [SYS_munmap] to unmap region(%016llx) DONE\n", mmap_addr);
			break;	
		}
	}
	//pthread_mutex_unlock(&hdb_mmap_regions_lock);
	
	if (succ)
		sci_unmmap_region(mmap_addr, size);
	
	return succ;
}

static int sci_write(int fd, void *buf, size_t count)
{
	int tid;
	int cpu = sci_get_cpu(&tid);
	//SCI_SPDK_LOG(DBG_IO, log_fd,"[SYS_write]: >> start fd(%d)\n", (u_int32_t)fd);
	ssize_t cnt = syscall_no_intercept(SYS_write, fd, buf, count);
	SCI_SPDK_LOG(DBG_IO, log_fd,"[SYS_write]CPU(%d)TID(%d) fd(0%d), buf(%p), count(%d), wrcnt(%d)\n", 
		cpu, tid, (u_int32_t)fd, buf, count, cnt);
	return cnt;	
}
static ssize_t sci_read(int fd, void *buf, size_t count)
{
	int tid;
	int cpu = sci_get_cpu(&tid);
	SCI_SPDK_LOG(DBG_IO, log_fd,"[SYS_read]CPU(%d)TID(%d) >>> starts fd(%d)\n", cpu, tid, (u_int32_t)fd);
	ssize_t data_received = syscall_no_intercept(SYS_read, fd, buf, count);
	SCI_SPDK_LOG(DBG_IO, log_fd,"[SYS_read]CPU(%d)TID(%d) fd(%d), buf(%p), count(%ld), rdcnt(%ld)\n", 
		cpu, tid, (u_int32_t)fd, buf, count, data_received);
	
	return data_received;
}
static off_t sci_lseek(int fd, off_t off, int whence)
{
	int tid;
	int cpu = sci_get_cpu(&tid);
	SCI_SPDK_LOG(DBG_IO, log_fd,"[SYS_lseek]CPU(%d)TID(%d) >>> starts fd(%d), off(%lu), whence(%d)\n", cpu, tid, (u_int32_t)fd, off, whence);
	off_t ret = syscall_no_intercept(SYS_lseek, fd, off, whence);
	SCI_SPDK_LOG(DBG_IO, log_fd,"[SYS_lseek]CPU(%d)TID(%d) fd(%d), off(%lu), whence(%d), ret(%lu)\n", cpu, tid, (u_int32_t)fd, off, whence, ret);
	
	return ret;	
}

static bool ends_with(const char *str, const char *suffix)
{
	if (!str || !suffix)
		return false;
	size_t len_str = strlen(str);
	size_t len_suffix = strlen(suffix);
	if (len_suffix > len_str)
		return false;
	return strncmp(str + len_str - len_suffix, suffix, len_suffix) == 0;
}

static int collect_kio_config_done = 0;
static int is_l64_q = 0;
static int is_pps_q = 0;

static int
hook(long syscall_number,
	long arg0, long arg1,
	long arg2, long arg3,
	long arg4, long arg5,
	long *result)
{
	(void) arg0;
	(void) arg2;
	(void) arg3;
	(void) arg4;
	(void) arg5;
	(void) result;
	
	if (!is_l64_q || is_pps_q)
		return 1;

#ifndef NO_SPDK
	if (syscall_number != SYS_clone &&
		syscall_number != SYS_clone3) {
		if (!spdk_check_init_status())
			return 1;
	}
#endif
	
	if (syscall_number == SYS_vfork) {
		*result = syscall_no_intercept(SYS_getpid);
		return 0;
	}
	
	/* re-direct to the correct license folder */
	if (syscall_number == SYS_open ||
		syscall_number == SYS_openat ||
		syscall_number == SYS_stat ||
		syscall_number == SYS_readlink)
	{
		char *path = (syscall_number == SYS_openat ? (char *)arg1 : (char *)arg0);
		char real_q_lic_fn[PATH_MAX];
		bool read_q_lic_needed = false;
		
		if (ends_with(path, "kc.lic")) {
			snprintf(real_q_lic_fn, PATH_MAX, "%s/kc.lic", q_lic_dir);
			SCI_SPDK_LOG(DBG_ERR, log_fd, "SYSCALL[%ld] shall use %s\n", syscall_number, real_q_lic_fn);
			read_q_lic_needed = true;
		}
		else if (ends_with(path, "q.k")) {
			snprintf(real_q_lic_fn, PATH_MAX, "%s/q.k", q_lic_dir);
			SCI_SPDK_LOG(DBG_ERR, log_fd, "SYSCALL[%ld] shall use %s\n", syscall_number, real_q_lic_fn);
			read_q_lic_needed = true;
		}
		
		if (read_q_lic_needed) {
			if (syscall_number == SYS_openat)
				*result = syscall_no_intercept(syscall_number, arg0, real_q_lic_fn, arg2, arg3, arg4, arg5);
			else 
				*result = syscall_no_intercept(syscall_number, real_q_lic_fn, arg1, arg2, arg3, arg4, arg5);
			return 0;
		}
	}

	int return_zero = 1;
	
	switch (syscall_number)
	{
		case SYS_read:	/* 0 */
			*result = sci_read((int)arg0, (void *)arg1, (size_t)arg2);
			break;
		case SYS_write:	/* 1 */
			*result = sci_write((int)arg0, (void*)arg1, (size_t)arg2);
			break;
		case SYS_open:	/* 2 */
			*result = sci_open((const char *)arg0, (int)arg1, (mode_t)arg2, 0);
			break;
		case SYS_close:	/* 3 */
			*result = sci_close((int)arg0);
			break;
		case SYS_stat:	/* 4 */
		case SYS_fstat:	/* 5 */
			if (1)
			{
				int tid;
				int cpu = sci_get_cpu(&tid);
				char abs_path[PATH_MAX] = "no path";
				struct stat *stat;
				if (syscall_number == SYS_stat) {
					realpath((char *)arg0, abs_path);
				}
				SCI_SPDK_LOG(DBG_TRACE, log_fd, "[%s]CPU(%d)TID(%d) >>> starts stats, path(%s)\n", 
						syscall_number == SYS_stat ? "SYS_stat" : "SYS_fstat", cpu, tid, abs_path);
				*result = syscall_no_intercept(syscall_number, arg0, arg1);
				if (*result == 0)
				{
					stat = (struct stat *)arg1;
				
					SCI_SPDK_LOG(DBG_TRACE, log_fd, "[%s]CPU(%d)TID(%d) stats(%lu,%lu,%lu), path(%s)\n", 
						syscall_number == SYS_stat ? "SYS_stat" : "SYS_fstat", cpu, tid,
						stat->st_size, stat->st_blksize, stat->st_blocks, abs_path);
				}
			}
			break;
		case SYS_lseek:	/* 8 */
			*result = sci_lseek((int)arg0, (off_t)arg1, (int)arg2);
			break;
		case SYS_mprotect:/* 10 */
			*result = syscall_no_intercept(SYS_mprotect, arg0, arg1, arg2);
			SCI_SPDK_LOG(DBG_TRACE, log_fd,"[SYS_mprotect]: >> addr(%016llx) len(%lu) prot(%x)\n", arg0, arg1, arg2);
			break;
		case SYS_pread64:	/* 17 */
			*result = sci_pread64((int)arg0, (void *)arg1, (size_t)arg2, (loff_t)arg3);
			break;
		case SYS_fcntl:		/* 72 */
			{
				int tid;
				int cpu = sci_get_cpu(&tid);
		#ifndef NO_SPDK
				if (arg1 == F_DUPFD)
				{
					SCI_SPDK_LOG(DBG_TRACE, log_fd,"[SYS_fcntl]CPU(%d)TID(%d) >>> starts fd(%d), cmd(%x), arg(%d)\n", 
						cpu, tid, arg0, arg1, arg2);

					//pthread_mutex_lock(&hdb_mmap_regions_lock);
					hdb_open_file *old_open_file = &hdb_open_files[arg0];
					if (old_open_file->map_entry != NULL) {
						old_open_file->close_wait_needed = 1;
						SCI_SPDK_LOG(DBG_TRACE, log_fd,"     Intercepted [SYS_fcntl] fd(%d), close_wait_needed set\n", arg0);
					}
					//pthread_mutex_unlock(&hdb_mmap_regions_lock);
					
					int fd = syscall_no_intercept(SYS_fcntl, arg0, arg1, arg2);
					*result = fd;
				
					if (fd != -1)
						sci_fcntl_dupfd("SYS_fcntl", arg0, fd);
					
					SCI_SPDK_LOG(DBG_TRACE, log_fd,"[SYS_fcntl]CPU(%d)TID(%d) fd(%d), cmd(%x), arg(%d), rtn_fd(%d)\n", 
						cpu, tid, arg0, arg1, arg2, fd);
				}
				else 
		#endif
				{
					*result = syscall_no_intercept(SYS_fcntl, arg0, arg1, arg2);
				}
			}
			break;
		case SYS_openat:	/* 257 */
			if (1)
			{
				const char *filename = (const char *)arg1;
				if (strncmp(filename, "/dev", 4) == 0 ||
					strncmp(filename, "/proc", 5) == 0)
				{
					if (strncmp(filename, "/proc/self/maps", 15) == 0)
						printf("[SYS_openat] opening /proc/self/maps\n");
					
					*result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
					break;
				}
			}
			*result = sci_openat((int)arg0, (const char *)arg1, (int)arg2, (int)arg3);
			break;
		case SYS_clone:
		case SYS_clone3:
			{
				int cpu = -1;
				int status = syscall_no_intercept(SYS_getcpu, &cpu, NULL, NULL);
				int tid = syscall_no_intercept(SYS_gettid);

				if (arg1 != 0)
					flags = arg0;
		
				SCI_SPDK_LOG(DBG_INFO, log_fd, ">>> %s: TID(%d) pid(%p) child(%p), cpu(%d)\n", 
					syscall_number == SYS_clone ? "SYS_clone" : "SYS_clone3", tid, (void *)arg2, (void *)arg3, cpu);
			}
			return_zero = 0;
			break;
		case SYS_mmap:
			{
				int tid;
				int cpu = sci_get_cpu(&tid);
				SCI_SPDK_LOG(DBG_IO, log_fd, "[SYS_mmap]CPU(%d)TID(%d) >>> starts addr(%p), len(%lu), prot(%d), flags(%x), fd(%d), off(%lu)\n", 
					cpu, tid, arg0, arg1, arg2, arg3, arg4, arg5);
				*result = sci_mmap((void*)arg0, (size_t)arg1, (int)arg2, (int)arg3, (int)arg4, (off_t)arg5, cpu, tid);	
				SCI_SPDK_LOG(DBG_IO, log_fd, "[SYS_mmap]CPU(%d)TID(%d) addr(%p), len(%lu), prot(%d), flags(%x), fd(%d), off(%lu), mmap_addr=%p\n", 
					cpu, tid, arg0, arg1, arg2, arg3, arg4, arg5, (void *)(*result));
			}
			break;
		case SYS_madvise:
			SCI_SPDK_LOG(DBG_TRACE, log_fd, ">>> start SYS_madvise, addr=%016llx, len=%d, adv=0x%x\n", arg0, arg1, arg2);
			*result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);	
			SCI_SPDK_LOG(DBG_TRACE, log_fd, ">>> done SYS_madvise, addr=%016llx, len=%d, adv=0x%x\n", arg0, arg1, arg2);
			break;
		case SYS_munmap:
			{
				int tid;
				int cpu = sci_get_cpu(&tid);
				SCI_SPDK_LOG(DBG_IO, log_fd, "[SYS_munmap]CPU(%d)TID(%d) >>> starts addr=%016llx, len=%lu\n", cpu, tid, arg0, arg1);
				int succ = sci_hdb_munmap((void *)arg0, cpu, tid);
				if (succ)
					*result = 0;
				else {
				#ifndef NO_SPDK
					if (_is_scratch_len(arg1))
					{
						sci_free_spdk_mem((void *)arg0, arg1);
						printf("freeing final scratch buf=%p\n", (void *)arg0);
						*result = 0;
					}
					else
				#endif
						*result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);			 		
				}
				SCI_SPDK_LOG(DBG_IO, log_fd, "[SYS_munmap]CPU(%d)TID(%d) addr=%016llx, len=%d\n", cpu, tid, arg0, arg1);
			}
			break;
		case SYS_mremap:
			SCI_SPDK_LOG(DBG_IO, log_fd, ">>> start SYS_mremap, addr=%016llx, old_len=%lu, new_len=%lu, new_addr=%016llx\n", arg0, arg1, arg2, arg4);	
			*result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
			SCI_SPDK_LOG(DBG_IO, log_fd, ">>> done SYS_mremap, addr=%016llx, old_len=%lu, new_len=%lu, new_addr=%016llx\n", arg0, arg1, arg2, arg4);	
			break;
		case SYS_futex:
			SCI_SPDK_LOG(DBG_MUTEX, log_fd, "[SYS_futex], addr=%016llx, to acquire >> \n", arg0);	
			*result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
			SCI_SPDK_LOG(DBG_MUTEX, log_fd, "[SYS_futex], addr=%016llx, to acquired << \n", arg0);		
			break;
		case SYS_userfaultfd:
			SCI_SPDK_LOG(DBG_HDB, log_fd, ">>> start SYS_userfaultfd, flags=%x\n", arg0);	
			*result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
			SCI_SPDK_LOG(DBG_HDB, log_fd, ">>> done SYS_userfaultfd, flags=%x\n", arg0);	
			break;
		case SYS_readlink:
			SCI_SPDK_LOG(DBG_TRACE, log_fd, ">>> start SYS_readlink, path(%s)\n", arg0);	
			*result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
			SCI_SPDK_LOG(DBG_TRACE, log_fd, ">>> done SYS_readlink\n");				
			break;			
		case SYS_newfstatat:
			SCI_SPDK_LOG(DBG_TRACE, log_fd, ">>> start SYS_newfstatat, dfd(%x), fn(%s)\n", arg0, arg1);	
			*result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
			SCI_SPDK_LOG(DBG_TRACE, log_fd, ">>> done SYS_newfstatat\n");
			break;
		default:
			SCI_SPDK_LOG(DBG_TRACE, log_fd, ">>> syscall[%d] start\n", syscall_number);
			*result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
			SCI_SPDK_LOG(DBG_TRACE, log_fd, "<<< syscall[%d] end\n", syscall_number);
			break;
	}

	if (return_zero)
		return 0;
	else 
		return 1;
}

static void
hook_child(void)
{
	assert(flags != -1);
}

static char *ps_name = NULL;
static char *pps_name = NULL;

static int get_token_dash_s(char *cmdline)
{
	int slave_cnt = 0;
	const char *search = "-s";
	char *found = strstr(cmdline, search);
	if (found)
		sscanf(found + strlen(search), "%d", &slave_cnt);
	return slave_cnt;
}

int sci_get_log_fd(void)
{
	return log_fd;
}

static __attribute__((constructor)) void
init(void)
{
	char *str = NULL;
	int is_parent_q = 0;
	
	/* ensure q license folder is there */
	q_lic_dir = sci_get_q_lic_dir();
	if (q_lic_dir == NULL) {
		printf("ERROR: Invalid Q License Folder\n");
		syscall_no_intercept(SYS_exit_group, 4);
	}

	/* For non-spdk we want all logs */
#ifndef NO_SPDK	
	sci_debug_level = sci_get_debug_level();	
	sci_debug_level |= (DBG_ERR|DBG_INIT);
#endif

	/* get process name by pid, replacing any '/' with '-', then
	   create process associated log file */
	my_ppid = syscall_no_intercept(SYS_getppid);
	my_pid = syscall_no_intercept(SYS_getpid);
	ps_name = sci_get_ps_name();
	if (ps_name == NULL) {
		printf("NULL ps_name\n");
		syscall_no_intercept(SYS_exit_group, 4);
	}
	is_l64_q = sci_is_l64_q();

	pps_name = sci_get_pps_name();
	if (pps_name == NULL) {
		printf("NULL pps_name\n");
		syscall_no_intercept(SYS_exit_group, 4);
	}
	is_pps_q = sci_is_pps_q();
		
	/* Do not intercept non-q processes or processes forked by q */
	if (!is_l64_q || is_pps_q)
		return;
	
	/* Initializing log for q process only */
	sprintf(log_path, "%s/ssnq_%ld_%s.log", log_dir, my_pid, ps_name);
	
	/* get full path name for current process */
	get_path_by_pid(my_pid, my_ps_full_path);
	get_path_by_pid(my_ppid, my_pps_full_path);
		
	log_fd = (int)syscall_no_intercept(SYS_open,
			log_path, O_CREAT | O_RDWR | /*O_APPEND*/O_TRUNC, (mode_t)0744);

	if (log_fd < 0)
		syscall_no_intercept(SYS_exit_group, 4);
	
	SCI_SPDK_LOG(DBG_INIT, log_fd, "log_fd=%u process=(%s)(%ld) parent=(%s)(%ld) debug_level=0x%x\n", 
			(unsigned int)log_fd, my_ps_full_path, my_pid, my_pps_full_path, my_ppid, sci_debug_level);
	
	/* Get slave count in order to match disk count */
	char cmdline[256];
	char procfn[32];
	FILE *f;
	snprintf(procfn, 32, "/proc/%ld/cmdline", my_pid);
	f = fopen(procfn, "r");
	if (!f) {
		perror("fopen");
		return;
	}
	size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
	fclose(f);
	if (n == 0) {
		perror("fread");
		return;
	}
	cmdline[n] = '\0';
	for (size_t i = 0; i < n; ++i) {
		if (cmdline[i] == '\0') {
			cmdline[i] = ' ';
		}
	}	
	slave_cnt = get_token_dash_s(cmdline);
	if (slave_cnt > MAX_JOB_CNT) {
		SCI_SPDK_LOG(DBG_ERR, log_fd, "ERROR: slave thread count %d over the limit %d\n", slave_cnt, MAX_JOB_CNT);
		syscall_no_intercept(SYS_exit_group, 4);
	}
	if (slave_cnt == 0)
		slave_cnt = 1;	/* must have at least main thread */
		
#ifndef NO_SPDK	
	/* Load HDB maps and setup file hash table */
	hdb_files = calloc(MAX_HDB_FILES, sizeof(hdb_file_entry *));
	if (hdb_files == NULL) {
		SCI_SPDK_LOG(DBG_ERR, log_fd, "ERROR: failed to allocate hdb_files array\n");
		syscall_no_intercept(SYS_exit_group, 4);
	}
	get_hdb_map_entries();
	
	/* Get ready open file table */
	hdb_open_files = calloc(MAX_OPEN_FILES, sizeof(hdb_open_file));
	if (hdb_open_files == NULL) {
		SCI_SPDK_LOG(DBG_ERR, log_fd, "ERROR: failed to allocate hdb_open_files array\n");
		syscall_no_intercept(SYS_exit_group, 4);
	}
	for (int i=0; i<MAX_OPEN_FILES; i++)
		hdb_open_files[i].map_entry = NULL;
	memset((void *)hdb_mmap_regions, 0, MAX_OPEN_FILES*sizeof(hdb_mmap_meta));
	pthread_mutex_init(&hdb_mmap_regions_lock, NULL);
#endif
	
	memset((void *)cpu_tables, 0, sizeof(struct cpu_table_t)*MAX_CPU_CNT);
	
	cpu_set_t set;
	CPU_ZERO(&set);
	if (sched_getaffinity(0, sizeof(cpu_set_t), &set) == 0) {
		int count = CPU_COUNT(&set);
		SCI_SPDK_LOG(DBG_INIT, log_fd, "This process can run on %d CPU(s): ", count);

		for (int i = 0; i < /*CPU_SETSIZE*/MAX_CPU_CNT; i++) {
			if (CPU_ISSET(i, &set)) cpu_tables[i].presented = 1;
		}
	} else {
		perror("sched_getaffinity");
		exit(EXIT_FAILURE);
	}
	pthread_mutex_init(&pin_slave_lock, NULL);
	memset((void *)slave_threads, 0, sizeof(struct slave_table_t)*MAX_JOB_CNT);
	for (int i = 0; i < slave_cnt; i++)
		slave_threads[i].core_id = -1;

#ifndef NO_SPDK
	/* this waiting has to be at the end of init because we want spdk module is
	   able to use log file too */
	SCI_SPDK_LOG(DBG_INIT, log_fd, "Checking SPDK initialization status ... \n");
	while (!spdk_check_init_status()) {
					struct timespec t;
					t.tv_sec = 1;
					t.tv_nsec = 0;
					syscall_no_intercept(SYS_nanosleep, &t, NULL);
	}
	SCI_SPDK_LOG(DBG_INIT, log_fd, "Checking SPDK initialization status DONE.\n");
	//sleep(2);/* sleep 2 more to wait for main_workder get ready */
#endif
	
ret:
	intercept_hook_point = hook;
	intercept_hook_point_clone_child = hook_child;
	SCI_SPDK_LOG(DBG_INIT, log_fd, "SCI exited constructor, %s, pid(%ld) ppid(%ld)\n", ps_name, my_pid, my_ppid);
}

static __attribute__((destructor)) void
deinit(void)
{
	printf("[SCI] process(%s,%ld) exiting ...\n", ps_name, my_pid);
	
	if (!is_l64_q || is_pps_q)
		goto ret;
	
#ifndef NO_SPDK	
	spdk_exit();
	
	while(1) {
		if (spdk_check_init_status() == 0)
			break;
		
		sleep(1);
	}
#endif
	
#ifndef NO_SPDK	
	if (hdb_files != NULL) {
		for (int64_t i=0; i<MAX_HDB_FILES; i++) {
			hdb_file_entry *hash_entry = hdb_files[i];
			
			if (hash_entry != NULL) {
				if (!list_empty(&hash_entry->file_queue)) {
					while (1) {
						hdb_map_entry *map_entry = NULL;
		
						if (list_empty(&hash_entry->file_queue))
							break;
		
						map_entry = list_entry(hash_entry->file_queue.next, hdb_map_entry, list);
						
						list_del_init(&map_entry->list);
						free(map_entry);					
					}
				}
				free(hash_entry);
			}
		}
		free(hdb_files);
	}
	if (hdb_open_files != NULL)
		free(hdb_open_files);

	pthread_mutex_destroy(&hdb_mmap_regions_lock);
	pthread_mutex_destroy(&pin_slave_lock);
#endif

ret:
		
	if (log_fd != -1) {
		syscall_no_intercept(SYS_close, log_fd);
		log_fd = -1;
	}

	printf("[SCI] process(%s,%ld) exited.\n", ps_name, my_pid);
}
