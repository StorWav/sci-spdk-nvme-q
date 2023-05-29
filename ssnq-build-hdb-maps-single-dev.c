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
 *   ssnq-build-hdb-maps-single-dev.c
 * 
 *   Mirroring Kdb+/Q HDB data to SPDK/NVMe drives and generating SSNQ.hdb.maps
 * 
 *   Author: Colin Zhu <czhu@nexnt.com>
 */

#pragma GCC diagnostic ignored "-Wformat-truncation="

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include <linux/limits.h>
#include <xxhash.h>

#include "ssnq_common.h"

#define SYS_BLOCK_PATH "/sys/class/nvme"
#define SERIAL_FILE "serial"
#define DEV_PATH_SIZE	32	/* device path size */

static FILE *file_hdb_maps = NULL;
const unsigned int max_slot = 67108863U;/* 26 bit */
static uint64_t total_file_size = 0;
static int total_file_count = 0;

typedef struct _ssnq_dev_t {
	char dev_path[DEV_PATH_SIZE];	/* /dev/nvmeXXn1 */
	char sn[SN_SIZE];
	int is_allocated;
	int fd;
} ssnq_dev_t;

static ssnq_dev_t ssnq_devs[MAX_DEV_CNT];
static int ssnq_dev_count = 0;

uint32_t get_hash26(const char *filename)
{
	unsigned int hash = XXH32(filename, strlen(filename), 0);

	if (hash >= max_slot)
		hash = (hash >> 6) & 0x03FFFFFF;
	
	return hash;
}

static char file_list_path[PATH_MAX] = {'\0'};
static char filename_hdb_maps[PATH_MAX] = {'\0'};
static char KIO_CONF_FILE[PATH_MAX] = {'\0'};
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
static void get_files(void)
{
	get_token_from_path_file("SSNQ_CONF", KIO_CONF_FILE);
	get_token_from_path_file("SSNQ_HDB_MAPS", filename_hdb_maps);
	get_token_from_path_file("SSNQ_FILE_LIST", file_list_path);
	
	printf("Get files (%s)(%s)(%s)\n", KIO_CONF_FILE, filename_hdb_maps, file_list_path);
	
	return;
err:
	exit(1);
}

void rtrim(char *str)
{
	int len = strlen(str);
	while (len > 0 && isspace(str[len - 1])) {
		str[--len] = '\0';
	}
}

void find_nvme_device_file(const char *target_serial_number, int ns, char *nvme_device_file)
{
	DIR *dir = opendir(SYS_BLOCK_PATH);
	if (dir == NULL) {
		perror("Error opening directory");
		return;
	}

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (strncmp(entry->d_name, "nvme", 4) == 0) {
			char serial_file_path[256];
			snprintf(serial_file_path, sizeof(serial_file_path), "%s/%s/%s", SYS_BLOCK_PATH, entry->d_name, SERIAL_FILE);

			FILE *serial_file = fopen(serial_file_path, "r");
			if (serial_file != NULL) {
				char serial_number[SN_SIZE];
				fgets(serial_number, sizeof(serial_number), serial_file);

				rtrim(serial_number);

				if (strcmp(serial_number, target_serial_number) == 0) {
					snprintf(nvme_device_file, DEV_PATH_SIZE, "/dev/%sn%d", entry->d_name, ns);
				}

				fclose(serial_file);
			}
		}
	}

	closedir(dir);
}

int select_disk(size_t disk_datasizes[MAX_DEV_CNT])
{
	uint64_t min_size = 0xFFFFFFFFFFFFFFFFULL;
	int min_idx = 0;
	
	for (int i=0; i<ssnq_dev_count; i++) {
		if (disk_datasizes[i] < min_size) {
			min_size = disk_datasizes[i];
			min_idx = i;
		}
	}
	
	return min_idx;	
}

void copy_file_data(const char *filepath, size_t disk_offsets[MAX_DEV_CNT], size_t disk_datasizes[MAX_DEV_CNT], int line_idx)
{
	char *buffer = NULL;
	
	int source_fd = open(filepath, O_RDONLY);
	if (source_fd < 0) {
		printf("Error opening source file(%s)\n", filepath);
		goto ret;
	}

	struct stat st;
	if (fstat(source_fd, &st) < 0) {
		printf("Error getting file size for file(%s)\n", filepath);
		goto ret;
	}

	time_t last_modified_time = st.st_mtime;
	size_t file_size = st.st_size;
	size_t allocated_size = (file_size % 4096 == 0 ? file_size : (file_size/4096+1)*4096);/* 4K align */
	size_t chunk_size = allocated_size;

	//printf("file(%s) size(%lu) chunk(%lu)\n", filepath, file_size, chunk_size);

	buffer = malloc(chunk_size);
	assert(buffer != NULL);
	int copy_done = 0;

	int disk_idx = line_idx % ssnq_dev_count;
	assert(disk_idx>=0 && disk_idx<ssnq_dev_count);

	ssize_t bytes_read = read(source_fd, buffer, /*chunk_size*/file_size);
	if (bytes_read < 0) {
		printf("Error reading source file(%s)\n", filepath);
		goto ret;
	}

	// Get the offset for the current disk
	uint64_t disk_offset = disk_offsets[disk_idx];

	if (bytes_read > 0) {
		// Do the actual copy to the disk here.
		ssize_t bytes_written = pwrite(ssnq_devs[disk_idx].fd, buffer, bytes_read, disk_offset);

  	  	if (bytes_written != bytes_read) {
			printf("Error writing to device[%d] for file(%s)\n", disk_idx, filepath);
			goto ret;
		} else {
			copy_done = 1;
		}
		
		//printf("Copied (%zd,%zd) bytes to disk%d at offset %zd\n", 
		//	bytes_read, bytes_written, disk, disk_offset);

		// Update the disk offset for the next file (isn't current offset same as size???)
		if (copy_done) {
			disk_offsets[disk_idx] += chunk_size;
			disk_datasizes[disk_idx] += chunk_size;
			total_file_count++;
			total_file_size += file_size;
			fprintf(file_hdb_maps, "map=%03d  %020lu  %020lu  %020lu  %010lu  %s  %08x  %s\n",
				disk_idx, disk_offset, chunk_size, file_size, last_modified_time, "ACTI", get_hash26(filepath), filepath);
		}
	}

ret:
	if (buffer != NULL)
		free(buffer);
	if (source_fd >= 0)
		close(source_fd);
}

void process_file_list(const char *file_list)
{
	FILE *file = fopen(file_list, "r");
	if (!file) {
		perror("Error opening file list");
		return;
	}

	uint64_t disk_offsets[MAX_DEV_CNT];
	memset(disk_offsets, 0, sizeof(disk_offsets));
	uint64_t disk_datasizes[MAX_DEV_CNT];
	memset(disk_datasizes, 0, sizeof(disk_datasizes));

	char filepath[PATH_MAX];
	char line[PATH_MAX];
	while (fgets(line, sizeof(line), file)) {
		int line_idx;
		sscanf(line, "%d %s", &line_idx, filepath);
		
		// Remove trailing newline character
		filepath[strcspn(filepath, "\n")] = 0;

		copy_file_data(filepath, disk_offsets, disk_datasizes, line_idx);
	}

	fclose(file);
}


int main()
{
	int i;
	int dev_idx = 0;
	memset((void *)ssnq_devs, 0, sizeof(ssnq_dev_t)*MAX_DEV_CNT);
	
	get_files();
	
	file_hdb_maps = fopen(filename_hdb_maps, "w");
	if (file_hdb_maps == NULL) {
		perror("Unable to open file");
		goto ret;
	}
	
	FILE *kiocfg_file = fopen(KIO_CONF_FILE, "r");
	if (kiocfg_file == NULL) {
		perror("Error opening kiocfg file");
		goto ret;
	}

	char line[256];
	while (fgets(line, sizeof(line), kiocfg_file)) {
		if (line[0] == '#' || strncmp(line, "disk", 4) != 0) {
			continue;
		}
		
		fprintf(file_hdb_maps, "%s", line);
		
		if (dev_idx >= MAX_DEV_CNT) {
			printf("Warning: max device count (%d) reached.\n", MAX_DEV_CNT);
			break;
		}
	
		int target_disk_num;
		char target_serial_number[SN_SIZE] = "";
		char pci_addr[PCI_ADDR_SIZE] = "";
		int ns;
		sscanf(line, "disk %d %s %s %d", &target_disk_num, target_serial_number, pci_addr, &ns);

		char nvme_device_file[DEV_PATH_SIZE] = "";
		find_nvme_device_file(target_serial_number, ns, nvme_device_file);

		if (strlen(nvme_device_file) > 0) {
			ssnq_dev_t *this_dev = &ssnq_devs[dev_idx];
			snprintf(this_dev->dev_path, DEV_PATH_SIZE, "%s", nvme_device_file);
			snprintf(this_dev->sn, SN_SIZE, "%s", target_serial_number);
			this_dev->is_allocated = 1;
			dev_idx++;
			printf("Found NVMe device file for serial number '%s': %s\n", target_serial_number, nvme_device_file);
		} else {
			printf("NVMe device with serial number '%s' not found\n", target_serial_number);
		}
	}

	fclose(kiocfg_file);
	ssnq_dev_count = dev_idx;
	
	for (i=0; i<MAX_DEV_CNT; i++) {
   		ssnq_dev_t *this_dev = &ssnq_devs[i];
   		
   		if (!this_dev->is_allocated)
   			break;
   			
		int fd = open(this_dev->dev_path, O_RDWR);
		if (fd < 0) {
			perror("Error opening device");
			goto ret;
		}
		this_dev->fd = fd;
   		
   		printf("device[%d] sn[%s] path[%s]\n", i, this_dev->sn, this_dev->dev_path);
	}
	printf("ssnq_dev_count=%d\n", ssnq_dev_count);
		
	if (ssnq_dev_count > 0)
		process_file_list(file_list_path);
		
	fprintf(file_hdb_maps, "file counts=%d, ave file size=%lu\n", total_file_count, total_file_size/total_file_count);

ret:
	for (i=0; i<MAX_DEV_CNT; i++) {
   		ssnq_dev_t *this_dev = &ssnq_devs[i];
   		
   		if (!this_dev->is_allocated)
   			break;
   			
		if (this_dev->fd > 0)
			close(this_dev->fd);
	}
	
	if (file_hdb_maps != NULL)
		fclose(file_hdb_maps);
		
	return 0;
}
