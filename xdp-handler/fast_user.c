/*
 *  Software Name : bmc-cache
 *  SPDX-FileCopyrightText: Copyright (c) 2021 Orange
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 *  This software is distributed under the
 *  GNU Lesser General Public License v2.1 only.
 *
 *  Author: Yoann GHIGOFF <yoann.ghigoff@orange.com> et al.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/resource.h>
#include <asm-generic/posix_types.h>
#include <linux/if_link.h>
#include <linux/limits.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "fast_common.h"

#define BPF_SYSFS_ROOT "/sys/fs/bpf"


struct bpf_progs_desc {
	char name[256];
	enum bpf_prog_type type;
	unsigned char pin;
	int map_prog_idx;
	struct bpf_program *prog;
};
// define our eBPF program.
static struct bpf_progs_desc progs[] = {
	{"fastPaxos", BPF_PROG_TYPE_XDP, 0, -1, NULL},
	{"HandlePrepare", BPF_PROG_TYPE_XDP, 0, FAST_PROG_XDP_HANDLE_PREPARE, NULL},
	{"HandlePrepareOK", BPF_PROG_TYPE_XDP, 0, FAST_PROG_XDP_HANDLE_PREPAREOK, NULL},
	{"HandleRequest", BPF_PROG_TYPE_XDP, 0, FAST_PROG_XDP_HANDLE_REQUEST, NULL},
	{"WriteBuffer", BPF_PROG_TYPE_XDP, 0, FAST_PROG_XDP_WRITE_BUFFER, NULL},
	{"PrepareFastReply", BPF_PROG_TYPE_XDP, 0, FAST_PROG_XDP_PREPARE_REPLY, NULL},

	{"FastBroadCast", BPF_PROG_TYPE_SCHED_CLS, 1, -1, NULL},
};


struct bpf_object *obj;
struct bpf_object_load_attr load_attr;
int err, prog_count;
int xdp_main_prog_fd;
char filename[PATH_MAX];
char commandname[PATH_MAX];
__u32 xdp_flags = 0;
int *interfaces_idx;

int map_progs_fd, map_progs_xdp_fd, map_progs_tc_fd, map_paxos_ctr_state_fd;
int map_prepare_buffer_fd, map_configure_fd, map_request_buffer_fd;
int interface_count = 0;
static int nr_cpus = 0;


void parse_cmdline(int argc, char *argv[]) {
	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	interface_count = argc - optind;
	if (interface_count <= 0) {
		fprintf(stderr, "Missing at least one required interface index\n");
		exit(EXIT_FAILURE);
	}

	interfaces_idx = calloc(sizeof(int), interface_count);
	if (interfaces_idx == NULL) {
		fprintf(stderr, "Error: failed to allocate memory\n");
		exit(1); // return 1;
	}

	for (int i = 0; i < interface_count && optind < argc; i++) {
		// printf("%d\n", if_nametoindex(argv[optind]));
		interfaces_idx[i] = if_nametoindex(argv[optind + i]);
	}

	// asd123www: XDP_FLAGS_DRV_MODE not supported! use XDP_FLAGS_SKB_MODE.
	xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
	nr_cpus = libbpf_num_possible_cpus();
}


void create_object() {
	obj = bpf_object__open(filename);
	if (!obj) {
		fprintf(stderr, "Error: bpf_object__open failed\n");
		exit(1); //return 1;
	}

	prog_count = sizeof(progs) / sizeof(progs[0]);
	for (int i = 0; i < prog_count; i++) {
		printf("progname: %s\n", progs[i].name);
		progs[i].prog = bpf_object__find_program_by_title(obj, progs[i].name);
		if (!progs[i].prog) {
			fprintf(stderr, "Error: bpf_object__find_program_by_title failed\n");
			exit(1); //return 1;
		}
		bpf_program__set_type(progs[i].prog, progs[i].type);
	}
	
	load_attr.obj = obj;
	load_attr.log_level = LIBBPF_WARN;

	/* Load/unload object into/from kernel */
	err = bpf_object__load_xattr(&load_attr);
	if (err) {
		fprintf(stderr, "Error: bpf_object__load_xattr failed\n");
		exit(1); //return 1;
	}
	map_progs_xdp_fd = bpf_object__find_map_fd_by_name(obj, "map_progs_xdp");
	if (map_progs_xdp_fd < 0) {
		fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
		exit(1); //return 1;
	}
	map_progs_tc_fd = bpf_object__find_map_fd_by_name(obj, "map_progs_tc");
	if (map_progs_tc_fd < 0) {
		fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
		exit(1);
		// return 1;
	}


	map_prepare_buffer_fd = bpf_object__find_map_fd_by_name(obj, "map_prepare_buffer");
	if (map_prepare_buffer_fd < 0) {
		fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
		exit(1); //return 1;
	}
	map_request_buffer_fd = bpf_object__find_map_fd_by_name(obj, "map_request_buffer");
	if (map_request_buffer_fd < 0) {
		fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
		exit(1); //return 1;
	}
	map_paxos_ctr_state_fd = bpf_object__find_map_fd_by_name(obj, "map_ctr_state");
	if (map_paxos_ctr_state_fd < 0) {
		fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
		exit(1); //return 1;
	}
}

void initial_prog_map () {
	for (int i = 0; i < prog_count; i++) {
		int prog_fd = bpf_program__fd(progs[i].prog);

		if (prog_fd < 0) {
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", progs[i].name);
			exit(1); //return 1;
		}

		if (progs[i].map_prog_idx != -1) {
			unsigned int map_prog_idx = progs[i].map_prog_idx;
			if (map_prog_idx < 0) {
				fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", progs[i].name);
				exit(1); //return 1;
			}

			switch (progs[i].type) {
			case BPF_PROG_TYPE_XDP:
				map_progs_fd = map_progs_xdp_fd;
				break;
			case BPF_PROG_TYPE_SCHED_CLS:
				map_progs_fd = map_progs_tc_fd;
				break;
			default:
				fprintf(stderr, "Error: Program type doesn't correspond to any prog array map\n");
				exit(1); //return 1;
			}

			// update map in bpf_tail_call, e.g. f[idx] = fd.
			err = bpf_map_update_elem(map_progs_fd, &map_prog_idx, &prog_fd, 0);
			if (err) {
				fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
				exit(1); // return 1;
			}
		}

		if (progs[i].pin) {
			int len = snprintf(filename, PATH_MAX, "%s/%s", BPF_SYSFS_ROOT, progs[i].name);
			if (len < 0) {
				fprintf(stderr, "Error: Program name '%s' is invalid\n", progs[i].name);
				exit(-1); // return -1;
			} else if (len >= PATH_MAX) {
				fprintf(stderr, "Error: Program name '%s' is too long\n", progs[i].name);
				exit(-1); // return -1;
			}
retry:
			if (bpf_program__pin_instance(progs[i].prog, filename, 0)) {
				fprintf(stderr, "Error: Failed to pin program '%s' to path %s\n", progs[i].name, filename);
				if (errno == EEXIST) {
					fprintf(stdout, "BPF program '%s' already pinned, unpinning it to reload it\n", progs[i].name);
					if (bpf_program__unpin_instance(progs[i].prog, filename, 0)) {
						fprintf(stderr, "Error: Fail to unpin program '%s' at %s\n", progs[i].name, filename);
						exit(-1);
						// return -1;
					}
					goto retry;
				}
				exit(-1);
				// return -1;
			}
		}
	}

	xdp_main_prog_fd = bpf_program__fd(progs[0].prog);
	if (xdp_main_prog_fd < 0) {
		fprintf(stderr, "Error: bpf_program__fd failed\n");
		exit(1); // return 1;
	}
}

void add_interrupt() {
	/* asd123www: 
		!!!!!! the user-space program shouldn't quit here.
				Otherwise the program will be lost, due to fd lost???
	*/
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	sigaddset(&signal_mask, SIGUSR1);

	int sig, cur_poll_count = 0, quit = 0;
	// FILE *fp = NULL;

	err = sigprocmask(SIG_BLOCK, &signal_mask, NULL);
	if (err != 0) {
		fprintf(stderr, "Error: Failed to set signal mask\n");
		exit(EXIT_FAILURE);
	}

	while (!quit) {
		err = sigwait(&signal_mask, &sig);
		if (err != 0) {
			fprintf(stderr, "Error: Failed to wait for signal\n");
			exit(EXIT_FAILURE);
		}

		switch (sig) {
			case SIGINT:
			case SIGTERM:
				quit = 1;
				break;

			default:
				fprintf(stderr, "Unknown signal\n");
				break;
		}
	}
	return;
}

void read_config() {
	map_configure_fd = bpf_object__find_map_fd_by_name(obj, "map_configure");
	if (map_configure_fd < 0) {
		fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
		exit(1); //return 1;
	}

	FILE *fp;
	char buff[255];
	int f = 0, port = 0;

	struct sockaddr_in sa;
	char str[INET_ADDRSTRLEN];
	struct paxos_configure conf;

	const char *eths[FAST_REPLICA_MAX] = {"9c:dc:71:56:8f:45",
										"9c:dc:71:56:bf:45", 
										"9c:dc:71:5e:2f:51", 
										"", 
										""}; 

	fp = fopen("../config.txt", "r");
	fscanf(fp, "%s", buff); // must be 'f'
	fscanf(fp, "%d", &f);
	for (int i = 0; i < 2*f + 1; ++i) {
		fscanf(fp, "%s", buff); // must be 'replica'
		fscanf(fp, "%s", buff);

		char *ipv4 = strtok(buff, ":");
		assert(ipv4 != NULL);
		char *port = strtok(NULL, ":");

		// store this IP address in sa:
		inet_pton(AF_INET, ipv4, &(sa.sin_addr));
		// now get it back and print it
		inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);
		conf.port = htons(atoi(port));
		conf.addr = sa.sin_addr.s_addr;
		sscanf(eths[i], "%x:%x:%x:%x:%x:%x", conf.eth, conf.eth + 1, conf.eth + 2, conf.eth + 3, conf.eth + 4, conf.eth + 5);
		err = bpf_map_update_elem(map_configure_fd, &i, &conf, 0);
	}

	fclose(fp);
	return;
}

int main(int argc, char *argv[]) {

	parse_cmdline(argc, argv);
	create_object();
	initial_prog_map();
	read_config();

	assert(bpf_obj_pin(map_prepare_buffer_fd, "/sys/fs/bpf/paxos_prepare_buffer") == 0);
	assert(bpf_obj_pin(map_request_buffer_fd, "/sys/fs/bpf/paxos_request_buffer") == 0);
	assert(bpf_obj_pin(map_paxos_ctr_state_fd, "/sys/fs/bpf/paxos_ctr_state") == 0);

	for (int i = 0; i < interface_count; i++) {
		if (bpf_set_link_xdp_fd(interfaces_idx[i], xdp_main_prog_fd, xdp_flags) < 0) {
			fprintf(stderr, "Error: bpf_set_link_xdp_fd failed for interface %d\n", interfaces_idx[i]);
			return 1;
		} else {
			printf("Main BPF program attached to XDP on interface %d\n", interfaces_idx[i]);
		}
	}

	for (int i = 0; i < interface_count && optind < argc; i++) {
		snprintf(commandname, PATH_MAX, "tc qdisc add dev %s clsact", argv[optind + i]);
		assert(system(commandname) == 0);
		snprintf(commandname, PATH_MAX, "tc filter add dev %s egress bpf object-pinned /sys/fs/bpf/FastBroadCast", argv[optind + i]);
		assert(system(commandname) == 0);
		printf("Main BPF program attached to TC on interface %d\n", interfaces_idx[i]);
	}

	add_interrupt();
	assert(remove("/sys/fs/bpf/paxos_prepare_buffer") == 0);
	assert(remove("/sys/fs/bpf/paxos_request_buffer") == 0);
	assert(remove("/sys/fs/bpf/paxos_ctr_state") == 0);

	for (int i = 0; i < interface_count; i++) {
		bpf_set_link_xdp_fd(interfaces_idx[i], -1, xdp_flags);
	}
	for (int i = 0; i < interface_count && optind < argc; i++) {
		snprintf(commandname, PATH_MAX, "tc filter del dev %s egress", argv[optind + i]);
		assert(system(commandname) == 0);
		snprintf(commandname, PATH_MAX, "tc qdisc del dev %s clsact", argv[optind + i]);
		assert(system(commandname) == 0);
	}
	assert(system("rm -f /sys/fs/bpf/FastBroadCast") == 0);
	printf("\nasd123www: quit safely!\n");

	return 0;
}

// gcc -g -O2 -Wall -DKBUILD_MODNAME="\"wzz\"" -I. -I./linux/tools/lib -I./linux/tools/include/uapi  -o test fast_test.c ./linux/tools/lib/bpf/libbpf.a -L./linux/tools/lib/bpf -l:libbpf.a -lelf  -lz