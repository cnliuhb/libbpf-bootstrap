// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Subao Network Inc. */
#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include "quicses.skel.h"

#define PORT 4999

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

int sock_bind(int progfd, int first)
{
	int sockfd;
	struct sockaddr_in srvaddr;
	int err;
	int optv = 1;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&srvaddr, 0, sizeof(srvaddr));
	srvaddr.sin_family = AF_INET;
	srvaddr.sin_addr.s_addr = INADDR_ANY;
	srvaddr.sin_port = htons(PORT);

	err = setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optv, sizeof(optv));
	if (err < 0) {
		perror("can not set reuseport");
		exit(EXIT_FAILURE);
	}

	if (first) {
		err = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
				 &progfd, sizeof(progfd));
		if (err < 0) {
			perror("can not set ebpf attach");
			exit(EXIT_FAILURE);
		}
	}

	err = bind(sockfd, (const struct sockaddr *)&srvaddr, sizeof(srvaddr));
	if (err < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

int sock_recv(int sockfd, char *name)
{
	char buffer[2048];
	int ret = read(sockfd, buffer, sizeof(buffer));
	printf("%s: recv pkt len %d\n", name, ret);

	return 0;
}

int main(int argc, char **argv)
{
	struct quicses_bpf *skel;
	int err;
	fd_set rfds;
	int maxfd;
	uint32_t outer_key, inner_key;
	int inner_map_fd;
	int srvfd1, srvfd2;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	skel = quicses_bpf__open();
	if (!skel) {
		perror("Failed to open BPF skeleton\n");
		return 1;
	}

	inner_map_fd = bpf_map_create(BPF_MAP_TYPE_SOCKMAP, NULL,
				      sizeof(uint32_t), sizeof(int), 2, NULL);
	bpf_map__set_inner_map_fd(skel->maps.outer_map, inner_map_fd);

	err = quicses_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	close(inner_map_fd);

	srvfd1 = sock_bind(bpf_program__fd(skel->progs.select_by_skb_data), 1);
	srvfd2 = sock_bind(bpf_program__fd(skel->progs.select_by_skb_data), 0);
	printf("create socket srv1-fd %d srv2-fd %d\n", srvfd1, srvfd2);

	inner_map_fd = bpf_map_create(BPF_MAP_TYPE_SOCKMAP, NULL,
				      sizeof(uint32_t), sizeof(int), 2, NULL);
	inner_key = 0;
	bpf_map_update_elem(inner_map_fd, &inner_key, &srvfd1, BPF_NOEXIST);
	inner_key = 1;
	bpf_map_update_elem(inner_map_fd, &inner_key, &srvfd2, BPF_NOEXIST);

	outer_key = 0;
	bpf_map_update_elem(bpf_map__fd(skel->maps.outer_map), &outer_key,
			    &inner_map_fd, 0);
	close(inner_map_fd);

	maxfd = srvfd1 > srvfd2 ? srvfd1 : srvfd2;
	FD_ZERO(&rfds);
	for (;;) {
		int nready;

		FD_SET(srvfd1, &rfds);
		FD_SET(srvfd2, &rfds);

		nready = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if (nready == -1) {
			perror("select error");
			break;
		}

		if (FD_ISSET(srvfd1, &rfds)) {
			sock_recv(srvfd1, "sock1");
		} else if (FD_ISSET(srvfd2, &rfds)) {
			sock_recv(srvfd2, "sock2");
		}
	}
cleanup:
	quicses_bpf__destroy(skel);
	return -err;
}
