#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libmnl/libmnl.h>
#include <linux/genetlink.h>

#include "gtp.h"
#include "genl.h"

static uint32_t seq;

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	unsigned int portid;
	uint32_t gtp_ifidx;
	int32_t genl_id;
	struct in_addr ms, sgsn;

	if (argc != 6) {
		printf("%s <gtp device> <version> <tid> <ms-addr> <sgsn-addr>\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}
	gtp_ifidx = if_nametoindex(argv[1]);

	nl = genl_socket_open();
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	genl_id = genl_lookup_family(nl, "gtp");
	if (genl_id < 0) {
		printf("not found gtp genl family\n");
		exit(EXIT_FAILURE);
	}

	if (inet_aton(argv[4], &ms) < 0) {
		perror("bad address for ms");
		exit(EXIT_FAILURE);
	}

	if (inet_aton(argv[5], &sgsn) < 0) {
		perror("bad address for sgsn");
		exit(EXIT_FAILURE);
	}

	nlh = genl_nlmsg_build_hdr(buf, genl_id, NLM_F_EXCL | NLM_F_ACK, ++seq,
				   GTP_CMD_TUNNEL_NEW);
	gtp_build_payload(nlh, atoi(argv[3]), gtp_ifidx, sgsn.s_addr,
			  ms.s_addr, atoi(argv[2]));

	if (genl_socket_talk(nl, nlh, seq, NULL, NULL) < 0)
		perror("genl_socket_talk");

	mnl_socket_close(nl);

	return 0;
}
