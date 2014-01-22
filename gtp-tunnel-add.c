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

static struct nlmsghdr *build_msg(int type, char *buf, int i, uint32_t ifidx,
				  uint32_t sgsn_addr, uint32_t ms_addr)
{
	struct nlmsghdr *nlh;

	nlh = genl_nlmsg_build_hdr(buf, type, NLM_F_ACK, ++seq,
				   GTP_CMD_TUNNEL_NEW);

	mnl_attr_put_u32(nlh, GTPA_VERSION, GTP_V0);
	mnl_attr_put_u32(nlh, GTPA_LINK, ifidx);
	mnl_attr_put_u32(nlh, GTPA_SGSN_ADDRESS, sgsn_addr);
	mnl_attr_put_u32(nlh, GTPA_MS_ADDRESS, ms_addr);
	mnl_attr_put_u64(nlh, GTPA_TID, i);

	return nlh;
}

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

	if (argc != 5) {
		printf("%s <gtp device> <tid> <ms-addr> <sgsn-addr>\n",
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

	if (inet_aton(argv[3], &ms) < 0) {
		perror("bad address for ms");
		exit(EXIT_FAILURE);
	}

	if (inet_aton(argv[4], &sgsn) < 0) {
		perror("bad address for sgsn");
		exit(EXIT_FAILURE);
	}

	nlh = build_msg(genl_id, buf, atoi(argv[2]), gtp_ifidx, ms.s_addr,
			sgsn.s_addr);

	if (genl_socket_talk(nl, nlh, seq, NULL, NULL) < 0)
		perror("genl_socket_talk");

	mnl_socket_close(nl);

	return 0;
}
