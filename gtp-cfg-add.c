#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <linux/genetlink.h>

#include "gtp.h"
#include "genl.h"

static uint32_t seq;

static struct nlmsghdr *build_msg(int type, char *buf, uint32_t ifidx)
{
	struct nlmsghdr *nlh;

	nlh = genl_nlmsg_build_hdr(buf, type, NLM_F_CREATE | NLM_F_ACK, ++seq,
				   GTP_CMD_CFG_NEW);

	mnl_attr_put_u32(nlh, GTPA_CFG_LINK, ifidx);
	mnl_attr_put_u32(nlh, GTPA_CFG_LOCAL_ADDR_IPV4, 0);

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

	if (argc != 2) {
		printf("%s <gtp device>\n", argv[0]);
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

	nlh = build_msg(genl_id, buf, gtp_ifidx);

	if (genl_socket_talk(nl, nlh, seq, NULL, NULL) < 0)
		perror("genl_socket_talk");

	mnl_socket_close(nl);

	return 0;
}
