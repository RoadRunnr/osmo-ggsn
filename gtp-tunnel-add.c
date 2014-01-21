#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <linux/genetlink.h>

#include "gtp.h"
#include "genl.h"

static uint32_t seq;

static struct nlmsghdr *build_msg(int type, char *buf, int i, uint32_t ifidx)
{
	struct nlmsghdr *nlh;

	nlh = genl_nlmsg_build_hdr(buf, type, NLM_F_ACK, ++seq,
				   GTP_CMD_TUNNEL_NEW);

	mnl_attr_put_u32(nlh, GTPA_VERSION, GTP_V0);
	mnl_attr_put_u32(nlh, GTPA_LINK, ifidx);
	mnl_attr_put_u32(nlh, GTPA_SGSN_ADDRESS, 0); /* XXX nested */
	mnl_attr_put_u32(nlh, GTPA_MS_ADDRESS, i); /* XXX nested */
	mnl_attr_put_u32(nlh, GTPA_TID, i);

	return nlh;
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	unsigned int portid;
	uint32_t gtp_ifidx = if_nametoindex(argv[1]);
	int32_t genl_id;
	int i;

	if (argc != 2) {
		printf("%s <gtp device>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

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

	printf("adding 1000000 tunnels\n");

	for (i = 0; i < 1000000; i++) {
		nlh = build_msg(genl_id, buf, i, gtp_ifidx);

		if (genl_socket_talk(nl, nlh, NULL, NULL) < 0)
			break;
	}

	printf("done\n");

	mnl_socket_close(nl);

	return 0;
}
