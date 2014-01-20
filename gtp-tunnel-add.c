#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <linux/genetlink.h>

#include "gtp.h"

static uint32_t seq;

static struct nlmsghdr *build_msg(int genl_type, char *buf, int i, uint32_t ifidx)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= genl_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = ++seq;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = GTP_CMD_TUNNEL_NEW;
	genl->version = 0;

	mnl_attr_put_u32(nlh, GTPA_VERSION, GTP_V0);
	mnl_attr_put_u32(nlh, GTPA_LINK, ifidx);
	mnl_attr_put_u32(nlh, GTPA_SGSN_ADDRESS, 0); /* XXX nested */
	mnl_attr_put_u32(nlh, GTPA_MS_ADDRESS, i); /* XXX nested */
	mnl_attr_put_u32(nlh, GTPA_TID, i);

	return nlh;
}

static int my_mnl_talk(struct mnl_socket *nl, struct nlmsghdr *nlh,
		       uint32_t portid)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int ret;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		perror("error");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	unsigned int portid;
	int i;

	if (argc != 3) {
		printf("%s <GTP genetlink family id> <gtp device>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	nl = mnl_socket_open(NETLINK_GENERIC);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	printf("adding 1000000 tunnels\n");

	for (i = 0; i < 1000000; i++) {
		nlh = build_msg(atoi(argv[1]), buf, i, if_nametoindex(argv[2]));

		if (my_mnl_talk(nl, nlh, portid) < 0)
			break;
	}

	printf("done\n");

	mnl_socket_close(nl);

	return 0;
}
