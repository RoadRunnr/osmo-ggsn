#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/genetlink.h>

#include "gtp.h"
#include "genl.h"

struct gtp_pdp {
	uint64_t	tid;
	struct in_addr	sgsn_addr;
	struct in_addr	ms_addr;
};

static uint32_t seq = 10;

static int genl_gtp_validate_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case GTPA_TID:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case GTPA_SGSN_ADDRESS:
	case GTPA_MS_ADDRESS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	default:
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int genl_gtp_attr_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[GTPA_MAX + 1] = {};
	struct gtp_pdp *pdp = data;
	struct genlmsghdr *genl;

	mnl_attr_parse(nlh, sizeof(*genl), genl_gtp_validate_cb, tb);
	if (tb[GTPA_TID])
		pdp->tid = mnl_attr_get_u64(tb[GTPA_TID]);
	if (tb[GTPA_SGSN_ADDRESS]) {
		pdp->sgsn_addr.s_addr =
			mnl_attr_get_u32(tb[GTPA_SGSN_ADDRESS]);
	}
	if (tb[GTPA_MS_ADDRESS]) {
		pdp->ms_addr.s_addr = mnl_attr_get_u32(tb[GTPA_MS_ADDRESS]);
	}

	printf("tid %llu ms_addr %s ", pdp->tid, inet_ntoa(pdp->sgsn_addr));
	printf("sgsn_addr %s\n", inet_ntoa(pdp->ms_addr));

	return MNL_CB_OK;
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	unsigned int portid;
	int32_t genl_id;
	struct gtp_pdp pdp;
	int i;

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

	nlh = genl_nlmsg_build_hdr(buf, genl_id, NLM_F_DUMP, 0,
				   GTP_CMD_TUNNEL_GET);

	if (genl_socket_talk(nl, nlh, seq, genl_gtp_attr_cb, &pdp) < 0) {
		perror("genl_socket_talk");
		return 0;
	}

	mnl_socket_close(nl);

	return 0;
}
