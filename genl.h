#ifndef _OSMO_SGSN_GENL_H_
#define _OSMO_SGSN_GENL_H_

#include <libmnl/libmnl.h>

struct mnl_socket *genl_socket_open(void);
int genl_socket_talk(struct mnl_socket *nl, struct nlmsghdr *nlh,
		     int (*cb)(const struct nlmsghdr *nlh, void *data),
		     void *data);
int genl_lookup_family(struct mnl_socket *nl, const char *family);

#endif
