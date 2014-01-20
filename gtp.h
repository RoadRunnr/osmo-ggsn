#ifndef _UAPI_LINUX_GTP_H_

enum gtp_genl_cmds {
	GTP_CMD_TUNNEL_NEW,
	GTP_CMD_TUNNEL_DELETE,
	GTP_CMD_TUNNEL_GET,

	GTP_CMD_TUNNEL_MAX,
};

enum gtp_version {
	GTP_V0 = 0,
	GTP_V1,
};

enum gtp_attrs {
	GTPA_UNSPEC = 0,
	GTPA_VERSION,
	GTPA_TID,	/* 64 bits for GTPv1 */
	GTPA_LINK,
	GTPA_SGSN_ADDRESS,
	GTPA_MS_ADDRESS,
	__GTPA_MAX,
};
#define GTPA_MAX (__GTPA_MAX + 1)

#endif /* _UAPI_LINUX_GTP_H_ */
