/* GTP according to GSM TS 09.60 / 3GPP TS 29.060 */

/* (C) 2012-2014 by sysmocom - s.f.m.c. GmbH
 * Author: Harald Welte <hwelte@sysmocom.de>
 * 	   Pablo Neira Ayuso <pablo@gnumonks.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/rculist.h>
#include <linux/jhash.h>
#include <linux/if_tunnel.h>
#include <linux/net.h>
#include <linux/file.h>

#include <net/net_namespace.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/genetlink.h>
#include <net/netns/generic.h>

#include "gtp.h"
#include "gtp_nl.h"

static u32 gtp_h_initval;

struct pdp_ctx {
	struct hlist_node hlist_tid;
	struct hlist_node hlist_addr;

	u64 tid;
	u8 gtp_version;
	u16 af;

	union {
		struct in6_addr ip6;
		struct in_addr ip4;
	} ms_addr;

	union {
		struct in6_addr ip6;
		struct in_addr ip4;
	} sgsn_addr;

	u16 flow;
	atomic_t tx_seq;

	struct rcu_head rcu_head;
};

/* One local instance of the GTP code base */
struct gtp_instance {
	struct list_head list;

	/* the socket */
	struct socket *sock0;
	struct socket *sock1u;

	struct net_device *dev;

	unsigned int hash_size;
	struct hlist_head *tid_hash;
	struct hlist_head *addr_hash;
};

static int gtp_net_id __read_mostly;

struct gtp_net {
	struct list_head gtp_instance_list;
};

static void gtp_encap_disable(struct gtp_instance *gti);

static inline u32 gtp0_hashfn(u64 tid)
{
	u32 *tid32 = (u32 *) &tid;
	return jhash_2words(tid32[0], tid32[1], gtp_h_initval);
}

static inline u32 gtp1u_hashfn(u32 tid)
{
	return jhash_1word(tid, gtp_h_initval);
}

static inline u32 ipv4_hashfn(u32 ip)
{
	return jhash_1word(ip, gtp_h_initval);
}

static inline u32 ipv6_hashfn(struct in6_addr *ip6)
{
	return jhash2((const u32 *) &ip6->s6_addr32, sizeof(*ip6)/sizeof(u32),
		      gtp_h_initval);
}

/* resolve a PDP context structure based on the 64bit TID */
static struct pdp_ctx *gtp0_pdp_find(struct gtp_instance *gti, u64 tid)
{
	struct hlist_head *head;
	struct pdp_ctx *pdp;

	head = &gti->tid_hash[gtp0_hashfn(tid) % gti->hash_size];

	hlist_for_each_entry_rcu(pdp, head, hlist_tid) {
		if (pdp->gtp_version == GTP_V0 && pdp->tid == tid)
			return pdp;
	}

	return NULL;
}

/* resolve a PDP context structure based on the 32bit TEI */
static struct pdp_ctx *gtp1_pdp_find(struct gtp_instance *gti, u32 tid)
{
	struct hlist_head *head;
	struct pdp_ctx *pdp;

	head = &gti->tid_hash[gtp1u_hashfn(tid) % gti->hash_size];

	hlist_for_each_entry_rcu(pdp, head, hlist_tid) {
		if (pdp->gtp_version == GTP_V1 && pdp->tid == tid)
			return pdp;
	}

	return NULL;
}

/* resolve a PDP context based on IPv4 address of MS */
static struct pdp_ctx *ipv4_pdp_find(struct gtp_instance *gti,
				     u32 ms_addr)
{
	struct hlist_head *head;
	struct pdp_ctx *pdp;

	head = &gti->addr_hash[ipv4_hashfn(ms_addr) % gti->hash_size];

	hlist_for_each_entry_rcu(pdp, head, hlist_addr) {
		if (pdp->af == AF_INET && pdp->ms_addr.ip4.s_addr == ms_addr)
			return pdp;
	}

	return NULL;
}

/* resolve a PDP context based on IPv6 address of MS */
static struct pdp_ctx *ipv6_pdp_find(struct gtp_instance *gti,
				     struct in6_addr *ms_addr)
{
	struct hlist_head *head;
	struct pdp_ctx *pdp;

	head = &gti->addr_hash[ipv6_hashfn(ms_addr) % gti->hash_size];

	hlist_for_each_entry_rcu(pdp, head, hlist_addr) {
		if (pdp->af == AF_INET6 &&
		    !memcmp(&pdp->ms_addr.ip6, ms_addr, sizeof(*ms_addr)))
			return pdp;
	}

	return NULL;
}


/* resolve the GTP instance for a given sock */
static inline struct gtp_instance *sk_to_gti(struct sock *sk)
{
	struct gtp_instance *gti;

	if (!sk)
		return NULL;

	sock_hold(sk);
	gti = (struct gtp_instance *) sk->sk_user_data;
	if (!gti) {
		sock_put(sk);
		return NULL;
	}

	return gti;
}

/* Check if the inner IP header has the source address assigned to the
 * current MS.
 */
static bool gtp_check_src_ms(struct sk_buff *skb, struct pdp_ctx *pctx,
			     unsigned int hdrlen)
{
	bool ret = false;

	if (skb->protocol == ntohs(ETH_P_IP)) {
		struct iphdr *iph;

		if (!pskb_may_pull(skb, hdrlen + sizeof(struct iphdr)))
			return false;

		iph = (struct iphdr *)
			(skb->data + hdrlen + sizeof(struct iphdr));
		ret = (iph->saddr != pctx->ms_addr.ip4.s_addr);

	} else if (skb->protocol == ntohs(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;

		if (!pskb_may_pull(skb, hdrlen + sizeof(struct ipv6hdr)))
			return false;

		ip6h = (struct ipv6hdr *)
			(skb->data + hdrlen + sizeof(struct ipv6hdr));
		ret = memcmp(&ip6h->saddr, &pctx->ms_addr.ip6,
			     sizeof(struct in6_addr)) == 0;
	}

	return ret;
}

/* 1 means pass up to the stack, -1 means drop and 0 means decapsulated */
static int gtp0_udp_encap_recv(struct gtp_instance *gti, struct sk_buff *skb)
{
	struct gtp0_header *gtp0;
	struct pdp_ctx *pctx;
	unsigned int hdrlen = sizeof(struct udphdr) + sizeof(*gtp0);
	int ret = 0;

	/* check for sufficient header size */
	if (!pskb_may_pull(skb, hdrlen))
		return -1;

	gtp0 = (struct gtp0_header *)(skb->data + sizeof(struct udphdr));

	/* check for GTP Version 0 */
	if ((gtp0->flags >> 5) != GTP_V0)
		return 1;

	/* check if it is T-PDU. if not -> userspace */
	if (gtp0->type != GTP_TPDU)
		return 1;

	rcu_read_lock();
	/* look-up the PDP context for the Tunnel ID */
	pctx = gtp0_pdp_find(gti, be64_to_cpu(gtp0->tid));
	if (!pctx) {
		ret = -1;
		goto out_rcu;
	}

	if (!gtp_check_src_ms(skb, pctx, hdrlen)) {
		ret = -1;
		goto out_rcu;
	}

	/* get rid of the GTP + UDP headers */
	__skb_pull(skb, hdrlen);
out_rcu:
	rcu_read_unlock();
	return ret;
}

static int gtp1u_udp_encap_recv(struct gtp_instance *gti, struct sk_buff *skb)
{
	struct gtp1_header *gtp1;
	struct pdp_ctx *pctx;
	unsigned int hdrlen = sizeof(struct udphdr) + sizeof(*gtp1);
	int ret = 0;

	/* check for sufficient header size */
	if (!pskb_may_pull(skb, hdrlen))
		return -1;

	gtp1 = (struct gtp1_header *)(skb->data + sizeof(struct udphdr));

	/* check for GTP Version 1 */
	if ((gtp1->flags >> 5) != GTP_V1)
		return 1;

	/* check if it is T-PDU. */
	if (gtp1->type != GTP_TPDU)
		return 1;

	/* From 29.060: "This field shall be present if and only if any one or
	 * more of the S, PN and E flags are set.".
	 *
	 * If any of the bit is set, then the remaining ones also have to be
	 * set.
	 */
	if (gtp1->flags & GTP1_F_MASK)
		hdrlen += 4;

	/* check for sufficient header size for extension */
	if (!pskb_may_pull(skb, hdrlen))
		return -1;

	/* look-up the PDP context for the Tunnel ID */
	rcu_read_lock();
	pctx = gtp1_pdp_find(gti, ntohl(gtp1->tid));
	if (!pctx) {
		ret = -1;
		goto out_rcu;
	}

	if (!gtp_check_src_ms(skb, pctx, hdrlen)) {
		ret = -1;
		goto out_rcu;
	}

	/* get rid of the UDP + GTP header + extensions */
	__skb_pull(skb, hdrlen);
out_rcu:
	rcu_read_unlock();
	return ret;
}

static void gtp_udp_encap_destroy(struct sock *sk)
{
	struct gtp_instance *gti = sk_to_gti(sk);

	if (gti) {
		gtp_encap_disable(gti);
		sock_put(sk);
	}
}

/* UDP encapsulation receive handler. See net/ipv4/udp.c.
 * Return codes: 0: success, <0: error, >0: passed up to userspace UDP.
 */
static int gtp_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct gtp_instance *gti;
	int ret;

	/* resolve the GTP instance to which the socket belongs */
	gti = sk_to_gti(sk);
	if (!gti)
		goto user;

	netdev_dbg(gti->dev, "encap_recv %p\n", sk);

	switch (udp_sk(sk)->encap_type) {
	case UDP_ENCAP_GTP0:
		netdev_dbg(gti->dev, "received GTP0 packet\n");
		ret = gtp0_udp_encap_recv(gti, skb);
		break;
	case UDP_ENCAP_GTP1U:
		netdev_dbg(gti->dev, "received GTP1U packet\n");
		ret = gtp1u_udp_encap_recv(gti, skb);
		break;
	default:
		ret = -1; /* shouldn't happen */
	}

	switch (ret) {
	case 1:
		netdev_dbg(gti->dev, "pass up to the process\n");
		goto user_put;
	case 0:
		netdev_dbg(gti->dev, "forwarding packet from GGSN to uplink\n");
		break;
	case -1:
		netdev_dbg(gti->dev, "GTP packet has been dropped\n");
		goto drop;
	}

	/* Now that the UDP and the GTP header have been removed, set up the
	 * new network header. This is required by the upper later to
	 * calculate the transport header.
	 */
	skb_reset_network_header(skb);

	/* re-submit via virtual tunnel device into regular network stack */
	secpath_reset(skb);
	skb_dst_drop(skb);
	nf_reset(skb);

	skb->dev = gti->dev;

	/* Force the upper layers to verify it. */
	skb->ip_summed = CHECKSUM_NONE;

	netif_rx(skb);
	sock_put(sk);

	return 0;
drop:
	kfree_skb(skb);
	return 0;

user_put:
	sock_put(sk);
user:
	return 1;
}

static int gtp_dev_init(struct net_device *dev)
{
	struct gtp_instance *gti = netdev_priv(dev);

	gti->dev		= dev;

	dev->tstats = alloc_percpu(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

static void gtp_dev_uninit(struct net_device *dev)
{
	struct gtp_instance *gti = netdev_priv(dev);

	gtp_encap_disable(gti);
	free_percpu(dev->tstats);
}

#define IP_UDP_LEN	(sizeof(struct iphdr) + sizeof(struct udphdr))

static inline void init_gtp_flow(struct flowi4 *fl4,
				 const struct sock *sk,
				 __be32 daddr)
{
	memset(fl4, 0, sizeof(*fl4));
	fl4->flowi4_oif = sk->sk_bound_dev_if;
	fl4->daddr = daddr;
	fl4->saddr = inet_sk(sk)->inet_saddr;
	fl4->flowi4_tos = RT_CONN_FLAGS(sk);
	fl4->flowi4_proto = sk->sk_protocol;
}

static struct rtable *
ip4_route_output_gtp(struct net *net, struct flowi4 *fl4,
		     const struct sock *sk,
		     __be32 daddr)
{
	init_gtp_flow(fl4, sk, daddr);
	return ip_route_output_key(net, fl4);
}

static inline void
gtp0_push_header(struct sk_buff *skb, struct pdp_ctx *pctx)
{
	struct gtp0_header *gtp0;
	int payload_len = skb->len;

	/* ensure there is sufficient headroom */
	gtp0 = (struct gtp0_header *) skb_push(skb, sizeof(*gtp0));

	gtp0->flags = 0x1e; /* V0, GTP-non-prime */
	gtp0->type = GTP_TPDU;
	gtp0->length = htons(payload_len);
	gtp0->seq = htons((atomic_inc_return(&pctx->tx_seq)-1) % 0xffff);
	gtp0->flow = htons(pctx->flow);
	gtp0->number = 0xFF;
	gtp0->spare[0] = gtp0->spare[1] = gtp0->spare[2] = 0xFF;
	gtp0->tid = cpu_to_be64(pctx->tid);
}

static inline void
gtp1_push_header(struct sk_buff *skb, struct pdp_ctx *pctx)
{
	struct gtp1_header *gtp1;
	int payload_len = skb->len;

	/* ensure there is sufficient headroom */
	gtp1 = (struct gtp1_header *) skb_push(skb, sizeof(*gtp1));

	/* Bits    8  7  6  5  4  3  2  1
	 *        +--+--+--+--+--+--+--+--+
	 *        |version |PT| 1| E| S|PN|
	 *	  +--+--+--+--+--+--+--+--+
	 * 	    0  0  1  1  1  0  0  0
	 */
	gtp1->flags = 0x38; /* V1, GTP-non-prime */
	gtp1->type = GTP_TPDU;
	gtp1->length = htons(payload_len);
	gtp1->tid = htonl((u32)pctx->tid);

	/* TODO: Suppport for extension header, sequence number and N-PDU.
	 * 	 Update the length field if any of them is available.
	 */
}

/* From Linux kernel 3.13: iptunnel_xmit_stats() */
static inline void
gtp_iptunnel_xmit_stats(int err, struct net_device_stats *err_stats,
			struct pcpu_sw_netstats __percpu *stats)
{
	if (err > 0) {
		struct pcpu_sw_netstats *tstats = this_cpu_ptr(stats);

		u64_stats_update_begin(&tstats->syncp);
		tstats->tx_bytes += err;
		tstats->tx_packets++;
		u64_stats_update_end(&tstats->syncp);
	} else if (err < 0) {
		err_stats->tx_errors++;
		err_stats->tx_aborted_errors++;
	} else {
		err_stats->tx_dropped++;
	}
}

struct gtp_pktinfo {
	struct sock *sk;
	union {
		struct iphdr	*iph;
		struct ipv6hdr	*ip6h;
	};
	union {
		struct flowi4	fl4;
	};
	struct rtable		*rt;
	struct pdp_ctx		*pctx;
	struct net_device	*dev;
};

static inline void
gtp_set_pktinfo_ipv4(struct gtp_pktinfo *pktinfo, struct sock *sk,
		     struct iphdr *iph,
		     struct pdp_ctx *pctx, struct rtable *rt,
		     struct flowi4 *fl4, struct net_device *dev)
{
	pktinfo->sk     = sk;
	pktinfo->iph	= iph;
	pktinfo->pctx	= pctx;
	pktinfo->rt	= rt;
	pktinfo->fl4	= *fl4;
	pktinfo->dev	= dev;
}

static int gtp_ip4_prepare_xmit(struct sk_buff *skb, struct net_device *dev,
				struct gtp_pktinfo *pktinfo)
{
	struct gtp_instance *gti = netdev_priv(dev);
	struct sock *sk;
	struct iphdr *iph;
	struct pdp_ctx *pctx;
	struct rtable *rt;
	struct flowi4 fl4;
	int df, mtu;

	/* Read the IP destination address and resolve the PDP context.
	 * Prepend PDP header with TEI/TID from PDP ctx.
	 */
	iph = ip_hdr(skb);
	pctx = ipv4_pdp_find(gti, iph->daddr);
	if (!pctx) {
		netdev_dbg(dev, "no PDP ctx found for this packet, skip\n");
		return -ENOENT;
	}
	netdev_dbg(dev, "found PDP context %p\n", pctx);

	/* Obtain route for the new encapsulated GTP packet */
	switch (pctx->gtp_version) {
	case GTP_V0:
		sk = gti->sock0->sk;
		break;
	case GTP_V1:
		sk = gti->sock1u->sk;
		break;
	default:
		return -ENOENT;
	}

	rt = ip4_route_output_gtp(sock_net(sk), &fl4,
				  gti->sock0->sk,
				  pctx->sgsn_addr.ip4.s_addr);
	if (IS_ERR(rt)) {
		netdev_dbg(dev, "no route to SSGN %pI4\n",
			   &pctx->sgsn_addr.ip4.s_addr);
		dev->stats.tx_carrier_errors++;
		goto err;
	}

	/* There is a routing loop */
	if (rt->dst.dev == dev) {
		netdev_dbg(dev, "circular route to SSGN %pI4\n",
			   &pctx->sgsn_addr.ip4.s_addr);
		dev->stats.collisions++;
		goto err_rt;
	}

	skb_dst_drop(skb);

	/* This is similar to tnl_update_pmtu() */
	df = iph->frag_off;
	if (df) {
		mtu = dst_mtu(&rt->dst) - dev->hard_header_len -
			sizeof(struct iphdr) - sizeof(struct udphdr);
		switch (pctx->gtp_version) {
		case GTP_V0:
			mtu -= sizeof(struct gtp0_header);
			break;
		case GTP_V1:
			mtu -= sizeof(struct gtp1_header);
			break;
		}
	} else
		mtu = dst_mtu(&rt->dst);

	rt->dst.ops->update_pmtu(&rt->dst, NULL, skb, mtu);

	if (!skb_is_gso(skb) && (iph->frag_off & htons(IP_DF)) &&
	    mtu < ntohs(iph->tot_len)) {
		netdev_dbg(dev, "packet too big, fragmentation needed\n");
		memset(IPCB(skb), 0, sizeof(*IPCB(skb)));
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(mtu));
		goto err_rt;
	}

	gtp_set_pktinfo_ipv4(pktinfo, sk, iph, pctx, rt, &fl4, dev);

	return 0;
err_rt:
	ip_rt_put(rt);
err:
	return -EBADMSG;
}

static int gtp_ip6_prepare_xmit(struct sk_buff *skb, struct net_device *dev,
				struct gtp_pktinfo *pktinfo)
{
	/* TODO IPV6 support */
	return 0;
}

static inline int
gtp_udp_tunnel_xmit(struct sk_buff *skb, __be16 port,
		    struct gtp_pktinfo *pktinfo)
{
	netdev_dbg(pktinfo->dev, "gtp -> IP src: %pI4 dst: %pI4\n",
		   &pktinfo->iph->saddr, &pktinfo->iph->daddr);

	return udp_tunnel_xmit_skb(pktinfo->rt, pktinfo->sk, skb,
				   pktinfo->fl4.saddr,
				   pktinfo->fl4.daddr,
				   pktinfo->iph->tos,
				   ip4_dst_hoplimit(&pktinfo->rt->dst),
				   htons(IP_DF), port, port, true, false);
}

static inline int
gtp_ip6tunnel_xmit(struct sk_buff *skb, struct gtp_pktinfo *pktinfo)
{
	/* TODO IPV6 support */
}

static netdev_tx_t gtp_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct udphdr *uh;
	unsigned int payload_len;
	struct gtp_pktinfo pktinfo;
	unsigned int proto = ntohs(skb->protocol);
	int gtph_len, err = -EINVAL;
	__be16 gtph_port;

	rcu_read_lock();

	/* ensure there is sufficient headroom */
	if (skb_cow_head(skb, dev->needed_headroom))
		goto tx_error;

	skb_reset_inner_headers(skb);

	switch (proto) {
	case ETH_P_IP:
		err = gtp_ip4_prepare_xmit(skb, dev, &pktinfo);
		break;
	case ETH_P_IPV6:
		err = gtp_ip6_prepare_xmit(skb, dev, &pktinfo);
		break;
	}

	if (err < 0)
		goto tx_error;

	/* Push down GTP header */
	switch (pktinfo.pctx->gtp_version) {
	case GTP_V0:
		gtph_port = htons(GTP0_PORT);
		gtph_len = sizeof(struct gtp0_header);

		gtp0_push_header(skb, pktinfo.pctx);
		break;
	case GTP_V1:
		gtph_port = htons(GTP1U_PORT);
		gtph_len = sizeof(struct gtp1_header);

		gtp1_push_header(skb, pktinfo.pctx);
		break;
	default:
		goto tx_error;
	}

	switch (proto) {
	case ETH_P_IP:
		err = gtp_udp_tunnel_xmit(skb, gtph_port, &pktinfo);
		break;
	case ETH_P_IPV6:
		/* Annotate length of the encapsulated packet */
		payload_len = skb->len;

		/* Push down and install the UDP header. */
		skb_push(skb, sizeof(struct udphdr));
		skb_reset_transport_header(skb);

		uh = udp_hdr(skb);

		uh->source = uh->dest = gtph_port;
		uh->len = htons(sizeof(struct udphdr) + payload_len + gtph_len);
		uh->check = 0;

		netdev_dbg(dev, "gtp -> UDP src: %u dst: %u (len %u)\n",
			   ntohs(uh->source), ntohs(uh->dest), ntohs(uh->len));

		nf_reset(skb);

		netdev_dbg(dev, "Good, now packet leaving from GGSN to SGSN\n");

		err = gtp_ip6tunnel_xmit(skb, &pktinfo);
		break;
	}

	rcu_read_unlock();

	gtp_iptunnel_xmit_stats(err, &dev->stats, dev->tstats);

	return NETDEV_TX_OK;
tx_error:
	rcu_read_unlock();
	dev->stats.tx_errors++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops gtp_netdev_ops = {
	.ndo_init		= gtp_dev_init,
	.ndo_uninit		= gtp_dev_uninit,
	.ndo_start_xmit		= gtp_dev_xmit,
};

static void gtp_link_setup(struct net_device *dev)
{
	dev->netdev_ops		= &gtp_netdev_ops;
	dev->destructor		= free_netdev;

	dev->hard_header_len = 0;
	dev->addr_len = 0;

	/* Zero header length */
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
	dev->tx_queue_len = 1000;

	dev->priv_flags	|= IFF_NO_QUEUE;
	dev->features   |= NETIF_F_LLTX;
	netif_keep_dst(dev);

	dev->needed_headroom    = LL_MAX_HEADER
		+ sizeof(struct iphdr)
		+ sizeof(struct udphdr)
		+ sizeof(struct gtp0_header);

}

static int gtp_hashtable_new(struct gtp_instance *gti, int hsize);
static void gtp_hashtable_free(struct gtp_instance *gti);
static int gtp_encap_enable(struct net_device *dev, struct gtp_instance *gti,
			    int fd_gtp0, int fd_gtp1);

static int gtp_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[])
{
	struct gtp_net *gn;
	struct gtp_instance *gti;
	int hashsize, err, fd0, fd1;

	if (!tb[IFLA_MTU])
		dev->mtu = 1500;

	gti = netdev_priv(dev);

	fd0 = nla_get_u32(data[IFLA_GTP_FD0]);
	fd1 = nla_get_u32(data[IFLA_GTP_FD1]);

	err = gtp_encap_enable(dev, gti, fd0, fd1);
	if (err < 0)
		goto out_err;

	if (!data[IFLA_GTP_HASHSIZE])
		hashsize = 1024;
	else
		hashsize = nla_get_u32(data[IFLA_GTP_HASHSIZE]);

	err = gtp_hashtable_new(gti, hashsize);
	if (err < 0)
		goto out_encap;

	err = register_netdevice(dev);
	if (err < 0) {
		netdev_dbg(dev, "failed to register new netdev %d\n", err);
		goto out_hashtable;
	}

	gn = net_generic(dev_net(dev), gtp_net_id);
	list_add_rcu(&gti->list, &gn->gtp_instance_list);

	netdev_dbg(dev, "registered new GTP interface\n");

	return 0;

out_hashtable:
	gtp_hashtable_free(gti);

out_encap:
	gtp_encap_disable(gti);

out_err:
	return err;
}

static void gtp_dellink(struct net_device *dev, struct list_head *head)
{
	struct gtp_instance *gti = netdev_priv(dev);

	gtp_encap_disable(gti);
	gtp_hashtable_free(gti);
	list_del_rcu(&gti->list);
	unregister_netdevice_queue(dev, head);
}

static const struct nla_policy gtp_policy[IFLA_GTP_MAX + 1] = {
	[IFLA_GTP_FD0]			= { .type = NLA_U32 },
	[IFLA_GTP_FD1]			= { .type = NLA_U32 },
	[IFLA_GTP_HASHSIZE]		= { .type = NLA_U32 },
};

static int gtp_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (!data || !data[IFLA_GTP_FD0] || !data[IFLA_GTP_FD1])
		return -EINVAL;

	return 0;
}

static size_t gtp_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(__u32));	/* IFLA_GTP_HASHSIZE */
}

static int gtp_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct gtp_instance *gti = netdev_priv(dev);

	if (nla_put_u32(skb, IFLA_GTP_HASHSIZE, gti->hash_size))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static struct rtnl_link_ops gtp_link_ops __read_mostly = {
	.kind		= "gtp",
	.maxtype	= IFLA_GTP_MAX,
	.policy		= gtp_policy,
	.priv_size	= sizeof(struct gtp_instance),
	.setup		= gtp_link_setup,
	.validate	= gtp_validate,
	.newlink	= gtp_newlink,
	.dellink	= gtp_dellink,
	.get_size	= gtp_get_size,
	.fill_info	= gtp_fill_info,
};

static struct net *gtp_genl_get_net(struct net *src_net, struct nlattr *tb[])
{
	struct net *net;
	/* Examine the link attributes and figure out which
	 * network namespace we are talking about.
	 */
	if (tb[GTPA_NET_NS_FD])
		net = get_net_ns_by_fd(nla_get_u32(tb[GTPA_NET_NS_FD]));
	else
		net = get_net(src_net);
	return net;
}

static int gtp_hashtable_new(struct gtp_instance *gti, int hsize)
{
	int i;

	gti->addr_hash = kmalloc(sizeof(struct hlist_head) * hsize, GFP_KERNEL);
	if (gti->addr_hash == NULL)
		return -ENOMEM;

	gti->tid_hash= kmalloc(sizeof(struct hlist_head) * hsize, GFP_KERNEL);
	if (gti->tid_hash == NULL)
		goto err1;

	gti->hash_size = hsize;

	for (i = 0; i < hsize; i++) {
		INIT_HLIST_HEAD(&gti->addr_hash[i]);
		INIT_HLIST_HEAD(&gti->tid_hash[i]);
	}
	return 0;
err1:
	kfree(gti->addr_hash);
	return -ENOMEM;
}

static void gtp_hashtable_free(struct gtp_instance *gti)
{
	struct pdp_ctx *pctx;
	int i;

	for (i = 0; i < gti->hash_size; i++) {
		hlist_for_each_entry_rcu(pctx, &gti->tid_hash[i], hlist_tid) {
			hlist_del_rcu(&pctx->hlist_tid);
			hlist_del_rcu(&pctx->hlist_addr);
			kfree_rcu(pctx, rcu_head);
		}
	}
	synchronize_rcu();
	kfree(gti->addr_hash);
	kfree(gti->tid_hash);
}

static int gtp_encap_enable(struct net_device *dev, struct gtp_instance *gti,
			    int fd_gtp0, int fd_gtp1)
{
	int err;
	struct socket *sock0, *sock1u;
	struct udp_tunnel_sock_cfg tuncfg = {NULL};

	netdev_dbg(dev, "enable gtp on %d, %d\n", fd_gtp0, fd_gtp1);

	sock0 = sockfd_lookup(fd_gtp0, &err);
	if (sock0 == NULL) {
		netdev_dbg(dev, "socket fd=%d not found (gtp0)\n", fd_gtp0);
		return -ENOENT;
	}

	if (sock0->sk->sk_protocol != IPPROTO_UDP) {
		netdev_dbg(dev, "socket fd=%d not UDP\n", fd_gtp0);
		err = -EINVAL;
		goto err1;
	}

	sock1u = sockfd_lookup(fd_gtp1, &err);
	if (sock1u == NULL) {
		netdev_dbg(dev, "socket fd=%d not found (gtp1u)\n", fd_gtp1);
		err = -ENOENT;
		goto err1;
	}

	if (sock1u->sk->sk_protocol != IPPROTO_UDP) {
		netdev_dbg(dev, "socket fd=%d not UDP\n", fd_gtp1);
		err = -EINVAL;
		goto err2;
	}

	netdev_dbg(dev, "enable gtp on %p, %p\n", sock0, sock1u);

	gti->sock0 = sock0;
	gti->sock1u = sock1u;

	tuncfg.sk_user_data = gti;
	tuncfg.encap_rcv = gtp_udp_encap_recv;
	tuncfg.encap_destroy = gtp_udp_encap_destroy;

	tuncfg.encap_type = UDP_ENCAP_GTP0;
	setup_udp_tunnel_sock(sock_net(gti->sock0->sk), gti->sock0, &tuncfg);

	tuncfg.encap_type = UDP_ENCAP_GTP1U;
	setup_udp_tunnel_sock(sock_net(gti->sock1u->sk), gti->sock1u, &tuncfg);

	err = 0;

err2:
	sockfd_put(sock1u);
err1:
	sockfd_put(sock0);
	return err;
}

static void gtp_encap_disable(struct gtp_instance *gti)
{
	if (gti->sock0 && gti->sock0->sk) {
		udp_sk(gti->sock0->sk)->encap_type = 0;
		rcu_assign_sk_user_data(gti->sock0->sk, NULL);
	}
	if (gti->sock1u && gti->sock1u->sk) {
		udp_sk(gti->sock1u->sk)->encap_type = 0;
		rcu_assign_sk_user_data(gti->sock1u->sk, NULL);
	}

	gti->sock0 = NULL;
	gti->sock1u = NULL;
}

static struct net_device *gtp_find_dev(struct net *net, int ifindex)
{
	struct gtp_net *gn = net_generic(net, gtp_net_id);
	struct gtp_instance *gti;

	list_for_each_entry_rcu(gti, &gn->gtp_instance_list, list) {
		if (ifindex == gti->dev->ifindex)
			return gti->dev;
	}
	return NULL;
}

static int ipv4_pdp_add(struct net_device *dev, struct genl_info *info)
{
	struct gtp_instance *gti = netdev_priv(dev);
	struct pdp_ctx *pctx;
	u16 flow = 0;
	u32 gtp_version, sgsn_addr, ms_addr, hash_ms, hash_tid;
	u64 tid;
	bool found = false;

	gtp_version = nla_get_u32(info->attrs[GTPA_VERSION]);
	switch (gtp_version) {
	case GTP_V0:
	case GTP_V1:
		break;
	default:
		return -EINVAL;
	}

	tid = nla_get_u64(info->attrs[GTPA_TID]);
	/* GTPv1 allows 32-bits tunnel IDs */
	if (gtp_version == GTP_V1 && tid > UINT_MAX)
		return -EINVAL;

	/* According to TS 09.60, sections 7.5.1 and 7.5.2, the flow label
	 * needs to be the same for uplink and downlink packets, so let's
	 * annotate this.
	 */
	if (gtp_version == GTP_V0) {
		if (!info->attrs[GTPA_FLOW])
			return -EINVAL;

		flow = nla_get_u16(info->attrs[GTPA_FLOW]);
	}

	sgsn_addr = nla_get_u32(info->attrs[GTPA_SGSN_ADDRESS]);
	ms_addr = nla_get_u32(info->attrs[GTPA_MS_ADDRESS]);

	hash_ms = ipv4_hashfn(ms_addr) % gti->hash_size;

	hlist_for_each_entry_rcu(pctx, &gti->addr_hash[hash_ms], hlist_addr) {
		if (pctx->ms_addr.ip4.s_addr == ms_addr) {
			found = true;
			break;
		}
	}

	if (found) {
		if (info->nlhdr->nlmsg_flags & NLM_F_EXCL)
			return -EEXIST;
		if (info->nlhdr->nlmsg_flags & NLM_F_REPLACE)
			return -EOPNOTSUPP;

		pctx->af = AF_INET;
		pctx->gtp_version = gtp_version;
		pctx->tid = tid;
		pctx->sgsn_addr.ip4.s_addr = sgsn_addr;
		pctx->ms_addr.ip4.s_addr = ms_addr;

		netdev_dbg(dev, "update tunnel id = %llx (pdp %p)\n",
			   tid, pctx);

		return 0;
	}

	pctx = kmalloc(sizeof(struct pdp_ctx), GFP_KERNEL);
	if (pctx == NULL)
		return -ENOMEM;

	pctx->af = AF_INET;
	pctx->gtp_version = gtp_version;
	pctx->tid = tid;
	pctx->sgsn_addr.ip4.s_addr = sgsn_addr;
	pctx->ms_addr.ip4.s_addr = ms_addr;
	pctx->flow = flow;
	atomic_set(&pctx->tx_seq, 0);

	switch (gtp_version) {
	case GTP_V0:
		/* TS 09.60: "The flow label identifies unambiguously a GTP
		 * flow.". We use the tid for this instead, I cannot find a
		 * situation in which this doesn't unambiguosly identify the
		 * PDP context.
		 */
		hash_tid = gtp0_hashfn(tid) % gti->hash_size;
		break;
	case GTP_V1:
		hash_tid = gtp1u_hashfn(tid) % gti->hash_size;
		break;
	}
	hlist_add_head_rcu(&pctx->hlist_addr, &gti->addr_hash[hash_ms]);
	hlist_add_head_rcu(&pctx->hlist_tid, &gti->tid_hash[hash_tid]);

	netdev_dbg(dev, "adding tunnel id = %llx (pdp %p)\n", tid, pctx);

	return 0;
}

static int gtp_genl_tunnel_new(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net;
	struct net_device *dev;

	if (!info->attrs[GTPA_VERSION] ||
	    !info->attrs[GTPA_LINK] ||
	    !info->attrs[GTPA_SGSN_ADDRESS] ||
	    !info->attrs[GTPA_MS_ADDRESS] ||
	    !info->attrs[GTPA_TID])
		return -EINVAL;

	net = gtp_genl_get_net(sock_net(skb->sk), info->attrs);
	if (IS_ERR(net))
		return PTR_ERR(net);

	/* Check if there's an existing gtpX device to configure */
	dev = gtp_find_dev(net, nla_get_u32(info->attrs[GTPA_LINK]));
	if (dev == NULL)
		return -ENODEV;

	return ipv4_pdp_add(dev, info);
}

static int gtp_genl_tunnel_delete(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net;
	struct gtp_instance *gti;
	struct net_device *dev;
	struct pdp_ctx *pctx;
	u32 gtp_version;
	u64 tid;

	if (!info->attrs[GTPA_VERSION] ||
	    !info->attrs[GTPA_LINK] ||
	    !info->attrs[GTPA_SGSN_ADDRESS] ||
	    !info->attrs[GTPA_MS_ADDRESS] ||
	    !info->attrs[GTPA_TID])
		return -EINVAL;

	gtp_version = nla_get_u32(info->attrs[GTPA_VERSION]);
	switch (gtp_version) {
	case GTP_V0:
	case GTP_V1:
		break;
	default:
		return -EINVAL;
	}

	tid = nla_get_u64(info->attrs[GTPA_TID]);
	/* GTPv1 allows 32-bits tunnel IDs */
	if (gtp_version == GTP_V1 && tid > UINT_MAX)
		return -EINVAL;

	net = gtp_genl_get_net(sock_net(skb->sk), info->attrs);
	if (IS_ERR(net))
		return PTR_ERR(net);

	/* Check if there's an existing gtpX device to configure */
	dev = gtp_find_dev(net, nla_get_u32(info->attrs[GTPA_LINK]));
	if (dev == NULL)
		return -ENODEV;

	gti = netdev_priv(dev);

	switch (gtp_version) {
	case GTP_V0:
		pctx = gtp0_pdp_find(gti, nla_get_u64(info->attrs[GTPA_TID]));
		break;
	case GTP_V1:
		pctx = gtp1_pdp_find(gti, nla_get_u64(info->attrs[GTPA_TID]));
		break;
	}

	if (pctx == NULL)
		return -ENOENT;

	netdev_dbg(dev, "deleting tunnel with ID %lld\n",
		   (unsigned long long) nla_get_u64(info->attrs[GTPA_TID]));

	hlist_del_rcu(&pctx->hlist_tid);
	hlist_del_rcu(&pctx->hlist_addr);
	kfree_rcu(pctx, rcu_head);

	return 0;
}

static struct genl_family gtp_genl_family = {
	.id		= GENL_ID_GENERATE,
	.name		= "gtp",
	.version	= 0,
	.hdrsize	= 0,
	.maxattr	= GTPA_MAX,
	.netnsok	= true,
};

static int
gtp_genl_fill_info(struct sk_buff *skb, u32 snd_portid, u32 snd_seq,
		   u32 type, struct pdp_ctx *pctx)
{
	void *genlh;

	genlh = genlmsg_put(skb, snd_portid, snd_seq, &gtp_genl_family, 0,
			    type);
	if (genlh == NULL)
		goto nlmsg_failure;

	if (nla_put_u32(skb, GTPA_VERSION, pctx->gtp_version) ||
	    nla_put_u32(skb, GTPA_SGSN_ADDRESS, pctx->sgsn_addr.ip4.s_addr) ||
	    nla_put_u32(skb, GTPA_MS_ADDRESS, pctx->ms_addr.ip4.s_addr) ||
	    nla_put_u64(skb, GTPA_TID, pctx->tid) ||
	    (pctx->gtp_version == GTP_V0 &&
	     nla_put_u16(skb, GTPA_FLOW, pctx->flow)))
		goto nla_put_failure;

	genlmsg_end(skb, genlh);
	return 0;

nlmsg_failure:
nla_put_failure:
	genlmsg_cancel(skb, genlh);
	return -EMSGSIZE;
}

static int gtp_genl_tunnel_get(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net;
	struct net_device *dev;
	struct gtp_instance *gti;
	struct pdp_ctx *pctx = NULL;
	struct sk_buff *skb2;
	u32 gtp_version;
	int err;

	if (!info->attrs[GTPA_VERSION] ||
	    !info->attrs[GTPA_LINK])
		return -EINVAL;

	gtp_version = nla_get_u32(info->attrs[GTPA_VERSION]);
	switch (gtp_version) {
	case GTP_V0:
	case GTP_V1:
		break;
	default:
		return -EINVAL;
	}

	net = gtp_genl_get_net(sock_net(skb->sk), info->attrs);
	if (IS_ERR(net))
		return PTR_ERR(net);

	/* Check if there's an existing gtpX device to configure */
	dev = gtp_find_dev(net, nla_get_u32(info->attrs[GTPA_LINK]));
	if (dev == NULL)
		return -ENODEV;

	gti = netdev_priv(dev);

	rcu_read_lock();
	if (info->attrs[GTPA_TID]) {
		u64 tid = nla_get_u64(info->attrs[GTPA_TID]);

		/* GTPv1 allows 32-bits tunnel IDs */
		if (gtp_version == GTP_V1 && tid > UINT_MAX) {
			err = -EINVAL;
			goto err_unlock;
		}

		switch (gtp_version) {
		case GTP_V0:
			pctx = gtp0_pdp_find(gti, tid);
			break;
		case GTP_V1:
			pctx = gtp1_pdp_find(gti, tid);
			break;
		}
	} else if (info->attrs[GTPA_MS_ADDRESS]) {
		u32 ip = nla_get_u32(info->attrs[GTPA_MS_ADDRESS]);

		pctx = ipv4_pdp_find(gti, ip);
	}

	if (pctx == NULL) {
		err = -ENOENT;
		goto err_unlock;
	}

	skb2 = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (skb2 == NULL) {
		err = -ENOMEM;
		goto err_unlock;
	}

	err = gtp_genl_fill_info(skb2, NETLINK_CB(skb).portid,
				 info->snd_seq, info->nlhdr->nlmsg_type, pctx);
	if (err < 0)
		goto err_unlock_free;

	rcu_read_unlock();
	return genlmsg_unicast(genl_info_net(info), skb2, info->snd_portid);

err_unlock_free:
	kfree_skb(skb2);
err_unlock:
	rcu_read_unlock();
	return err;
}

static int
gtp_genl_tunnel_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	int i, k = cb->args[0], ret;
	unsigned long tid = cb->args[1];
	struct gtp_instance *last_gti = (struct gtp_instance *)cb->args[2], *gti;
	struct pdp_ctx *pctx;
	struct net *net = sock_net(skb->sk);
	struct gtp_net *gn = net_generic(net, gtp_net_id);

	if (cb->args[4])
		return 0;

	list_for_each_entry_rcu(gti, &gn->gtp_instance_list, list) {
		if (last_gti && last_gti != gti)
			continue;
		else
			last_gti = NULL;

		for (i = k; i < gti->hash_size; i++) {
			hlist_for_each_entry_rcu(pctx, &gti->tid_hash[i], hlist_tid) {
				if (tid && tid != pctx->tid)
					continue;
				else
					tid = 0;

				ret = gtp_genl_fill_info(skb,
							 NETLINK_CB(cb->skb).portid,
							 cb->nlh->nlmsg_seq,
							 cb->nlh->nlmsg_type, pctx);
				if (ret < 0) {
					cb->args[0] = i;
					cb->args[1] = pctx->tid;
					cb->args[2] = (unsigned long)gti;
					goto out;
				}
			}
		}
	}
	cb->args[4] = 1;
out:
	return skb->len;
}

static struct nla_policy gtp_genl_policy[GTPA_MAX + 1] = {
	[GTPA_LINK]		= { .type = NLA_U32, },
	[GTPA_VERSION]		= { .type = NLA_U32, },
	[GTPA_TID]		= { .type = NLA_U64, },
	[GTPA_SGSN_ADDRESS]	= { .type = NLA_NESTED, },
	[GTPA_MS_ADDRESS]	= { .type = NLA_NESTED, },
	[GTPA_FLOW]		= { .type = NLA_U16, },
	[GTPA_NET_NS_FD]	= { .type = NLA_U32, },
};

static const struct genl_ops gtp_genl_ops[] = {
	{
		.cmd = GTP_CMD_TUNNEL_NEW,
		.doit = gtp_genl_tunnel_new,
		.policy = gtp_genl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = GTP_CMD_TUNNEL_DELETE,
		.doit = gtp_genl_tunnel_delete,
		.policy = gtp_genl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = GTP_CMD_TUNNEL_GET,
		.doit = gtp_genl_tunnel_get,
		.dumpit = gtp_genl_tunnel_dump,
		.policy = gtp_genl_policy,
		.flags = GENL_ADMIN_PERM,
	},
};

static int __net_init gtp_net_init(struct net *net)
{
	struct gtp_net *gn = net_generic(net, gtp_net_id);

	INIT_LIST_HEAD(&gn->gtp_instance_list);

	return 0;
}

static void __net_exit gtp_net_exit(struct net *net)
{
	struct gtp_net *gn = net_generic(net, gtp_net_id);
	struct gtp_instance *gti;
	LIST_HEAD(list);

	rtnl_lock();
	list_for_each_entry(gti, &gn->gtp_instance_list, list)
		gtp_dellink(gti->dev, &list);

	unregister_netdevice_many(&list);
	rtnl_unlock();
}

static struct pernet_operations gtp_net_ops = {
	.init = gtp_net_init,
	.exit = gtp_net_exit,
	.id   = &gtp_net_id,
	.size = sizeof(struct gtp_net),
};

static int __init gtp_init(void)
{
	int err;

	get_random_bytes(&gtp_h_initval, sizeof(gtp_h_initval));

	err = rtnl_link_register(&gtp_link_ops);
	if (err < 0)
		goto error_out;

	err = genl_register_family_with_ops(&gtp_genl_family, gtp_genl_ops);
	if (err < 0)
		goto unreg_rtnl_link;

	err = register_pernet_subsys(&gtp_net_ops);
	if (err < 0)
		goto unreg_genl_family;

	pr_info("GTP module loaded (pdp ctx size %Zd bytes)\n",
		sizeof(struct pdp_ctx));
	return 0;

unreg_genl_family:
	genl_unregister_family(&gtp_genl_family);
unreg_rtnl_link:
	rtnl_link_unregister(&gtp_link_ops);
error_out:
	pr_err("error loading GTP module loaded\n");
	return err;
}
late_initcall(gtp_init);

static void __exit gtp_fini(void)
{
	unregister_pernet_subsys(&gtp_net_ops);
	genl_unregister_family(&gtp_genl_family);
	rtnl_link_unregister(&gtp_link_ops);

	pr_info("GTP module unloaded\n");
}
module_exit(gtp_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Harald Welte <hwelte@sysmocom.de>");
MODULE_ALIAS_RTNL_LINK("gtp");
MODULE_ALIAS_NETDEV("gtp0");
