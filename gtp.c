/* GTP according to GSM TS 09.60 / 3GPP TS 29.060 */

/* (C) 2012-2014 by sysmocom - s.f.m.c. GmbH
 * Author: Harald Welte <hwelte@sysmocom.de>
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

#include <net/protocol.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/genetlink.h>

#include "gtp.h"
#include "gtp_nl.h"

static u32 gtp_h_initval;
static struct workqueue_struct *gtp_wq;

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

	/* address for local UDP socket */
	struct sockaddr_in gtp0_addr;
	struct sockaddr_in gtp1u_addr;

	/* the socket */
	struct socket *sock0;
	struct socket *sock1u;
	struct work_struct sock_work;

	struct net_device *dev;
	struct net_device *real_dev;

	unsigned int hash_size;
	struct hlist_head *tid_hash;
	struct hlist_head *addr_hash;
};

static LIST_HEAD(gtp_instance_list); /* XXX netns */

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
		pr_info("af %u : pdp->ms %pI4 == ms %pI4\n",
			pdp->af, &pdp->ms_addr.ip4, &ms_addr);
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
static bool gtp_check_src_ms(struct sk_buff *skb, struct pdp_ctx *pctx)
{
	bool ret = false;

	if (skb->protocol == ntohs(ETH_P_IP)) {
		struct iphdr *iph;

		if (!pskb_may_pull(skb, sizeof(struct iphdr)))
			return false;

		iph = (struct iphdr *)skb->data;
		ret = (iph->saddr != pctx->ms_addr.ip4.s_addr);

	} else if (skb->protocol == ntohs(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;

		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
			return false;

		ip6h = (struct ipv6hdr *)skb->data;
		ret = memcmp(&ip6h->saddr, &pctx->ms_addr.ip6,
			     sizeof(struct in6_addr)) == 0;
	}

	return ret;
}

static int gtp0_udp_encap_recv(struct gtp_instance *gti, struct sk_buff *skb)
{
	struct gtp0_header *gtp0;
	struct pdp_ctx *pctx;
	u64 tid;

	pr_info("gtp0 udp received\n");

	gtp0 = (struct gtp0_header *)skb->data;

	/* check for GTP Version 0 */
	if ((gtp0->flags >> 5) != GTP_V0)
		goto out;

	/* check if it is T-PDU. if not -> userspace */
	if (gtp0->type != GTP_TPDU)
		goto out;

	/* look-up the PDP context for the Tunnel ID */
	tid = be64_to_cpu(gtp0->tid);

	rcu_read_lock();
	pctx = gtp0_pdp_find(gti, tid);
	if (!pctx)
		goto out_rcu;

	/* get rid of the GTP header */
	__skb_pull(skb, sizeof(*gtp0));

	if (!gtp_check_src_ms(skb, pctx))
		goto out_rcu;

	rcu_read_unlock();
	return 0;

out_rcu:
	rcu_read_unlock();
out:
	return -1;
}

static u8 gtp1u_header_len[] = {
	[0]					= 0,	/* 0 */
	[GTP1_F_SEQ]				= 2,	/* 2 */
	[GTP1_F_NPDU]				= 1,	/* 1 */
	[GTP1_F_SEQ|GTP1_F_NPDU]		= 3,	/* 2 + 1 */
	[GTP1_F_EXTHDR]				= 1,	/* 1 */
	[GTP1_F_EXTHDR|GTP1_F_SEQ]		= 3,	/* 1 + 2 */
	[GTP1_F_EXTHDR|GTP1_F_NPDU]		= 2,	/* 1 + 1 */
	[GTP1_F_EXTHDR|GTP1_F_NPDU|GTP1_F_SEQ]	= 4,	/* 1 + 1 + 2 */
};

static int gtp1u_udp_encap_recv(struct gtp_instance *gti, struct sk_buff *skb)
{
	struct gtp1_header *gtp1;
	struct pdp_ctx *pctx;
	unsigned int gtp1_hdrlen = sizeof(*gtp1);

	pr_info("gtp1 udp received\n");

	/* check for sufficient header size */
	if (!pskb_may_pull(skb, sizeof(*gtp1)))
		goto out;

	gtp1 = (struct gtp1_header *)skb->data;

	/* check for GTP Version 1 */
	if ((gtp1->flags >> 5) != GTP_V1)
		goto out;

	/* check if it is T-PDU. */
	if (gtp1->type != GTP_TPDU)
		goto out;

	/* look-up table for faster length computing */
	gtp1_hdrlen = gtp1u_header_len[gtp1->flags & GTP1_F_MASK];

	/* check for sufficient header size */
	if (gtp1_hdrlen && !pskb_may_pull(skb, gtp1_hdrlen))
		goto out_rcu;

	/* look-up the PDP context for the Tunnel ID */
	rcu_read_lock();
	pctx = gtp1_pdp_find(gti, ntohl(gtp1->tid));
	if (!pctx)
		goto out_rcu;

	/* get rid of the GTP header */
	__skb_pull(skb, sizeof(*gtp1) + gtp1_hdrlen);

	/* FIXME: actually take care of extension header chain */

	if (!gtp_check_src_ms(skb, pctx))
		goto out_rcu;

	rcu_read_unlock();
	return 0;

out_rcu:
	rcu_read_unlock();
out:
	return -1;
}

/* UDP encapsulation receive handler. See net/ipv4/udp.c.
 * Return codes: 0: success, <0: error, >0: passed up to userspace UDP.
 */
static int gtp_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct gtp_instance *gti;
	int ret;

	pr_info("gtp udp received\n");

	/* resolve the GTP instance to which the socket belongs */
	gti = sk_to_gti(sk);
	if (!gti)
		goto user;

	/* UDP verifies the packet length, but this may be fragmented, so make
	 * sure the UDP header is linear.
	 */
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto user_put;

	__skb_pull(skb, sizeof(struct udphdr));

	switch (udp_sk(sk)->encap_type) {
	case UDP_ENCAP_GTP0:
		ret = gtp0_udp_encap_recv(gti, skb);
		break;
	case UDP_ENCAP_GTP1U:
		ret = gtp1u_udp_encap_recv(gti, skb);
		break;
	default:
		ret = -1; /* shouldn't happen */
	}

	/* Not a valid GTP packet, drop it. */
	if (unlikely(ret < 0))
		goto drop;

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

	dev->flags              = IFF_NOARP;
	gti->dev		= dev;

	dev->tstats = alloc_percpu(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	/* create the socket outside of rtnl to avoid a possible deadlock */
	queue_work(gtp_wq, &gti->sock_work);

	return 0;
}

static void gtp_destroy_bind_sock(struct gtp_instance *gti);

static void gtp_dev_uninit(struct net_device *dev)
{
	struct gtp_instance *gti = netdev_priv(dev);

	gtp_destroy_bind_sock(gti);
	free_percpu(dev->tstats);
}

#define IP_UDP_LEN	(sizeof(struct iphdr) + sizeof(struct udphdr))

static struct rtable *
ip4_route_output_gtp(struct net *net, struct flowi4 *fl4,
		     __be32 daddr, __be32 saddr, __u8 tos, int oif)
{
	memset(fl4, 0, sizeof(*fl4));
	fl4->flowi4_oif = oif;
	fl4->daddr = daddr;
	fl4->saddr = saddr;
	fl4->flowi4_tos = tos;
	fl4->flowi4_proto = IPPROTO_UDP;
	return ip_route_output_key(net, fl4);
}

static inline void
gtp0_push_header(struct sk_buff *skb, struct pdp_ctx *pctx, int payload_len)
{
	struct gtp0_header *gtp0;

	/* ensure there is sufficient headroom */
	skb_cow(skb, sizeof(*gtp0) + IP_UDP_LEN);
	gtp0 = (struct gtp0_header *) skb_push(skb, sizeof(*gtp0));

	gtp0->flags = 0x1e; /* V0, GTP-non-prime */
	gtp0->type = GTP_TPDU;
	gtp0->length = htons(payload_len);
	gtp0->seq = htons((atomic_inc_return(&pctx->tx_seq)-1) % 0xffff);
	gtp0->flow = htonl(pctx->flow);
	gtp0->number = 0xFF;
	gtp0->spare[0] = gtp0->spare[1] = gtp0->spare[2] = 0xFF;
	gtp0->tid = cpu_to_be64(pctx->tid);
}

static inline void
gtp1_push_header(struct sk_buff *skb, struct pdp_ctx *pctx, int payload_len)
{
	struct gtp1_header *gtp1;

	/* ensure there is sufficient headroom */
	skb_cow(skb, sizeof(*gtp1) + IP_UDP_LEN);
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
	union {
		struct iphdr	*iph;
		struct ipv6hdr	*ip6h;
	};
	union {
		struct flowi4	fl4;
	};
	struct rtable		*rt;
	struct pdp_ctx		*pctx;
};

static inline void
gtp_set_pktinfo_ipv4(struct gtp_pktinfo *pktinfo, struct iphdr *iph,
		     struct pdp_ctx *pctx, struct rtable *rt,
		     struct flowi4 *fl4)
{
	pktinfo->iph	= iph;
	pktinfo->pctx	= pctx;
	pktinfo->rt	= rt;
	pktinfo->fl4	= *fl4;
}

static int gtp_ip4_prepare_xmit(struct sk_buff *skb, struct net_device *dev,
				struct gtp_pktinfo *pktinfo)
{
	struct gtp_instance *gti = netdev_priv(dev);
	struct inet_sock *inet = inet_sk(gti->sock0->sk);
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
		netdev_dbg(dev, "no PDP context, skipping\n");
		return -ENOENT;
	}
	netdev_dbg(dev, "found PDP context %p\n", pctx);

	/* Obtain route for the new encapsulated GTP packet */
	rt = ip4_route_output_gtp(dev_net(dev), &fl4,
				  pctx->sgsn_addr.ip4.s_addr,
				  inet->inet_saddr, 0,
				  gti->real_dev->ifindex);
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
	skb_dst_set(skb, &rt->dst);

	/* This is similar to tnl_update_pmtu() */
	df = iph->frag_off;
	if (df) {
		mtu = dst_mtu(&rt->dst) - gti->real_dev->hard_header_len -
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
		mtu = skb_dst(skb) ? dst_mtu(skb_dst(skb)) : dev->mtu;

	if (skb_dst(skb))
		skb_dst(skb)->ops->update_pmtu(skb_dst(skb), NULL, skb, mtu);

	if (!skb_is_gso(skb) && (iph->frag_off & htons(IP_DF)) &&
	    mtu < ntohs(iph->tot_len)) {
		memset(IPCB(skb), 0, sizeof(*IPCB(skb)));
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(mtu));
		goto err_rt;
	}

	gtp_set_pktinfo_ipv4(pktinfo, iph, pctx, rt, &fl4);

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

static inline void
gtp_push_ip4hdr(struct sk_buff *skb, struct gtp_pktinfo *pktinfo)
{
	struct iphdr *iph;

	/* Push down and install the IP header. Similar to iptunnel_xmit() */
	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);

	iph = ip_hdr(skb);

	iph->version	=	4;
	iph->ihl	=	sizeof(struct iphdr) >> 2;
	iph->frag_off	=	htons(IP_DF);
	iph->protocol	=	IPPROTO_UDP;
	iph->tos	=	pktinfo->iph->tos;
	iph->daddr	=	pktinfo->fl4.daddr;
	iph->saddr	=	pktinfo->fl4.saddr;
	iph->ttl	=	ip4_dst_hoplimit(&pktinfo->rt->dst);

	pr_info("gtp -> IP src: %pI4 dst: %pI4\n", &iph->saddr, &iph->daddr);
}

static inline void
gtp_push_ip6hdr(struct sk_buff *skb, struct gtp_pktinfo *pktinfo)
{
	/* TODO IPV6 support */
}

static netdev_tx_t gtp_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct gtp_instance *gti = netdev_priv(dev);
	struct udphdr *uh;
	unsigned int payload_len;
	struct gtp_pktinfo pktinfo;
	unsigned int proto = ntohs(skb->protocol);
	int err;

	/* UDP socket not initialized, skip */
	if (!gti->sock0) {
		pr_info("xmit: no socket / need cfg, skipping\n");
		return NETDEV_TX_OK;
	}

	rcu_read_lock();
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

	/* Annotate length of the encapsulated packet */
	payload_len = skb->len;

	/* Push down GTP header */
	switch (pktinfo.pctx->gtp_version) {
	case GTP_V0:
		gtp0_push_header(skb, pktinfo.pctx, payload_len);
		break;
	case GTP_V1:
		gtp1_push_header(skb, pktinfo.pctx, payload_len);
		break;
	}

	/* Push down and install the UDP header. */
	skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);

	uh = udp_hdr(skb);
	switch (pktinfo.pctx->gtp_version) {
	case GTP_V0:
		uh->source = uh->dest = htons(GTP0_PORT);
		break;
	case GTP_V1:
		uh->source = uh->dest = htons(GTP1U_PORT);
		break;
	}

	uh->len = htons(sizeof(struct udphdr) + payload_len);
	uh->check = 0;

	pr_info("gtp -> UDP src: %u dst: %u (len %u)\n",
		ntohs(uh->source), ntohs(uh->dest), ntohs(uh->len));

	switch (proto) {
	case ETH_P_IP:
		gtp_push_ip4hdr(skb, &pktinfo);
		break;
	case ETH_P_IPV6:
		gtp_push_ip6hdr(skb, &pktinfo);
		break;
	}
	rcu_read_unlock();

	nf_reset(skb);

	err = ip_local_out(skb);
	gtp_iptunnel_xmit_stats(err, &dev->stats, dev->tstats);

	return NETDEV_TX_OK;
tx_error:
	rcu_read_unlock();
	pr_info("no route to reach destination\n");
	dev->stats.tx_errors++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops gtp_netdev_ops = {
	.ndo_init		= gtp_dev_init,
	.ndo_uninit		= gtp_dev_uninit,
	.ndo_start_xmit		= gtp_dev_xmit,
};

static int gtp_create_bind_sock(struct gtp_instance *gti);

/* Scheduled at device creation to bind to a socket */
static void gtp_sock_work(struct work_struct *work)
{
	struct gtp_instance *gti =
		container_of(work, struct gtp_instance, sock_work);

	gtp_create_bind_sock(gti);
}

static void gtp_link_setup(struct net_device *dev)
{
	struct gtp_instance *gti = netdev_priv(dev);

	dev->netdev_ops		= &gtp_netdev_ops;
	dev->destructor		= free_netdev;

	INIT_WORK(&gti->sock_work, gtp_sock_work);
}

static int gtp_hashtable_new(struct gtp_instance *gti, int hsize);
static void gtp_hashtable_free(struct gtp_instance *gti);

static int gtp_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[])
{
	struct net_device *real_dev;
	struct gtp_instance *gti;
	int hashsize, err;

	pr_info("gtp_newlink\n");

	if (!tb[IFLA_LINK])
		return -EINVAL;

	real_dev = __dev_get_by_index(src_net, nla_get_u32(tb[IFLA_LINK]));
	if (!real_dev)
		return -ENODEV;

	dev_hold(real_dev);

	if (!tb[IFLA_MTU])
		dev->mtu = real_dev->mtu;
	else if (dev->mtu > real_dev->mtu)
		return -EINVAL;

	gti = netdev_priv(dev);
	gti->real_dev = real_dev;

	gti->gtp0_addr.sin_addr.s_addr =
	gti->gtp1u_addr.sin_addr.s_addr =
		nla_get_u32(data[IFLA_GTP_LOCAL_ADDR_IPV4]);

	if (!data[IFLA_GTP_HASHSIZE])
		hashsize = 1024;
	else
		hashsize = nla_get_u32(data[IFLA_GTP_HASHSIZE]);

	err = gtp_hashtable_new(gti, hashsize);
	if (err < 0)
		return err;

	err = register_netdevice(dev);
	if (err < 0)
		goto err1;

	list_add_rcu(&gti->list, &gtp_instance_list);

	pr_info("registered new %s interface\n", dev->name);

	return 0;
err1:
	pr_info("failed to register new netdev %d\n", err);
	gtp_hashtable_free(gti);
	return err;
}

static void gtp_dellink(struct net_device *dev, struct list_head *head)
{
	struct gtp_instance *gti = netdev_priv(dev);

	gtp_hashtable_free(gti);
	dev_put(gti->real_dev);
	list_del_rcu(&gti->list);
	unregister_netdevice_queue(dev, head);
}

static const struct nla_policy gtp_policy[IFLA_GTP_MAX + 1] = {
	[IFLA_GTP_LOCAL_ADDR_IPV4]	= { .type = NLA_U32 },
	[IFLA_GTP_HASHSIZE]		= { .type = NLA_U32 },
};

static int gtp_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (!data || !data[IFLA_GTP_LOCAL_ADDR_IPV4])
		return -EINVAL;

	return 0;
}

static size_t gtp_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(__u32)) +	/* IFLA_GTP_LOCAL_ADDR_IPV4 */
	       nla_total_size(sizeof(__u32));	/* IFLA_GTP_HASHSIZE */
}

static int gtp_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct gtp_instance *gti = netdev_priv(dev);

	if (nla_put_u32(skb, IFLA_GTP_LOCAL_ADDR_IPV4,
			gti->gtp0_addr.sin_addr.s_addr) ||
	    nla_put_u32(skb, IFLA_GTP_HASHSIZE, gti->hash_size))
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

static int gtp_create_bind_sock(struct gtp_instance *gti)
{
	int rc;
	struct sockaddr_in sin;
	struct sock *sk;

	/* Create and bind the socket for GTP0 */
	rc = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &gti->sock0);
	if (rc < 0)
		goto out;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(GTP0_PORT);
	rc = kernel_bind(gti->sock0, (struct sockaddr *) &sin, sizeof(sin));
	if (rc < 0)
		goto out;

	sk = gti->sock0->sk;
	udp_sk(sk)->encap_type = UDP_ENCAP_GTP0;
	udp_sk(sk)->encap_rcv = gtp_udp_encap_recv;
	sk->sk_user_data = gti;
	udp_encap_enable();

	/* Create and bind the socket for GTP1 user-plane */
	rc = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &gti->sock1u);
	if (rc < 0)
		goto out_free0;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(GTP1U_PORT);
	rc = kernel_bind(gti->sock1u, (struct sockaddr *) &sin, sizeof(sin));
	if (rc < 0)
		goto out_free1;

	sk = gti->sock1u->sk;
	udp_sk(sk)->encap_type = UDP_ENCAP_GTP1U;
	udp_sk(sk)->encap_rcv = gtp_udp_encap_recv;
	sk->sk_user_data = gti;

	pr_info("socket successfully binded\n");

	return 0;

out_free1:
	kernel_sock_shutdown(gti->sock1u, SHUT_RDWR);
	sk_release_kernel(gti->sock1u->sk);
out_free0:
	kernel_sock_shutdown(gti->sock0, SHUT_RDWR);
	sk_release_kernel(gti->sock0->sk);
out:
	return rc;
}

static void gtp_destroy_bind_sock(struct gtp_instance *gti)
{
	if (gti->sock1u) {
		kernel_sock_shutdown(gti->sock1u, SHUT_RDWR);
		sk_release_kernel(gti->sock1u->sk);
	}
	if (gti->sock0) {
		kernel_sock_shutdown(gti->sock0, SHUT_RDWR);
		sk_release_kernel(gti->sock0->sk);
	}
}

static struct net_device *gtp_find_dev(int ifindex)
{
	struct gtp_instance *gti;

	list_for_each_entry_rcu(gti, &gtp_instance_list, list) {
		if (ifindex == gti->dev->ifindex)
			return gti->dev;
	}
	return NULL;
}

static int ipv4_pdp_add(struct gtp_instance *gti, struct genl_info *info)
{
	u32 hash_ms;
	u32 hash_tid;
	struct pdp_ctx *pctx;
	u32 gtp_version, link, sgsn_addr, ms_addr, tid;
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

	link = nla_get_u32(info->attrs[GTPA_LINK]);
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

		pr_info("update tunnel id = %u (pdp %p)\n", tid, pctx);

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
	atomic_set(&pctx->tx_seq, 0);

	hash_tid = ipv4_hashfn(tid) % gti->hash_size;

	hlist_add_head_rcu(&pctx->hlist_addr, &gti->addr_hash[hash_ms]);
	hlist_add_head_rcu(&pctx->hlist_tid, &gti->tid_hash[hash_tid]);

	pr_info("adding tunnel id = %u (pdp %p)\n", tid, pctx);

	return 0;
}

static int gtp_genl_tunnel_new(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	struct gtp_instance *gti;

	if (!info->attrs[GTPA_VERSION] ||
	    !info->attrs[GTPA_LINK] ||
	    !info->attrs[GTPA_SGSN_ADDRESS] ||
	    !info->attrs[GTPA_MS_ADDRESS] ||
	    !info->attrs[GTPA_TID])
		return -EINVAL;

	/* Check if there's an existing gtpX device to configure */
	dev = gtp_find_dev(nla_get_u32(info->attrs[GTPA_LINK]));
	if (dev == NULL)
		return -ENODEV;

	gti = netdev_priv(dev);

	return ipv4_pdp_add(gti, info);
}

static int gtp_genl_tunnel_delete(struct sk_buff *skb, struct genl_info *info)
{
	struct gtp_instance *gti;
	struct net_device *dev;
	struct pdp_ctx *pctx;
	u32 gtp_version;
	u64 tid;

	pr_info("deleting tunnel\n");

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

	/* Check if there's an existing gtpX device to configure */
	dev = gtp_find_dev(nla_get_u32(info->attrs[GTPA_LINK]));
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

	hlist_del_rcu(&pctx->hlist_tid);
	hlist_del_rcu(&pctx->hlist_addr);
	kfree_rcu(pctx, rcu_head);

	return 0;
}

static int gtp_genl_tunnel_get(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	struct gtp_instance *gti;

	pr_info("get tunnel\n");

	if (!info->attrs[GTPA_VERSION] ||
	    !info->attrs[GTPA_LINK])
		return -EINVAL;

	/* Check if there's an existing gtpX device to configure */
	dev = gtp_find_dev(nla_get_u32(info->attrs[GTPA_LINK]));
	if (dev == NULL)
		return -ENODEV;

	gti = netdev_priv(dev);

	if (info->attrs[GTPA_TID])
		pr_info("by tid\n");
	else if (info->attrs[GTPA_MS_ADDRESS])
		pr_info("by ms\n");
	else
		return -EINVAL;

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

	pr_info("filling info for tunnel %llu\n", pctx->tid);

	if (nla_put_u32(skb, GTPA_VERSION, pctx->gtp_version) ||
	    nla_put_u32(skb, GTPA_SGSN_ADDRESS, pctx->sgsn_addr.ip4.s_addr) ||
	    nla_put_u32(skb, GTPA_MS_ADDRESS, pctx->ms_addr.ip4.s_addr) ||
	    nla_put_u64(skb, GTPA_TID, pctx->tid))
		goto nla_put_failure;

	return genlmsg_end(skb, genlh);

nlmsg_failure:
nla_put_failure:
	return -EMSGSIZE;
}

static int
gtp_genl_tunnel_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	int i, k = cb->args[0], ret;
	unsigned long tid = cb->args[1];
	struct gtp_instance *last_gti = (struct gtp_instance *)cb->args[2], *gti;
	struct pdp_ctx *pctx;

	if (cb->args[4])
		return 0;

	list_for_each_entry_rcu(gti, &gtp_instance_list, list) {
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
	[GTPA_VERSION]		= { .type = NLA_U32, },
	[GTPA_LINK]		= { .type = NLA_U32, },
	[GTPA_SGSN_ADDRESS]	= { .type = NLA_NESTED, },
	[GTPA_MS_ADDRESS]	= { .type = NLA_NESTED, },
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

static int __init gtp_init(void)
{
	int err;

	gtp_wq = alloc_workqueue("gtp", 0, 0);
	if (!gtp_wq)
		return -ENOMEM;

	get_random_bytes(&gtp_h_initval, sizeof(gtp_h_initval));

	err = genl_register_family_with_ops(&gtp_genl_family, gtp_genl_ops);
	if (err < 0)
		return err;

	err = rtnl_link_register(&gtp_link_ops);
	if (err < 0)
		goto err1;

	pr_info("GTP module loaded (pdp ctx size %Zd bytes)\n",
		sizeof(struct pdp_ctx));
	return 0;
err1:
	pr_info("error loading GTP module loaded\n");
	genl_unregister_family(&gtp_genl_family);
	return err;
}

static void __exit gtp_fini(void)
{
	rtnl_link_unregister(&gtp_link_ops);
	genl_unregister_family(&gtp_genl_family);
	destroy_workqueue(gtp_wq);

	pr_info("GTP module unloaded\n");
}

module_init(gtp_init);
module_exit(gtp_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Harald Welte <hwelte@sysmocom.de>");
MODULE_ALIAS_RTNL_LINK("gtp");
MODULE_ALIAS_NETDEV("gtp0");
