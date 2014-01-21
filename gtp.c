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
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/rculist.h>
#include <linux/jhash.h>
#include <linux/if_tunnel.h>
#include <linux/etherdevice.h>

#include <net/protocol.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/genetlink.h>

#include "gtp.h"

/* Resides in include/uapi/linux/udp.h */
#ifndef UDP_ENCAP_GTP0
#define UDP_ENCAP_GTP0		4
#endif

#ifndef UDP_ENCAP_GTP1U
#define UDP_ENCAP_GTP1U		5
#endif

struct pcpu_tstats {
	u64	rx_packets;
	u64	rx_bytes;
	u64	tx_packets;
	u64	tx_bytes;
	struct u64_stats_sync	syncp;
};

/* general GTP protocol related definitions */

#define GTP0_PORT	3386
#define GTP1U_PORT	2152

#define GTP_TPDU	255

struct gtp0_header {	/* According to GSM TS 09.60 */
	uint8_t flags;
	uint8_t type;
	uint16_t length;
	uint16_t seq;
	uint16_t flow;
	uint8_t number;
	uint8_t spare[3];
	uint64_t tid;
} __attribute__ ((packed));

struct gtp1_header_short { /* According to 3GPP TS 29.060 */
	uint8_t flags;
	uint8_t type;
	uint16_t length;
	uint32_t tid;
} __attribute__ ((packed));

#define gtp1u_header gtp1_header_short /* XXX */

/* implementation-specific definitions */

/* FIXME: initialize this !! */
static uint32_t gtp_h_initval;

struct gsn {
	struct list_head list;
};

struct pdp_ctx {
	struct hlist_node hlist_tid;
	struct hlist_node hlist_addr;

	uint64_t tid;
	uint8_t gtp_version;
	unsigned short int af;

	union {
		struct in6_addr ip6;
		uint32_t ip4;
	} ms_addr;

	union {
		struct in6_addr ip6;
		uint32_t ip4;
	} sgsn_addr;

	/* user plane and control plane address of remote GSN */
	struct sockaddr remote_c;
	struct sockaddr remote_u;
	uint16_t flow;
	atomic_t tx_seq;
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

	struct net_device *dev;

	/* FIXME: hash / tree of pdp contexts */
	unsigned int hash_size;
	struct hlist_head *tid_hash;
	struct hlist_head *addr_hash;
};

static LIST_HEAD(gtp_instance_list); /* XXX netns */

static inline uint32_t gtp0_hashfn(uint64_t tid)
{
	uint32_t *tid32 = (uint32_t *) &tid;
	return jhash_2words(tid32[0], tid32[1], gtp_h_initval);
}

static inline uint32_t gtp1u_hashfn(uint32_t tid)
{
	return jhash_1word(tid, gtp_h_initval);
}

static inline uint32_t ipv4_hashfn(uint32_t ip)
{
	return jhash_1word(ip, gtp_h_initval);
}

static inline uint32_t ipv6_hashfn(struct in6_addr *ip6)
{
	return jhash2((const u32 *) &ip6->s6_addr32, sizeof(*ip6)/4, gtp_h_initval);
}


/* resolve a PDP context structure based on the 64bit TID */
static struct pdp_ctx *gtp0_pdp_find(struct gtp_instance *gti, uint64_t tid)
{
	struct hlist_head *head;
	struct pdp_ctx *pdp;

	head = &gti->tid_hash[gtp0_hashfn(tid) % gti->hash_size];

	hlist_for_each_entry_rcu(pdp, head, hlist_tid) {
		if (pdp->gtp_version == 0 && pdp->tid == tid)
			return pdp;
	}

	return NULL;
}

/* resolve a PDP context structure based on the 32bit TEI */
static struct pdp_ctx *gtp1_pdp_find(struct gtp_instance *gti, uint32_t tid)
{
	struct hlist_head *head;
	struct pdp_ctx *pdp;

	head = &gti->tid_hash[gtp1u_hashfn(tid) % gti->hash_size];

	hlist_for_each_entry_rcu(pdp, head, hlist_tid) {
		if (pdp->gtp_version == 1 && pdp->tid == tid)
			return pdp;
	}

	return NULL;
}

/* resolve a PDP context based on IPv4 address of MS */
static struct pdp_ctx *ipv4_pdp_find(struct gtp_instance *gti,
				     uint32_t ms_addr)
{
	struct hlist_head *head;
	struct pdp_ctx *pdp;

	head = &gti->addr_hash[ipv4_hashfn(ms_addr) % gti->hash_size];

	hlist_for_each_entry_rcu(pdp, head, hlist_addr) {
		if (pdp->af == AF_INET && pdp->ms_addr.ip4 == ms_addr)
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

/* UDP encapsulation receive handler. See net/ipv4/udp.c.
 * Return codes: 0: succes, <0: error, >0: passed up to userspace UDP */
static int gtp0_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct gtp0_header *gtp0 = (struct gtp0_header *) skb_transport_header(skb);
	struct gtp_instance *gti;
	struct pdp_ctx *pctx;
	uint64_t tid;
	int rc;

	/* resolve the GTP instance to which the socket belongs */
	gti = sk_to_gti(sk);
	if (!gti)
		goto user;

	/* check for sufficient header size */
	if (!pskb_may_pull(skb, sizeof(struct udphdr) + sizeof(*gtp0)))
		goto drop_put;

	/* check for GTP Version 0 */
	if ((gtp0->flags >> 5) != 0)
		goto drop_put;

	/* check if it is T-PDU. if not -> userspace */
	if (gtp0->type != GTP_TPDU)
		goto user_put;

	/* look-up the PDP context for the Tunnel ID */
	tid = be64_to_cpu(gtp0->tid);

	rcu_read_lock_bh();
	pctx = gtp0_pdp_find(gti, tid);
	if (!pctx)
		goto drop_put_rcu;

	/* get rid of the UDP and GTP header */
	__skb_pull(skb, sizeof(struct udphdr) + sizeof(*gtp0));

	/* FIXME: check if the inner IP header has the source address
	 * assigned to the current MS */

	/* re-submit via virtual tunnel device into regular network
	 * stack */
	secpath_reset(skb);
	skb_dst_drop(skb);
	nf_reset(skb);

	rc = dev_forward_skb(gti->dev, skb);

drop_put_rcu:
	rcu_read_unlock_bh();
drop_put:
	sock_put(sk);
	return 0;

user_put:
	sock_put(sk);
user:
	return 1;
}

/* UDP encapsulation receive handler. See net/ipv4/udp.c.
 * Return codes: 0: succes, <0: error, >0: passed up to userspace UDP */
static int gtp1u_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct gtp1_header_short *gtp1 =
		(struct gtp1_header_short *) skb_transport_header(skb);
	struct gtp0_header *gtp0 = (struct gtp0_header *) gtp1;
	struct gtp_instance *gti;
	struct pdp_ctx *pctx;
	unsigned int min_len = sizeof(*gtp1);
	uint64_t tid;
	int rc;

	/* resolve the GTP instance to which the socket belongs */
	gti = sk_to_gti(sk);
	if (!gti)
		goto user;

	/* check for sufficient header size */
	if (!pskb_may_pull(skb, sizeof(struct udphdr) + sizeof(*gtp1)))
		goto drop_put;

	/* check for GTP Version 1 */
	if ((gtp0->flags >> 5) != 1)
		goto drop_put;

	/* FIXME: a look-up table might be faster than computing the
	 * length iteratively */

	/* sequence number present */
	if (gtp0->flags & 0x02)
		min_len += 2;

	/* N-PDU number present */
	if (gtp0->flags & 0x01)
		min_len++;

	/* next extension header type present */
	if (gtp0->flags & 0x04)
		min_len += 1;

	/* check if it is T-PDU. */
	if (gtp0->type != GTP_TPDU)
		goto drop_put;

	/* check for sufficient header size */
	if (!pskb_may_pull(skb, sizeof(struct udphdr) + min_len))
		goto drop_put;

	/* FIXME: actually take care of extension header chain */

	/* look-up the PDP context for the Tunnel ID */
	tid = ntohl(gtp1->tid);
	rcu_read_lock_bh();
	pctx = gtp1_pdp_find(gti, tid);
	if (!pctx)
		goto drop_put_rcu;

	/* get rid of the UDP and GTP header */
	__skb_pull(skb, sizeof(struct udphdr) + sizeof(*gtp1));

	/* FIXME: check if the inner IP header has the source address
	 * assigned to the current MS */

	/* re-submit via virtual tunnel device into regular network
	 * stack */
	secpath_reset(skb);
	skb_dst_drop(skb);
	nf_reset(skb);

	rc = dev_forward_skb(gti->dev, skb);

drop_put_rcu:
	rcu_read_unlock_bh();
drop_put:
	sock_put(sk);
	return 0;
user:
	return 1;
}

static struct lock_class_key gtp_eth_tx_busylock;
static int gtp_dev_init(struct net_device *dev)
{
	struct gtp_instance *gti = netdev_priv(dev);

	gti->dev = dev;
	eth_hw_addr_random(dev);
	memset(&dev->broadcast[0], 0xff, 6);
	dev->qdisc_tx_busylock = &gtp_eth_tx_busylock;

	dev->tstats = alloc_percpu(struct pcpu_tstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

static void gtp_dev_uninit(struct net_device *dev)
{
	dev_put(dev);
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

static netdev_tx_t gtp_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct gtp_instance *gti = netdev_priv(dev);
	struct pdp_ctx *pctx;
	struct pcpu_tstats *tstats;
	struct iphdr *old_iph, *iph;
	struct udphdr *uh;
	unsigned int payload_len;
	int df, mtu;
	struct rtable *rt = NULL;
	struct flowi4 fl4;
	struct net_device *tdev;

	/* XXX */
	return NETDEV_TX_OK;

	/* read the IP desination address and resolve the PDP context.
	 * Prepend PDP header with TEI/TID from PDP ctx */
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iph = ip_hdr(skb);
		rcu_read_lock_bh();
		pctx = ipv4_pdp_find(gti, iph->daddr);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr *iph6 = ipv6_hdr(skb);
		rcu_read_lock_bh();
		pctx = ipv6_pdp_find(gti, &iph6->daddr);
	} else
		return NETDEV_TX_OK;

	/* FIXME: does this include IP+UDP but not Eth header? */
	payload_len = skb->len;

	if (pctx->gtp_version == 0) {
		struct gtp0_header *gtp0;

		/* ensure there is sufficient headroom */
		skb_cow(skb, sizeof(*gtp0) + IP_UDP_LEN);
		gtp0 = (struct gtp0_header *) skb_push(skb, sizeof(*gtp0));

		gtp0->flags = 0;
		gtp0->type = GTP_TPDU;
		gtp0->length = payload_len;
		gtp0->seq = atomic_inc_return(&pctx->tx_seq) % 0xffff;
		gtp0->flow = pctx->flow;
		gtp0->number = 0xFF;
		gtp0->spare[0] = gtp0->spare[1] = gtp0->spare[2] = 0;
		gtp0->tid = pctx->tid;

	} else if (pctx->gtp_version == 1) {
		struct gtp1u_header *gtp1u;

		/* ensure there is sufficient headroom */
		skb_cow(skb, sizeof(*gtp1u) + IP_UDP_LEN);
		gtp1u = (struct gtp1u_header *) skb_push(skb, sizeof(*gtp1u));

		gtp1u->flags = (1 << 5) | 0x10; /* V1, GTP-non-prime */
		gtp1u->type = GTP_TPDU;
		gtp1u->length = payload_len;
		gtp1u->tid = pctx->tid;

	} else {
		rcu_read_unlock_bh();
		return NETDEV_TX_OK;
	}

	old_iph = ip_hdr(skb);

	/* new UDP and IP header in front of GTP header */

	skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);
	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->dst);

	/* XXX */
	rt = ip4_route_output_gtp(dev_net(dev), &fl4,
				  0, 0, 0, 0);
	/*
				  pctx->remote_u...,
				  gtpi->gtp0_addr,
				  old_iph->tos,
				  FIXME_link);

ip4_route_output_gtp(struct net *net, struct flowi4 *fl4,
		     __be32 daddr, __be32 saddr, __u8 tos, int oif)
	*/

	if (IS_ERR(rt)) {
		dev->stats.tx_carrier_errors++;
		goto tx_error;
	}
	tdev = rt->dst.dev;

	if (tdev == dev) {
		ip_rt_put(rt);
		dev->stats.collisions++;
		goto tx_error;
	}

	df = old_iph->frag_off;
	if (df)
		// XXX: tunnel->hlen: it depends on GTP0 / GTP1
		mtu = dst_mtu(&rt->dst) - dev->hard_header_len -
			sizeof(struct udphdr) - sizeof(struct gtp0_header);
	else
		mtu = skb_dst(skb) ? dst_mtu(skb_dst(skb)) : dev->mtu;

	if (skb_dst(skb))
		skb_dst(skb)->ops->update_pmtu(skb_dst(skb), NULL, skb, mtu);

	if (skb->protocol == htons(ETH_P_IP)) {
		df |= (old_iph->frag_off & htons(IP_DF));

		if ((old_iph->frag_off & htons(IP_DF)) &&
		    mtu < ntohs(old_iph->tot_len)) {
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
				  htonl(mtu));
			ip_rt_put(rt);
			goto tx_error;
		}
#if IS_ENABLED(CONFIG_IPV6)
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
//#warning FIXME implement IPv6
	}
#endif

	iph = ip_hdr(skb);
	iph->version = 4;
	iph->ihl = sizeof(struct iphdr) >> 2;
	iph->frag_off = old_iph->frag_off;
	iph->protocol = IPPROTO_UDP;
	iph->tos = old_iph->tos;
	iph->daddr = fl4.daddr;
	iph->saddr = fl4.saddr;
	iph->ttl = ip4_dst_hoplimit(&rt->dst);

	uh = udp_hdr(skb);
	if (pctx->gtp_version == 0)
		uh->source = uh->dest = GTP0_PORT;
	else
		uh->source = uh->dest = GTP1U_PORT;

	uh->len = sizeof(struct udphdr) + payload_len;

	rcu_read_unlock_bh();

	nf_reset(skb);
	tstats = this_cpu_ptr(dev->tstats);
	/* XXX update stats? */
//	__IPTUNNEL_XMIT(tstats, &dev->stats);

	return NETDEV_TX_OK;

tx_error:
	dev->stats.tx_errors++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops gtp_netdev_ops = {
	.ndo_init		= gtp_dev_init,
	.ndo_uninit		= gtp_dev_uninit,
	.ndo_start_xmit		= gtp_dev_xmit,
};

enum {
	IFLA_GTP_UNSPEC,
	IFLA_GTP_LOCAL_ADDR_IPV4,
	IFLA_GTP_LOCAL_ADDR_IPV6,
	__IFLA_GTP_MAX,
};
#define IFLA_GTP_MAX	(__IFLA_GTP_MAX - 1)

static const struct nla_policy gtp_link_policy[IFLA_GTP_MAX + 1] = {
	[IFLA_GTP_LOCAL_ADDR_IPV4] = { .len = sizeof(struct in_addr) },
	[IFLA_GTP_LOCAL_ADDR_IPV6] = { .len = sizeof(struct in6_addr) },
};

static void gtp_link_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->priv_flags		&= ~(IFF_TX_SKB_SHARING);
	dev->tx_queue_len	= 0;

	dev->netdev_ops		= &gtp_netdev_ops;
	dev->destructor		= free_netdev,

	memset(dev->broadcast, 0, ETH_ALEN);
}

static int gtp_link_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}

	if (!data)
		return 0;

	if (data[IFLA_GTP_LOCAL_ADDR_IPV4] &&
	    data[IFLA_GTP_LOCAL_ADDR_IPV6])
		return -EINVAL;

	if (data[IFLA_GTP_LOCAL_ADDR_IPV4])
		return 0;
	else if (data[IFLA_GTP_LOCAL_ADDR_IPV6])
		return 0;

	return -EINVAL;
}

static int gtp_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[])
{
	struct gtp_instance *gti = netdev_priv(dev);
	int err;

	pr_info("calling newlink gtp ...\n");

	if (!tb[IFLA_LINK])
		return -EINVAL;
	gti->dev = __dev_get_by_index(src_net, nla_get_u32(tb[IFLA_LINK]));

	if (data && data[IFLA_GTP_LOCAL_ADDR_IPV4]) {
		gti->gtp0_addr.sin_addr.s_addr =
		gti->gtp1u_addr.sin_addr.s_addr =
			nla_get_u32(data[IFLA_GTP_LOCAL_ADDR_IPV4]);
	}

	if (dev->type == ARPHRD_ETHER && !tb[IFLA_ADDRESS])
		eth_hw_addr_random(dev);

	if (!tb[IFLA_MTU])
		dev->mtu = gti->dev->mtu;
	else if (dev->mtu > gti->dev->mtu)
		return -EINVAL;

	err = register_netdevice(dev);
	if (err < 0)
		goto err1;

	list_add_rcu(&gti->list, &gtp_instance_list);

	pr_info("registered new netdev\n");

	return 0;
err1:
	pr_info("failed to register new netdev %d\n", err);
	return err;
}

static void gtp_dellink(struct net_device *dev, struct list_head *head)
{
	struct gtp_instance *gti = netdev_priv(dev);

	unregister_netdevice_queue(dev, head);
	list_del_rcu(&gti->list);
}

static int gtp_changelink(struct net_device *dev, struct nlattr *tb[],
			  struct nlattr *data[])
{
	/* FIXME: local IP address for GTP UDP sockets */
	return -EOPNOTSUPP;
}

static size_t gtp_link_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(struct in_addr)) +
	       nla_total_size(sizeof(struct in6_addr));
}

static int gtp_link_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct gtp_instance *gti = netdev_priv(dev);

	if (nla_put_u32(skb, IFLA_GTP_LOCAL_ADDR_IPV4,
			gti->gtp0_addr.sin_addr.s_addr) < 0)
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static struct rtnl_link_ops gtp_link_ops __read_mostly = {
	.kind		= "gtp",
	.maxtype	= IFLA_GTP_MAX,
	.policy		= gtp_link_policy,
	.priv_size	= sizeof(struct gtp_instance),
	.setup		= gtp_link_setup,
	.validate	= gtp_link_validate,
	.newlink	= gtp_newlink,
	.dellink	= gtp_dellink,
	.changelink	= gtp_changelink,
	.get_size	= gtp_link_get_size,
	.fill_info	= gtp_link_fill_info,
};

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
	udp_sk(sk)->encap_rcv = gtp0_udp_encap_recv;
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
	udp_sk(sk)->encap_rcv = gtp1u_udp_encap_recv;

	return 0;

out_free1:
	sock_release(gti->sock1u);
out_free0:
	sock_release(gti->sock0);
out:
	return rc;
}

static void gtp_destroy_bind_sock(struct gtp_instance *gti)
{
	sock_release(gti->sock1u);
	sock_release(gti->sock0);
}

static int ipv4_pdp_add(struct gtp_instance *gti, uint32_t sgsn_addr,
			uint32_t ms_addr, uint32_t version, uint64_t tid)
{
	uint32_t hash_ms = ipv4_hashfn(ms_addr) % gti->hash_size;
	uint32_t hash_tid = ipv4_hashfn(tid) % gti->hash_size;
	struct pdp_ctx *pctx;

	pctx = kmalloc(sizeof(struct pdp_ctx), GFP_KERNEL);
	if (pctx == NULL)
		return -ENOMEM;

	pctx->gtp_version = version;
	pctx->tid = tid;
	pctx->sgsn_addr.ip4 = sgsn_addr;
	pctx->ms_addr.ip4 = ms_addr;

	hlist_add_head_rcu(&pctx->hlist_addr, &gti->addr_hash[hash_ms]);
	hlist_add_head_rcu(&pctx->hlist_tid, &gti->tid_hash[hash_tid]);

	return 0;
}

static int gtp_tunnels;

static int gtp_genl_tunnel_new(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct net_device *dev;
	struct gtp_instance *gti;
	u32 gtp_version, link, sgsn_addr, ms_addr, tid;
	int err;

	pr_info("adding new tunnel\n");

	if (!info->attrs[GTPA_VERSION] ||
	    !info->attrs[GTPA_LINK] ||
	    !info->attrs[GTPA_SGSN_ADDRESS] ||
	    !info->attrs[GTPA_MS_ADDRESS] ||
	    !info->attrs[GTPA_TID])
		return -EINVAL;

	gtp_version = nla_get_u32(info->attrs[GTPA_VERSION]);
	link = nla_get_u32(info->attrs[GTPA_LINK]);
	sgsn_addr = nla_get_u32(info->attrs[GTPA_SGSN_ADDRESS]);
	ms_addr = nla_get_u32(info->attrs[GTPA_MS_ADDRESS]);
	tid = nla_get_u64(info->attrs[GTPA_TID]);

	pr_info("  tunnel id = %u\n", tid);

	dev = dev_get_by_index(net, nla_get_u32(info->attrs[GTPA_LINK]));
	if (dev == NULL)
		return -ENOENT;

	if (strncmp(dev->name, "gtp", 3) != 0)
		return -EOPNOTSUPP;

	gti = netdev_priv(dev);

	if (gtp_tunnels == 0) {
		int i;

		gti->addr_hash= kmalloc(sizeof(struct hlist_head) * 1024,
					 GFP_KERNEL);
		if (gti->addr_hash == NULL)
			return -ENOMEM;

		gti->tid_hash= kmalloc(sizeof(struct hlist_head) * 1024,
					 GFP_KERNEL);
		if (gti->tid_hash == NULL)
			goto err1;

		gti->hash_size = 1024;

		for (i = 0; i < 1024; i++) {
			INIT_HLIST_HEAD(&gti->addr_hash[i]);
			INIT_HLIST_HEAD(&gti->tid_hash[i]);
		}

		err = gtp_create_bind_sock(gti);
		if (err < 0)
			goto err2;
	}

	err = ipv4_pdp_add(gti, gtp_version, sgsn_addr, ms_addr, tid);
	if (err < 0)
		goto err3;

	gtp_tunnels++;
	return 0;
err3:
	gtp_destroy_bind_sock(gti);
err2:
	kfree(gti->addr_hash);
err1:
	kfree(gti->tid_hash);
	return err;
}

static int gtp_genl_tunnel_delete(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct net_device *dev;

	pr_info("deleting tunnel\n");

	if (!info->attrs[GTPA_VERSION] ||
	    !info->attrs[GTPA_LINK] ||
	    !info->attrs[GTPA_SGSN_ADDRESS] ||
	    !info->attrs[GTPA_MS_ADDRESS] ||
	    !info->attrs[GTPA_TID])
		return -EINVAL;

	dev = dev_get_by_index(net, nla_get_u32(info->attrs[GTPA_LINK]));
	if (dev == NULL)
		return -ENOENT;

	if (strncmp(dev->name, "gtp", 3) != 0)
		return -EOPNOTSUPP;

	if (--gtp_tunnels == 0)
		gtp_destroy_bind_sock(netdev_priv(dev));

	return 0;
}

static int gtp_genl_tunnel_get(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct net_device *dev;

	pr_info("get tunnel\n");

	if (!info->attrs[GTPA_VERSION] ||
	    !info->attrs[GTPA_LINK])
		return -EINVAL;

	dev = dev_get_by_index(net, nla_get_u32(info->attrs[GTPA_LINK]));
	if (dev == NULL)
		return -ENOENT;

	if (strncmp(dev->name, "gtp", 3) != 0)
		return -EOPNOTSUPP;

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
gtp_genl_fill_info(struct sk_buff *skb, uint32_t snd_portid, uint32_t snd_seq,
		   uint32_t type, struct pdp_ctx *pctx)
{
	void *genlh;

	genlh = genlmsg_put(skb, snd_portid, snd_seq, &gtp_genl_family, 0,
			    type);
	if (genlh == NULL)
		goto nlmsg_failure;

	pr_info("filling info for tunnel %llu\n", pctx->tid);

	if (nla_put_u32(skb, GTPA_VERSION, pctx->tid) ||
	    nla_put_u32(skb, GTPA_SGSN_ADDRESS, pctx->sgsn_addr.ip4) ||
	    nla_put_u32(skb, GTPA_MS_ADDRESS, pctx->ms_addr.ip4) ||
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
	int i, k = cb->args[0], tid = cb->args[1], ret;
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
			hlist_for_each_entry_rcu(pctx, &gti->addr_hash[i], hlist_tid) {
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
	pr_info("GTP module unloaded\n");
	rtnl_link_unregister(&gtp_link_ops);
	genl_unregister_family(&gtp_genl_family);
}

module_init(gtp_init);
module_exit(gtp_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Harald Welte <hwelte@sysmocom.de>");
MODULE_ALIAS_RTNL_LINK("gtp");
MODULE_ALIAS_NETDEV("gtp0");
