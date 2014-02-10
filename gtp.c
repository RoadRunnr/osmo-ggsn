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

	bool socket_enabled;

	/* address for local UDP socket */
	struct sockaddr_in gtp0_addr;
	struct sockaddr_in gtp1u_addr;

	/* the socket */
	struct socket *sock0;
	struct socket *sock1u;

	struct net_device *dev;
	struct net_device *real_dev;

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
		pr_info("af %u : pdp->ms %pI4 == ms %pI4\n",
			pdp->af, &pdp->ms_addr.ip4, &ms_addr);
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
	struct gtp0_header *gtp0;
	struct gtp_instance *gti;
	struct pdp_ctx *pctx;
	uint64_t tid;

	pr_info("gtp0 udp received\n");

	/* resolve the GTP instance to which the socket belongs */
	gti = sk_to_gti(sk);
	if (!gti)
		goto user;

	/* UDP always verifies the packet length. */
	__skb_pull(skb, sizeof(struct udphdr));

	/* check for sufficient header size */
	if (!pskb_may_pull(skb, sizeof(*gtp0)))
		goto user_put;

	gtp0 = (struct gtp0_header *)skb->data;

	/* check for GTP Version 0 */
	if ((gtp0->flags >> 5) != 0)
		goto user_put;

	/* check if it is T-PDU. if not -> userspace */
	if (gtp0->type != GTP_TPDU)
		goto user_put;

	/* look-up the PDP context for the Tunnel ID */
	tid = be64_to_cpu(gtp0->tid);

	rcu_read_lock_bh();
	pctx = gtp0_pdp_find(gti, tid);
	if (!pctx)
		goto user_put_rcu;

	/* get rid of the GTP header */
	__skb_pull(skb, sizeof(*gtp0));

	skb_reset_network_header(skb);

	/* We're about to requeue the skb, so return resources
	 * to its current owner (a socket receive buffer).
	 */
	skb_orphan(skb);

	/* FIXME: check if the inner IP header has the source address
	 * assigned to the current MS */

	/* re-submit via virtual tunnel device into regular network
	 * stack */
	secpath_reset(skb);
	skb_dst_drop(skb);
	nf_reset(skb);

	skb->dev = gti->dev;

	/* Force the upper layers to verify it. */
	skb->ip_summed = CHECKSUM_NONE;

	netif_rx(skb);

	rcu_read_unlock_bh();
	sock_put(sk);

	return 0;

user_put_rcu:
	rcu_read_unlock_bh();
user_put:
	sock_put(sk);
user:
	return 1;
}

/* UDP encapsulation receive handler. See net/ipv4/udp.c.
 * Return codes: 0: succes, <0: error, >0: passed up to userspace UDP */
static int gtp1u_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct gtp1_header_short *gtp1;
	struct gtp0_header *gtp0;
	struct gtp_instance *gti;
	struct pdp_ctx *pctx;
	unsigned int min_len = sizeof(*gtp1);
	uint64_t tid;

	pr_info("gtp1 udp received\n");

	/* resolve the GTP instance to which the socket belongs */
	gti = sk_to_gti(sk);
	if (!gti)
		goto user;

	/* UDP always verifies the packet length. */
	__skb_pull(skb, sizeof(struct udphdr));

	/* check for sufficient header size */
	if (!pskb_may_pull(skb, sizeof(*gtp1)))
		goto user_put;

	gtp1 = (struct gtp1_header_short *)skb->data;
	gtp0 = (struct gtp0_header *)gtp1;

	/* check for GTP Version 1 */
	if ((gtp0->flags >> 5) != 1)
		goto user_put;

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
		goto user_put;

	/* check for sufficient header size */
	if (!pskb_may_pull(skb, sizeof(struct udphdr) + min_len))
		goto user_put;

	/* FIXME: actually take care of extension header chain */

	/* look-up the PDP context for the Tunnel ID */
	tid = ntohl(gtp1->tid);
	rcu_read_lock_bh();
	pctx = gtp1_pdp_find(gti, tid);
	if (!pctx)
		goto user_put_rcu;

	/* get rid of the GTP header */
	__skb_pull(skb, sizeof(*gtp1));

	skb_reset_network_header(skb);

	/* FIXME: check if the inner IP header has the source address
	 * assigned to the current MS */

	/* We're about to requeue the skb, so return resources
	 * to its current owner (a socket receive buffer).
	 */
	skb_orphan(skb);

	/* re-submit via virtual tunnel device into regular network
	 * stack */
	secpath_reset(skb);
	skb_dst_drop(skb);
	nf_reset(skb);

	skb->dev = gti->dev;

	/* Force the upper layers to verify it. */
	skb->ip_summed = CHECKSUM_NONE;

	netif_rx(skb);
	rcu_read_unlock_bh();
	sock_put(sk);

	return 0;

user_put_rcu:
	rcu_read_unlock_bh();
user_put:
	sock_put(sk);
user:
	return 1;
}

static struct lock_class_key gtp_eth_tx_busylock;
static int gtp_dev_init(struct net_device *dev)
{
	struct gtp_instance *gti = netdev_priv(dev);

	dev->flags              = IFF_NOARP;
	gti->dev = dev;
	dev->qdisc_tx_busylock = &gtp_eth_tx_busylock;

	dev->tstats = alloc_percpu(struct pcpu_tstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
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
	gtp0->seq = htons(atomic_inc_return(&pctx->tx_seq) % 0xffff);
	gtp0->flow = htonl(pctx->flow);
	gtp0->number = 0xFF;
	gtp0->spare[0] = gtp0->spare[1] = gtp0->spare[2] = 0xFF;
	gtp0->tid = cpu_to_be64(pctx->tid);
}

static inline void
gtp1u_push_header(struct sk_buff *skb, struct pdp_ctx *pctx, int payload_len)
{
	struct gtp1u_header *gtp1u;

	/* ensure there is sufficient headroom */
	skb_cow(skb, sizeof(*gtp1u) + IP_UDP_LEN);
	gtp1u = (struct gtp1u_header *) skb_push(skb, sizeof(*gtp1u));

	gtp1u->flags = 0x10; /* V1, GTP-non-prime */
	gtp1u->type = GTP_TPDU;
	gtp1u->length = htons(payload_len);
	gtp1u->tid = htonl((u32)pctx->tid);
}

static netdev_tx_t gtp_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct gtp_instance *gti = netdev_priv(dev);
	struct pdp_ctx *pctx = NULL;
	struct pcpu_tstats *tstats;
	struct iphdr *old_iph, *iph;
	struct udphdr *uh;
	unsigned int payload_len;
	int df, mtu, err;
	struct rtable *rt = NULL;
	struct flowi4 fl4;
	struct net_device *tdev;
	struct inet_sock *inet;

	/* UDP socket not initialized, skip */
	if (!gti->sock0) {
		pr_info("xmit: no socket / need cfg, skipping\n");
		return NETDEV_TX_OK;
	}

	inet = inet_sk(gti->sock0->sk);

	/* read the IP desination address and resolve the PDP context.
	 * Prepend PDP header with TEI/TID from PDP ctx */
	rcu_read_lock_bh();
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iph = ip_hdr(skb);
		pctx = ipv4_pdp_find(gti, iph->daddr);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr *iph6 = ipv6_hdr(skb);
		pctx = ipv6_pdp_find(gti, &iph6->daddr);
	}

	if (!pctx) {
		rcu_read_unlock_bh();
		pr_info("no pdp ctx found, skipping\n");
		return NETDEV_TX_OK;
	}

	pr_info("found pdp ctx %p\n", pctx);

	/* Obtain route for the new encapsulated GTP packet */
	rt = ip4_route_output_gtp(dev_net(dev), &fl4, pctx->sgsn_addr.ip4,
				  inet->inet_saddr, 0,
				  gti->real_dev->ifindex);
	if (IS_ERR(rt)) {
		pr_info("no rt found, skipping\n");
		dev->stats.tx_carrier_errors++;
		goto tx_error;
	}
	tdev = rt->dst.dev;

	/* There is a routing loop */
	if (tdev == dev) {
		pr_info("rt loop, skipping\n");
		ip_rt_put(rt);
		dev->stats.collisions++;
		goto tx_error;
	}

	payload_len = skb->len;

	/* Pushing GTP header */
	pr_info("pushing gtp header\n");
	switch (pctx->gtp_version) {
	case GTP_V0:
		gtp0_push_header(skb, pctx, payload_len);
		break;
	case GTP_V1:
		gtp1u_push_header(skb, pctx, payload_len);
		break;
	default:
		/* Should not happen */
		goto out;
	}

	old_iph = ip_hdr(skb);

	pr_info("pushing UDP/IP header\n");
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

	pr_info("gtp -> IP src: %pI4 dst: %pI4\n", &iph->saddr, &iph->daddr);

	uh = udp_hdr(skb);
	if (pctx->gtp_version == 0)
		uh->source = uh->dest = htons(GTP0_PORT);
	else
		uh->source = uh->dest = htons(GTP1U_PORT);

	uh->len = htons(sizeof(struct udphdr) + payload_len);
	uh->check = 0;

	pr_info("gtp -> UDP src: %u dst: %u (len %u)\n",
		ntohs(uh->source), ntohs(uh->dest), ntohs(uh->len));

	rcu_read_unlock_bh();

	nf_reset(skb);
	/* XXX update stats? */
	tstats = this_cpu_ptr(dev->tstats);

	err = ip_local_out(skb);
	if (unlikely(net_xmit_eval(err)))
		pr_info("error in ip_local_out\n");

	return NETDEV_TX_OK;
out:
	rcu_read_unlock_bh();
	return NETDEV_TX_OK;
tx_error:
	rcu_read_unlock_bh();
	pr_info("no route to reach destination\n");
	dev->stats.tx_errors++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops gtp_netdev_ops = {
	.ndo_init		= gtp_dev_init,
	.ndo_start_xmit		= gtp_dev_xmit,
};

static void gtp_link_setup(struct net_device *dev)
{
	dev->priv_flags		&= ~(IFF_TX_SKB_SHARING);
	dev->tx_queue_len	= 0;

	dev->netdev_ops		= &gtp_netdev_ops;
	dev->destructor		= free_netdev;
}

static int gtp_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[])
{
	struct net_device *real_dev;
	struct gtp_instance *gti;
	int err;

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

	err = register_netdevice(dev);
	if (err < 0)
		goto err1;

	list_add_rcu(&gti->list, &gtp_instance_list);

	pr_info("registered new %s interface\n", dev->name);

	return 0;
err1:
	pr_info("failed to register new netdev %d\n", err);
	return err;
}

static void gtp_dellink(struct net_device *dev, struct list_head *head)
{
	struct gtp_instance *gti = netdev_priv(dev);

	dev_put(gti->real_dev);
	list_del_rcu(&gti->list);
	unregister_netdevice_queue(dev, head);
}

static struct rtnl_link_ops gtp_link_ops __read_mostly = {
	.kind		= "gtp",
	.priv_size	= sizeof(struct gtp_instance),
	.setup		= gtp_link_setup,
	.newlink	= gtp_newlink,
	.dellink	= gtp_dellink,
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
	/* XXX release tunnels in the hashes*/
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
	udp_sk(sk)->encap_rcv = gtp0_udp_encap_recv;
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
	udp_sk(sk)->encap_rcv = gtp1u_udp_encap_recv;
	sk->sk_user_data = gti;

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

/* This configuration routine sets up the hashtable and it links the UDP
 * socket to the device.
 */
static int gtp_genl_cfg_new(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	struct gtp_instance *gti;
	int err;

	if (!info->attrs[GTPA_LINK])
		return -EINVAL;

	/* Check if there's an existing gtpX device to configure */
	dev = gtp_find_dev(nla_get_u32(info->attrs[GTPA_CFG_LINK]));
	if (dev == NULL)
		return -ENODEV;

	gti = netdev_priv(dev);

	/* Create the UDP socket if needed */
	if (info->nlhdr->nlmsg_flags & NLM_F_CREATE) {
		if (gti->socket_enabled)
			return -EBUSY;

		if (!info->attrs[GTPA_CFG_LOCAL_ADDR_IPV4])
			return -EINVAL;

		gti->gtp0_addr.sin_addr.s_addr =
		gti->gtp1u_addr.sin_addr.s_addr =
			nla_get_u32(info->attrs[GTPA_CFG_LOCAL_ADDR_IPV4]);

		/* XXX fix hardcoded hashtable size */
		err = gtp_hashtable_new(gti, 1024);
		if (err < 0)
			return err;

		err = gtp_create_bind_sock(gti);
		if (err < 0)
			goto err1;

		gti->socket_enabled = true;
	} else {
		/* XXX configuration updates not yet supported */
		return -EOPNOTSUPP;
	}

	return 0;
err1:
	gtp_hashtable_free(gti);
	return err;
}

static int gtp_genl_cfg_get(struct sk_buff *skb, struct genl_info *info)
{
	/* XXX */
	return 0;
}

static int gtp_genl_cfg_delete(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	struct gtp_instance *gti;

	if (!info->attrs[GTPA_LINK])
		return -EINVAL;

	/* Check if there's an existing gtpX device to configure */
	dev = gtp_find_dev(nla_get_u32(info->attrs[GTPA_CFG_LINK]));
	if (dev == NULL)
		return -ENODEV;

	gti = netdev_priv(dev);
	gtp_destroy_bind_sock(gti);
	gtp_hashtable_free(gti);

	return 0;
}

static int ipv4_pdp_add(struct gtp_instance *gti, struct genl_info *info)
{
	uint32_t hash_ms;
	uint32_t hash_tid;
	struct pdp_ctx *pctx;
	u32 gtp_version, link, sgsn_addr, ms_addr, tid;
	bool found = false;

	gtp_version = nla_get_u32(info->attrs[GTPA_VERSION]);
	link = nla_get_u32(info->attrs[GTPA_LINK]);
	sgsn_addr = nla_get_u32(info->attrs[GTPA_SGSN_ADDRESS]);
	ms_addr = nla_get_u32(info->attrs[GTPA_MS_ADDRESS]);
	tid = nla_get_u64(info->attrs[GTPA_TID]);

	hash_ms = ipv4_hashfn(ms_addr) % gti->hash_size;

	hlist_for_each_entry_rcu(pctx, &gti->addr_hash[hash_ms], hlist_addr) {
		if (pctx->ms_addr.ip4 == ms_addr) {
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
		pctx->sgsn_addr.ip4 = sgsn_addr;
		pctx->ms_addr.ip4 = ms_addr;

		pr_info("update tunnel id = %u (pdp %p)\n", tid, pctx);

		return 0;
	}

	pctx = kmalloc(sizeof(struct pdp_ctx), GFP_KERNEL);
	if (pctx == NULL)
		return -ENOMEM;

	pctx->af = AF_INET;
	pctx->gtp_version = gtp_version;
	pctx->tid = tid;
	pctx->sgsn_addr.ip4 = sgsn_addr;
	pctx->ms_addr.ip4 = ms_addr;

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

	if (!gti->socket_enabled)
		return -ENETDOWN;

	return ipv4_pdp_add(gti, info);
}

static int gtp_genl_tunnel_delete(struct sk_buff *skb, struct genl_info *info)
{
	struct gtp_instance *gti;
	struct net_device *dev;

	pr_info("deleting tunnel\n");

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

	/* XXX not yet implemented */

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
		.cmd = GTP_CMD_CFG_NEW,
		.doit = gtp_genl_cfg_new,
		.policy = gtp_genl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = GTP_CMD_CFG_DELETE,
		.doit = gtp_genl_cfg_delete,
		.policy = gtp_genl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = GTP_CMD_CFG_GET,
		.doit = gtp_genl_cfg_get,
		.policy = gtp_genl_policy,
		.flags = GENL_ADMIN_PERM,
	},
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
	struct gtp_instance *gti;

	list_for_each_entry_rcu(gti, &gtp_instance_list, list) {
		pr_info("delete instance gtp %p\n", gti);
		gtp_destroy_bind_sock(gti);
		gtp_hashtable_free(gti);
	}
	rtnl_link_unregister(&gtp_link_ops);
	genl_unregister_family(&gtp_genl_family);

	pr_info("GTP module unloaded\n");
}

module_init(gtp_init);
module_exit(gtp_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Harald Welte <hwelte@sysmocom.de>");
MODULE_ALIAS_RTNL_LINK("gtp");
MODULE_ALIAS_NETDEV("gtp0");
