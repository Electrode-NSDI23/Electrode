/*
 *  Software Name : bmc-cache
 *  SPDX-FileCopyrightText: Copyright (c) 2021 Orange
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 *  This software is distributed under the
 *  GNU Lesser General Public License v2.1 only.
 *
 *  Author: Yoann GHIGOFF <yoann.ghigoff@orange.com> et al.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "linux/tools/lib/bpf/bpf_helpers.h"

#include "fast_common.h"


#define ADJUST_HEAD_LEN 128
#define MTU 1500
#define MAX_DATA_LEN 64
#define REQ_MAX_DATA_LEN 128

/*
 function calls are not allowed while holding a lock....
 Cause Paxos is in fact a serialized protocol, we limit our to one-core, then no lock is needed.
 */

/* program maps */
struct bpf_map_def SEC("maps") map_progs_xdp = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = FAST_PROG_XDP_MAX,
};
struct bpf_map_def SEC("maps") map_progs_tc = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = FAST_PROG_TC_MAX,
};

struct bpf_map_def SEC("maps") map_configure = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct paxos_configure),
	.max_entries = FAST_REPLICA_MAX,
};

// control state, only changes in user-space(except lastOp).
struct paxos_ctr_state {
	enum ReplicaStatus state; // asd123www: maybe we don't need it...
	int myIdx, leaderIdx, batchSize; // it's easier to maintain in user-space.
	__u64 view, lastOp;
};
struct bpf_map_def SEC("maps") map_ctr_state = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct paxos_ctr_state),
	.max_entries = 1,
};
struct bpf_map_def SEC("maps") map_msg_lastOp = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
};


struct paxos_quorum {
	__u32 view, opnum, bitset;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct paxos_quorum);
	__uint(max_entries, QUORUM_BITSET_ENTRY);
} map_quorum SEC(".maps");



struct paxos_batch {
	__u32 counter;
	struct bpf_spin_lock lock;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct paxos_batch);
	__uint(max_entries, 1);
} batch_context SEC(".maps");


struct bpf_map_def SEC("maps") map_prepare_buffer = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1<<20,
};
struct bpf_map_def SEC("maps") map_request_buffer = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1<<20,
};


static inline __u16 compute_ip_checksum(struct iphdr *ip) {
    __u32 csum = 0;
    __u16 *next_ip_u16 = (__u16 *)ip;

    ip->check = 0;
#pragma clang loop unroll(full)
    for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
        csum += *next_ip_u16++;
    }

	return ~((csum & 0xffff) + (csum >> 16));
}

static inline int compute_message_type(char *payload, void *data_end) {
	if (payload + PREPARE_TYPE_LEN < data_end &&
		payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'P' &&
	 	payload[20] == 'r' && payload[21] =='e' && payload[22] =='p' && 
	 	payload[23] =='a' && payload[24] =='r' && payload[25] =='e' && payload[26] =='M') {
			// PrepareMessage in `vr`.
		return FAST_PROG_XDP_HANDLE_PREPARE;
	} else if (payload + REQUEST_TYPE_LEN < data_end && 
		payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'R' && 
		payload[20] == 'e' && payload[21] =='q' && payload[22] =='u' && 
	 	payload[23] =='e' && payload[24] =='s' && payload[25] =='t' && payload[26] =='M') {
			// Request message in `vr`.
		return FAST_PROG_XDP_HANDLE_REQUEST;
	} else if (payload + PREPAREOK_TYPE_LEN < data_end &&
		payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'P' &&
	 	payload[20] == 'r' && payload[21] =='e' && payload[22] =='p' && 
	 	payload[23] =='a' && payload[24] =='r' && payload[25] =='e' && payload[26] =='O') {
			// PrepareOK message in `vr`.
		return FAST_PROG_XDP_HANDLE_PREPAREOK;
	} else if (payload + MYPREPAREOK_TYPE_LEN < data_end &&
		payload[10] == 'v' && payload[11] == 'r' && payload[13] == 'M' &&
	 	payload[14] == 'y' && payload[15] =='P' && payload[16] =='r') {
			// MyPrepareOK message in `vr`.
		return FAST_PROG_XDP_HANDLE_PREPAREOK;
	}
	return -1;
}

SEC("fastPaxos")
int fastPaxos_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS; // boundary check.
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS; // check it's udp packet.
	if (udp + 1 > data_end) return XDP_PASS; // boundary check.
	if (udp -> dest != htons(12345)) return XDP_PASS; // port check, our process bound to 12345.
	if (payload + MAGIC_LEN > data_end) return XDP_PASS; // don't have magic bits...
	// asd123www: currently, we don't support reassembly.
	if (payload[0] != 0x18 || payload[1] != 0x03 || payload[2] != 0x05 || payload[3] != 0x20) return XDP_PASS;
	payload = payload + MAGIC_LEN;
	if (payload + sizeof(__u64) > data_end) return XDP_PASS; // don't have typelen...

	__u64 typeLen = *(__u64 *)payload;
	payload = payload + sizeof(__u64);
	if (typeLen >= MTU || payload + typeLen > data_end) return XDP_PASS; // don't have type str...
	
	__u32 zero = 0;

#ifdef FAST_REPLY
	if (payload + PREPARE_TYPE_LEN < data_end &&
		payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'P' &&
	 	payload[20] == 'r' && payload[21] =='e' && payload[22] =='p' && 
	 	payload[23] =='a' && payload[24] =='r' && payload[25] =='e' && payload[26] =='M') {
			// PrepareMessage in `vr`.
		bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_HANDLE_PREPARE);
		return XDP_PASS;
	}
#endif

#ifdef FAST_QUORUM_PRUNE
	if (payload + PREPAREOK_TYPE_LEN < data_end &&
		payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'P' &&
	 	payload[20] == 'r' && payload[21] =='e' && payload[22] =='p' && 
	 	payload[23] =='a' && payload[24] =='r' && payload[25] =='e' && payload[26] =='O') {
			// PrepareOK message in `vr`.
		__u64 *context = bpf_map_lookup_elem(&map_msg_lastOp, &zero);
		if (context) {
			*context = (void *)payload + typeLen - data;
			bpf_xdp_adjust_head(ctx, *context);
			bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_HANDLE_PREPAREOK);
		}
		return XDP_PASS;
	}
	if (payload + MYPREPAREOK_TYPE_LEN < data_end &&
		payload[10] == 'v' && payload[11] == 'r' && payload[13] == 'M' &&
	 	payload[14] == 'y' && payload[15] =='P' && payload[16] =='r') {
			// MyPrepareOK message in `vr`.
		__u64 *context = bpf_map_lookup_elem(&map_msg_lastOp, &zero);
		if (context) {
			*context = (void *)payload + typeLen - data;
			bpf_xdp_adjust_head(ctx, *context);
			bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_HANDLE_PREPAREOK);
		}
		return XDP_PASS;
	}
#endif

	/* Optimization for adaptive batching, ignore.
	else if (payload + REQUEST_TYPE_LEN < data_end && 
		payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'R' && 
		payload[20] == 'e' && payload[21] =='q' && payload[22] =='u' && 
	 	payload[23] =='e' && payload[24] =='s' && payload[25] =='t' && payload[26] =='M') {
			// Request message in `vr`.
		bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_HANDLE_REQUEST);
	} */
	return XDP_PASS;
}

// This function will not be called, ignore.
SEC("HandleRequest")
int HandleRequest_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (payload + MAGIC_LEN + sizeof(__u64) + REQUEST_TYPE_LEN + FAST_PAXOS_DATA_LEN > data_end) return XDP_PASS;
	payload += MAGIC_LEN + sizeof(__u64) + REQUEST_TYPE_LEN + FAST_PAXOS_DATA_LEN; // point to our extra_data.

	// stateless, therefore we only have to maintain batching thing.
	__u32 zero = 0;
	struct paxos_batch *context = bpf_map_lookup_elem(&batch_context, &zero);
	struct paxos_ctr_state *ctr_state = bpf_map_lookup_elem(&map_ctr_state, &zero);
	if (!context || !ctr_state) return XDP_PASS;

	__u32 num = 0;
	bpf_spin_lock(&context -> lock);
	context -> counter = (context -> counter + 1) % ctr_state -> batchSize;
	num = context -> counter;
	bpf_spin_unlock(&context -> lock);
	
	if (num == 0) return XDP_PASS; // reach batchSize, notice user-space.
	if (payload + REQ_MAX_DATA_LEN < data_end) return XDP_PASS;

	char *pt = bpf_ringbuf_reserve(&map_request_buffer, REQ_MAX_DATA_LEN + sizeof(__u16) + sizeof(__u32), 0);
	if (pt) {
		*(__u16 *)pt = udp -> source;
		pt += sizeof(__u16);
		*(__u32 *)pt = ip -> saddr;
		pt += sizeof(__u32);

		for (int i = 0; i < REQ_MAX_DATA_LEN; ++i) 
			if (payload + i + 1 <= data_end) pt[i] = payload[i];
		bpf_ringbuf_submit(pt - sizeof(__u16) - sizeof(__u32), 0);
	}
	return XDP_DROP;
}

SEC("HandlePrepareOK")
int HandlePrepareOK_main(struct xdp_md *ctx) {
	// now data points to `fastPaxos header`.
	// we should parse this.
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	if (data + FAST_PAXOS_DATA_LEN > data_end) return XDP_DROP;
	__u32 msg_view = *((__u32*)data + 0);
	__u32 msg_opnum = *((__u32*)data + 1);
	__u32 msg_replicaIdx = *((__u32*)data + 2);
	__u32 idx = msg_opnum & (QUORUM_BITSET_ENTRY - 1);
	struct paxos_quorum *entry = bpf_map_lookup_elem(&map_quorum, &idx);
	if (!entry) return XDP_PASS;


	__u32 count = 0;
	if (entry -> view != msg_view || entry -> opnum != msg_opnum) return XDP_PASS;
	
	entry -> bitset |= 1 << msg_replicaIdx;
	count = __builtin_popcount(entry -> bitset);

	if (count != QUORUM_SIZE - 1) return XDP_DROP; // ignore PrepareOK that will not affect consensus.
	// asd123www: may change buffering here in the future.
	__u32 zero = 0;
	__u64 *context = bpf_map_lookup_elem(&map_msg_lastOp, &zero);
	if (context) bpf_xdp_adjust_head(ctx, -((int)*context));
	return XDP_PASS;
}

SEC("HandlePrepare")
int HandlePrepare_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	// parsing message's info.
	if (payload + MAGIC_LEN + sizeof(__u64) + PREPARE_TYPE_LEN + FAST_PAXOS_DATA_LEN > data_end) return XDP_PASS;
	payload += MAGIC_LEN + sizeof(__u64) + PREPARE_TYPE_LEN; // point to our extra_data.
	__u64 msg_view = *((__u32*)payload + 0);
	__u64 msg_lastOp = *((__u32*)payload + 1);
	__u64 msg_batchStart = *((__u32*)payload + 2);
	payload += 3 * sizeof(__u32);

	__u32 zero = 0;
	__u64 *context = bpf_map_lookup_elem(&map_msg_lastOp, &zero);
	struct paxos_ctr_state *ctr_state = bpf_map_lookup_elem(&map_ctr_state, &zero);
	if (!context || !ctr_state) return XDP_PASS; // can't find the context...

	// asd123www: rare case, not handled properly now.
	if (ctr_state -> state != STATUS_NORMAL) return XDP_DROP;
	if (msg_view < ctr_state -> view) return XDP_DROP; // hear a stale  message, we shouldn't respond to that.
	if (msg_view > ctr_state -> view) return XDP_PASS; // view change... offload to user-space.

	// Resend the prepareOK message
	if (msg_lastOp <= ctr_state -> lastOp) {
		bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_PREPARE_REPLY);
		return XDP_PASS;
	}
	// rare case, to user-space.
	// asd123www: actually there is a buffering thing...
	if (msg_batchStart > ctr_state -> lastOp + 1) return XDP_PASS;

	*context = msg_lastOp;
	ctr_state -> lastOp = msg_lastOp;
	bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_WRITE_BUFFER);
	return XDP_PASS;
}

// currently we don't support reassembly, modify this in future if we want.
SEC("WriteBuffer")
int WriteBuffer_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 
					MAGIC_LEN + sizeof(__u64) + PREPARE_TYPE_LEN + FAST_PAXOS_DATA_LEN; // points to .proto message.
	if (payload >= data_end) return XDP_PASS;
	if (payload + MAX_DATA_LEN < data_end) return XDP_PASS;

	// buffer not enough, offload to user-space.
	// It's easy to avoid cause VR sends `CommitMessage` make followers keep up with the leader.
	char *pt = bpf_ringbuf_reserve(&map_prepare_buffer, MAX_DATA_LEN, 0);
	if (pt) {
		for (int i = 0; i < MAX_DATA_LEN; ++i) 
			if (payload + i + 1 <= data_end) pt[i] = payload[i];
		bpf_ringbuf_submit(pt, 0); // guarantee to succeed.
		bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_PREPARE_REPLY);
	}
	return XDP_PASS;
}


SEC("PrepareFastReply")
int PrepareFastReply_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (payload + MAGIC_LEN + sizeof(__u64) + PREPARE_TYPE_LEN + FAST_PAXOS_DATA_LEN + sizeof(__u64) >= data_end) return XDP_PASS;	
	
	// read our state.
	__u32 zero = 0;
	__u64 *msg_lastOp = bpf_map_lookup_elem(&map_msg_lastOp, &zero);
	struct paxos_ctr_state *ctr_state = bpf_map_lookup_elem(&map_ctr_state, &zero);
	if (!msg_lastOp || !ctr_state) return XDP_PASS; // can't find the context...

	struct paxos_configure *leaderInfo = bpf_map_lookup_elem(&map_configure, &ctr_state -> leaderIdx);
	if (!leaderInfo) return XDP_PASS;

	// do reply.
	*(__u32 *)payload = NONFRAG_MAGIC;
	payload += sizeof(__u32);
	*(__u64 *)payload = MYPREPAREOK_TYPE_LEN;
	payload += sizeof(__u64); 
	// change "specpaxos.vr.proto.PrepareMessage" to "specpaxos.vr.MyPrepareOK"
	payload[13] = 'M', payload[14] = 'y', payload[15] = 'P', payload[16] = 'r',
	payload[17] = 'e', payload[18] = 'p', payload[19] = 'a', payload[20] = 'r',
	payload[21] = 'e', payload[22] = 'O', payload[23] = 'K';
	payload += MYPREPAREOK_TYPE_LEN;

	*(__u32 *)payload = ctr_state -> view; // must equal to message.
	*((__u32 *)payload + 1) = *msg_lastOp; // must equal to message.
	*((__u32 *)payload + 2) = ctr_state -> myIdx; // our's may advance.
	payload += FAST_PAXOS_DATA_LEN;
	if (payload + sizeof(__u64) * 3 + sizeof(__u32) > data_end) {
		// asd123www: wrong!!!
		// make sure message length is big enough!
		return XDP_PASS;
	}
	*(__u64 *)payload = sizeof(__u64) * 2 + sizeof(__u32);
	*((__u64 *)payload + 1) = ctr_state -> view; // must equal to message.
	*((__u64 *)payload + 2) = *msg_lastOp; // our's may advance.
	payload += sizeof(__u64) * 3;
	*(__u32 *)payload = ctr_state -> myIdx;
	payload += sizeof(__u32);

	udp -> source = udp -> dest;
	udp -> dest = leaderInfo -> port;
	udp -> len = htons(payload - (char *)udp); // calc length.
	udp -> check = 0; // computing udp checksum is not required

	ip -> tot_len = htons(payload - (char *)udp + sizeof(struct iphdr));
	ip -> saddr = ip -> daddr;
	ip -> daddr = leaderInfo -> addr;
	ip -> check = compute_ip_checksum(ip);

	unsigned char tmp_mac[ETH_ALEN];
	memcpy(tmp_mac, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

	bpf_xdp_adjust_tail(ctx, (void *)payload - data_end);
	return XDP_TX;
}


SEC("FastBroadCast")
int FastBroadCast_main(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
	
	if (ip + 1 > data_end) return TC_ACT_OK;
	if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;
	if (udp + 1 > data_end) return TC_ACT_OK;
	if (udp -> source != htons(12345)) return TC_ACT_OK; // not Paxos packet.

	if (payload + MAGIC_LEN > data_end) return TC_ACT_OK; // don't have magic bits...
	if (payload[0] != 0x18 || payload[1] != 0x03 || payload[2] != 0x05 || payload[3] != 0x20) return TC_ACT_OK;
	payload = payload + MAGIC_LEN;
	if (payload + sizeof(__u64) > data_end) return TC_ACT_OK; // don't have typelen...
	__u64 typeLen = *(__u64 *)payload;
	payload = payload + sizeof(__u64);
	char *type_str = payload;
	if (type_str + 5 >= data_end) return TC_ACT_OK;
	if (typeLen >= MTU || payload + typeLen > data_end) return TC_ACT_OK; // don't have type str...
	payload += typeLen;
	if (payload + FAST_PAXOS_DATA_LEN > data_end) return TC_ACT_OK;

	__u32 msg_view = *(__u32*)payload;
	__u32 is_broadcast = msg_view & BROADCAST_SIGN_BIT;
	msg_view ^= is_broadcast;
	__u32 msg_lastOp = *((__u32*)payload + 1);
	int msg_type = compute_message_type(type_str, data_end);

	if (msg_type == FAST_PROG_XDP_HANDLE_PREPARE) { // clear bitset entry.
		__u32 idx = msg_lastOp & (QUORUM_BITSET_ENTRY - 1);
		struct paxos_quorum *entry = bpf_map_lookup_elem(&map_quorum, &idx);
		if (entry) {
			if (entry -> view != msg_view || entry -> opnum != msg_lastOp) {
				entry -> view = msg_view;
				entry -> opnum = msg_lastOp;
				entry -> bitset = 0;
			}
		}
	}

	if (!is_broadcast) return TC_ACT_OK;

	__u32 zero = 0;
	struct paxos_ctr_state *ctr_state = bpf_map_lookup_elem(&map_ctr_state, &zero);
	if (!ctr_state) return TC_ACT_OK; // can't find the context...

	char id, nxt;
	if (type_str[0] == 's' && type_str[1] == 'p') {
		id = !ctr_state -> leaderIdx;

		nxt = id + 1;
		nxt += ctr_state -> leaderIdx == nxt;
		type_str[0] = nxt;
		type_str[1] = 'M'; // sign for multicast.
		if (nxt < CLUSTER_SIZE) bpf_clone_redirect(skb, skb -> ifindex, 0);
	} else {
		id = type_str[0];

		nxt = id + 1;
		nxt += ctr_state -> leaderIdx == nxt;
		type_str[0] = nxt;
		if (nxt < CLUSTER_SIZE) bpf_clone_redirect(skb, skb -> ifindex, 0);
	}

	// Why so verbose? `bpf_clone_redirect` may change buffer — from linux manual.
	data_end = (void *)(long)skb->data_end;
	data     = (void *)(long)skb->data;
	eth = data;
	ip = data + sizeof(struct ethhdr);
	udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + MAGIC_LEN;
	if (payload + sizeof(__u64) > data_end) return TC_ACT_OK; // don't have typelen...
	typeLen = *(__u64 *)payload;
	payload = payload + sizeof(__u64);
	type_str = payload;
	if (type_str + 5 >= data_end) return TC_ACT_SHOT;
	if (typeLen >= MTU || payload + typeLen > data_end) return TC_ACT_SHOT; // don't have type str...
	payload += typeLen;
	if (payload + FAST_PAXOS_DATA_LEN > data_end) return TC_ACT_SHOT;

	*(__u32*)payload = msg_view;
	type_str[0] = 's', type_str[1] = 'p';
	struct paxos_configure *replicaInfo = bpf_map_lookup_elem(&map_configure, &id);
	if (!replicaInfo) return TC_ACT_SHOT;
	udp -> dest = replicaInfo -> port;
	udp -> check = 0;
	ip -> daddr = replicaInfo -> addr;
	ip -> check = compute_ip_checksum(ip);
	memcpy(eth -> h_dest, replicaInfo -> eth, ETH_ALEN);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
