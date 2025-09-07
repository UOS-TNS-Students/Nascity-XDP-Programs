#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

char LICENSE[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") proto_cnt = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = (__u32)0xFFFF
};

static int get_proto_ipv4(void *data, __u64 offset, void *data_end)
{
	struct iphdr *ip = data + offset;

	if ((__u64)(ip + 1) > (__u64)data_end) // not (__u64)ip + 1!!
		return 0;
	return ip->protocol;
}

static int __always_inline get_proto_ipv6(void *data, __u64 offset, void *data_end)
{
	struct ipv6hdr *ip = data + offset;

	if ((__u64)(ip + 1) > (__u64)data_end)
		return 0;
	return ip->nexthdr;
}

SEC("xdp")
int proto_counter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int ret = XDP_PASS;

	struct ethhdr *eth = data;
	__u64 offset;
	__u16 h_proto;
	__u32 ipproto;

	__u64 *value;

	offset = sizeof(*eth);
	if ((__u64)data + offset > (__u64)data_end)
		return ret;
	h_proto = eth->h_proto;

	if (h_proto == bpf_htons(ETH_P_IP))
		ipproto = get_proto_ipv4(data, offset, data_end);
	else if (h_proto == bpf_htons(ETH_P_IPV6))
		ipproto = get_proto_ipv6(data, offset, data_end);
	else
		ipproto = 0;

	value = bpf_map_lookup_elem(&proto_cnt, &ipproto);
	if (value)
		*value += 1;
	else
	{
		__u64 val = 1;
		bpf_map_update_elem(&proto_cnt, &ipproto, &val, BPF_NOEXIST);
	}

	return ret;
}
