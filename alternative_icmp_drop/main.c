#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_icmp_odd_even(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	__u16 h_proto = bpf_ntohs(eth->h_proto);
	__u64 off = sizeof(*eth);

	// IPv4
	if (h_proto == ETH_P_IP)
	{
		struct iphdr *ip4 = (struct iphdr *)(((char *)data) + off);

		if ((void *)(ip4 + 1) >	data_end)
			return XDP_PASS;
		if (ip4->protocol != IPPROTO_ICMP)
			return XDP_PASS;

		__u32 ihl = ip4->ihl * 4;
		if (ihl < sizeof(*ip4))
			return XDP_PASS;
		if ((long)data + off + ihl > (long)data_end)
			return XDP_PASS;

		struct icmphdr *icmp = (struct icmphdr *)((char *)ip4 + ihl);
		if ((void *)(icmp + 1) > data_end)
			return XDP_PASS;

		__u16 seq;
		seq = bpf_ntohs(icmp->un.echo.sequence);
		if (seq & 1U)
			return XDP_DROP;
	}

	return XDP_PASS;
}
