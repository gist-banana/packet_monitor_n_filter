#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

BPF_TABLE(MAPTYPE, uint32_t, long, dropcnt, 256);
BPF_ARRAY(hash_addr, u64,2);

// iphdr value : tos(o) / tot_len(o) / id(o) / frag_off(o) / ttl(o) / protocol(o) / check(o) / saddr / daddr

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

static inline int saddr_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
	return 0;
    return iph -> saddr;
}

static inline int tos_ipv4(void *data, u64 nh_off, void *data_end) {
	struct iphdr *iph = data + nh_off;

	if ((void*)&iph[1] > data_end)
		return 0;
	return iph -> tos;
}

static inline int tot_len_ipv4(void *data, u64 nh_off, void *data_end) {
	struct iphdr *iph = data + nh_off;

	if ((void*)&iph[1] > data_end)
		return 0;
	return iph -> tot_len;
}

static inline int id_ipv4(void *data, u64 nh_off, void *data_end) {
	struct iphdr *iph = data + nh_off;

	if ((void*)&iph[1] > data_end)
		return 0;
	return iph -> id;
}

static inline int frag_off_ipv4(void *data, u64 nh_off, void *data_end) {
	struct iphdr *iph = data + nh_off;
	
	if ((void*)&iph[1] > data_end)
		return 0;
	return iph -> frag_off;
}

static inline int ttl_ipv4(void *data, u64 nh_off, void *data_end) {
	struct iphdr *iph = data + nh_off;

	if ((void*)&iph[1] > data_end)
		return 0;
	return iph -> ttl;
}

static inline int protocol_ipv4(void *data, u64 nh_off, void *data_end) {
	struct iphdr *iph = data + nh_off;

	if ((void*)&iph[1] > data_end)
		return 0;
	return iph -> protocol;
}

static inline int check_ipv4(void *data, u64 nh_off, void *data_end) {
	struct iphdr *iph = data + nh_off;

	if ((void*)&iph[1] > data_end)
		return 0;
	return iph -> check;
}

static inline int daddr_ipv4(void *data, u64 nh_off, void *data_end) {
	struct iphdr *iph = data + nh_off;

	if ((void*)&iph[1] > data_end)
		return 0;
	return iph -> daddr;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}

int xdp_prog1(struct CTXTYPE *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    // drop packets
    int rc = RETURNCODE; // let pass XDP_PASS or redirect to tx via XDP_TX
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    uint32_t index;
    u64 in0 = 0;
    u64 in1 = 1;

    // ip header values : tos(o) / tot_len(o) / id(o) / frag_off(o) / ttl(o) / protocol(o) / check(o) / saddr(o) / daddr(o)
    u32 ip_daddr = 0;
    u64 ip_saddr = 0;
    u8 ip_tos = 0;
    u16 ip_tot_len = 0;
    u16 ip_id = 0;
    u16 ip_frag_off = 0;
    u8 ip_ttl = 0;
    u8 ip_protocol = 0;
    u16 ip_check = 0;

    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
        return rc;

    h_proto = eth->h_proto;

    // parse double vlans
    #pragma unroll
    for (int i=0; i<2; i++) {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr;

            vhdr = data + nh_off;
            nh_off += sizeof(struct vlan_hdr);
            if (data + nh_off > data_end)
                return rc;
                h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    if (h_proto == htons(ETH_P_IP))
    {
        index = parse_ipv4(data, nh_off, data_end);
    	ip_saddr = saddr_ipv4(data, nh_off, data_end);
	ip_tos = tos_ipv4(data, nh_off, data_end);
	ip_tot_len = tot_len_ipv4(data, nh_off, data_end);
	ip_id = id_ipv4(data, nh_off,data_end);
	ip_frag_off = frag_off_ipv4(data, nh_off, data_end);
	ip_ttl = ttl_ipv4(data, nh_off, data_end);
	ip_protocol = protocol_ipv4(data, nh_off, data_end);
	ip_check = check_ipv4(data, nh_off, data_end);
	ip_daddr = daddr_ipv4(data, nh_off, data_end);
    }
    else if (h_proto == htons(ETH_P_IPV6))
       index = parse_ipv6(data, nh_off, data_end);
    else
        index = 0;

    hash_addr.update(&in0, &ip_saddr);

    value = dropcnt.lookup(&index);
    if (value)
        __sync_fetch_and_add(value, 1);

    return rc;
}
