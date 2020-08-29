#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

//BPF_HASH(hash_test, u64, u64, 10240 );	// -size default : 10240 but for test, I use 2
BPF_HASH(black_list,u32, u8, 10240);

// 192.168.1.2 = 33663168
// 192.168.1.14 = 234989760

static inline int saddr_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
	return 0;
    return iph-> saddr;
}

int xdp_prog1(struct CTXTYPE *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    u64 ip_addr = 0;
    u64 *check_ip = 0;
//    u64 target_ip = 33663168;
    // 3232235778 = 192.168.1.2 or 33663168

    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
        return XDP_DROP;

    h_proto = eth->h_proto;
	
    // THIS PART -> TEST HASH TEST - BEGIN
//    hash_test.update(&target_ip, &one);
    // THIS PART -> TEST HASH TEST - END

    // parse double vlans

    if (h_proto == htons(ETH_P_IP))
    {
    	ip_addr = saddr_ipv4(data, nh_off, data_end);
    }
    
    check_ip = black_list.lookup(&ip_addr); // right now, compares the value of the key. Should change it to comparing the keys

    if (check_ip != NULL) // after looking up a value in the map, it must be tested if the return value isnt' NULL
    {
//	if (*saved_flag != 0) // hash map has the ip addresses saved as keys so don't need to compare the values inside
		return XDP_DROP;	// drop packet
    }
	return XDP_PASS;
}
