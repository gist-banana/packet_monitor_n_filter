from bcc import BPF

b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>

int kprobe__dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb) 
{
    bpf_trace_printk("send a packet! len = %d protocol = %x\\n", skb->len, skb->protocol);
    return 0;
}
""", debug = 0)

print("tracing...")

while 1:
    try :
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError :
        continue
    print(msg)
