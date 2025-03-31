#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "maps.h"
char _license[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN 14 /* Total octets in header.	 */
#define MAX_PAYLOAD_SIZE 128
#define TC_ACT_UNSPEC -1
#define TC_ACT_OK      0
#define TC_ACT_SHOT    2

SEC("tc")
int capture_packet(struct __sk_buff *skb) {
 
    
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // 解析以太网头
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    // 仅处理 IPv4 数据包
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // 解析 IP 头
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    // 仅处理 TCP 协议
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // 解析 TCP 头
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return TC_ACT_OK;

    // 检查目标端口是否为 MySQL (3306)
    if (tcp->dest != bpf_htons(3306))
        return TC_ACT_OK;

    // 输出数据包元信息到内核调试日志
    char fmt[] = "Captured TCP packet: src_port=%d, dest_port=%d\n";
    bpf_trace_printk(fmt, sizeof(fmt), bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
    
        // 计算各层协议头长度
        __u32 eth_hlen = ETH_HLEN;
        __u32 ip_hlen = ip->ihl * 4; // IP头长度是以4字节为单位
        __u32 tp_hlen = tcp->doff * 4; // TCP头长度是以4字节为单位
        __u32 total_hlen = eth_hlen + ip_hlen + tp_hlen;
        __u32 data_len = skb->len;
        __u32 payload_len = 0;
        u8 payload[MAX_PAYLOAD_SIZE];
        // 提取payload数据
        if (skb->len > total_hlen) {
            payload_len = skb->len - total_hlen;
           // bpf_printk("data length:%d Payload length: %d\n", data_len, payload_len);
            if (payload_len > sizeof(payload))  
                payload_len = sizeof(payload);
            /* 确保payload长度有效 */
            if (payload_len <= 0) 
                return TC_ACT_OK;
            
            // 使用bpf_skb_pull_data确保数据在内存中连续可访问
            if (bpf_skb_pull_data(skb, total_hlen + payload_len) < 0) {
                //bpf_printk("Failed to pull data");
                return TC_ACT_OK;
            }
            
            // 重新获取数据指针，因为bpf_skb_pull_data可能会改变它们
            void *data_ptr = (void *)(long)skb->data;
            data_ptr += total_hlen;
            // void *data_end_new = (void *)(long)skb->data_end;
            if(payload_len>0) {
                bpf_probe_read_kernel(payload, sizeof(payload), data_ptr);
                // 3 代表执行sql语句
                if(payload[4]!=3){
                    return TC_ACT_OK;
                }
                __u16 source_port = 0;
                bpf_probe_read_kernel(&source_port, sizeof(source_port), &tcp->source);
                source_port = bpf_ntohs(source_port);
                
                u32 random_value = bpf_get_prandom_u32() & 0xFFFF;
                u32 key = (u32)source_port << 16 | random_value;
                // bpf_printk("source_port:%d    random:%d   key:%u\n", source_port,random_value,key);
                bpf_map_update_elem(&sql_map,&key, payload, BPF_ANY);
            }
        }
    return TC_ACT_OK;
}


