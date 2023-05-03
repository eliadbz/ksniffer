#include <linux/module.h>
#include <linux/printk.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <linux/string.h>

static struct nf_hook_ops *nf_sniffer_ingress_ops = NULL;
static struct nf_hook_ops *nf_sniffer_egress_ops = NULL;

static unsigned int nf_printpacket_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;   // IP header
	struct udphdr *udph; // UDP header
	struct tcphdr *tcph; // TCP header
	const char* ip_to_filter = "8.8.8.8";
	char *dest_ip = (char*)kmalloc(16, GFP_KERNEL);
	char *source_ip = (char*)kmalloc(16, GFP_KERNEL);
	if(!skb)
		return NF_ACCEPT;
	iph = ip_hdr(skb); // Retrieve the IP headers from the packet
	sprintf(source_ip, "%pI4",&iph->addrs.saddr); // Convert the IP addresses into string format
	sprintf(dest_ip, "%pI4",&iph->addrs.daddr);
	if((strcmp(source_ip, ip_to_filter) != 0) && (strcmp(dest_ip, ip_to_filter) != 0)){ // Check if that is the specific IP we would like to sniff
		return NF_ACCEPT;
	}
	if(iph->protocol == IPPROTO_UDP){
		udph = udp_hdr(skb);
		printk(KERN_INFO "UDP Packet: %s:%d -> %s:%d", source_ip, udph->source, dest_ip, udph->dest);
	}
	else if(iph->protocol == IPPROTO_TCP){
		tcph = tcp_hdr(skb);
		printk(KERN_INFO "TCP Packet: %s:%d -> %s:%d", source_ip, tcph->source, dest_ip, tcph->dest);
	}
	else{
		printk(KERN_INFO "Other Packet: %s: -> %s", source_ip, dest_ip);
	}
	return NF_ACCEPT;
}

static int __init start(void){
	nf_sniffer_ingress_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL); // Hook for incoming packets
	nf_sniffer_egress_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL); // Hook for outgoing packets

	if (nf_sniffer_ingress_ops != NULL){
		nf_sniffer_ingress_ops->hook = (nf_hookfn*) nf_printpacket_handler; // Function handler
		nf_sniffer_ingress_ops->hooknum = NF_INET_PRE_ROUTING; // Incoming packets
		nf_sniffer_ingress_ops->pf = NFPROTO_IPV4; // IPV4
		nf_sniffer_ingress_ops->priority = NF_IP_PRI_FIRST;

		nf_register_net_hook(&init_net, nf_sniffer_ingress_ops); // Registering the hook
	}
	if (nf_sniffer_egress_ops != NULL){
		nf_sniffer_egress_ops->hook = (nf_hookfn*) nf_printpacket_handler;
		nf_sniffer_egress_ops->hooknum = NF_INET_POST_ROUTING;
		nf_sniffer_egress_ops->pf = NFPROTO_IPV4;
		nf_sniffer_egress_ops->priority = NF_IP_PRI_FIRST;

		nf_register_net_hook(&init_net, nf_sniffer_egress_ops);
	}
    pr_info("[+] Starting to sniff...\n");
    
    return 0; // non-zero means the module failed
}

static void __exit end(void){
	if(nf_sniffer_ingress_ops != NULL) { // Freeing the allocated memory
		nf_unregister_net_hook(&init_net, nf_sniffer_ingress_ops);
		kfree(nf_sniffer_ingress_ops);
	}
	if(nf_sniffer_egress_ops != NULL) {
		nf_unregister_net_hook(&init_net, nf_sniffer_egress_ops);
		kfree(nf_sniffer_egress_ops);
	}
    pr_info("[+] Finished sniffing...\n");
}

module_init(start);
module_exit(end);

MODULE_LICENSE("GPL");