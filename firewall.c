#include <linux/module.h>         // Needed by all modules
#include <linux/kernel.h>         // Needed for KERN_INFO
#include <linux/init.h>           // Needed for the macros
#include <linux/skbuff.h>
#include <linux/netfilter.h>      // Needed for hooks
#include <linux/netfilter_ipv4.h> // Needed for hooks
#include <linux/ip.h>             // Ip header
#include <linux/tcp.h>            // TCP header
#include <linux/udp.h>            // UDP header
#include <linux/types.h>
static struct nf_hook_ops nfho;         //struct holding set of hook function options

static long dropped=0;            //number of packets dropped
static long accepted=0;           //number of packets accepted

static int ports[10];             //array to pass in the ports you want to block
static int args=0;                //tells you how many ports you need to block
module_param_array(ports,int,&args,0000);   //grabs the amount from the command line



//function to be called by hook
unsigned int hook_func(unsigned int hooknum,
        struct sk_buff **skb,
        const struct net_device *in,        //device in         ex; eth0
        const struct net_device *out,       //device out
        int (*okfn)(struct sk_buff *))      //buff
{

    struct iphdr *ip_header;       // ip header struct
    struct tcphdr *tcp_header;     // tcp header struct
    struct udphdr *udp_header;     // udp header struct
    struct sk_buff *sock_buff;

    unsigned int sport =0,          //source port
                 dport=0;           //dest port

    int i=0;                        //used for for loop

    sock_buff = skb;                //grab skb and store in sock_buffer

    if (!sock_buff)                 //if it doesnt work just accept
        return NF_ACCEPT;

    ip_header = (struct iphdr *)skb_network_header(sock_buff);  //cast to the ip header
    if (!ip_header)                 //accept if it doesnt work
        return NF_ACCEPT;


    //if TCP PACKET
    if(ip_header->protocol==IPPROTO_TCP)
    {
        tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);      //cast to tcp header


        sport = htons((unsigned short int) tcp_header->source);                 //grab source port
        dport = htons((unsigned short int) tcp_header->dest);                   //grab dest port
        printk(" IN: %s\n",sock_buff->dev->name);
        printk(" Protocol: TCP\n");
        printk(" Length: %d\n",sock_buff->len);
        printk(" TTL: %d\n",ip_header->ttl);
        printk(" ID: %d\n",ip_header->id);
        printk(" S_PORT: %i\n",sport);
        printk(" D_PORT: %i\n\n",dport);

    }

    //if UDP PACKET
    if(ip_header->protocol==IPPROTO_UDP)
    {
        udp_header= (struct udphdr*)((__u32 *)ip_header+ ip_header->ihl);       //cast to udp header
        sport = ntohs((unsigned short int) udp_header->source);                 //grab source port
        dport = ntohs((unsigned short int) udp_header->dest);                   //grab dest port
        printk(" IN: %s\n",sock_buff->dev->name);
        printk(" Protocol: UDP\n");
        printk(" Length: %d\n",sock_buff->len);
        printk(" TTL: %d\n",ip_header->ttl);
        printk(" ID: %d\n",ip_header->id);
        printk(" S_PORT: %d\n",sport);
        printk(" D_PORT: %d\n\n",dport);
    }

    //check if we want to drop the packet based on port
    for(i=0;i<args;i++)
    {
        if(sport==ports[i] || dport==ports[i])
        {
            printk("block on port %i\n\n",ports[i]);
            dropped++;
            return NF_DROP;
        }
    }


    accepted++;

    return NF_ACCEPT;
}

//Called when module loaded using 'insmod'
int init_module()
{
    nfho.hook = hook_func;                       //function to call when conditions below met
    nfho.hooknum = 1;             		         //called right after packet recieved, first hook in Netfilter NF_IP_PRE_ROUTING
    nfho.pf = PF_INET;                           //IPV4 packets
    nfho.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
    nf_register_hook(&nfho);                     //register hook

    return 0;                                    //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{

    //display total number of packets dropped and accepted
    printk("Accepted: %ld \n",accepted);
    printk("Dropped:  %ld \n",dropped);

    nf_unregister_hook(&nfho);                     //cleanup unregister hook
}
