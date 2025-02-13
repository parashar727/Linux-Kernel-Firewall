#include <linux/module.h>
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");

#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1
#define MAX_IPS 1024
#define MAX_PROTOS 10

#define NETLINK_USER 31
#define MSG_ADD_IP 1 
#define MSG_REM_IP 2
#define MSG_ADD_PROTO 3 
#define MSG_REM_PROTO 4 
#define MSG_LIST_RULES 5 

struct ip_mask_pair 
{
  __be32 addr;
  __be32 mask;
  bool active;
};

struct nlink_msg_data
{
  unsigned int msg_type;
  union {
    struct {
      __be32 addr;
      __be32 mask;
    } ip;
    unsigned char proto;
  } data;
};

static struct ip_mask_pair *blocked_ips;
static char *blocked_protos;
static int num_protos;
static struct sock *nl_sock;
static struct nf_hook_ops *nf_blockip_hook;
static struct nf_hook_ops *nf_blockproto_hook;

static int find_ip_slot(void)
{
  int i;
  for(i=0; i<MAX_IPS; i++)
  {
    if(!blocked_ips[i].active)
    {
      return i;
    }
  }
  return -1;
}

static int add_ip(__be32 addr, __be32 mask)
{
  int free_slot = find_ip_slot();

  if(free_slot < 0)
  {
    printk(KERN_ERR "Error: Not enough space in ip rules array\n");
    return -ENOSPC;
  }

  blocked_ips[free_slot].addr = addr;
  blocked_ips[free_slot].mask = mask;
  blocked_ips[free_slot].active = true;

  return 0;
}

static int remove_ip(__be32 addr)
{
  int i;

  for(i=0; i<MAX_IPS; i++)
  {
    if(blocked_ips[i].active == true && blocked_ips[i].addr == addr)
    {
      blocked_ips[i].active = false;
      return 0;
    }
  }

  return -ENOENT;
}

static int add_proto(unsigned char proto)
{
  if(num_protos >= MAX_PROTOS)
  {
    printk(KERN_ERR "Error: Not enough space in protocol rules array\n");
    return -ENOSPC;
  }

  blocked_protos[num_protos++] = proto;

  return 0;
}

static int remove_proto(unsigned char proto)
{
  int i;

  for(i=0; i<num_protos; i++)
  {
    if(blocked_protos[i] == proto)
    {
      if(i < num_protos - 1)
      {
        memmove(&blocked_protos[i], &blocked_protos[i + 1], num_protos - i - 1);
      }
      num_protos--;
      return 0;
    }
  }

  return -ENOENT;
}

static void send_rules_list(u32 pid)
{
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  int i, size;
  char *data;

  size = 1;
  for(i=0; i<MAX_IPS; i++)
  {
    if(blocked_ips[i].active)
    {
      size += 64;
    }
  }

  for(i=0; i<num_protos; i++)
  {
    size += 32;
  }

  skb = nlmsg_new(size, GFP_KERNEL);
  if(!skb)
  {
    return;
  }

  nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, size, 0);
  if(!nlh)
  {
    kfree_skb(skb);
    return;
  }

  data = nlmsg_data(nlh);
  data[0] = '\0';
  
  for(i=0; i<MAX_IPS; i++)
  {
    if(blocked_ips[i].active)
    {
      sprintf(data + strlen(data), "IP: %pI4/%pI4\n", &blocked_ips[i].addr, &blocked_ips[i].mask);
    }
  }

  for(i=0; i<num_protos; i++)
  {
    sprintf(data + strlen(data) ,"Proto: %u\n", blocked_protos[i]);
  }

  nlmsg_unicast(nl_sock, skb, pid);
}

static void recv_nlink_msg(struct sk_buff *skb)
{
  struct nlmsghdr *nlh;
  struct nlink_msg_data *msg_data;
  int ret = 0;
  
  nlh = (struct nlmsghdr *)skb->data;
  msg_data = (struct nlink_msg_data *)nlmsg_data(nlh);

  switch(msg_data->msg_type)
  {
    case MSG_ADD_IP:
      ret = add_ip(msg_data->data.ip.addr, msg_data->data.ip.mask);
      break;
    case MSG_REM_IP:
      ret = remove_ip(msg_data->data.ip.addr);
      break;
    case MSG_ADD_PROTO:
      ret = add_proto(msg_data->data.proto);
      break;
    case MSG_REM_PROTO:
      ret = remove_proto(msg_data->data.proto);
      break;
    case MSG_LIST_RULES:
      send_rules_list(nlh->nlmsg_pid);
      break;
  }
}

static unsigned int nf_blockip_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  int i;

  if(!skb)
  {
    return NF_ACCEPT;
  }

  iph = ip_hdr(skb);
  if(!iph)
  {
    return NF_ACCEPT;
  }

  for(i=0; i<MAX_IPS; i++)
  {
    if(!blocked_ips[i].active)
    {
      continue;
    }

    if(blocked_ips[i].active && ((iph->saddr & blocked_ips[i].mask) == (blocked_ips[i].addr & blocked_ips[i].mask)))
    {
      printk(KERN_INFO "Blocked packet from %pI4\n", &blocked_ips[i].addr);
      return NF_DROP;
    }
  }

  return NF_ACCEPT;
}

static unsigned int nf_blockproto_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  int i;

  if(!skb)
  {
    return NF_ACCEPT;
  }

  iph = ip_hdr(skb);
  if(!iph)
  {
    return NF_ACCEPT;
  }

  for(i=0; i<num_protos; i++)
  {
    if(iph->protocol == blocked_protos[i])
    {
      printk(KERN_INFO "Blocked packet with protocol %u", blocked_protos[i]);
      return NF_DROP;
    }
  }

  return NF_ACCEPT;
}

static int init_netlink(void)
{
  struct netlink_kernel_cfg cfg;
  cfg.input = recv_nlink_msg;

  nl_sock = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
  if(!nl_sock)
  {
    return -ENOMEM;
  }

  return 0;
}

static int init_netfilter_hooks(void)
{
  nf_blockip_hook = kzalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
  nf_blockproto_hook = kzalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);

  if(!nf_blockip_hook || !nf_blockproto_hook)
  {
    kfree(nf_blockip_hook);
    kfree(nf_blockproto_hook);
    return -ENOMEM;
  }

  nf_blockproto_hook->hook = (nf_hookfn*)nf_blockproto_handler;
  nf_blockproto_hook->hooknum = NF_INET_PRE_ROUTING;
  nf_blockproto_hook->pf = PF_INET;
  nf_blockproto_hook->priority = NF_IP_PRI_FIRST;

  nf_blockip_hook->hook = (nf_hookfn*)nf_blockip_handler;
  nf_blockip_hook->hooknum = NF_INET_PRE_ROUTING;
  nf_blockip_hook->pf = PF_INET;
  nf_blockip_hook->priority = NF_INET_PRE_ROUTING + 1;

  nf_register_net_hook(&init_net, nf_blockproto_hook);
  nf_register_net_hook(&init_net, nf_blockip_hook);

  return 0;
}

static int __init firewall_init(void)
{
  blocked_ips = kzalloc(sizeof(struct ip_mask_pair) * MAX_IPS, GFP_KERNEL);
  blocked_protos = kzalloc(sizeof(unsigned char) * MAX_PROTOS, GFP_KERNEL);

  int ret = 0;

  if(!blocked_ips || !blocked_protos)
  {
    kfree(blocked_ips);
    kfree(blocked_protos);
    return -ENOMEM;
  }
  
  ret = init_netlink();
  if(ret < 0)
  {
    return ret;
  }

  ret = init_netfilter_hooks();
  if(ret < 0)
  {
    return ret;
  }

  printk(KERN_INFO "Firewall module loaded\n");
  return 0;
}

static void __exit firewall_exit(void)
{
  if(nl_sock)
  {
    netlink_kernel_release(nl_sock);
  }

  if(nf_blockip_hook)
  {
    nf_unregister_net_hook(&init_net, nf_blockip_hook);
  }
  if(nf_blockproto_hook)
  {
    nf_unregister_net_hook(&init_net, nf_blockproto_hook);
  }

  kfree(blocked_ips);
  kfree(blocked_protos);
  kfree(nf_blockip_hook);
  kfree(nf_blockproto_hook);

  printk(KERN_INFO "Firewall module unloaded\n");
}

module_init(firewall_init);
module_exit(firewall_exit);
