#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_USER 31
#define MSG_ADD_IP 1
#define MSG_REM_IP 2
#define MSG_ADD_PROTO 3
#define MSG_REM_PROTO 4
#define MSG_LIST_RULES 5

#define MAX_PAYLOAD 1024

struct nlink_msg_data
{
  unsigned int msg_type;
  union {
    struct {
      uint32_t addr;
      uint32_t mask;
    } ip;
    unsigned char proto;
  } data;
};

static int sock_fd;
static struct sockaddr_nl src_addr, dest_addr;

int init_netlink()
{
  sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
  if(sock_fd < 0)
  {
    perror("Socket could not be created\n");
    return -1;
  }

  memset(&src_addr, 0, sizeof(src_addr));
  src_addr.nl_family = AF_NETLINK;
  src_addr.nl_pid = getpid();

  if(bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0)
  {
    perror("Socket binding failed\n");
    close(sock_fd);
    return -1;
  }

  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.nl_family = AF_NETLINK;
  dest_addr.nl_pid = 0;
  dest_addr.nl_groups = 0;

  return 0;
}

int send_to_kernel(struct nlink_msg_data *msg_data)
{
  struct nlmsghdr *nlh;
  struct iovec iov;
  struct msghdr msg;

  nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct nlink_msg_data)));
  memset(nlh, 0, NLMSG_SPACE(sizeof(struct nlink_msg_data)));

  nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct nlink_msg_data));
  nlh->nlmsg_pid = getpid();
  nlh->nlmsg_flags = 0;

  memcpy(NLMSG_DATA(nlh), msg_data, sizeof(struct nlink_msg_data));

  iov.iov_base = (void *)nlh;
  iov.iov_len = nlh->nlmsg_len;

  memset(&msg, 0, sizeof(msg));
  msg.msg_name = (void *)&dest_addr;
  msg.msg_namelen = sizeof(dest_addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  if(sendmsg(sock_fd, &msg, 0) < 0)
  {
    perror("Message could not be send\n");
    free(nlh);
    return -1;
  }
  
  free(nlh);
  return 0;
}

void receive_rules_list()
{
  struct nlmsghdr *nlh;
  struct iovec iov;
  struct msghdr msg;
  char buffer[MAX_PAYLOAD];

  nlh = (struct nlmsghdr *)malloc(MAX_PAYLOAD);
  memset(nlh, 0, MAX_PAYLOAD);

  iov.iov_base = (void *)nlh;
  iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);

  memset(&msg, 0, sizeof(msg));
  msg.msg_name = (void *)&dest_addr;
  msg.msg_namelen = sizeof(dest_addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  if(recvmsg(sock_fd, &msg, 0) < 0)
  {
    perror("Message could not be received\n");
    free(nlh);
    return;
  }

  printf("\nCurrent Firewall Rules:\n");
  printf("------------------------\n");
  printf("%s", (char *)NLMSG_DATA(nlh));

  free(nlh);
}

int parse_ip_mask(const char *ip_mask, uint32_t *addr, uint32_t *mask)
{
  char ip_str[16];
  int cidr;

  if (sscanf(ip_mask, "%15[^/]/%d", ip_str, &cidr) != 2) 
  {
    fprintf(stderr, "Invalid IP/CIDR format. Use: xxx.xxx.xxx.xxx/yy\n");
    return -1;
  }

  if(cidr < 0 || cidr > 32)
  {
    fprintf(stderr, "Invalid CIDR value, must be 0-32\n");
    return -1;
  }

  if (inet_pton(AF_INET, ip_str, addr) != 1) {
    fprintf(stderr, "Invalid IP address format\n");
    return -1;
  }

  *mask = cidr ? htonl(~((1U << (32 - cidr)) - 1)) : 0;
    
  return 0;
}

void print_usage() {
  printf("Usage:\n");
  printf("  Add IP:    firewall -a <ip_address>/<cidr>\n");
  printf("  Remove IP: firewall -r <ip_address>\n");
  printf("  Add Proto: firewall -p <protocol_number>\n");
  printf("  Del Proto: firewall -d <protocol_number>\n");
  printf("  List Rules: firewall -l\n");
  printf("\nExample:\n");
  printf("  firewall -a 192.168.1.0/24    # Block 192.168.1.0/24 network\n");
  printf("  firewall -p 17                # Block UDP (protocol 17)\n");
}

int main(int argc, char *argv[]) 
{
  struct nlink_msg_data msg_data;
  int opt;

  if (argc < 2) 
  {
    print_usage();
    return 1;
  }

  if (init_netlink() < 0) 
  {
    return 1;
  }

    while ((opt = getopt(argc, argv, "a:r:p:d:l")) != -1) {
        switch (opt) {
            case 'a': // Add IP
                memset(&msg_data, 0, sizeof(msg_data));
                msg_data.msg_type = MSG_ADD_IP;
                if (parse_ip_mask(optarg, &msg_data.data.ip.addr, 
                                &msg_data.data.ip.mask) < 0)
                    return 1;
                send_to_kernel(&msg_data);
                printf("Added IP rule\n");
                break;

            case 'r': // Remove IP
                memset(&msg_data, 0, sizeof(msg_data));
                msg_data.msg_type = MSG_REM_IP;
                if (inet_pton(AF_INET, optarg, &msg_data.data.ip.addr) != 1) {
                    fprintf(stderr, "Invalid IP address format\n");
                    return 1;
                }
                send_to_kernel(&msg_data);
                printf("Removed IP rule\n");
                break;

            case 'p': // Add protocol
                memset(&msg_data, 0, sizeof(msg_data));
                msg_data.msg_type = MSG_ADD_PROTO;
                msg_data.data.proto = (unsigned char)atoi(optarg);
                send_to_kernel(&msg_data);
                printf("Added protocol rule\n");
                break;

            case 'd': // Remove protocol
                memset(&msg_data, 0, sizeof(msg_data));
                msg_data.msg_type = MSG_REM_PROTO;
                msg_data.data.proto = (unsigned char)atoi(optarg);
                send_to_kernel(&msg_data);
                printf("Removed protocol rule\n");
                break;

            case 'l': // List rules
                memset(&msg_data, 0, sizeof(msg_data));
                msg_data.msg_type = MSG_LIST_RULES;
                send_to_kernel(&msg_data);
                receive_rules_list();
                break;

            default:
                print_usage();
                return 1;
    }
  }

  close(sock_fd);
  return 0;
}
