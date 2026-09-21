#ifndef NETPATH_COMMON_H
#define NETPATH_COMMON_H

enum stage {
	STAGE_SOCKET = 0,
	STAGE_IP     = 1,
	STAGE_ROUTE  = 2,
	STAGE_DEV    = 3,
	STAGE_DRIVER = 4,
	STAGE_MAX
};

#define IFNAMSIZ_NP 16

struct event {
	unsigned long long skb;
	unsigned long long ts_ns;
	unsigned int pid;
	unsigned char stage;
	unsigned char pad[3];
	char comm[16];

	unsigned int saddr;
	unsigned int daddr;
	unsigned short sport;
	unsigned short dport;

	unsigned int ifindex;
	char ifname[IFNAMSIZ_NP];

	unsigned char src_mac[6];
	unsigned char dst_mac[6];

	unsigned int len;
};

#endif /* NETPATH_COMMON_H */
