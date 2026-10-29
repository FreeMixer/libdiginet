/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
 *
 * A private network for a test, without root: a user and network namespace of the test's own,
 * where it is uid 0 and holds every capability over that namespace only, veth pairs made with
 * one rtnetlink message each, and a way to give the capabilities up again. Nothing here touches
 * the machine's own interfaces.
 */
#ifndef DIGINET_TEST_NETNS_H
#define DIGINET_TEST_NETNS_H

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

static int ns_write(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ssize_t n = write(fd, text, strlen(text));
	close(fd);
	return n == (ssize_t)strlen(text) ? 0 : -1;
}

/* Enter a new user and network namespace as its uid 0, so a program this process starts keeps
 * the namespace's capabilities too. 0, or -1 with errno where the machine allows no such
 * namespace. */
static int ns_enter(void)
{
	char map[64];
	uid_t uid = getuid();
	gid_t gid = getgid();
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0)
		return -1;
	snprintf(map, sizeof map, "0 %u 1\n", (unsigned)uid);
	if (ns_write("/proc/self/uid_map", map) < 0)
		return -1;
	if (ns_write("/proc/self/setgroups", "deny") < 0 && errno != ENOENT)
		return -1;
	snprintf(map, sizeof map, "0 %u 1\n", (unsigned)gid);
	return ns_write("/proc/self/gid_map", map);
}

static int ns_up(const char *name)
{
	struct ifreq ifr;
	int ctl = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (ctl < 0)
		return -1;
	memset(&ifr, 0, sizeof ifr);
	snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", name);
	int r = ioctl(ctl, SIOCGIFFLAGS, &ifr);
	if (r == 0) {
		ifr.ifr_flags |= IFF_UP;
		r = ioctl(ctl, SIOCSIFFLAGS, &ifr);
	}
	close(ctl);
	return r;
}

static void ns_attr(struct nlmsghdr *h, unsigned short type, const void *data, size_t len)
{
	struct rtattr *a = (struct rtattr *)((char *)h + NLMSG_ALIGN(h->nlmsg_len));
	a->rta_type = type;
	a->rta_len = (unsigned short)RTA_LENGTH(len);
	if (len)
		memcpy(RTA_DATA(a), data, len);
	h->nlmsg_len = NLMSG_ALIGN(h->nlmsg_len) + RTA_ALIGN(a->rta_len);
}

static struct rtattr *ns_nest(struct nlmsghdr *h, unsigned short type)
{
	struct rtattr *a = (struct rtattr *)((char *)h + NLMSG_ALIGN(h->nlmsg_len));
	ns_attr(h, type, NULL, 0);
	return a;
}

static void ns_end(struct nlmsghdr *h, struct rtattr *nest)
{
	nest->rta_len = (unsigned short)((char *)h + h->nlmsg_len - (char *)nest);
}

/* A veth pair `a` <-> `b`, both up: what goes out of one comes in on the other. 0, or -1. */
static int ns_veth(const char *a, const char *b)
{
	struct {
		struct nlmsghdr h;
		char buf[512];
	} req;
	memset(&req, 0, sizeof req);
	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.h.nlmsg_type = RTM_NEWLINK;
	req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
	ns_attr(&req.h, IFLA_IFNAME, a, strlen(a) + 1);
	struct rtattr *info = ns_nest(&req.h, IFLA_LINKINFO);
	ns_attr(&req.h, IFLA_INFO_KIND, "veth", 5);
	struct rtattr *data = ns_nest(&req.h, IFLA_INFO_DATA);
	struct rtattr *peer = ns_nest(&req.h, VETH_INFO_PEER);
	struct ifinfomsg pi;
	memset(&pi, 0, sizeof pi);
	memcpy((char *)&req.h + req.h.nlmsg_len, &pi, sizeof pi);
	req.h.nlmsg_len += NLMSG_ALIGN(sizeof pi);
	ns_attr(&req.h, IFLA_IFNAME, b, strlen(b) + 1);
	ns_end(&req.h, peer);
	ns_end(&req.h, data);
	ns_end(&req.h, info);

	int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (s < 0)
		return -1;
	struct sockaddr_nl to = { .nl_family = AF_NETLINK };
	char ack[1024];
	int ok = sendto(s, &req, req.h.nlmsg_len, 0, (struct sockaddr *)&to, sizeof to) == (ssize_t)req.h.nlmsg_len;
	ssize_t n = ok ? recv(s, ack, sizeof ack, 0) : -1;
	close(s);
	struct nlmsghdr *r = (struct nlmsghdr *)ack;
	if (n < (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)) || r->nlmsg_type != NLMSG_ERROR ||
	    ((struct nlmsgerr *)NLMSG_DATA(r))->error != 0)
		return -1;
	return ns_up(a) == 0 && ns_up(b) == 0 ? 0 : -1;
}

/* Give up every capability this process holds, effective, permitted and inheritable: from
 * here on it is as unprivileged as any user's process. 0, or -1. */
static int ns_drop_caps(void)
{
	struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
	struct __user_cap_data_struct d[2];
	memset(d, 0, sizeof d);
	return (int)syscall(SYS_capset, &h, d);
}

#endif
