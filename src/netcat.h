/*
 * netcat.h -- main header project file
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2004  Giovanni Giacobbi
 *
 * $Id: netcat.h,v 1.35 2004/01/03 16:42:07 themnemonic Exp $
 */

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 ***************************************************************************/

#ifndef NETCAT_H
#define NETCAT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>		/* 基本类型定义 */
#include <sys/time.h>		/* timeval, time_t */
#include <sys/socket.h>
#include <sys/uio.h>		/* 读取/写入向量所需的 */
#include <sys/param.h>		/* 定义MAXHOSTNAMELEN和其他内容 */
#include <netinet/in.h>
#include <arpa/inet.h>		/* inet_ntop(), inet_pton() */

/* 其他未选中的杂项包括 */
#if 0
#include <netinet/in_systm.h>	/* misc crud that netinet/ip.h references */
#include <netinet/ip.h>		/* IPOPT_LSRR, header stuff */
#endif

/* 这些对保持源代码可读性很有用 */
#ifndef STDIN_FILENO
# define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
# define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
# define STDERR_FILENO 2
#endif
#ifndef SHUT_RDWR
# define SHUT_RDWR 2
#endif

/* 查找随机例程 */
#if defined(HAVE_RANDOM) && defined(HAVE_SRANDOM)
# define USE_RANDOM		/* try with most modern random routines */
# define SRAND srandom
# define RAND random
#elif defined(HAVE_RAND) && defined(HAVE_SRAND)
# define USE_RANDOM		/* otherwise fallback to the older rand() */
# define SRAND srand
# define RAND rand
#endif				/* 如果它们都不在，请更改操作系统! */

/* 必须将其定义为字符串表示法中可能的最长Internet地址长度。 
 * 错误修正：看来Solaris 7没有定义此标准。 可以使用以下变通办法，
 * 因为这将更改为引入IPv6支持 */
#ifdef INET_ADDRSTRLEN
# define NETCAT_ADDRSTRLEN INET_ADDRSTRLEN
#else
# define NETCAT_ADDRSTRLEN 16
#endif

/* FIXME：我应该搜索有关此端口名标准的更多信息。 目前，我将为此固定我自己的尺寸 */
#define NETCAT_MAXPORTNAMELEN 64

/* 确定我们是否可以在此计算机上使用RFC 2292扩展（到目前为止，我仅发现支持该功能的linux） */
#ifdef HAVE_STRUCT_IN_PKTINFO
# if defined(SOL_IP) && defined(IP_PKTINFO)
#  define USE_PKTINFO
# endif
#endif

/* MAXINETADDR定义成功查找主机名后保存的主机别名的最大数量。 请不要将此值在内存使用中也发挥重要作用。 
 * 大约需要一个结构：MAXINETADDRS *（NETCAT_ADDRSTRLEN sizeof（struct in_addr） */
#define MAXINETADDRS 6

#ifndef INADDR_NONE
# define INADDR_NONE 0xffffffff
#endif

/* FIXME：我们是否真的应该更改此定义？ 可能不是. */
#ifdef MAXHOSTNAMELEN
# undef MAXHOSTNAMELEN		/* 在aix上可能太小，请修复 */
#endif
#define MAXHOSTNAMELEN 256

/* 逻辑类型bool的TRUE和FALSE值 */
#ifndef TRUE
# define TRUE 1
#endif
#ifndef FALSE
# define FALSE 0
#endif

/* 这只是一个逻辑类型，但有很大帮助 */
#ifndef __cplusplus
# ifndef bool
#  define bool unsigned char
# endif
#endif
#define BOOL_TO_STR(__var__) (__var__ ? "TRUE" : "FALSE")
#define NULL_STR(__var__) (__var__ ? __var__ : "(null)")

/* 有些操作系统仍不支持POSIX标准 */
#ifndef HAVE_IN_PORT_T
typedef unsigned short in_port_t;
#endif

/* Netcat基本操作模式 */

typedef enum {
  NETCAT_UNSPEC,
  NETCAT_CONNECT,
  NETCAT_LISTEN,
  NETCAT_TUNNEL
} nc_mode_t;

/* 公认的协议 */

typedef enum {
  NETCAT_PROTO_UNSPEC,
  NETCAT_PROTO_TCP,
  NETCAT_PROTO_UDP
} nc_proto_t;

/* 用于队列缓冲和数据跟踪。 'head'字段是指向缓冲区段开始的指针，而'pos'表示数据流的实际位置。 
 * 如果'head'为NULL，则意味着该缓冲区中没有动态分配的数据，但是它可能仍包含一些本地数据段
 * （例如，在堆栈内部分配）。 'len'表示从'pos'开始的缓冲区的长度。
*/

typedef struct {
  unsigned char *head;
  unsigned char *pos;
  int len;
} nc_buffer_t;

/* 这是标准的netcat主机记录。 它包含一个'权威'名称字段，该字段可以为空，
 * 以及网络符号和点分字符串符号中的IP地址列表。*/

typedef struct {
  char name[MAXHOSTNAMELEN];			/* DNS名称 */
  char addrs[MAXINETADDRS][NETCAT_ADDRSTRLEN];	/* ascii格式的IP地址 */
  struct in_addr iaddrs[MAXINETADDRS];		/* 真实地址 */
} nc_host_t;

/* 标准netcat端口记录。 它包含端口名称（可以为空）以及端口号（以数字和字符串形式） */

typedef struct {
  char name[NETCAT_MAXPORTNAMELEN];	/* 规范端口名称 */
  char ascnum[8];			/* ascii端口号 */
  unsigned short num;			/* 端口号 */
  /* FIXME：这只是一个测试! */
  in_port_t netnum;			/* 网络字节顺序的端口号 */
} nc_port_t;

/* 这是保存套接字记录的更复杂的结构. [...] */

typedef struct {
  int fd, domain, timeout;
  nc_proto_t proto;
  nc_host_t local_host, host;
  nc_port_t local_port, port;
  nc_buffer_t sendq, recvq;
} nc_sock_t;

/* Netcat包括 */

#include "proto.h"
#include "intl.h"
#include "misc.h"

#endif	/* !NETCAT_H */
