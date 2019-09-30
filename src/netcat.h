/*
 * netcat.h -- main header project file
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: netcat.h,v 1.16 2002/05/06 15:05:54 themnemonic Exp $
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
#include <sys/time.h>		/* timeval, time_t */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>		/* inet_ntop(), inet_pton() */

/* other misc unchecked includes */
#include <netinet/in_systm.h>	/* misc crud that netinet/ip.h references */
#include <netinet/ip.h>		/* IPOPT_LSRR, header stuff */
#include <time.h>

/* These are useful to keep the source readable */
#ifndef STDIN_FILENO
# define STDIN_FILENO 0
#endif

#ifndef STDOUT_FILENO
# define STDOUT_FILENO 1
#endif

#ifndef STDERR_FILENO
# define STDERR_FILENO 2
#endif

/* #undef _POSIX_SOURCE	*/	/* might need this for something? */


#ifdef HAVE_RANDOM		/* try with most modern random routines */
# define SRAND srandom
# define RAND random
#elif defined HAVE_RAND		/* otherwise fallback to the older rand() */
# define SRAND srand
# define RAND rand
#else				/* if none of them are here, CHANGE OS! */
# error "Couldn't find any random() library function"
#endif

/* handy stuff: */
#define SA struct sockaddr	/* FIXME: this needs to be removed ASAP */
#define SLEAZE_PORT 31337	/* for UDP-scan RTT trick, change if ya want */
#define USHORT unsigned short	/* use these for options an' stuff */
#define BIGSIZ 8192		/* big buffers */

#define NETCAT_ADDRSTRLEN INET_ADDRSTRLEN

/* MAXINETADDR defines the maximum number of host aliases that are saved after
   a successfully hostname lookup. Please not that this value will also take
   a significant role in the memory usage. Approximately one struct takes:
   MAXINETADDRS * (NETCAT_ADDRSTRLEN + sizeof(struct in_addr)) */
#define MAXINETADDRS 6

#ifndef INADDR_NONE
# define INADDR_NONE 0xffffffff
#endif
#ifdef MAXHOSTNAMELEN
# undef MAXHOSTNAMELEN		/* might be too small on aix, so fix it */
#endif
#define MAXHOSTNAMELEN 256

/* TRUE and FALSE values for logical type `bool' */
#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

/* this is just a logical type, but helps a lot */
#ifndef __cplusplus
# ifndef bool
#  define bool unsigned char
# endif
#endif

typedef struct netcat_host_struct {
  char name[MAXHOSTNAMELEN];		/* dns name */
  char addrs[MAXINETADDRS][24];		/* ascii-format IP addresses */
  struct in_addr iaddrs[MAXINETADDRS];	/* real addresses: in_addr.s_addr: ulong */
} netcat_host;

typedef struct netcat_port_struct {
  char name[64];
  char ascnum[8];
  unsigned short num;
} netcat_port;

#include "proto.h"
#include "intl.h"
#include "misc.h"

#endif	/* !NETCAT_H */
