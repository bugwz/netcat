/*
 * core.c -- core loops and most critical routines
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: core.c,v 1.13 2002/05/31 13:42:15 themnemonic Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "netcat.h"

static int core_udp_connect(nc_sock_t *ncsock)
{
  int ret, sock;
  struct sockaddr_in myaddr;
  debug_v("core_udp_connect(ncsock=%p)", (void *)ncsock);

  sock = netcat_socket_new(PF_INET, SOCK_DGRAM);
  if (sock < 0)
    return -1;

  /* prepare myaddr for the bind() call */
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = htons(ncsock->local_port.num);
  memcpy(&myaddr.sin_addr, &ncsock->local_host.iaddrs[0], sizeof(myaddr.sin_addr));
  /* only call bind if it really needed */
  if (myaddr.sin_port || myaddr.sin_addr.s_addr) {
    ret = bind(sock, (struct sockaddr *)&myaddr, sizeof(myaddr));
    if (ret < 0)
      goto err;
  }

  /* now prepare myaddr for the connect() call */
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = htons(ncsock->port.num);
  memcpy(&myaddr.sin_addr, &ncsock->host.iaddrs[0], sizeof(myaddr.sin_addr));
  ret = connect(sock, (struct sockaddr *)&myaddr, sizeof(myaddr));
  if (ret < 0)
    goto err;

  return sock;

 err:
  close(sock);
  return -1;
}				/* end of core_udp_connect() */

/* Emulates a TCP connection but using the UDP protocol.  There is a listening
   socket that catches the first valid packet and assumes the packet endpoints
   as the endpoints for the final connection. */

static int core_udp_listen(nc_sock_t *ncsock)
{
  int ret, sock, sockopt = 1, timeout = ncsock->timeout;
  bool use_ancillary = FALSE;
  struct sockaddr_in myaddr;
  struct timeval tt;		/* needed by the select() call */
  debug_v("core_udp_listen(ncsock=%p)", (void *)ncsock);

  sock = netcat_socket_new(PF_INET, SOCK_DGRAM);
  if (sock < 0)
    return -1;

  /* prepare myaddr for the bind() call */
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = htons(ncsock->local_port.num);
  memcpy(&myaddr.sin_addr, &ncsock->local_host.iaddrs[0], sizeof(myaddr.sin_addr));
  /* only call bind if it really needed -- most of the cases in this function */
  if (myaddr.sin_port || myaddr.sin_addr.s_addr) {
    ret = bind(sock, (struct sockaddr *)&myaddr, sizeof(myaddr));
    if (ret < 0)
      goto err;
  }

#ifdef USE_PKTINFO
  /* set the right flag in order to obtain the ancillary data */
  ret = setsockopt(sock, SOL_IP, IP_PKTINFO, &sockopt, sizeof(sockopt));
  if (ret >= 0)
    use_ancillary = TRUE;
#else
# warning "Couldn't setup ancillary data helpers"
#endif

  /* since this protocol is connectionless, we need a special handling here.
     We want to simulate a two-ends connection but in order to do this we need
     a remote address and a local address (in case we bound to INADDR_ANY).
     Wait here until a packet is received, and use its source and destination
     addresses as default endpoints.  If we have the zero-I/O option set, we
     just eat the packet and will never return (if a timeout is not set). */
  tt.tv_sec = timeout;
  tt.tv_usec = 0;

  while (TRUE) {
    fd_set ins;

    FD_ZERO(&ins);
    FD_SET(sock, &ins);
    select(sock + 1, &ins, NULL, NULL, (timeout > 0 ? &tt : NULL));

    if (FD_ISSET(sock, &ins)) {
      int recv_ret, write_ret;
      struct msghdr my_hdr;
      unsigned char buf[1024], anc_buf[512];
      struct iovec my_hdr_vec;
      struct sockaddr_in rem_addr;
      struct sockaddr_in local_addr;
      bool local_fetch = FALSE;

      /* I've looked for this code for a lot of hours, and finally found the
         RFC 2292 which provides a socket API for fetching the destination
         interface of the incoming packet. */
      memset(&my_hdr, 0, sizeof(my_hdr));
      memset(&rem_addr, 0, sizeof(rem_addr));
      memset(&local_addr, 0, sizeof(local_addr));
      my_hdr.msg_name = &rem_addr;
      my_hdr.msg_namelen = sizeof(rem_addr);
      /* initialize the vector struct and then the vectory member of the header */
      my_hdr_vec.iov_base = buf;
      my_hdr_vec.iov_len = sizeof(buf);
      my_hdr.msg_iov = &my_hdr_vec;
      my_hdr.msg_iovlen = 1;
      /* now the most important part: the ancillary data, used to recovering the dst */
      my_hdr.msg_control = anc_buf;
      my_hdr.msg_controllen = sizeof(anc_buf);

      /* now check the remote address.  If we are simulating a routing then
         use the MSG_PEEK flag, which leaves the received packet untouched */
      recv_ret = recvmsg(sock, &my_hdr, (opt_zero ? 0 : MSG_PEEK));

      debug_v("received packet from %s:%d%s", netcat_inet_ntop(&rem_addr.sin_addr),
		ntohs(rem_addr.sin_port), (opt_zero ? "" : ", using as default dest"));

      /* let's hope that there is some ancillary data! */
      if (my_hdr.msg_controllen > 0) {
	struct cmsghdr *get_cmsg;

	/* We don't know which is the order of the ancillary messages and we
	   dont know how many are there.  So I simply parse all of them until
	   we find the right one, checking the index type. */
	for (get_cmsg = CMSG_FIRSTHDR(&my_hdr); get_cmsg;
		get_cmsg = CMSG_NXTHDR(&my_hdr, get_cmsg)) {
	  debug_v("Analizing ancillary header (id=%d)", get_cmsg->cmsg_type);

#ifdef USE_PKTINFO
	  if (get_cmsg->cmsg_type == IP_PKTINFO) {
	    struct in_pktinfo *get_pktinfo;

	    /* can we get this field double? RFC isn't clear on this */
	    assert(local_fetch == FALSE);
	    get_pktinfo = (struct in_pktinfo *) CMSG_DATA(get_cmsg);
	    memcpy(&local_addr.sin_addr, &get_pktinfo->ipi_spec_dst, sizeof(local_addr.sin_addr));
	    local_addr.sin_port = myaddr.sin_port;
	    local_addr.sin_family = myaddr.sin_family;
	    local_fetch = TRUE;
	  }
#endif
	}
      }

      if (local_fetch) {
	char tmpbuf[127];

	strncpy(tmpbuf, netcat_inet_ntop(&rem_addr.sin_addr), sizeof(tmpbuf));
	ncprint(NCPRINT_VERB1, _("Received packet from %s:%d -> %s:%d (local)"),
		tmpbuf, ntohs(rem_addr.sin_port), netcat_inet_ntop(&local_addr.sin_addr),
		ntohs(local_addr.sin_port));
      }
      else
	ncprint(NCPRINT_VERB1, _("Received packet from %s:%d"),
		netcat_inet_ntop(&rem_addr.sin_addr), ntohs(rem_addr.sin_port));

      if (opt_zero) {
	/* FIXME: why don't allow -z with -L? but only for udp! (?) */
	write_ret = write(STDOUT_FILENO, buf, recv_ret);
	bytes_recv += write_ret;
	debug_dv("write_u(stdout) = %d", write_ret);

	if (write_ret < 0) {
	  perror("write_u(stdout)");
	  exit(EXIT_FAILURE);
	}

	/* FIXME: handle write_ret != read_ret */

	/* if the hexdump option is set, hexdump the received data */
	if (opt_hexdump) {
#ifndef USE_OLD_HEXDUMP
	  fprintf(output_fd, "Received %d bytes from %s:%d\n", recv_ret,
		netcat_inet_ntop(&rem_addr.sin_addr), ntohs(rem_addr.sin_port));
#endif
	  netcat_fhexdump(output_fd, '<', buf, write_ret);
	}
      }
      else {
	nc_sock_t dup_socket;

	memset(&dup_socket, 0, sizeof(dup_socket));
	dup_socket.domain = ncsock->domain;
	dup_socket.proto = ncsock->proto;
	memcpy(&dup_socket.local_host.iaddrs[0], &local_addr.sin_addr, sizeof(local_addr));
	memcpy(&dup_socket.host.iaddrs[0], &rem_addr.sin_addr, sizeof(local_addr));
	dup_socket.local_port.num = ntohs(local_addr.sin_port);
	dup_socket.port.num = ntohs(rem_addr.sin_port);
	close(sock);

	/* this is all we want from this function */
	debug_dv("calling the udp_connect() function...");
	return core_udp_connect(&dup_socket);
      }
    }
    else			/* select() timed out! */
      break;
  }				/* end of packet receiving loop */

  /* no packets until timeout, set errno and proceed to general error handling */
  errno = ETIMEDOUT;

 err:
  close(sock);
  return -1;
}				/* end of core_udp_listen() */

static int core_tcp_connect(nc_sock_t *ncsock)
{
  int ret, sock, timeout = ncsock->timeout;
  struct timeval timest;
  fd_set outs;
  debug_v("core_tcp_connect(ncsock=%p)", (void *)ncsock);

  /* since we are nonblocking now, we could start as many connections as we
     want but it's not a great idea connecting more than one host at time */
  sock = netcat_socket_new_connect(PF_INET, SOCK_STREAM,
			&ncsock->host.iaddrs[0], ncsock->port.num,
			&ncsock->local_host.iaddrs[0], ncsock->local_port.num);

  if (sock < 0)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT, "Couldn't create connection (err=%d): %s",
	    sock, strerror(errno));

  /* initialize select()'s variables */
  FD_ZERO(&outs);
  FD_SET(sock, &outs);
  timest.tv_sec = timeout;
  timest.tv_usec = 0;

  ret = select(sock + 1, NULL, &outs, NULL, (timeout > 0 ? &timest : NULL));
  if (ret > 0) {
    int ret, get_ret;
    unsigned int get_len = sizeof(get_ret);	/* socklen_t */

    /* ok, select([single]), so sock must have triggered this */
    assert(FD_ISSET(sock, &outs));

    /* fetch the errors of the socket and handle system request errors */
    ret = getsockopt(sock, SOL_SOCKET, SO_ERROR, &get_ret, &get_len);
    if (ret < 0)
      ncprint(NCPRINT_ERROR | NCPRINT_EXIT, "Critical system request failed: %s",
	      strerror(errno));

    /* POSIX says that SO_ERROR expects an int, so my_len MUST be untouched */
    assert(get_len == sizeof(get_ret));

    debug_v("Connection returned errcode=%d (%s)", get_ret, strerror(get_ret));
    if (get_ret > 0) {
      char tmp;

      /* Ok, select() returned a write event for this socket AND getsockopt()
         said that some errors happened.  This mean that EOF is expected. */
      ret = read(sock, &tmp, 1);
      assert(ret == 0);

      shutdown(sock, 2);
      close(sock);
      ncsock->fd = -1;
      errno = get_ret;		/* value returned by getsockopt(SO_ERROR) */
      return -1;
    }
    return sock;
  }
  else if (ret)			/* Argh, select() returned error! */
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT, "Critical system request failed: %s",
	    strerror(errno));

  /* select returned 0, this means connection timed out for our timing
     directives (in fact the socket has a longer timeout usually, so we need
     to abort the connection try, set the proper errno and return */
  shutdown(sock, 2);
  close(sock);
  errno = ETIMEDOUT;
  return -1;
}				/* end of core_tcp_connect() */

/* This function loops inside the accept() loop until a *VALID* connection is
   fetched.  If an unwanted connection arrives, it is shutdown() and close()d.
   If zero I/O mode is enabled, ALL connections are refused and it stays
   unconditionally in listen mode until timeout elapses, if given, otherwise
   forever.
   Returns: The new socket descriptor for the fetched connection */

static int core_tcp_listen(nc_sock_t *ncsock)
{
  int sock_listen, sock_accept, timeout = ncsock->timeout;
  debug_v("core_tcp_listen(ncsock=%p)", (void *)ncsock);

  sock_listen = netcat_socket_new_listen(&ncsock->local_host.iaddrs[0],
			ncsock->local_port.num);
  if (sock_listen < 0)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT, "Couldn't setup listen socket (err=%d)",
	    sock_listen);

  while (TRUE) {
    struct sockaddr_in my_addr;
    unsigned int my_len = sizeof(my_addr);	/* this *IS* socklen_t */

    sock_accept = netcat_socket_accept(sock_listen, timeout);
    /* reset the timeout to the "use remaining time" value (see network.c file)
       if it exited with timeout we also return this function, so losing the
       original value is not a bad thing. */
    timeout = -1;

    /* failures in netcat_socket_accept() cause this function to return */
    if (sock_accept < 0)
      return -1;

    /* FIXME: i want a library function like netcat_peername() that fetches it
       and resolves with netcat_resolvehost().
       i also must check _resolvehost() */
    getpeername(sock_accept, (struct sockaddr *)&my_addr, &my_len);

    /* if a remote address (and optionally some ports) have been specified we
       assume it as the only ip and port that it is allowed to connect to
       this socket */

    if ((ncsock->host.iaddrs[0].s_addr && memcmp(&ncsock->host.iaddrs[0],
	 &my_addr.sin_addr, sizeof(ncsock->host.iaddrs[0]))) ||
	(netcat_flag_count() && !netcat_flag_get(ntohs(my_addr.sin_port)))) {
      ncprint(NCPRINT_VERB2, _("Unwanted connection from %s:%hu (refused)"),
	      netcat_inet_ntop(&my_addr.sin_addr), ntohs(my_addr.sin_port));
      goto refuse;
    }
    ncprint(NCPRINT_VERB1, _("Connection from %s:%hu"),
	    netcat_inet_ntop(&my_addr.sin_addr), ntohs(my_addr.sin_port));

    /* with zero I/O mode we don't really accept any connection */
    if (opt_zero)
      goto refuse;

    /* we have got our socket, now exit the loop */
    break;

 refuse:
    shutdown(sock_accept, 2);
    close(sock_accept);
    continue;
  }			/* end of infinite accepting loop */

  /* we don't need a listening socket anymore */
  close(sock_listen);
  return sock_accept;
}				/* end of core_tcp_listen() */

/* ... */

int core_connect(nc_sock_t *ncsock)
{
  assert(ncsock);

  if (ncsock->proto == NETCAT_PROTO_TCP)
    return ncsock->fd = core_tcp_connect(ncsock);
  else if (ncsock->proto == NETCAT_PROTO_UDP)
    return ncsock->fd = core_udp_connect(ncsock);
  else
    abort();

  return -1;
}

/* ... */

int core_listen(nc_sock_t *ncsock)
{
  assert(ncsock);

  if (ncsock->proto == NETCAT_PROTO_TCP)
    return ncsock->fd = core_tcp_listen(ncsock);
  else if (ncsock->proto == NETCAT_PROTO_UDP)
    return ncsock->fd = core_udp_listen(ncsock);
  else
    abort();

  return -1;
}

/* handle stdin/stdout/network I/O. */

int core_readwrite(nc_sock_t *nc_main, nc_sock_t *nc_tunnel)
{
  int fd_stdin, fd_stdout, fd_sock, fd_max;
  int read_ret, write_ret, pbuf_len = 0;
  unsigned char buf[1024], *pbuf = NULL, *ptmp = NULL;
  fd_set ins;
  bool inloop = TRUE;
  struct timeval delayer;

  delayer.tv_sec = 0;
  delayer.tv_usec = 0;

  debug_v("readwrite(nc_main=%p, nc_tunnel=%p)", (void *)nc_main, (void *)nc_tunnel);

  /* set the actual input and output fds and find out the max fd + 1 */
  fd_sock = nc_main->fd;
  assert(fd_sock >= 0);
  if (nc_tunnel) {
    fd_stdin = fd_stdout = nc_tunnel->fd;
    assert(fd_stdin >= 0);
  }
  else {
    fd_stdin = (use_stdin ? STDIN_FILENO : -1);
    fd_stdout = STDOUT_FILENO;
  }
  fd_max = 1 + (fd_stdin > fd_sock ? fd_stdin : fd_sock);

  while (inloop) {
    /* reset the ins events watch because some changes could happen */
    FD_ZERO(&ins);
    FD_SET(fd_sock, &ins);

    /* if we have a send buffer being sent OR we are in udp mode AND the
       remote address have not been initialized yet (for example because
       no packets have been received so far, THEN don't watch stdin */
    if (ptmp) {
      if ((delayer.tv_sec == 0) && (delayer.tv_usec == 0))
	delayer.tv_sec = opt_interval;
    }
    else if (fd_stdin >= 0)
      FD_SET(fd_stdin, &ins);

    debug_v("entering select()...");
    select(fd_max, &ins, NULL, NULL,
	   (delayer.tv_sec || delayer.tv_usec ? &delayer : NULL));

    /* reading from stdin.  We support the buffered output by lines, which is
       controlled by the global variable opt_interval.  If it is set, we fetch
       the buffer in the usual way, but we park it in a temporary buffer.  Once
       finished, the buffer is flushed and everything returns normal. */
    if (FD_ISSET(fd_stdin, &ins)) {
      read_ret = read(fd_stdin, buf, sizeof(buf));
      debug_dv("read(stdin) = %d", read_ret);

      if (read_ret < 0) {
	perror("read(stdin)");
	exit(EXIT_FAILURE);
      }
      else if (read_ret == 0) {
	debug_v("EOF Received from stdin! (ignored!)");
	/* FIXME: So, it seems that nc110 stops from setting 0 in the &ins
	   after it got an eof.. in fact in some circumstances after the initial
	   eof it won't be recovered and will keep triggering select() for nothing. */
	/* anyway, kill everything if this is a tunnel */
	if (opt_tunnel)
	  inloop = FALSE;
      }
      else {
	if (opt_interval) {
	  int i = 0;

	  while (i < read_ret)
	    if (buf[i++] == '\n')
	      break;

	  if (i < read_ret) {
	    pbuf_len = read_ret - i;
	    pbuf = ptmp = malloc(pbuf_len);
	    memcpy(pbuf, &buf[i], pbuf_len);
	    /* prepare the timeout timer so we don't fall back to the following
	       buffer-handling section.  We already sent out something and we
	       have to wait the right time before sending more. */
	    delayer.tv_sec = opt_interval;
	  }

	  read_ret = i;
        }
	write_ret = write(fd_sock, buf, read_ret);
	bytes_sent += write_ret;		/* update statistics */
	debug_dv("write(net) = %d", write_ret);

	if (write_ret < 0) {
	  perror("write(net)");
	  exit(EXIT_FAILURE);
	}

	/* if the option is set, hexdump the received data */
	if (opt_hexdump) {
#ifndef USE_OLD_HEXDUMP
	  fprintf(output_fd, "Sent %u bytes to the socket\n", write_ret);
#endif
	  netcat_fhexdump(output_fd, '>', buf, write_ret);
	}

      }
    }				/* end of reading from stdin section */

    /* reading from the socket (net). */
    if (FD_ISSET(fd_sock, &ins)) {
      struct sockaddr_in recv_addr;	/* only used by UDP proto */
      unsigned int recv_len = sizeof(recv_addr);

      if (nc_main->proto == NETCAT_PROTO_UDP) {
	memset(&recv_addr, 0, sizeof(recv_addr));
	/* this allows us to fetch packets from different addresses */
	read_ret = recvfrom(fd_sock, buf, sizeof(buf), 0,
			    (struct sockaddr *)&recv_addr, &recv_len);
	/* when recvfrom() call fails, recv_addr remains untouched */
	debug_dv("recvfrom(net) = %d (address=%s:%d)", read_ret,
		netcat_inet_ntop(&recv_addr.sin_addr), ntohs(recv_addr.sin_port));
      }
      else {
	/* common file read fallback */
	read_ret = read(fd_sock, buf, sizeof(buf));
	debug_dv("read(net) = %d", read_ret);
      }

      if (read_ret < 0) {
	perror("read(net)");
	exit(EXIT_FAILURE);
      }
      else if (read_ret == 0) {
	debug_v("EOF Received from the net");
	inloop = FALSE;
      }
      else {
	/* check for telnet codes (if enabled).  Note that the buffered output
           interval does NOT apply to telnet code answers */
	if (opt_telnet)
	  netcat_telnet_parse(fd_sock, buf, &read_ret);

	/* the telnet parsing could have returned 0 chars! */
	if (read_ret) {
	  write_ret = write(fd_stdout, buf, read_ret);
	  bytes_recv += write_ret;
	  debug_dv("write(stdout) = %d", write_ret);

	  if (write_ret < 0) {
	    perror("write(stdout)");
	    exit(EXIT_FAILURE);
	  }

	  /* FIXME: handle write_ret != read_ret */

	  /* if option is set, hexdump the received data */
	  if (opt_hexdump) {
#ifndef USE_OLD_HEXDUMP
	    if (nc_main->proto == NETCAT_PROTO_UDP)
	      fprintf(output_fd, "Received %d bytes from %s:%d\n", write_ret,
		netcat_inet_ntop(&recv_addr.sin_addr), ntohs(recv_addr.sin_port));
	    else
	      fprintf(output_fd, "Received %d bytes from the socket\n", write_ret);
#endif
	    netcat_fhexdump(output_fd, '<', buf, write_ret);
	  }
	}
      }
    }			/* end of reading from the socket section */

    /* now handle the buffered data (if any) */
    if (ptmp && (delayer.tv_sec == 0) && (delayer.tv_usec == 0)) {
      int i = 0;

      while (i < pbuf_len)
	if (pbuf[i++] == '\n')
	  break;

      /* if this reaches 0, the buffer is over and we can clean it */
      pbuf_len -= i;

      write_ret = write(fd_sock, pbuf, i);
      bytes_sent += write_ret;
      debug_dv("write(stdout)[buf] = %d", write_ret);

      if (write_ret < 0) {
	perror("write(stdout)[buf]");
	exit(EXIT_FAILURE);
      }

      bytes_sent += write_ret;

      /* check if the buffer is over.  If so, clean it and start back reading
         the stdin (or the other socket in case of tunnel mode) */
      if (pbuf_len == 0) {
	free(ptmp);
	ptmp = NULL;
	pbuf = NULL;
      }
      else
	pbuf += i;
    }				/* end of buffered data section */
  }				/* end of while (inloop) */

  return 0;
}				/* end of core_readwrite() */
