/*
 * netcat.c -- main project file
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2003  Giovanni Giacobbi
 *
 * $Id: netcat.c,v 1.63 2003/08/21 15:27:18 themnemonic Exp $
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
#include <signal.h>
#include <getopt.h>
#include <time.h>		/* time（2）用作随机种子 */

/* int gatesidx = 0; */		/* LSRR跳数 */
/* int gatesptr = 4; */		/* 初始LSRR指针，可设置 */
/* nc_host_t **gates = NULL; */	/* LSRR跃点主机 */
/* char *optbuf = NULL; */	/* LSRR或sockopts */
FILE *output_fp = NULL;		/* 输出fd（FIXME：我不喜欢） */
bool use_stdin = TRUE;		/* 告诉标准输入是否已关闭 */
bool signal_handler = TRUE;	/* 从外部处理信号 */
bool got_sigterm = FALSE;	/* 如果为TRUE，则应用程序必须退出 */
bool got_sigint = FALSE;	/* 如果为TRUE，则应用程序应退出 */
bool got_sigusr1 = FALSE;	/* 设置后，应用程序应打印统计信息 */
bool commandline_need_newline = FALSE;	/* 花式输出处理 */

/* 全局选项标示 */
nc_mode_t netcat_mode = 0;	/* Netcat的工作方式 */
bool opt_eofclose = FALSE;	/* 从stdin关闭EOF上的连接 */
bool opt_debug = FALSE;		/* 调试输出 */
bool opt_numeric = FALSE;	/* 不解析主机名 */
bool opt_random = FALSE;	/* 使用随机端口 */
bool opt_udpmode = FALSE;	/* 使用udp协议代替tcp */
bool opt_telnet = FALSE;	/* 在telnet模式下回答 */
bool opt_hexdump = FALSE;	/* 十六进制流量 */
bool opt_zero = FALSE;		/* 零I /O模式（什么都不期望） */
int opt_interval = 0;		/* 线路/端口之间的延迟（以秒为单位） */
int opt_verbose = 0;		/* 冗长（> 1表示更详细） */
int opt_wait = 0;		/* 等待时间 */
char *opt_outputfile = NULL;	/* hexdump输出文件 */
char *opt_exec = NULL;		/* 程序在连接后执行 */
nc_proto_t opt_proto = NETCAT_PROTO_TCP; /* 用于连接的协议 */


/* 信号处理 */

static void got_term(int z)
{
  if (!got_sigterm)
    ncprint(NCPRINT_VERB1, _("Terminated."));
  debug_v(("_____ RECEIVED SIGTERM _____ [signal_handler=%s]",
	  BOOL_TO_STR(signal_handler)));
  got_sigterm = TRUE;
  if (signal_handler)			/* 默认操作 */
    exit(EXIT_FAILURE);
}

static void got_int(int z)
{
  if (!got_sigint)
    ncprint(NCPRINT_VERB1, _("Exiting."));
  debug_v(("_____ RECEIVED SIGINT _____ [signal_handler=%s]",
	  BOOL_TO_STR(signal_handler)));
  got_sigint = TRUE;
  if (signal_handler) {			/* 默认操作 */
    if (commandline_need_newline)	/* 如果我们正在等待输入 */
      printf("\n");
    netcat_printstats(FALSE);
    exit(EXIT_FAILURE);
  }
}

static void got_usr1(int z)
{
  debug_dv(("_____ RECEIVED SIGUSR1 _____ [signal_handler=%s]",
	   BOOL_TO_STR(signal_handler)));
  if (signal_handler)			/* 默认操作 */
    netcat_printstats(TRUE);
  else
    got_sigusr1 = TRUE;
}

/* 执行一个外部文件，使其stdin/stdout/stderr成为实际的套接字 */

static void ncexec(nc_sock_t *ncsock)
{
  int saved_stderr;
  char *p;
  assert(ncsock && (ncsock->fd >= 0));

  /* 保存stderr的fd，因为稍后可能需要它 */
  saved_stderr = dup(STDERR_FILENO);

  /* 复制子程序的套接字 */
  dup2(ncsock->fd, STDIN_FILENO);	/* 绑定的精确顺序 */
  close(ncsock->fd);			/* 显然至关重要；这是 */
  dup2(STDIN_FILENO, STDOUT_FILENO);	/* 直接从'inetd'中划出. */
  dup2(STDIN_FILENO, STDERR_FILENO);	/* 还复制stderr通道 */

  /* 更改已执行程序的标签 */
  if ((p = strrchr(opt_exec, '/')))
    p++;			/* 较短的argv[0] */
  else
    p = opt_exec;

  /* 用新的替换该过程 */
#ifndef USE_OLD_COMPAT
  execl("/bin/sh", p, "-c", opt_exec, NULL);
#else
  execl(opt_exec, p, NULL);
#endif
  dup2(saved_stderr, STDERR_FILENO);
  ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Couldn't execute %s: %s"),
	  opt_exec, strerror(errno));
}				/* ncexec()的结尾 */

/* main：处理命令行参数和监听状态 */

int main(int argc, char *argv[])
{
  int c, glob_ret = EXIT_FAILURE;
  int total_ports, left_ports, accept_ret = -1, connect_ret = -1;
  struct sigaction sv;
  nc_port_t local_port;		/* 使用-p选项指定的本地端口 */
  nc_host_t local_host;		/* 用于bind（）ing操作的本地主机 */
  nc_host_t remote_host;
  nc_sock_t listen_sock;
  nc_sock_t connect_sock;
  nc_sock_t stdio_sock;

  memset(&local_port, 0, sizeof(local_port));
  memset(&local_host, 0, sizeof(local_host));
  memset(&remote_host, 0, sizeof(remote_host));
  memset(&listen_sock, 0, sizeof(listen_sock));
  memset(&connect_sock, 0, sizeof(listen_sock));
  memset(&stdio_sock, 0, sizeof(stdio_sock));
  listen_sock.domain = PF_INET;
  connect_sock.domain = PF_INET;

#ifdef ENABLE_NLS
  setlocale(LC_MESSAGES, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  /* 设置信号处理系统 */
  sigemptyset(&sv.sa_mask);
  sv.sa_flags = 0;
  sv.sa_handler = got_int;
  sigaction(SIGINT, &sv, NULL);
  sv.sa_handler = got_term;
  sigaction(SIGTERM, &sv, NULL);
  sv.sa_handler = got_usr1;
  sigaction(SIGUSR1, &sv, NULL);
  /* 忽略一些无聊的信号 */
  sv.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sv, NULL);
  sigaction(SIGURG, &sv, NULL);

  /* 如果没有给出任何args，则从stdin中获取它们并生成argv */
  if (argc == 1)
    netcat_commandline_read(&argc, &argv);

  /* 检查命令行开关 */
  while (TRUE) {
    int option_index = 0;
    static const struct option long_options[] = {
	{ "close",	no_argument,		NULL, 'c' },
	{ "debug",	no_argument,		NULL, 'd' },
	{ "exec",	required_argument,	NULL, 'e' },
	{ "gateway",	required_argument,	NULL, 'g' },
	{ "pointer",	required_argument,	NULL, 'G' },
	{ "help",	no_argument,		NULL, 'h' },
	{ "interval",	required_argument,	NULL, 'i' },
	{ "listen",	no_argument,		NULL, 'l' },
	{ "tunnel",	required_argument,	NULL, 'L' },
	{ "dont-resolve", no_argument,		NULL, 'n' },
	{ "output",	required_argument,	NULL, 'o' },
	{ "local-port",	required_argument,	NULL, 'p' },
	{ "tunnel-port", required_argument,	NULL, 'P' },
	{ "randomize",	no_argument,		NULL, 'r' },
	{ "source",	required_argument,	NULL, 's' },
	{ "tunnel-source", required_argument,	NULL, 'S' },
#ifndef USE_OLD_COMPAT
	{ "tcp",	no_argument,		NULL, 't' },
	{ "telnet",	no_argument,		NULL, 'T' },
#else
	{ "tcp",	no_argument,		NULL, 1 },
	{ "telnet",	no_argument,		NULL, 't' },
#endif
	{ "udp",	no_argument,		NULL, 'u' },
	{ "verbose",	no_argument,		NULL, 'v' },
	{ "version",	no_argument,		NULL, 'V' },
	{ "hexdump",	no_argument,		NULL, 'x' },
	{ "wait",	required_argument,	NULL, 'w' },
	{ "zero",	no_argument,		NULL, 'z' },
	{ 0, 0, 0, 0 }
    };

    c = getopt_long(argc, argv, "cde:g:G:hi:lL:no:p:P:rs:S:tTuvVxw:z",
		    long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
    case 'c':			/* 从stdin关闭EOF上的连接 */
      opt_eofclose = TRUE;
      break;
    case 'd':			/* 启用调试 */
      opt_debug = TRUE;
      break;
    case 'e':			/* 编为exec */
      if (opt_exec)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Cannot specify `-e' option double"));
      opt_exec = strdup(optarg);
      break;
    case 'G':			/* srcrt网关指针val */
      break;
    case 'g':			/* srcroute hop[s] */
      break;
    case 'h':			/* 显示帮助并退出 */
      netcat_printhelp(argv[0]);
      exit(EXIT_SUCCESS);
    case 'i':			/* 线/端口间隔时间（秒) */
      opt_interval = atoi(optarg);
      if (opt_interval <= 0)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Invalid interval time \"%s\""), optarg);
      break;
    case 'l':			/* 模式标志：监听模式 */
      if (netcat_mode != NETCAT_UNSPEC)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("You can specify mode flags (`-l' and `-L') only once"));
      netcat_mode = NETCAT_LISTEN;
      break;
    case 'L':			/* 模式标志：隧道模式 */
      if (netcat_mode != NETCAT_UNSPEC)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("You can specify mode flags (`-l' and `-L') only once"));
      if (opt_zero)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-L' and `-z' options are incompatible"));
      do {
	char *div = strchr(optarg, ':');

	if (div && *(div + 1))
	  *div++ = '\0';
	else
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Invalid target string for `-L' option"));

	/* 查找用于建立隧道的远程地址和远程端口 */
	if (!netcat_resolvehost(&connect_sock.host, optarg))
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
	  	  _("Couldn't resolve tunnel target host: %s"), optarg);
	if (!netcat_getport(&connect_sock.port, div, 0))
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
	  	  _("Invalid tunnel target port: %s"), div);

	connect_sock.proto = opt_proto;
	connect_sock.timeout = opt_wait;
	netcat_mode = NETCAT_TUNNEL;
      } while (FALSE);
      break;
    case 'n':			/* 仅数字，不进行DNS查找 */
      opt_numeric = TRUE;
      break;
    case 'o':			/* 将十六进制转储日志输出到文件 */
      opt_outputfile = strdup(optarg);
      opt_hexdump = TRUE;	/* 默示 */
      break;
    case 'p':			/* 本地源端口 */
      if (!netcat_getport(&local_port, optarg, 0))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Invalid local port: %s"),
		optarg);
      break;
    case 'P':			/* 仅在隧道模式（源端口）中使用 */
      if (!netcat_getport(&connect_sock.local_port, optarg, 0))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Invalid tunnel connect port: %s"), optarg);
      break;
    case 'r':			/* 将各种事物随机化 */
      opt_random = TRUE;
      break;
    case 's':			/* 本地源地址 */
      /* 查找源地址并将其分配给连接地址 */
      if (!netcat_resolvehost(&local_host, optarg))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Couldn't resolve local host: %s"), optarg);
      break;
    case 'S':			/* 仅在隧道模式（源ip）中使用 */
      if (!netcat_resolvehost(&connect_sock.local_host, optarg))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Couldn't resolve tunnel local host: %s"), optarg);
      break;
    case 1:			/* 使用TCP协议（默认） */
#ifndef USE_OLD_COMPAT
    case 't':
#endif
      opt_proto = NETCAT_PROTO_TCP;
      break;
#ifdef USE_OLD_COMPAT
    case 't':
#endif
    case 'T':			/* 回复telnet代码 */
      opt_telnet = TRUE;
      break;
    case 'u':			/* 使用UDP协议 */
      opt_proto = NETCAT_PROTO_UDP;
      break;
    case 'v':			/* 冗长（两次=更多冗长）*/
      opt_verbose++;
      break;
    case 'V':			/* 显示版本并退出 */
      netcat_printversion();
      exit(EXIT_SUCCESS);
    case 'w':			/* 等待时间（以秒为单位）*/
      opt_wait = atoi(optarg);
      if (opt_wait <= 0)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Invalid wait-time: %s"),
		optarg);
      break;
    case 'x':			/* 十六进制流量 */
      opt_hexdump = TRUE;
      break;
    case 'z':			/* 很少或没有数据xfer */
      if (netcat_mode == NETCAT_TUNNEL)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-L' and `-z' options are incompatible"));
      opt_zero = TRUE;
      break;
    default:
      ncprint(NCPRINT_EXIT, _("Try `%s --help' for more information."), argv[0]);
    }
  }

  if (opt_zero && opt_exec)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-e' and `-z' options are incompatible"));

  /* 初始化标志缓冲区以跟踪指定的端口 */
  netcat_flag_init(65535);

#ifndef DEBUG
  /* 检查调试支持 */
  if (opt_debug)
    ncprint(NCPRINT_WARNING,
	    _("Debugging support not compiled, option `-d' discarded. Using maximum verbosity."));
#endif

  /* 仅在需要时随机化 */
  if (opt_random)
#ifdef USE_RANDOM
    SRAND(time(0));
#else
    ncprint(NCPRINT_WARNING,
	    _("Randomization support not compiled, option `-r' discarded."));
#endif

  /* 处理-o选项。 失败退出 */
  if (opt_outputfile) {
    output_fp = fopen(opt_outputfile, "w");
    if (!output_fp)
      ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Failed to open output file: %s"),
	      strerror(errno));
  }
  else
    output_fp = stderr;

  debug_v(("Trying to parse non-args parameters (argc=%d, optind=%d)", argc,
	  optind));

  /* 尝试获取主机名参数 */
  if (optind < argc) {
    char *myhost = argv[optind++];
    if (!netcat_resolvehost(&remote_host, myhost))
      ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Couldn't resolve host \"%s\""),
	      myhost);
  }

  /* 现在循环所有其他（可能是可选的）端口范围参数 */
  while (optind < argc) {
    const char *get_argv = argv[optind++];
    char *q, *parse = strdup(get_argv);
    int port_lo = 0, port_hi = 65535;
    nc_port_t port_tmp;

    if (!(q = strchr(parse, '-')))	/* 简单数字? */
      q = strchr(parse, ':');		/* 尝试使用其他分隔符 */

    if (!q) {
      if (netcat_getport(&port_tmp, parse, 0))
	netcat_flag_set(port_tmp.num, TRUE);
      else
	goto got_err;
    }
    else {		/* 可以采用以下形式：N1-N2，-N2，N1- */
      *q++ = 0;
      if (*parse) {
	if (netcat_getport(&port_tmp, parse, 0))
	  port_lo = port_tmp.num;
	else
	  goto got_err;
      }
      if (*q) {
	if (netcat_getport(&port_tmp, q, 0))
	  port_hi = port_tmp.num;
	else
	  goto got_err;
      }
      if (!*parse && !*q)		/* 不接受格式'-' */
	goto got_err;

      /* 现在更新标志集（这是int，所以即使hi == 65535也可以）*/
      while (port_lo <= port_hi)
	netcat_flag_set(port_lo++, TRUE);
    }

    free(parse);
    continue;

 got_err:
    free(parse);
    ncprint(NCPRINT_ERROR, _("Invalid port specification: %s"), get_argv);
    exit(EXIT_FAILURE);
  }

  debug_dv(("Arguments parsing complete! Total ports=%d", netcat_flag_count()));
#if 0
  /* 纯调试代码 */
  c = 0;
  while ((c = netcat_flag_next(c))) {
    printf("Got port=%d\n", c);
  }
  exit(0);
#endif

  /* 处理监听模式和隧道模式（索引号较高） */
  if (netcat_mode > NETCAT_CONNECT) {
    /* 在隧道模式下，opt_zero标志是非法的，而在侦听模式下，这意味着不应接受任何连接。 
     * 对于UDP，这意味着不应将任何远程地址用作默认端点，这意味着我们无法发送任何内容。 
     * 在这两种情况下，stdin都不再有用，因此请将其关闭 */
    if (opt_zero) {
      close(STDIN_FILENO);
      use_stdin = FALSE;
    }

    /* 准备套接字var并开始监听 */
    listen_sock.proto = opt_proto;
    listen_sock.timeout = opt_wait;
    memcpy(&listen_sock.local_host, &local_host, sizeof(listen_sock.local_host));
    memcpy(&listen_sock.local_port, &local_port, sizeof(listen_sock.local_port));
    memcpy(&listen_sock.host, &remote_host, sizeof(listen_sock.host));
    accept_ret = core_listen(&listen_sock);

    /* 在零I / O模式下，由于不接受任何连接，因此core_tcp_listen（）调用将
     * 始终返回-1（ETIMEDOUT），因此，我们的工作现已完成 */
    if (accept_ret < 0) {
      /* 因为我打算使`-z'与`-L'兼容，所以我需要检查导致此故障的确切错误。 */
      if (opt_zero && (errno == ETIMEDOUT))
	exit(0);

      ncprint(NCPRINT_VERB1 | NCPRINT_EXIT, _("Listen mode failed: %s"),
	      strerror(errno));
    }

    /* 如果我们处于侦听模式，请运行核心循环并在返回时退出。 否则，现在是时候连接到目标主机
     * 并将它们隧道连接在一起了（这意味着转到下一部分 */
    if (netcat_mode == NETCAT_LISTEN) {
      if (opt_exec) {
	ncprint(NCPRINT_VERB2, _("Passing control to the specified program"));
	ncexec(&listen_sock);		/* 这不会返回 */
      }
      core_readwrite(&listen_sock, &stdio_sock);
      debug_dv(("Listen: EXIT"));
    }
    else {
      /* 否则我们将处于隧道模式。 connect_sock var已由命令行参数初始化 */
      assert(netcat_mode == NETCAT_TUNNEL);
      connect_ret = core_connect(&connect_sock);

      /* 连接失败？ （我们无法在UDP模式下获得此信息） */
      if (connect_ret < 0) {
	assert(opt_proto != NETCAT_PROTO_UDP);
	ncprint(NCPRINT_VERB1, "%s: %s",
		netcat_strid(&connect_sock.host, &connect_sock.port),
		strerror(errno));
      }
      else {
	glob_ret = EXIT_SUCCESS;
	core_readwrite(&listen_sock, &connect_sock);
	debug_dv(("Tunnel: EXIT (ret=%d)", glob_ret));
      }
    }

    /* 所有工作都ok，请进行清理 */
    goto main_exit;
  }				/* 侦听和隧道模式处理结束 */

  /* 我们需要外部连接，这是连接模式 */
  netcat_mode = NETCAT_CONNECT;

  /* 首先检查是否已指定主机参数 */
  if (!remote_host.iaddrs[0].s_addr) {
    /* FIXME：网络规范指出主机地址“ 0”是要连接的有效主机，但是此中断的检查将假定未指定 */
    ncprint(NCPRINT_NORMAL, _("%s: missing hostname argument"), argv[0]);
    ncprint(NCPRINT_EXIT, _("Try `%s --help' for more information."), argv[0]);
  }

  /* 因为端口是第二个参数，所以检查端口可能就足够了 */
  total_ports = netcat_flag_count();
  if (total_ports == 0)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
	    _("No ports specified for connection"));

  c = 0;			/* 必须为netcat_flag_next（）设置为0  */
  left_ports = total_ports;
  while (left_ports > 0) {
    /* 'c'是独立于排序方法（线性或随机）的端口号。 在线性模式下，它还用于获取下一个端口号 */
    if (opt_random)
      c = netcat_flag_rand();
    else
      c = netcat_flag_next(c);
    left_ports--;		/* 减少端口总数以尝试 */

    /* 因为我们现在正在非阻塞状态，所以我们可以根据需要启动任意数量的连接，但这不是一次连接多个主机的好主意 */
    connect_sock.proto = opt_proto;
    connect_sock.timeout = opt_wait;
    memcpy(&connect_sock.local_host, &local_host,
	   sizeof(connect_sock.local_host));
    memcpy(&connect_sock.local_port, &local_port,
	   sizeof(connect_sock.local_port));
    memcpy(&connect_sock.host, &remote_host, sizeof(connect_sock.host));
    netcat_getport(&connect_sock.port, NULL, c);

    /* FIXME：在udp模式和NETCAT_CONNECT中，opt_zero毫无意义 */
    connect_ret = core_connect(&connect_sock);

    /* 连接失败？ （我们无法在UDP模式下获得此信息） */
    if (connect_ret < 0) {
      int ncprint_flags = NCPRINT_VERB1;
      assert(connect_sock.proto != NETCAT_PROTO_UDP);

      /* 如果我们是端口扫描或多个连接，则仅显示详细级别为1的开放端口. */
      if (total_ports > 1)
	ncprint_flags = NCPRINT_VERB2;

      ncprint(ncprint_flags, "%s: %s",
	      netcat_strid(&connect_sock.host, &connect_sock.port),
	      strerror(errno));
      continue;			/* go with next port */
    }

    /* 当进行端口扫描（或检查单个端口）时，如果至少有一个端口可用，我们很高兴. */
    glob_ret = EXIT_SUCCESS;

    if (opt_zero) {
      shutdown(connect_ret, 2);
      close(connect_ret);
    }
    else {
      if (opt_exec) {
	ncprint(NCPRINT_VERB2, _("Passing control to the specified program"));
	ncexec(&connect_sock);		/* 这不会返回 */
      }
      core_readwrite(&connect_sock, &stdio_sock);
      /* FIXME：增加一点延迟 */
      debug_v(("Connect: EXIT"));

      /* 两个信号都在core_readwrite（）内部处理，但是在SIGINT信号得到完全处理的同时，
       * SIGTERM需要从该函数外部进行某些操作，因为未清除该标志 */
      if (got_sigterm)
	break;
    }
  }			/* 一会儿结束（left_ports> 0）*/

  /* 所有基本模式都应返回此处进行最终清理 */
 main_exit:
  debug_v(("Main: EXIT (cleaning up)"));

  netcat_printstats(FALSE);
  return glob_ret;
}				/* main()结尾 */
