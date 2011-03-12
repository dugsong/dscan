# $Id: configure.ac,v 1.6 2002/12/10 05:42:36 dugsong Exp $

AC_INIT(dscan, 1.0)
AC_CONFIG_AUX_DIR(config)

AM_INIT_AUTOMAKE(dscan, 1.0)
AM_CONFIG_HEADER(config.h)

# Initialize prefix.
if test "$prefix" = "NONE"; then prefix="/usr/local"; fi

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S

# Checks for libraries.
AC_LBL_LIBRARY_NET
AC_CHECK_LIB(resolv, gethostbyname)

# Checks for libevent
AC_MSG_CHECKING(for libevent)
AC_ARG_WITH(libevent,
[  --with-libevent=DIR     use libevent in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/include/event.h -a -f $withval/lib/libevent.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	EVENTINC="-I$withval/include"
	EVENTLIB="-L$withval/lib -levent"
     elif test -f $withval/event.h -a -f $withval/libevent.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	EVENTINC="-I$withval"
	EVENTLIB="-L$withval -levent"
     else
        AC_ERROR(event.h or libevent.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f /usr/include/event.h -a -f /usr/lib/libevent.a; then
     EVENTLIB="-levent"
  elif test -f ${prefix}/include/event.h -a -f ${prefix}/lib/libevent.a; then
     EVENTINC="-I${prefix}/include"
     EVENTLIB="-L${prefix}/lib -levent"
  else
     AC_MSG_RESULT(no)
     AC_ERROR(libevent not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(EVENTINC)
AC_SUBST(EVENTLIB)

# Checks for libpcap
AC_MSG_CHECKING(for libpcap)
AC_ARG_WITH(libpcap,
[  --with-libpcap=DIR      use libpcap in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/pcap.h -a -f $withval/libpcap.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	PCAPINC="-I$withval -I$withval/bpf"
	PCAPLIB="-L$withval -lpcap"
     elif test -f $withval/include/pcap.h -a \
	       -f $withval/include/net/bpf.h; then
	owd=`pwd`
	if cd $withval; then withval=`pwd`; cd $owd; fi
	PCAPINC="-I$withval/include"
	if test -f $withval/lib/libwpcap.a; then
	   PCAPLIB="-L$withval/lib -lwpcap"
	else
	   PCAPLIB="-L$withval/lib -lpcap"
        fi
     else
        AC_ERROR(pcap.h, net/bpf.h, or libpcap.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/pcap.h; then
     PCAPINC="-I${prefix}/include"
     if test -f ${prefix}/lib/libwpcap.a; then
	PCAPLIB="-L${prefix}/lib -lwpcap"
     else
        PCAPLIB="-L${prefix}/lib -lpcap"
     fi
  elif test -f /usr/include/pcap/pcap.h; then
     PCAPINC="-I/usr/include/pcap"
     PCAPLIB="-lpcap"
  elif test -f /usr/include/pcap.h; then
     PCAPLIB="-lpcap"
  elif test -f /sw/include/pcap.h; then
     PCAPINC="-I/sw/include"
     PCAPLIB="-L/sw/lib -lpcap"
  else
     AC_MSG_RESULT(no)
     AC_ERROR(libpcap not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(PCAPINC)
AC_SUBST(PCAPLIB)

# Checks for (installed) libdnet
AC_MSG_CHECKING(for libdnet)
AC_ARG_WITH(libdnet,
[  --with-libdnet=DIR      use libdnet in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/src/libdnet.a; then
	DNETINC="-I$withval/include"
	DNETLIB="-L$withval/src -ldnet `$withval/dnet-config --libs`"
     elif test -x $withval/bin/dnet-config; then
	DNETINC="`$withval/bin/dnet-config --cflags`"
	DNETLIB="`$withval/bin/dnet-config --libs`"
     else
        AC_ERROR(dnet-config not found in $withval/bin)
     fi
     ;;
  esac ],
[ if test -x ${prefix}/bin/dnet-config; then
     DNETINC="`${prefix}/bin/dnet-config --cflags`"
     DNETLIB="`${prefix}/bin/dnet-config --libs`"
  else
     AC_MSG_RESULT(no)
     AC_ERROR(libdnet not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(DNETINC)
AC_SUBST(DNETLIB)

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
if test "$GCC" = yes ; then
   CFLAGS="$CFLAGS -Wall"
fi

AC_CHECK_FUNCS(clock_getres setproctitle sigaction strlcpy)
AC_REPLACE_FUNCS(strsep)

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
