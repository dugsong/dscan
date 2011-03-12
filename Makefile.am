## $Id: Makefile.am,v 1.5 2002/12/04 01:54:11 dugsong Exp $

AUTOMAKE_OPTIONS = foreign no-dependencies

INCLUDES = @PCAPINC@ @EVENTINC@ @DNETINC@ -I$(top_srcdir)/compat

LDADD = @LIBOBJS@ @PCAPLIB@ @EVENTLIB@ @DNETLIB@

sbin_PROGRAMS = dscan

dscan_SOURCES = ares.c ares.h bag.c bag.h dscan-int.h dscan.c dscan.h hash.c \
	hash.h main.c mysignal.c mysignal.h ndb.c ndb.h osstack.c osstack.h \
	parse.c parse.h pcaputil.c pcaputil.h print.c print.h recv.c scan.c

man_MANS = dscan.8

dscan.8.txt: dscan.8
	groff -t -e -man -Tascii dscan.8 | col -bx > $@

strsep.o: $(top_srcdir)/compat/strsep.c
	$(COMPILE) -c $<

ahost: ahost.o ares.o bag.o parse.o
	$(LINK) ahost.o ares.o bag.o parse.o $(LDADD)

bag-test: bag-test.o bag.o parse.o
	$(LINK) bag-test.o bag.o parse.o $(LDADD) -ledit -ltermcap

EXTRA_DIST = LICENSE config/install-sh config/missing config/mkinstalldirs \
	compat/strsep.c compat/sys/queue.h compat/sys/tree.h \
	ahost.c bag-test.c $(man_MANS)

DISTCLEANFILES = *~

