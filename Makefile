# SPDX-License-Identifier: GPL-2.0-or-later
#
# PASST - Plug A Simple Socket Transport
#  for qemu/UNIX domain socket mode
#
# PASTA - Pack A Subtle Tap Abstraction
#  for network namespace/tap device mode
#
# Copyright (c) 2021 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

VERSION ?= $(shell git describe --tags HEAD 2>/dev/null || echo "unknown\ version")

# Does the target platform allow IPv4 connections to be handled via
# the IPv6 socket API? (Linux does)
DUAL_STACK_SOCKETS := 1

TARGET ?= $(shell $(CC) -dumpmachine)
$(if $(TARGET),,$(error Failed to get target architecture))
# Get 'uname -m'-like architecture description for target
TARGET_ARCH := $(firstword $(subst -, ,$(TARGET)))
TARGET_ARCH := $(patsubst [:upper:],[:lower:],$(TARGET_ARCH))
TARGET_ARCH := $(patsubst arm%,arm,$(TARGET_ARCH))
TARGET_ARCH := $(subst powerpc,ppc,$(TARGET_ARCH))

# On some systems enabling optimization also enables source fortification,
# automagically. Do not override it.
FORTIFY_FLAG :=
ifeq ($(shell $(CC) -O2 -dM -E - < /dev/null 2>&1 | grep ' _FORTIFY_SOURCE ' > /dev/null; echo $$?),1)
FORTIFY_FLAG := -D_FORTIFY_SOURCE=2
endif

FLAGS := -Wall -Wextra -Wno-format-zero-length -Wformat-security
FLAGS += -pedantic -std=c11 -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
FLAGS +=  $(FORTIFY_FLAG) -O2 -pie -fPIE
FLAGS += -DPAGE_SIZE=$(shell getconf PAGE_SIZE)
FLAGS += -DVERSION=\"$(VERSION)\"
FLAGS += -DDUAL_STACK_SOCKETS=$(DUAL_STACK_SOCKETS)

PASST_SRCS = arch.c arp.c checksum.c conf.c dhcp.c dhcpv6.c epoll_ctl.c \
	flow.c fwd.c icmp.c igmp.c inany.c iov.c ip.c isolation.c lineread.c \
	log.c mld.c ndp.c netlink.c migrate.c packet.c passt.c pasta.c pcap.c \
	pif.c repair.c tap.c tcp.c tcp_buf.c tcp_splice.c tcp_vu.c udp.c \
	udp_flow.c udp_vu.c util.c vhost_user.c virtio.c vu_common.c
QRAP_SRCS = qrap.c
PASST_REPAIR_SRCS = passt-repair.c
SRCS = $(PASST_SRCS) $(QRAP_SRCS) $(PASST_REPAIR_SRCS)

MANPAGES = passt.1 pasta.1 qrap.1 passt-repair.1

PASST_HEADERS = arch.h arp.h checksum.h conf.h dhcp.h dhcpv6.h epoll_ctl.h \
	flow.h fwd.h flow_table.h icmp.h icmp_flow.h inany.h iov.h ip.h \
	isolation.h lineread.h log.h migrate.h ndp.h netlink.h packet.h \
	passt.h pasta.h pcap.h pif.h repair.h siphash.h tap.h tcp.h tcp_buf.h \
	tcp_conn.h tcp_internal.h tcp_splice.h tcp_vu.h udp.h udp_flow.h \
	udp_internal.h udp_vu.h util.h vhost_user.h virtio.h vu_common.h
HEADERS = $(PASST_HEADERS) seccomp.h

C := \#include <sys/random.h>\nint main(){int a=getrandom(0, 0, 0);}
ifeq ($(shell printf "$(C)" | $(CC) -S -xc - -o - >/dev/null 2>&1; echo $$?),0)
	FLAGS += -DHAS_GETRANDOM
endif

ifeq ($(shell :|$(CC) -fstack-protector-strong -S -xc - -o - >/dev/null 2>&1; echo $$?),0)
	FLAGS += -fstack-protector-strong
endif

prefix		?= /usr/local
exec_prefix	?= $(prefix)
bindir		?= $(exec_prefix)/bin
datarootdir	?= $(prefix)/share
docdir		?= $(datarootdir)/doc/passt
mandir		?= $(datarootdir)/man
man1dir		?= $(mandir)/man1

ifeq ($(TARGET_ARCH),x86_64)
BIN := passt passt.avx2 pasta pasta.avx2 qrap passt-repair
else
BIN := passt pasta qrap passt-repair
endif

all: $(BIN) $(MANPAGES) docs

static: FLAGS += -static -DGLIBC_NO_STATIC_NSS
static: clean all

seccomp.h: seccomp.sh $(PASST_SRCS) $(PASST_HEADERS)
	@ EXTRA_SYSCALLS="$(EXTRA_SYSCALLS)" ARCH="$(TARGET_ARCH)" CC="$(CC)" ./seccomp.sh seccomp.h $(PASST_SRCS) $(PASST_HEADERS)

seccomp_repair.h: seccomp.sh $(PASST_REPAIR_SRCS)
	@ ARCH="$(TARGET_ARCH)" CC="$(CC)" ./seccomp.sh seccomp_repair.h $(PASST_REPAIR_SRCS)

passt: $(PASST_SRCS) $(HEADERS)
	$(CC) $(FLAGS) $(CFLAGS) $(CPPFLAGS) $(PASST_SRCS) -o passt $(LDFLAGS)

passt.avx2: FLAGS += -Ofast -mavx2 -ftree-vectorize -funroll-loops
passt.avx2: $(PASST_SRCS) $(HEADERS)
	$(CC) $(filter-out -O2,$(FLAGS)) $(CFLAGS) $(CPPFLAGS) \
		$(PASST_SRCS) -o passt.avx2 $(LDFLAGS)

passt.avx2: passt

pasta.avx2 pasta.1 pasta: pasta%: passt%
	ln -sf $< $@

qrap: $(QRAP_SRCS) passt.h
	$(CC) $(FLAGS) $(CFLAGS) $(CPPFLAGS) -DARCH=\"$(TARGET_ARCH)\" $(QRAP_SRCS) -o qrap $(LDFLAGS)

passt-repair: $(PASST_REPAIR_SRCS) seccomp_repair.h
	$(CC) $(FLAGS) $(CFLAGS) $(CPPFLAGS) $(PASST_REPAIR_SRCS) -o passt-repair $(LDFLAGS)

valgrind: EXTRA_SYSCALLS += rt_sigprocmask rt_sigtimedwait rt_sigaction	\
			    rt_sigreturn getpid gettid kill clock_gettime \
			    mmap|mmap2 munmap open unlink gettimeofday futex \
			    statx readlink
valgrind: FLAGS += -g -DVALGRIND
valgrind: all

.PHONY: clean
clean:
	$(RM) $(BIN) *~ *.o seccomp.h seccomp_repair.h pasta.1 \
		passt.tar passt.tar.gz *.deb *.rpm \
		passt.pid README.plain.md

install: $(BIN) $(MANPAGES) docs
	mkdir -p $(DESTDIR)$(bindir) $(DESTDIR)$(man1dir)
	cp -d $(BIN) $(DESTDIR)$(bindir)
	cp -d $(MANPAGES) $(DESTDIR)$(man1dir)
	mkdir -p $(DESTDIR)$(docdir)
	cp -d README.plain.md $(DESTDIR)$(docdir)/README.md
	cp -d doc/demo.sh $(DESTDIR)$(docdir)

uninstall:
	$(RM) $(BIN:%=$(DESTDIR)$(prefix)/bin/%)
	$(RM) $(MANPAGES:%=$(DESTDIR)$(man1dir)/%)
	$(RM) $(DESTDIR)$(docdir)/README.md
	$(RM) $(DESTDIR)$(docdir)/demo.sh
	-rmdir $(DESTDIR)$(docdir)

pkgs: static
	tar cf passt.tar -P --xform 's//\/usr\/bin\//' $(BIN)
	tar rf passt.tar -P --xform 's//\/usr\/share\/man\/man1\//' \
		$(MANPAGES)
	gzip passt.tar
	EMAIL="sbrivio@redhat.com" fakeroot alien --to-deb \
		--description="User-mode networking for VMs and namespaces" \
		-k --version=$(shell git rev-parse --short HEAD) \
		passt.tar.gz
	fakeroot alien --to-rpm --target=$(shell uname -m) \
		--description="User-mode networking for VMs and namespaces" \
		-k --version=g$(shell git rev-parse --short HEAD) passt.tar.gz

# TODO: This hack makes a "plain" Markdown version of README.md that can be
# reasonably shipped as documentation file, while the current README.md is
# definitely intended for web browser consumption. It should probably work the
# other way around: the web version should be obtained by adding HTML and
# JavaScript portions to a plain Markdown, instead. However, cgit needs to use
# a file in the git tree. Find a better way around this.
docs: README.md
	@(								\
		skip=0;							\
		while read l; do					\
			case $$l in					\
			"## Demo")	exit 0		;;		\
			"<!"*)				;;		\
			"</"*)		skip=1		;;		\
			"<"*)		skip=2		;;		\
			esac;						\
									\
			[ $$skip -eq 0 ]	&& echo "$$l";		\
			[ $$skip -eq 1 ]	&& skip=0;		\
		done < README.md;					\
	) > README.plain.md

clang-tidy: $(PASST_SRCS) $(HEADERS)
	clang-tidy $(PASST_SRCS) -- $(filter-out -pie,$(FLAGS) $(CFLAGS) $(CPPFLAGS)) \
	           -DCLANG_TIDY_58992

cppcheck: $(PASST_SRCS) $(HEADERS)
	if cppcheck --check-level=exhaustive /dev/null > /dev/null 2>&1; then \
		CPPCHECK_EXHAUSTIVE="--check-level=exhaustive";		\
	else								\
		CPPCHECK_EXHAUSTIVE=;					\
	fi;								\
	cppcheck --std=c11 --error-exitcode=1 --enable=all --force	\
	--inconclusive --library=posix --quiet				\
	$${CPPCHECK_EXHAUSTIVE}						\
	--inline-suppr							\
	--suppress=missingIncludeSystem \
	--suppress=unusedStructMember					\
	$(filter -D%,$(FLAGS) $(CFLAGS) $(CPPFLAGS)) -D CPPCHECK_6936  \
	$(PASST_SRCS) $(HEADERS)
