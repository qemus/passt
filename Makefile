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

BASE_CPPFLAGS := -D_XOPEN_SOURCE=700 -D_GNU_SOURCE $(FORTIFY_FLAG)
BASE_CPPFLAGS += -DPAGE_SIZE=$(shell getconf PAGE_SIZE)
BASE_CPPFLAGS += -DVERSION=\"$(VERSION)\"

BASE_CFLAGS := -std=c11 -pie -fPIE -O2
BASE_CFLAGS += -pedantic -Wall -Wextra -Wno-format-zero-length -Wformat-security

PASST_SRCS = arch.c arp.c bitmap.c checksum.c conf.c dhcp.c dhcpv6.c \
	epoll_ctl.c flow.c fwd.c fwd_rule.c icmp.c igmp.c inany.c iov.c ip.c \
	isolation.c lineread.c log.c mld.c ndp.c netlink.c migrate.c packet.c \
	passt.c pasta.c pcap.c pif.c repair.c serialise.c tap.c tcp.c \
	tcp_buf.c tcp_splice.c tcp_vu.c udp.c udp_flow.c udp_vu.c util.c \
	vhost_user.c virtio.c vu_common.c
QRAP_SRCS = qrap.c
PASST_REPAIR_SRCS = passt-repair.c
PESTO_SRCS = pesto.c bitmap.c fwd_rule.c inany.c ip.c lineread.c serialise.c
SRCS = $(PASST_SRCS) $(QRAP_SRCS) $(PASST_REPAIR_SRCS) $(PESTO_SRCS)

MANPAGES = passt.1 pasta.1 pesto.1 qrap.1 passt-repair.1

PASST_HEADERS = arch.h arp.h bitmap.h checksum.h conf.h dhcp.h dhcpv6.h \
	epoll_ctl.h flow.h fwd.h fwd_rule.h flow_table.h icmp.h icmp_flow.h \
	inany.h iov.h ip.h isolation.h lineread.h log.h migrate.h ndp.h \
	netlink.h packet.h passt.h pasta.h pcap.h pif.h repair.h serialise.h \
	siphash.h tap.h tcp.h tcp_buf.h tcp_conn.h tcp_internal.h tcp_splice.h \
	tcp_vu.h udp.h udp_flow.h udp_internal.h udp_vu.h util.h vhost_user.h \
	virtio.h vu_common.h
QRAP_HEADERS = arp.h ip.h passt.h util.h
PASST_REPAIR_HEADERS = linux_dep.h

C := \#include <sys/random.h>\nint main(){int a=getrandom(0, 0, 0);}
ifeq ($(shell printf "$(C)" | $(CC) -S -xc - -o - >/dev/null 2>&1; echo $$?),0)
	BASE_CPPFLAGS += -DHAS_GETRANDOM
endif

ifeq ($(shell :|$(CC) -fstack-protector-strong -S -xc - -o - >/dev/null 2>&1; echo $$?),0)
	BASE_CFLAGS += -fstack-protector-strong
endif

prefix		?= /usr/local
exec_prefix	?= $(prefix)
bindir		?= $(exec_prefix)/bin
datarootdir	?= $(prefix)/share
docdir		?= $(datarootdir)/doc/passt
mandir		?= $(datarootdir)/man
man1dir		?= $(mandir)/man1

BASEBIN := passt qrap passt-repair pesto
ifeq ($(TARGET_ARCH),x86_64)
BASEBIN += passt.avx2
endif

BIN = $(BASEBIN) pasta
ifeq ($(TARGET_ARCH),x86_64)
BIN += pasta.avx2
endif

all: $(BIN) $(MANPAGES) docs

static: BASE_CPPFLAGS += -DGLIBC_NO_STATIC_NSS
static: BASE_CFLAGS += -static
static: clean all

seccomp.h: seccomp.sh $(PASST_SRCS) $(PASST_HEADERS)
	@ EXTRA_SYSCALLS="$(EXTRA_SYSCALLS)" ARCH="$(TARGET_ARCH)" CC="$(CC)" ./seccomp.sh seccomp.h $(PASST_SRCS) $(PASST_HEADERS)

seccomp_repair.h: seccomp.sh $(PASST_REPAIR_SRCS) $(PASST_REPAIR_HEADERS)
	@ ARCH="$(TARGET_ARCH)" CC="$(CC)" ./seccomp.sh seccomp_repair.h $(PASST_REPAIR_SRCS)

seccomp_pesto.h: seccomp.sh $(PESTO_SRCS)
	@ ARCH="$(TARGET_ARCH)" CC="$(CC)" ./seccomp.sh seccomp_pesto.h $(PESTO_SRCS)

$(BASEBIN): %:
	$(CC) $(BASE_CPPFLAGS) $(CPPFLAGS) $(BASE_CFLAGS) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) -o $@

passt: $(PASST_SRCS) $(PASST_HEADERS) seccomp.h

passt.avx2: BASE_CFLAGS += -Ofast -mavx2 -ftree-vectorize -funroll-loops
passt.avx2: $(PASST_SRCS) $(PASST_HEADERS) seccomp.h

pasta.avx2 pasta.1 pasta: pasta%: passt%
	ln -sf $< $@

qrap: BASE_CPPFLAGS += -DARCH=\"$(TARGET_ARCH)\"
qrap: $(QRAP_SRCS) $(QRAP_HEADERS)

passt-repair: $(PASST_REPAIR_SRCS) $(PASST_REPAIR_HEADERS) seccomp_repair.h

pesto: BASE_CPPFLAGS += -DPESTO
pesto: $(PESTO_SRCS) $(PESTO_HEADERS) seccomp_pesto.h

valgrind: EXTRA_SYSCALLS += rt_sigprocmask rt_sigtimedwait rt_sigaction	\
			    rt_sigreturn getpid gettid kill clock_gettime \
			    mmap|mmap2 munmap open unlink gettimeofday futex \
			    statx readlink
valgrind: BASE_CPPFLAGS += -DVALGRIND
valgrind: BASE_CFLAGS += -g
valgrind: all

.PHONY: clean
clean:
	$(RM) $(BIN) *~ *.o seccomp.h seccomp_repair.h seccomp_pesto.h pasta.1 \
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

CLANG_TIDY = clang-tidy
CLANG_TIDY_FLAGS = -DCLANG_TIDY_58992

clang-tidy: passt.clang-tidy passt-repair.clang-tidy pesto.clang-tidy

.PHONY: %.clang-tidy
%.clang-tidy:
	$(CLANG_TIDY) $(filter %.c,$^) -- $(BASE_CPPFLAGS) $(CPPFLAGS) $(CLANG_TIDY_FLAGS)

passt.clang-tidy: $(PASST_SRCS) $(PASST_HEADERS) seccomp.h
passt-repair.clang-tidy: $(PASST_REPAIR_SRCS) $(PASST_REPAIR_HEADERS) seccomp_repair.h
pesto.clang-tidy: $(PESTO_SRCS) $(PESTO_HEADERS) seccomp_pesto.h

CPPCHECK = cppcheck
CPPCHECK_FLAGS = --std=c11 --error-exitcode=1 --enable=all --force	\
	--inconclusive --library=posix --quiet				\
	--inline-suppr							\
	$(shell if $(CPPCHECK) --quiet --check-level=exhaustive /dev/null; then \
		echo "--check-level=exhaustive";			\
	else								\
		echo "";						\
	fi)								\
	--suppress=missingIncludeSystem

cppcheck: passt.cppcheck passt-repair.cppcheck pesto.cppcheck

.PHONY: %.cppcheck
%.cppcheck:
	$(CPPCHECK) $(CPPCHECK_FLAGS) $(BASE_CPPFLAGS) $^

passt.cppcheck: BASE_CPPFLAGS += -UPESTO
passt.cppcheck: CPPCHECK_FLAGS += --suppress=unusedStructMember
passt.cppcheck: $(PASST_SRCS) $(PASST_HEADERS) seccomp.h

passt-repair.cppcheck: CPPCHECK_FLAGS += --suppress=unusedStructMember
passt-repair.cppcheck: $(PASST_REPAIR_SRCS) $(PASST_REPAIR_HEADERS) seccomp_repair.h

pesto.cppcheck: BASE_CPPFLAGS += -DPESTO
pesto.cppcheck: CPPCHECK_FLAGS += --suppress=unusedFunction:bitmap.c
pesto.cppcheck: CPPCHECK_FLAGS += --suppress=unusedFunction:inany.h
pesto.cppcheck: CPPCHECK_FLAGS += --suppress=unusedFunction:inany.c
pesto.cppcheck: CPPCHECK_FLAGS += --suppress=unusedFunction:ip.h
pesto.cppcheck: CPPCHECK_FLAGS += --suppress=unusedFunction:serialise.c
pesto.cppcheck: CPPCHECK_FLAGS += --suppress=staticFunction:fwd_rule.c
pesto.cppcheck: $(PESTO_SRCS) $(PESTO_HEADERS) seccomp_pesto.h
