# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright Red Hat
# Author: David Gibson <david@gibson.dropbear.id.au>

TARGETS = reuseaddr-priority recv-zero udp-close-dup listen-vs-repair \
	tcp-close-rst
SRCS = reuseaddr-priority.c recv-zero.c udp-close-dup.c listen-vs-repair.c \
	tcp-close-rst.c
CFLAGS = -Wall

all: cppcheck clang-tidy $(TARGETS:%=check-%)

$(TARGETS): %: %.c common.c common.h

check-%: %
	./$<

cppcheck:
	cppcheck --std=c11 --error-exitcode=1 --enable=all --force \
		--check-level=exhaustive --inline-suppr \
		--inconclusive --library=posix --quiet \
		--suppress=missingIncludeSystem \
		$(SRCS)

clang-tidy:
	clang-tidy --checks=*,\
	-altera-id-dependent-backward-branch,\
	-altera-unroll-loops,\
	-android-cloexec-accept,\
	-bugprone-easily-swappable-parameters,\
	-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,\
	-concurrency-mt-unsafe,\
	-cppcoreguidelines-avoid-non-const-global-variables,\
	-cppcoreguidelines-init-variables,\
	-cppcoreguidelines-macro-to-enum,\
	-google-readability-braces-around-statements,\
	-hicpp-braces-around-statements,\
	-llvmlibc-restrict-system-libc-headers,\
	-misc-include-cleaner,\
	-modernize-macro-to-enum,\
	-readability-braces-around-statements,\
	-readability-function-cognitive-complexity,\
	-readability-identifier-length,\
	-readability-isolate-declaration \
	$(SRCS)

clean:
	rm -f $(TARGETS) *.o *~
