#! /bin/sh
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# PASST - Plug A Simple Socket Transport
#  for qemu/UNIX domain socket mode
#
# PASTA - Pack A Subtle Tap Abstraction
#  for network namespace/tap device mode
#
# test/build/static_checkers.sh - Run static checkers
#
# Copyright Red Hat
# Author: David Gibson <david@gibson.dropbear.id.au>

. $(dirname ${0})/../exeter/sh/exeter.sh

# do_check() - Run static checker as a test if the binary is available
# $1:	Static checker (uased as both executable name and make target)
# $@:	Any additional arguments required to make
do_check() {
	checker="${1}"
	shift
	if ! which "${checker}" >/dev/null 2>/dev/null; then
		exeter_skip "${checker} not available"
	fi
	make "${@}" "${checker}"
}

exeter_register cppcheck do_check cppcheck -C ..
exeter_set_description cppcheck "passt sources pass cppcheck"

exeter_register clang_tidy do_check clang-tidy -C ..
exeter_set_description clang_tidy "passt sources pass clang-tidy"

exeter_register flake8 do_check flake8
exeter_set_description flake8 "passt tests in Python pass flake8"

exeter_register mypy do_check mypy
exeter_set_description mypy "passt tests in Python pass mypy --strict"

exeter_main "${@}"
