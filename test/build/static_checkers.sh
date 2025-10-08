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

. $(dirname $0)/../exeter/sh/exeter.sh

exeter_register cppcheck make -C .. cppcheck
exeter_set_description cppcheck "passt sources pass cppcheck"

exeter_register clang_tidy make -C .. clang-tidy
exeter_set_description clang_tidy "passt sources pass clang-tidy"

exeter_register flake8 make flake8
exeter_set_description flake8 "passt tests in Python pass flake8"

exeter_register mypy make mypy
exeter_set_description mypy "passt tests in Python pass mypy --strict"

exeter_main "$@"
