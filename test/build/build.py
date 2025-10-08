#! /usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# PASST - Plug A Simple Socket Transport
#  for qemu/UNIX domain socket mode
#
# PASTA - Pack A Subtle Tap Abstraction
#  for network namespace/tap device mode
#
# test/build/build.py - Test build and install targets
#
# Copyright Red Hat
# Author: David Gibson <david@gibson.dropbear.id.au>

import contextlib
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Iterator

import exeter


def sh(cmd: str) -> None:
    """Run given command in a shell"""
    subprocess.run(cmd, shell=True)


@contextlib.contextmanager
def clone_sources() -> Iterator[str]:
    """Create a temporary copy of the passt sources.

    When the context enters create a temporary directory and copy the
    passt sources into it.  Clean it up when the context exits.
    """

    os.chdir('..')  # Move from test/ to repo base
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=False) as tmpdir:
        sh(f"cp --parents -d $(git ls-files) {tmpdir}")
        os.chdir(tmpdir)
        yield tmpdir


def test_make(target: str, expected_files: list[str]) -> None:
    """Test `make {target}`

    Arguments:
    target -- make target to invoke
    expected_files -- files make is expected to create

    Verifies that
      1) `make target` completes successfully
      2) expected_files care created by `make target`
      3) expected_files are removed by `make clean`
    """

    ex_paths = [Path(f) for f in expected_files]
    with clone_sources():
        for p in ex_paths:
            assert not p.exists(), f"{p} existed before make"
        sh(f'make {target} CFLAGS="-Werror"')
        for p in ex_paths:
            assert p.exists(), f"{p} wasn't made"
        sh('make clean')
        for p in ex_paths:
            assert not p.exists(), f"{p} existed after make clean"


exeter.register('make_passt', test_make, 'passt', ['passt'])
exeter.register('make_pasta', test_make, 'pasta', ['pasta'])
exeter.register('make_qrap', test_make, 'qrap', ['qrap'])
exeter.register('make_all', test_make, 'all', ['passt', 'pasta', 'qrap'])


@exeter.test
def test_install_uninstall() -> None:
    """Test `make install` and `make uninstall`

    Tests that `make install` installs the expected files to the
    install prefix, and that `make uninstall` removes them again.
    """

    with clone_sources():
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=False) \
             as prefix:
            bindir = Path(prefix) / 'bin'
            mandir = Path(prefix) / 'share/man'
            progs = ['passt', 'pasta', 'qrap']

            # Install
            sh(f'make install CFLAGS="-Werror" prefix={prefix}')

            for prog in progs:
                exe = bindir / prog
                assert exe.is_file(), f"{exe} does not exist as a regular file"
                sh(f'man -M {mandir} -W {prog}')

            # Uninstall
            sh(f'make uninstall prefix={prefix}')

            for prog in progs:
                exe = bindir / prog
                assert not exe.exists(), f"{exe} exists after uninstall"
                sh(f'! man -M {mandir} -W {prog}')


if __name__ == '__main__':
    exeter.main()
