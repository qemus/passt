<!---
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (c) 2025 Red Hat
Author: Yumei Huang <yuhuang@redhat.com>
-->

# Contributing to passt

Thank you for your interest in contributing! This document explains how
to prepare patches and participate in the email-based review process.

## Workflow

### 1. Clone the project

    git clone git://passt.top/passt

### 2. Make Changes and Commit

* You can decide to work on the master branch or a separate branch as below:

        cd passt
        git checkout -b my-feature-branch

* Edit the source code or documentation following the
  [Linux kernel coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html).

* Stage your changes:

        git add <file1> <file2> ...

* Commit with a message:

        git commit

    The message should describe your changes. See
    [this link](https://docs.kernel.org/process/submitting-patches.html#describe-your-changes)
    for details. Here is an example of commit message format:

        Subsystem: Brief summary

        More detailed explanation if needed, wrapped at 72 chars.

    The `Subsystem` means: which part of the code your change touches.
    For example, it could be "tcp", "test", or "doc" etc.

    If there are some references, use "Links:" tag for anything.

    Besides, passt uses the Linux kernel's "Signed-off-by" process. If you can
    certify the below:

        Developer's Certificate of Origin 1.1

        By making a contribution to this project, I certify that:

            (a) The contribution was created in whole or in part by me and I
                have the right to submit it under the open source license
                indicated in the file; or

            (b) The contribution is based upon previous work that, to the best
                of my knowledge, is covered under an appropriate open source
                license and I have the right under that license to submit that
                work with modifications, whether created in whole or in part
                by me, under the same open source license (unless I am
                permitted to submit under a different license), as indicated
                in the file; or

            (c) The contribution was provided directly to me by some other
                person who certified (a), (b) or (c) and I have not modified
                it.

            (d) I understand and agree that this project and the contribution
                are public and that a record of the contribution (including all
                personal information I submit with it, including my sign-off) is
                maintained indefinitely and may be redistributed consistent with
                this project or the open source license(s) involved.

    Add this line:

	    Signed-off-by: Random J Developer <random@developer.example.org>

    using your name. This will be done for you automatically if you use
    `git commit -s`.  Reverts should also include "Signed-off-by". `git
    revert -s` does that for you.

    Any further SoBs (Signed-off-by:'s) following the author's SoB are
    from people handling and transporting the patch, but were not involved
    in its development. SoB chains should reflect the **real** route a
    patch took as it was propagated to the maintainers, with the first SoB
    entry signalling primary authorship of a single author.

### 3. Generate Patches

Use `git format-patch` to generate patch(es):

    git format-patch -o outgoing/ origin/master

It will generate numbered patch files such as 0001-...patch, 0002-...patch
etc. in the `outgoing` folder.

Or you can use `git format-patch -n`. For example if you want to format just
three patches:

    git format-patch -3 -o outgoing/

If you send a series of patches, use the `--cover-letter` option with
`git format-patch`:

    git format-patch -o outgoing/ origin/main --cover-letter

This will generate a cover letter besides your patches. Edit the cover
letter before sending.

### 4. Send Patches

Use `git send-email` to send patches directly to the mailing list:

    git send-email --to=passt-dev@passt.top outgoing/000*.patch

If there are CCs (e.g. maintainers, reviewers), you can add them with `--cc`:

    git send-email --to=passt-dev@passt.top --cc=maintainer@example.com
    outgoing/000*.patch

### 5. Responding to Review Feedback

* Be open to feedback on both code and documentation.

* Update your patch as needed, and regenerate patches:

        git add <file1> <file2> ...
        git commit --amend
        git format-patch -v2 -o outgoing/ origin/master

* Send the revised patches:

        git send-email --to=passt-dev@passt.top outgoing/v2-000*.patch

### 6. Tips and Best Practices

* Keep changes focused and easy to review. Please refer to
  [split-changes](https://docs.kernel.org/process/submitting-patches.html#split-changes)
  to separate each logical change into a separate patch.

* Test your changes thoroughly. Refer to
  [test/README.md](/passt/tree/test/README.md) file for testing.
  It's recommended to run at least a 'make cppcheck' and 'make clang-tidy'
  other than a specific manual test of the functionality / issue at hand.

* Include documentation updates if your change affects usage.

Thank you for helping improve passt! Your contributions make a big difference.
