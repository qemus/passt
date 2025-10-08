# SPDX-License-Identifier: GPL-2.0-or-later
#
# Tests makefile
#
# Copyright Red Hat
# Author: David Gibson <david@gibson.dropbear.id.au>

BATS = bats -j $(shell nproc)
EXETOOL = exeter/exetool/exetool
WGET = wget -c
FLAKE8 = flake8
MYPY = mypy --strict

DEBIAN_IMGS = debian-8.11.0-openstack-amd64.qcow2 \
	debian-10-nocloud-amd64.qcow2 \
	debian-10-generic-arm64.qcow2 \
	debian-10-generic-ppc64el-20220911-1135.qcow2 \
	debian-11-nocloud-amd64.qcow2 \
	debian-11-generic-arm64.qcow2 \
	debian-11-generic-ppc64el-20250703-2162.qcow2 \
	debian-sid-nocloud-amd64-daily.qcow2 \
	debian-sid-nocloud-arm64-daily.qcow2 \
	debian-sid-nocloud-ppc64el-daily.qcow2

FEDORA_IMGS = Fedora-Cloud-Base-26-1.5.x86_64.qcow2 \
	Fedora-Cloud-Base-27-1.6.x86_64.qcow2 \
	Fedora-Cloud-Base-28-1.1.x86_64.qcow2 \
	Fedora-Cloud-Base-28-1.1.aarch64.qcow2 \
	Fedora-Cloud-Base-29-1.2.x86_64.qcow2 \
	Fedora-Cloud-Base-29-1.2.aarch64.qcow2 \
	Fedora-Cloud-Base-30-1.2.x86_64.qcow2 \
	Fedora-Cloud-Base-30-1.2.aarch64.qcow2 \
	Fedora-Cloud-Base-31-1.9.x86_64.qcow2 \
	Fedora-Cloud-Base-31-1.9.aarch64.qcow2 \
	Fedora-Cloud-Base-32-1.6.x86_64.qcow2 \
	Fedora-Cloud-Base-32-1.6.aarch64.qcow2 \
	Fedora-Cloud-Base-33-1.2.x86_64.qcow2 \
	Fedora-Cloud-Base-33-1.2.aarch64.qcow2 \
	Fedora-Cloud-Base-34-1.2.x86_64.qcow2 \
	Fedora-Cloud-Base-34-1.2.aarch64.qcow2 \
	Fedora-Cloud-Base-35-1.2.x86_64.qcow2 \
	Fedora-Cloud-Base-35-1.2.aarch64.qcow2

OPENSUSE_IMGS = openSUSE-Leap-15.1-JeOS.x86_64-kvm-and-xen.qcow2 \
	openSUSE-Leap-15.2-JeOS.x86_64-kvm-and-xen.qcow2 \
	openSUSE-Leap-15.3-JeOS.x86_64-kvm-and-xen.qcow2 \
	openSUSE-Tumbleweed-ARM-JeOS-efi.aarch64.raw.xz \
	openSUSE-Tumbleweed-ARM-JeOS-efi.armv7l.raw.xz

UBUNTU_OLD_IMGS = trusty-server-cloudimg-amd64-disk1.img \
	trusty-server-cloudimg-i386-disk1.img \
	trusty-server-cloudimg-ppc64el-disk1.img
UBUNTU_NEW_IMGS = xenial-server-cloudimg-powerpc-disk1.img \
	jammy-server-cloudimg-s390x.img
UBUNTU_IMGS = $(UBUNTU_OLD_IMGS) $(UBUNTU_NEW_IMGS)

DOWNLOAD_ASSETS = $(EXETOOL) mbuto podman \
	$(DEBIAN_IMGS) $(FEDORA_IMGS) $(OPENSUSE_IMGS) $(UBUNTU_IMGS)
TESTDATA_ASSETS = small.bin big.bin medium.bin \
	rampstream
LOCAL_ASSETS = mbuto.img mbuto.mem.img podman/bin/podman QEMU_EFI.fd \
	$(DEBIAN_IMGS:%=prepared-%) $(FEDORA_IMGS:%=prepared-%) \
	$(UBUNTU_NEW_IMGS:%=prepared-%) \
	nstool guest-key guest-key.pub $(TESTDATA_ASSETS)

ASSETS = $(DOWNLOAD_ASSETS) $(LOCAL_ASSETS)

EXETER_PYPATH = exeter/py3
EXETER_PYTHON = build/build.py
EXETER_BATS = smoke/smoke.sh.bats \
	$(EXETER_PYTHON:%=%.bats) build/static_checkers.sh.bats
BATS_FILES = $(EXETER_BATS) \
	podman/test/system/505-networking-pasta.bats

# Python test code (for linters)
PYPKGS = $(EXETER_PYTHON)

CFLAGS = -Wall -Werror -Wextra -pedantic -std=c99

assets: $(ASSETS)

.PHONY: pull-%
pull-%: %
	git -C $* pull

exeter:
	git clone https://gitlab.com/dgibson/exeter.git

exeter/exetool/exetool: pull-exeter

mbuto:
	git clone git://mbuto.sh/mbuto

mbuto/mbuto: pull-mbuto

podman:
	git clone https://github.com/containers/podman.git

# To succesfully build podman, you will need gpgme and systemd
# development packages
podman/bin/podman: pull-podman
	$(MAKE) -C podman

guest-key guest-key.pub:
	ssh-keygen -f guest-key -N ''

mbuto.img: passt.mbuto mbuto/mbuto guest-key.pub rampstream-check.sh $(TESTDATA_ASSETS)
	./mbuto/mbuto -p ./$< -c lz4 -f $@

mbuto.mem.img: passt.mem.mbuto mbuto ../passt.avx2
	./mbuto/mbuto -p ./$< -c lz4 -f $@

nstool: nstool.c
	$(CC) $(CFLAGS) -o $@ $^

QEMU_EFI.fd:
	./find-arm64-firmware.sh $@

prepared-%.qcow2: %.qcow2 ./prepare-distro-img.sh
	qemu-img create -f qcow2 -F qcow2 -b $< $@
	./prepare-distro-img.sh $@

prepared-%.img: %.img ./prepare-distro-img.sh
	qemu-img create -f qcow2 -F qcow2 -b $< $@
	./prepare-distro-img.sh $(IMGTYPE) $@

small.bin:
	dd if=/dev/urandom bs=2k count=1 of=$@

medium.bin:
	dd if=/dev/urandom bs=1k count=5 of=$@

big.bin:
	dd if=/dev/urandom bs=1M count=10 of=$@

flake8: pull-exeter
	PYTHONPATH=$(EXETER_PYPATH) $(FLAKE8) $(PYPKGS)

mypy: pull-exeter
	PYTHONPATH=$(EXETER_PYPATH) $(MYPY) $(PYPKGS)

$(EXETER_BATS): %.bats: % $(EXETOOL)
	PYTHONPATH=$(EXETER_PYPATH) $(EXETOOL) bats -- $< > $@

bats: $(BATS_FILES) pull-podman
	PYTHONPATH=$(EXETER_PYPATH) CONTAINERS_HELPER_BINARY_DIR=.. $(BATS) $(BATS_FILES)

check: assets
	./run

debug: assets
	DEBUG=1 ./run

clean:
	rm -f perf.js *~
	rm -rf .mypy_cache
	rm -f $(LOCAL_ASSETS)
	rm -f $(EXETER_BATS)
	rm -rf test_logs
	rm -f prepared-*.qcow2 prepared-*.img

realclean: clean
	rm -rf $(DOWNLOAD_ASSETS)

# Debian downloads
debian-8.11.0-openstack-%.qcow2:
	$(WGET) -O $@ https://cloud.debian.org/images/cloud/OpenStack/archive/8.11.0/debian-8.11.0-openstack-$*.qcow2

debian-10-nocloud-%.qcow2:
	$(WGET) -O $@ https://cloud.debian.org/images/cloud/buster/latest/debian-10-nocloud-$*.qcow2

debian-10-generic-ppc64el-20220911-1135.qcow2:
	$(WGET) -O $@ https://cloud.debian.org/images/cloud/buster/20220911-1135/debian-10-generic-ppc64el-20220911-1135.qcow2

debian-10-generic-%.qcow2:
	$(WGET) -O $@ https://cloud.debian.org/images/cloud/buster/latest/debian-10-generic-$*.qcow2

debian-11-nocloud-%.qcow2:
	$(WGET) -O $@ https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-nocloud-$*.qcow2

debian-11-generic-%.qcow2:
	$(WGET) -O $@ https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-$*.qcow2

debian-11-generic-ppc64el-20250703-2162.qcow2:
	$(WGET) -O $@ https://cloud.debian.org/images/cloud/bullseye/20250703-2162/debian-11-generic-ppc64el-20250703-2162.qcow2

debian-sid-nocloud-%-daily.qcow2:
	$(WGET) -O $@ https://cloud.debian.org/images/cloud/sid/daily/latest/debian-sid-nocloud-$*-daily.qcow2

# Fedora downloads
Fedora-Cloud-Base-26-1.5.%.qcow2:
	$(WGET) -O $@ http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/26/CloudImages/$*/images/Fedora-Cloud-Base-26-1.5.$*.qcow2

Fedora-Cloud-Base-27-1.6.%.qcow2:
	$(WGET) -O $@ http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/27/CloudImages/$*/images/Fedora-Cloud-Base-27-1.6.$*.qcow2

Fedora-Cloud-Base-28-1.1.%.qcow2:
	$(WGET) -O $@ http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/28/Cloud/$*/images/Fedora-Cloud-Base-28-1.1.$*.qcow2

Fedora-Cloud-Base-29-1.2.%.qcow2:
	$(WGET) -O $@ http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/29/Cloud/$*/images/Fedora-Cloud-Base-29-1.2.$*.qcow2

Fedora-Cloud-Base-30-1.2.%.qcow2:
	$(WGET) -O $@ http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/30/Cloud/$*/images/Fedora-Cloud-Base-30-1.2.$*.qcow2

Fedora-Cloud-Base-31-1.9.%.qcow2:
	$(WGET) -O $@ http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/31/Cloud/$*/images/Fedora-Cloud-Base-31-1.9.$*.qcow2

Fedora-Cloud-Base-32-1.6.%.qcow2:
	$(WGET) -O $@ https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/32/Cloud/$*/images/Fedora-Cloud-Base-32-1.6.$*.qcow2

Fedora-Cloud-Base-33-1.2.%.qcow2:
	$(WGET) -O $@ https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/33/Cloud/$*/images/Fedora-Cloud-Base-33-1.2.$*.qcow2

Fedora-Cloud-Base-34-1.2.%.qcow2:
	$(WGET) -O $@ https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/34/Cloud/$*/images/Fedora-Cloud-Base-34-1.2.$*.qcow2

Fedora-Cloud-Base-35-1.2.%.qcow2:
	$(WGET) -O $@ https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/35/Cloud/$*/images/Fedora-Cloud-Base-35-1.2.$*.qcow2

# OpenSuSE downloads
openSUSE-Leap-15.1-JeOS.x86_64-kvm-and-xen.qcow2:
	$(WGET) -O $@ https://download.opensuse.org/distribution/leap/15.1/jeos/openSUSE-Leap-15.1-JeOS.x86_64-kvm-and-xen.qcow2

openSUSE-Leap-15.2-JeOS.x86_64-kvm-and-xen.qcow2:
	$(WGET) -O $@ https://download.opensuse.org/distribution/leap/15.2/appliances/openSUSE-Leap-15.2-JeOS.x86_64-kvm-and-xen.qcow2

openSUSE-Leap-15.3-JeOS.x86_64-kvm-and-xen.qcow2:
	$(WGET) -O $@ https://download.opensuse.org/distribution/leap/15.3/appliances/openSUSE-Leap-15.3-JeOS.x86_64-kvm-and-xen.qcow2

openSUSE-Tumbleweed-ARM-JeOS-efi.aarch64.raw.xz:
	$(WGET) -O $@ http://download.opensuse.org/ports/aarch64/tumbleweed/appliances/openSUSE-Tumbleweed-ARM-JeOS-efi.aarch64.raw.xz

openSUSE-Tumbleweed-ARM-JeOS-efi.armv7l.raw.xz:
	$(WGET) -O $@ http://download.opensuse.org/ports/armv7hl/tumbleweed/appliances/openSUSE-Tumbleweed-ARM-JeOS-efi.armv7l.raw.xz

# Ubuntu downloads
trusty-server-cloudimg-%-disk1.img:
	$(WGET) -O $@ https://cloud-images.ubuntu.com/trusty/current/trusty-server-cloudimg-$*-disk1.img

xenial-server-cloudimg-powerpc-disk1.img:
	$(WGET) -O $@ https://cloud-images.ubuntu.com/xenial/current/xenial-server-cloudimg-powerpc-disk1.img

jammy-server-cloudimg-s390x.img:
	$(WGET) -O $@ https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-s390x.img
