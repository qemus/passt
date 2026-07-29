#!/bin/sh -e
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# PASST - Plug A Simple Socket Transport
#
# demo.sh - Set up namespace with pasta, start qemu and passt, step by step
#
# Copyright (c) 2020-2022 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

# mbuto_profile() - Profile for https://mbuto.sh/, sourced, return after setting
mbuto_profile() {
	PROGS="${PROGS:-ash,dash,bash ip mount ls ln chmod insmod mkdir sleep
	       lsmod modprobe find grep mknod mv rm umount iperf3 dhclient cat
	       hostname chown socat dd strace ping killall sysctl wget,curl}"

	KMODS="${KMODS:- virtio_net virtio_pci}"

	LINKS="${LINKS:-
		 ash,dash,bash		/init
		 ash,dash,bash		/bin/sh}"

	DIRS="${DIRS} /tmp /sbin /var/log /var/run /var/lib"

	# shellcheck disable=SC2016
	FIXUP="${FIXUP}"'
		cat > /sbin/dhclient-script << EOF
#!/bin/sh

[ -n "\${new_interface_mtu}" ]       && ip link set dev \${interface} mtu \${new_interface_mtu}

[ -n "\${new_ip_address}" ]          && ip addr add \${new_ip_address}/\${new_subnet_mask} dev \${interface}
[ -n "\${new_routers}" ]             && for r in \${new_routers}; do ip route add default via \${r} dev \${interface}; done
[ -n "\${new_domain_name_servers}" ] && for d in \${new_domain_name_servers}; do echo "nameserver \${d}" >> /etc/resolv.conf; done
[ -n "\${new_domain_name}" ]         && echo "search \${new_domain_name}" >> /etc/resolf.conf
[ -n "\${new_domain_search}" ]       && (printf "search"; for d in \${new_domain_search}; do printf " %s" "\${d}"; done; printf "\n") >> /etc/resolv.conf
[ -n "\${new_ip6_address}" ]         && ip addr add \${new_ip6_address}/\${new_ip6_prefixlen} dev \${interface}
[ -n "\${new_dhcp6_name_servers}" ]  && for d in \${new_dhcp6_name_servers}; do echo "nameserver \${d}%\${interface}" >> /etc/resolv.conf; done
[ -n "\${new_dhcp6_domain_search}" ] && (printf "search"; for d in \${new_dhcp6_domain_search}; do printf " %s" "\${d}"; done; printf "\n") >> /etc/resolv.conf
[ -n "\${new_host_name}" ]           && hostname "\${new_host_name}"
exit 0
EOF

		chmod 755 /sbin/dhclient-script

		mkdir -p /etc/dhcp
		echo "timeout 3;" > /etc/dhcp/dhclient.conf

		ln -s /sbin /usr/sbin
		:> /etc/fstab

		echo
		echo "The guest is up and running. Networking is not configured yet:"
		echo
		echo "$ ip address show"
		echo
		ip address show
		echo
		echo "...the next step will take care of that."
		read x

		echo "$ ip link set dev eth0 up"
		ip link set dev eth0 up
		sleep 3
		echo "$ dhclient -4 -1 -sf /sbin/dhclient-script"
		dhclient -4 -1 -sf /sbin/dhclient-script
		sleep 2
		echo "$ dhclient -6 -1 -sf /sbin/dhclient-script"
		dhclient -6 -1 -sf /sbin/dhclient-script
		sleep 2
		echo
		echo "$ ip address show"
		ip address show
		echo
		echo "$ ip route show"
		ip route show
		echo
		echo "...done."
		read x

		echo "Checking connectivity..."
		echo
		echo "$ wget --no-check-certificate https://passt.top/ || curl -k https://passt.top/"
		wget --no-check-certificate https://passt.top/ || curl -k https://passt.top/
		echo "...done."
		read x

		echo "An interactive shell will start now. When you are done,"
		echo "use ^C to terminate the guest and exit the demo."
		echo

		sh +m
'
}

[ "${0##*/}" = "mbuto" ] && mbuto_profile && return 0

# cmd() - Show command being executed, then run it
# $@: Command and arguments
cmd() {
	echo "$" "$@"
	"$@"
}

# next() - Go to next step once a key is pressed, sets $KEY
next() {
	KEY="$(dd ibs=1 count=1 2>/dev/null)"
	echo
}

# cleanup() - Terminate pasta and passt, clean up, restore TTY settings
# shellcheck disable=SC2317
cleanup() {
	[ -f "${DEMO_DIR}/pasta.pid" ] && kill "$(cat "${DEMO_DIR}/pasta.pid")"
	[ -f "${DEMO_DIR}/passt.pid" ] && kill "$(cat "${DEMO_DIR}/passt.pid")"
	rm -rf "${DEMO_DIR}" 2>/dev/null
	[ -n "${STTY_BACKUP}" ] && stty "${STTY_BACKUP}"
}

# start_pasta_delayed() - Start pasta once $DEMO_DIR/pasta.wait is gone
start_pasta_delayed() {
	trap '' EXIT
	while [ -d "${DEMO_DIR}/pasta.wait" ]; do sleep 1; done
	cmd pasta --config-net -P "${DEMO_DIR}/pasta.pid" \
		"$(cat "${DEMO_DIR}/shell.pid")"
	echo
	echo "...pasta is running."
	exit 0
}

# start_mbuto_delayed() - Run mbuto once, and if, $DEMO_DIR/mbuto.wait is gone
start_mbuto_delayed() {
	trap '' EXIT
	while [ -d "${DEMO_DIR}/mbuto.wait" ]; do sleep 1; done
	cmd git -C "${DEMO_DIR}" clone git://mbuto.sh/mbuto
	echo
	cmd "${DEMO_DIR}/mbuto/mbuto" \
		-p "$(realpath "${0}")" -f "${DEMO_DIR}/demo.img"

	mkdir "${DEMO_DIR}/mbuto.done"
	exit 0
}

# into_ns() - Entry point and demo script to run inside new namespace
into_ns() {
	echo "We're in the new namespace now."
	next

	echo "Networking is not configured yet:"
	echo
	cmd ip link show
	echo
	cmd ip address show
	next

	echo "Let's run pasta(1) to configure networking and connect this"
	echo "namespace. Note that we'll run pasta(1) from outside this"
	echo "namespace, because it needs to implement the connection between"
	echo "this namespace and the initial (\"outer\") one."
	next

	echo "$$" > "${DEMO_DIR}/shell.pid"
	rmdir "${DEMO_DIR}/pasta.wait"
	next

	echo "Back to the new namespace, networking is configured:"
	echo
	cmd ip link show
	echo
	cmd ip address show
	next

	echo "and we can now start passt(1), to connect this namespace to a"
	echo "virtual machine. If you want to start a shell in this namespace,"
	echo "press 's' now. Exiting the shell will resume the script."
	next
	[ "${KEY}" = "s" ] && ${SHELL}

	cmd passt -P "${DEMO_DIR}/passt.pid" -s "${DEMO_DIR}/passt.socket"
	echo
	echo "...passt is running."
	next

	__arch="$(uname -m)"
	case ${__arch} in
	x86_64)
		__arch_supported=1
		__qemu_arch="qemu-system-x86_64 -M pc,accel=kvm:tcg"
		;;
	*)
		__arch_supported=0
		;;
	esac

	if [ "${__arch_supported}" -eq 1 ]; then
		echo "We're ready to start a virtual machine now. This script"
		echo "can download and use mbuto (https://mbuto.sh/) to build a"
		echo "basic initramfs image. Otherwise, press 's' to skip this"
		echo "step, and start an existing virtual machine yourself."

		next
	else
		echo "This script doesn't know, yet, how to run a virtual"
		echo "machine on your architecture (${__arch}). Please start an"
		echo "existing virtual machine yourself."
		echo
	fi

	if [ "${__arch_supported}" -eq 0 ] || [ "${KEY}" = "s" ]; then
		echo "Start a virtual machine now. Pressing any key here will"
		echo "terminate passt and pasta, and clean up."
		next

		exit 0
	fi

	rmdir "${DEMO_DIR}/mbuto.wait"
	while [ ! -d "${DEMO_DIR}/mbuto.done" ]; do sleep 1; done
	echo "The guest image is ready. The next step will start the guest."
	echo "Use ^C to terminate it."
	next

	# shellcheck disable=SC2086
	cmd ${__qemu_arch}						    \
		-smp "$(nproc)" -m 1024					    \
		-nographic -serial stdio -nodefaults -no-reboot -vga none   \
		-initrd "${DEMO_DIR}/demo.img"				    \
		-kernel "/boot/vmlinuz-$(uname -r)" -append "console=ttyS0" \
		-device virtio-net-pci,netdev=s				    \
		-netdev stream,id=s,server=off,addr.type=unix,addr.path="${DEMO_DIR}/passt.socket" || :
}

STTY_BACKUP="$(stty -g)"
stty -icanon

trap cleanup EXIT INT
[ "${1}" = "into_ns" ] && into_ns && exit 0

DEMO_DIR="$(mktemp -d)"
mkdir "${DEMO_DIR}/pasta.wait"
mkdir "${DEMO_DIR}/mbuto.wait"

echo "This script sets up a network and user namespace using pasta(1), then"
echo "starts a virtual machine in it, connected via passt(1), pausing at every"
echo "step. Press any key to go to the next step."
next

echo "Let's create the network and user namespace, first. This could be done"
echo "with pasta(1) itself (just issue \`pasta\`), but for the sake of this"
echo "script we'll create it first with unshare(1), and run the next steps"
echo "of this script from there."
next

start_pasta_delayed &
start_mbuto_delayed &
DEMO_DIR="${DEMO_DIR}" cmd unshare -rUn "${0}" into_ns

exit 0
